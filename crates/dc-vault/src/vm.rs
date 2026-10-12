//! The micro-VM builder: memory-locked guest RAM, identity-mapped long-mode
//! page tables, a two-segment GDT, and the vCPU state to enter 64-bit mode
//! directly (no BIOS, no real-mode dance — the hypervisor IS the firmware).
//!
//! Guest physical map (4 MiB, single `KVM_SET_USER_MEMORY_REGION`):
//! ```text
//!   0x0001000   PML4 (entry 0 → PDPT)
//!   0x0002000   PDPT (entry 0 → 1 GiB huge page, present|rw)
//!   0x0003000   PD   (unused leaf when the PDPT covers with a huge page;
//!                     kept mapped for future 2 MiB splits)
//!   0x0004000   GDT: null, code64 (L=1), data
//!   0x0010000   payload entry (RIP)
//!   0x0110000   seed page (host CSPRNG entropy, injected pre-run)
//!   0x0111000   sealed result page (key out, magic stamp)
//!   0x0200000   stack top
//! ```

use crate::kvm::*;
use crate::payload::{RESULT_MAGIC, RESULT_MAGIC_OFFSET, SESSION_KEY_LEN, layout};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Instant;

/// PDE/PT flags: present | read-write.
const PRESENT_RW: u64 = 0x03;
/// Present | read-write | huge (1 GiB leaf in a PDPT entry).
const PRESENT_RW_HUGE: u64 = 0x83;

/// Guest-RAM owner: page-aligned, mlock'd from construction to drop, and
/// zeroized on drop (the seed and any residual key material never hit
/// swap or a post-free allocator).
pub struct GuestRam {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: the mapping is private to this instance and not aliased
// elsewhere; the KVM VM fd that maps it is dropped before this is.
unsafe impl Send for GuestRam {}

impl GuestRam {
    pub fn allocate(len: usize) -> Result<Self, KvmError> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(KvmError::RunMap {
                errno: std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOMEM),
            });
        }
        // Lock the pages into physical RAM: no swap, no core-dump path.
        if unsafe { libc::mlock(ptr, len) } != 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ENOMEM);
            unsafe { libc::munmap(ptr, len) };
            return Err(KvmError::RunMap { errno });
        }
        unsafe { std::ptr::write_bytes(ptr, 0, len) };
        Ok(Self {
            ptr: ptr as *mut u8,
            len,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: exclusive mapping owned by self.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn write_at(&mut self, guest_phys: u64, bytes: &[u8]) {
        let off = guest_phys as usize;
        assert!(off + bytes.len() <= self.len, "guest write out of RAM");
        // SAFETY: exclusive mutable mapping owned by self.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(off), bytes.len()) };
    }

    pub fn read_at(&self, guest_phys: u64, len: usize) -> &[u8] {
        let off = guest_phys as usize;
        assert!(off + len <= self.len, "guest read out of RAM");
        // SAFETY: see as_slice.
        unsafe { std::slice::from_raw_parts(self.ptr.add(off), len) }
    }

    fn volatile_zero(&mut self, guest_phys: u64, len: usize) {
        let off = guest_phys as usize;
        assert!(off + len <= self.len);
        // SAFETY: volatile so the compiler cannot elide the wipe.
        unsafe {
            for i in 0..len {
                std::ptr::write_volatile(self.ptr.add(off + i), 0u8);
            }
        }
    }
}

impl Drop for GuestRam {
    fn drop(&mut self) {
        // Zeroize before unlock+unmap.
        // SAFETY: owned mapping.
        unsafe {
            std::ptr::write_volatile(self.ptr, 0);
            for i in 0..self.len {
                std::ptr::write_volatile(self.ptr.add(i), 0u8);
            }
            libc::munlock(self.ptr as *const libc::c_void, self.len);
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

/// VM state summary for the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryEncryption {
    /// AMD SEV (KVM_X86_SEV_VM).
    Sev,
    /// AMD SEV-ES.
    SevEs,
    /// Software-protected VM (the TDX/SNP migration path).
    SwProtected,
    /// No memory encryption available (development only — refuses to
    /// certify under `--vault` with `require_encrypted` semantics).
    None,
}

impl MemoryEncryption {
    pub fn label(self) -> &'static str {
        match self {
            Self::Sev => "AMD SEV",
            Self::SevEs => "AMD SEV-ES",
            Self::SwProtected => "SW-protected VM",
            Self::None => "none",
        }
    }
}

/// The live micro-VM.
pub struct MicroVm {
    pub ram: GuestRam,
    #[allow(dead_code)] // owned fd: keeps the VM alive
    pub vm_fd: std::os::fd::OwnedFd,
    pub vcpu_fd: std::os::fd::OwnedFd,
    pub encryption: MemoryEncryption,
    kvm_run: *mut u8,
    kvm_run_len: usize,
    exits: u32,
}

// The kvm_run mapping is shared with the kernel but owned by this struct.
unsafe impl Send for MicroVm {}

/// What happened when the vCPU stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultRunOutcome {
    /// Guest halted: result page stamped with the magic.
    Completed {
        key: [u8; SESSION_KEY_LEN],
    },
    HaltedWithoutStamp,
    Shutdown,
    InternalError(u32),
    ExitIo(u16),
    Failed,
}

impl MicroVm {
    /// Build the guest and the vCPU state. `encryption` picks the VM type
    /// actually used.
    pub fn build(kvm: &Kvm, encryption: MemoryEncryption) -> Result<Self, KvmError> {
        let vm_type = match encryption {
            MemoryEncryption::Sev => KVM_X86_SEV_VM,
            MemoryEncryption::SevEs => KVM_X86_SEV_ES_VM,
            MemoryEncryption::SwProtected => KVM_X86_SW_PROTECTED_VM,
            MemoryEncryption::None => KVM_X86_DEFAULT_VM,
        };
        let vm_fd = kvm.create_vm(vm_type)?;
        let mut ram = GuestRam::allocate(layout::GUEST_RAM)?;

        // Page tables: PML4[0] → PDPT @0x2000; PDPT[0] = huge 1 GiB page.
        // SAFETY: raw writes into our own aligned mapping.
        unsafe {
            std::ptr::write_volatile(ram.ptr.add(0x1000) as *mut u64, 0x2000 | PRESENT_RW);
            std::ptr::write_volatile(ram.ptr.add(0x2000) as *mut u64, PRESENT_RW_HUGE);
        }

        // GDT at 0x4000: [0] null, [1] code64, [2] data.
        // code64: L=1, type=0x0B (exec/read), present, granularity.
        let code_desc: u64 = 0x00AF_9A00_0000_FFFF;
        let data_desc: u64 = 0x00CF_9200_0000_FFFF;
        ram.write_at(layout::GDT + 8, &code_desc.to_le_bytes());
        ram.write_at(layout::GDT + 16, &data_desc.to_le_bytes());

        // Payload + zeroed seed/result pages.
        ram.write_at(layout::PAYLOAD, &crate::payload::payload_bytes());
        // (seed injected by `inject_seed` before the run)

        // Map the whole guest RAM as slot 0.
        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: ram.len as u64,
            userspace_addr: ram.ptr as u64,
        };
        let vm_borrow = unsafe { BorrowedFd::borrow_raw(vm_fd.as_raw_fd()) };
        VmIo::set_user_memory_region(vm_borrow, &region)?;

        // vCPU + entry state.
        let vcpu_fd = VmIo::create_vcpu(vm_borrow, 0)?;
        let vcpu_borrow = unsafe { BorrowedFd::borrow_raw(vcpu_fd.as_raw_fd()) };

        let code = KvmSegment {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x08,
            type_: 0x0B,
            present: 1,
            dpl: 0,
            db: 0,
            s: 1,
            l: 1, // 64-bit
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let data = KvmSegment {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x10,
            type_: 0x03,
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let sregs = KvmSregs {
            cs: code,
            ds: data,
            es: data,
            fs: KvmSegment {
                unusable: 1,
                ..data
            },
            gs: KvmSegment {
                unusable: 1,
                ..data
            },
            ss: data,
            tr: KvmSegment {
                unusable: 1,
                type_: 0x0B,
                present: 0,
                ..data
            },
            ldt: KvmSegment {
                unusable: 1,
                ..data
            },
            cr0: X86_CR0_PE | X86_CR0_PG,
            cr2: 0,
            cr3: layout::PAGE_TABLES,
            cr4: X86_CR4_PAE,
            cr8: 0,
            efer: X86_EFER_LME_LMA,
            apic_base: 0,
            interrupt_bitmap: [0; 4],
        };
        VmIo::set_sregs(vcpu_borrow, &sregs)?;
        VmIo::set_regs(
            vcpu_borrow,
            &KvmRegs {
                rip: layout::PAYLOAD,
                rsp: layout::STACK_TOP,
                rflags: 0x2,
                ..KvmRegs::default()
            },
        )?;

        // Map kvm_run for the run loop.
        let kvm_run_len = kvm.vcpu_mmap_size()?;
        let kvm_run = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                kvm_run_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                vcpu_fd.as_raw_fd(),
                0,
            )
        };
        if kvm_run == libc::MAP_FAILED {
            return Err(KvmError::RunMap {
                errno: std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOMEM),
            });
        }

        Ok(Self {
            ram,
            vm_fd,
            vcpu_fd,
            encryption,
            kvm_run: kvm_run as *mut u8,
            kvm_run_len,
            exits: 0,
        })
    }

    /// Inject host entropy into the seed page (called before `run`).
    pub fn inject_seed(&mut self, seed: &[u8; SESSION_KEY_LEN]) {
        self.ram.write_at(layout::SEED_PAGE, seed);
    }

    /// Run the vCPU until halt/exit. Deadline-guarded: a wedged guest
    /// fails the session in bounded time instead of hanging the wipe.
    pub fn run(&mut self, deadline: Instant) -> Result<VaultRunOutcome, KvmError> {
        let vcpu_borrow = unsafe { BorrowedFd::borrow_raw(self.vcpu_fd.as_raw_fd()) };
        loop {
            if Instant::now() >= deadline {
                return Ok(VaultRunOutcome::Failed);
            }
            let ret = unsafe { libc::ioctl(vcpu_borrow.as_raw_fd(), KVM_RUN, 0usize) };
            self.exits += 1;
            if ret < 0 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                if errno == libc::EINTR {
                    continue;
                }
                return Err(KvmError::Ioctl {
                    what: "KVM_RUN",
                    errno,
                });
            }
            // SAFETY: the kvm_run mapping is MAP_SHARED with the vCPU fd.
            let reason = unsafe {
                std::ptr::read_volatile(self.kvm_run.add(KVM_RUN_EXIT_REASON_OFFSET) as *const u32)
            };
            match reason {
                KVM_EXIT_HLT => {
                    let stamped = self
                        .ram
                        .read_at(layout::RESULT_PAGE + RESULT_MAGIC_OFFSET as u64, 8);
                    if stamped == RESULT_MAGIC.to_le_bytes() {
                        let mut key = [0u8; SESSION_KEY_LEN];
                        key.copy_from_slice(self.ram.read_at(layout::RESULT_PAGE, SESSION_KEY_LEN));
                        return Ok(VaultRunOutcome::Completed { key });
                    }
                    return Ok(VaultRunOutcome::HaltedWithoutStamp);
                }
                KVM_EXIT_SHUTDOWN => return Ok(VaultRunOutcome::Shutdown),
                KVM_EXIT_FAIL_ENTRY | KVM_EXIT_INTERNAL_ERROR => {
                    return Ok(VaultRunOutcome::InternalError(reason));
                }
                KVM_EXIT_IO => {
                    let port = unsafe {
                        std::ptr::read_volatile(
                            self.kvm_run.add(KVM_RUN_IO_OFFSET + 2) as *const u16
                        )
                    };
                    return Ok(VaultRunOutcome::ExitIo(port));
                }
                _ => return Ok(VaultRunOutcome::Failed),
            }
        }
    }

    /// Wipe the key material out of guest RAM after the session key has
    /// been consumed (defense-in-depth after the Drop zeroization).
    pub fn scrub_result_page(&mut self) {
        self.ram.volatile_zero(layout::RESULT_PAGE, 0x1000);
        self.ram.volatile_zero(layout::SEED_PAGE, 0x1000);
    }

    pub fn exits(&self) -> u32 {
        self.exits
    }
}

impl Drop for MicroVm {
    fn drop(&mut self) {
        // SAFETY: owned mappings; vm/vcpu fds drop after.
        unsafe {
            libc::munmap(self.kvm_run as *mut libc::c_void, self.kvm_run_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_ram_is_zeroed_and_locked() {
        let mut ram = GuestRam::allocate(0x2000).expect("small mlock'd mapping");
        assert!(ram.as_slice().iter().all(|b| *b == 0));
        ram.write_at(0x100, &[1, 2, 3, 4]);
        assert_eq!(ram.read_at(0x100, 4), &[1, 2, 3, 4]);
        // Drop path zeroizes; nothing to assert beyond not crashing.
    }

    #[test]
    fn oversized_guest_write_is_refused() {
        let mut ram = GuestRam::allocate(0x1000).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ram.write_at(0xFF0, &[0u8; 32]); // crosses the mapping end
        }));
        assert!(result.is_err(), "out-of-RAM guest writes must panic loudly");
    }

    /// Full boot test — only meaningful when /dev/kvm exists and is
    /// usable (CI containers may not expose it; the vault gate in dc
    /// treats that as a clean refusal, not a test failure).
    #[test]
    fn micro_vm_boots_and_stamps_result_page() {
        let kvm = match Kvm::open() {
            Ok(k) => k,
            Err(KvmError::NoKvm(_)) => {
                eprintln!("skipping: no /dev/kvm in this environment");
                return;
            }
            Err(e) => panic!("unexpected KVM error: {e:?}"),
        };
        let mut vm = MicroVm::build(&kvm, MemoryEncryption::None).expect("build micro VM");
        vm.inject_seed(&[0x42u8; SESSION_KEY_LEN]);
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        match vm.run(deadline).expect("kvm run") {
            VaultRunOutcome::Completed { key } => {
                assert_ne!(key, [0u8; SESSION_KEY_LEN]);
            }
            other => panic!("vault guest did not complete: {other:?}"),
        }
        vm.scrub_result_page();
    }
}
