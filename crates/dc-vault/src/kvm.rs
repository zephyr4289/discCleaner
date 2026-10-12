//! Raw KVM ioctl surface (Linux `include/uapi/linux/kvm.h`, x86-64).
//!
//! Everything is reproduced as pinned literals with layout assertions —
//! the KVM UAPI is frozen per Linus' ABI rules, and each ioctl number is
//! recomputed from its `_IO/_IOR/_IOW` definition so a typo cannot survive
//! the constant-check tests.

#![allow(dead_code)] // full surface kept for the passthrough plumbing

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd as _, OwnedFd};

const KVMIO: libc::c_ulong = 0xAE;

const fn io(nr: libc::c_ulong) -> libc::c_ulong {
    (KVMIO << 8) | nr
}
const fn ior(nr: libc::c_ulong, size: libc::c_ulong) -> libc::c_ulong {
    (2 << 30) | (size << 16) | io(nr)
}
const fn iow(nr: libc::c_ulong, size: libc::c_ulong) -> libc::c_ulong {
    (1 << 30) | (size << 16) | io(nr)
}

// --- ioctls on /dev/kvm -----------------------------------------------------
pub const KVM_GET_API_VERSION: libc::c_ulong = io(0x00); // _IO
pub const KVM_CREATE_VM: libc::c_ulong = io(0x01); // _IO, arg = vm type
pub const KVM_CHECK_EXTENSION: libc::c_ulong = io(0x03); // _IO, arg = cap id
pub const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = io(0x04); // _IO

// --- ioctls on the VM fd ----------------------------------------------------
/// `_IOW(KVMIO, 0x46, struct kvm_userspace_memory_region)` (32 bytes:
/// two u32 words + three u64 words, no padding on any supported ABI).
pub const KVM_SET_USER_MEMORY_REGION: libc::c_ulong = iow(0x46, 32);
/// `_IO(KVMIO, 0xe0)` — actually `_IOW(KVMIO, 0xe0, kvm_create_device)`;
/// see `KVM_CREATE_DEVICE_SIZE`.
pub const KVM_CREATE_DEVICE: libc::c_ulong = iow(0xe0, 12);
pub const KVM_CREATE_DEVICE_SIZE: libc::c_ulong = 12;

// --- ioctls on the vCPU fd ---------------------------------------------------
pub const KVM_CREATE_VCPU: libc::c_ulong = io(0x41); // _IO
pub const KVM_RUN: libc::c_ulong = io(0x80);
/// `_IOR(KVMIO, 0x81, struct kvm_regs)` — 18 × u64 = 144 bytes.
pub const KVM_GET_REGS: libc::c_ulong = ior(0x81, 144);
pub const KVM_SET_REGS: libc::c_ulong = iow(0x82, 144);
/// `_IOR(KVMIO, 0x83, struct kvm_sregs)` — 280 bytes on x86-64.
pub const KVM_GET_SREGS: libc::c_ulong = ior(0x83, 280);
pub const KVM_SET_SREGS: libc::c_ulong = iow(0x84, 280);

// --- VM types (x86, `KVM_CREATE_VM` argument) ------------------------------
pub const KVM_X86_DEFAULT_VM: u64 = 0;
/// AMD SEV guest VM (memory encrypted with guest-only ASID key).
pub const KVM_X86_SEV_VM: u64 = 1;
/// AMD SEV-ES (encrypted state on top of encrypted memory).
pub const KVM_X86_SEV_ES_VM: u64 = 2;
/// Software-isolated guest (KVM_SW_PROTECTED_VM — the TDX/SNP migration path).
pub const KVM_X86_SW_PROTECTED_VM: u64 = 3;

// --- vCPU exit reasons -------------------------------------------------------
pub const KVM_EXIT_UNKNOWN: u32 = 0;
pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_HLT: u32 = 5;
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;
pub const KVM_EXIT_FAIL_ENTRY: u32 = 9;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 10;

/// `struct kvm_regs` — 18 u64: rax rbx rcx rdx rsi rdi rsp rbp r8..r15,
/// rip, rflags.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

const _: () = assert!(std::mem::size_of::<KvmRegs>() == 144);

/// `struct kvm_segment` (24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    /// 64-bit code flag (L).
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

const _: () = assert!(std::mem::size_of::<KvmSegment>() == 24);

/// `struct kvm_sregs` — 8 segments + control registers + EFER + LAPIC base
/// + interrupt bitmap (KVM_MAX_INTERRUPTS = 256 → 4 × u64).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

const _: () = assert!(std::mem::size_of::<KvmSregs>() == 280);

/// `struct kvm_userspace_memory_region` (40 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KvmUserspaceMemoryRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
}

const _: () = assert!(std::mem::size_of::<KvmUserspaceMemoryRegion>() == 32);

// --- kvm_run field offsets (struct kvm_run, stable UAPI) ---------------------
/// `exit_reason` is a u32 at offset 8 of the mmap'd `kvm_run`.
pub const KVM_RUN_EXIT_REASON_OFFSET: usize = 8;
/// The `io` union member starts at offset 32.
pub const KVM_RUN_IO_OFFSET: usize = 32;

/// CR0 bits.
pub const X86_CR0_PE: u64 = 0x1;
pub const X86_CR0_PG: u64 = 0x8000_0000;
/// CR4 PAE (required for long-mode page tables).
pub const X86_CR4_PAE: u64 = 0x20;
/// EFER LME | LMA — long mode enabled + active.
pub const X86_EFER_LME_LMA: u64 = 0x500;

/// Errors from the raw KVM surface.
#[derive(Debug, thiserror::Error)]
pub enum KvmError {
    #[error("/dev/kvm unavailable: {0} — VMX/SVM not exposed or kvm module not loaded")]
    NoKvm(String),
    #[error("KVM API version {got} != 12 (expected the frozen UAPI)")]
    ApiVersion { got: i32 },
    #[error("KVM ioctl {what} failed: errno {errno}")]
    Ioctl { what: &'static str, errno: i32 },
    #[error("KVM run mmap failed: errno {errno}")]
    RunMap { errno: i32 },
}

pub type KvmResult<T> = Result<T, KvmError>;

/// Open `/dev/kvm` and verify the API version.
pub struct Kvm {
    fd: OwnedFd,
}

impl Kvm {
    pub fn open() -> KvmResult<Self> {
        let fd = std::fs::File::open("/dev/kvm")
            .map_err(|e| KvmError::NoKvm(e.to_string()))?
            .into();
        let kvm = Self { fd };
        let version = kvm.api_version()?;
        if version != 12 {
            return Err(KvmError::ApiVersion { got: version });
        }
        Ok(kvm)
    }

    pub fn api_version(&self) -> KvmResult<i32> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_GET_API_VERSION, 0usize) };
        errno_check("KVM_GET_API_VERSION", ret)
    }

    pub fn check_extension(&self, cap: libc::c_ulong) -> KvmResult<i32> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_CHECK_EXTENSION, cap) };
        errno_check("KVM_CHECK_EXTENSION", ret)
    }

    /// Create a VM of the given type. `Err(ENOENT/EINVAL)`-shaped failures
    /// mean the kernel has no support for that VM type — the caller treats
    /// this as a capability probe.
    pub fn create_vm(&self, vm_type: u64) -> KvmResult<OwnedFd> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_CREATE_VM, vm_type) };
        errno_check("KVM_CREATE_VM", ret).map(|r| {
            // SAFETY: a successful KVM_CREATE_VM returns a brand-new fd
            // (positive c_int) that we now own exclusively.
            unsafe { OwnedFd::from_raw_fd(r) }
        })
    }

    /// Probe whether the kernel supports a confidential-VM type by trying
    /// to create one (immediately dropped).
    pub fn vm_type_supported(&self, vm_type: u64) -> bool {
        self.create_vm(vm_type).is_ok()
    }

    pub fn vcpu_mmap_size(&self) -> KvmResult<usize> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0usize) };
        errno_check("KVM_GET_VCPU_MMAP_SIZE", ret).map(|r| r as usize)
    }
}

/// VCPU / VM-fd helper namespace.
pub struct VmIo;

impl VmIo {
    pub fn set_user_memory_region(
        vm: BorrowedFd<'_>,
        region: &KvmUserspaceMemoryRegion,
    ) -> KvmResult<()> {
        let ret = unsafe {
            libc::ioctl(
                vm.as_raw_fd(),
                KVM_SET_USER_MEMORY_REGION,
                region as *const KvmUserspaceMemoryRegion,
            )
        };
        errno_check("KVM_SET_USER_MEMORY_REGION", ret).map(|_| ())
    }

    pub fn create_vcpu(vm: BorrowedFd<'_>, id: u64) -> KvmResult<OwnedFd> {
        let ret = unsafe { libc::ioctl(vm.as_raw_fd(), KVM_CREATE_VCPU, id) };
        errno_check("KVM_CREATE_VCPU", ret).map(|r| {
            // SAFETY: a successful KVM_CREATE_VCPU returns a fresh fd.
            unsafe { OwnedFd::from_raw_fd(r) }
        })
    }

    pub fn get_regs(vcpu: BorrowedFd<'_>) -> KvmResult<KvmRegs> {
        let mut regs = KvmRegs::default();
        let ret = unsafe { libc::ioctl(vcpu.as_raw_fd(), KVM_GET_REGS, &mut regs as *mut KvmRegs) };
        errno_check("KVM_GET_REGS", ret).map(|_| regs)
    }

    pub fn set_regs(vcpu: BorrowedFd<'_>, regs: &KvmRegs) -> KvmResult<()> {
        let ret = unsafe { libc::ioctl(vcpu.as_raw_fd(), KVM_SET_REGS, regs as *const KvmRegs) };
        errno_check("KVM_SET_REGS", ret).map(|_| ())
    }

    pub fn get_sregs(vcpu: BorrowedFd<'_>) -> KvmResult<KvmSregs> {
        let mut sregs = KvmSregs {
            cs: KvmSegment::default(),
            ds: KvmSegment::default(),
            es: KvmSegment::default(),
            fs: KvmSegment::default(),
            gs: KvmSegment::default(),
            ss: KvmSegment::default(),
            tr: KvmSegment::default(),
            ldt: KvmSegment::default(),
            cr0: 0,
            cr2: 0,
            cr3: 0,
            cr4: 0,
            cr8: 0,
            efer: 0,
            apic_base: 0,
            interrupt_bitmap: [0; 4],
        };
        let ret =
            unsafe { libc::ioctl(vcpu.as_raw_fd(), KVM_GET_SREGS, &mut sregs as *mut KvmSregs) };
        errno_check("KVM_GET_SREGS", ret).map(|_| sregs)
    }

    pub fn set_sregs(vcpu: BorrowedFd<'_>, sregs: &KvmSregs) -> KvmResult<()> {
        let ret = unsafe { libc::ioctl(vcpu.as_raw_fd(), KVM_SET_SREGS, sregs as *const KvmSregs) };
        errno_check("KVM_SET_SREGS", ret).map(|_| ())
    }
}

/// Assert an ioctl return value; echo it back on success.
fn errno_check(what: &'static str, ret: libc::c_int) -> KvmResult<libc::c_int> {
    if ret < 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return Err(KvmError::Ioctl { what, errno });
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_are_pinned() {
        // Recomputed from the UAPI definitions:
        assert_eq!(KVM_GET_API_VERSION, 0xAE00);
        assert_eq!(KVM_CREATE_VM, 0xAE01);
        assert_eq!(KVM_CHECK_EXTENSION, 0xAE03);
        assert_eq!(KVM_GET_VCPU_MMAP_SIZE, 0xAE04);
        assert_eq!(KVM_CREATE_VCPU, 0xAE41);
        assert_eq!(KVM_RUN, 0xAE80);
        assert_eq!(KVM_SET_USER_MEMORY_REGION, 0x4020_AE46);
        assert_eq!(KVM_GET_REGS, 0x8090_AE81);
        assert_eq!(KVM_SET_REGS, 0x4090_AE82);
        assert_eq!(KVM_GET_SREGS, 0x8118_AE83);
        assert_eq!(KVM_SET_SREGS, 0x4118_AE84);
    }

    #[test]
    fn uapi_struct_layouts_are_frozen() {
        assert_eq!(std::mem::offset_of!(KvmRegs, rsp), 48);
        assert_eq!(std::mem::offset_of!(KvmRegs, rip), 128);
        assert_eq!(std::mem::offset_of!(KvmRegs, rflags), 136);
        assert_eq!(std::mem::offset_of!(KvmSegment, base), 0);
        assert_eq!(std::mem::offset_of!(KvmSegment, limit), 8);
        assert_eq!(std::mem::offset_of!(KvmSegment, selector), 12);
        assert_eq!(std::mem::offset_of!(KvmSregs, cs), 0);
        assert_eq!(std::mem::offset_of!(KvmSregs, cr0), 192);
        assert_eq!(std::mem::offset_of!(KvmSregs, cr3), 208);
        assert_eq!(std::mem::offset_of!(KvmSregs, efer), 232);
        assert_eq!(
            std::mem::offset_of!(KvmUserspaceMemoryRegion, guest_phys_addr),
            8
        );
        assert_eq!(
            std::mem::offset_of!(KvmUserspaceMemoryRegion, memory_size),
            16
        );
        assert_eq!(
            std::mem::offset_of!(KvmUserspaceMemoryRegion, userspace_addr),
            24
        );
    }

    #[test]
    fn missing_kvm_fails_clean() {
        // On CI (no /dev/kvm, or a sandbox exposing it) this must be a
        // clean KvmError — never a panic. If KVM exists, construction
        // must succeed with the frozen API version.
        match Kvm::open() {
            Ok(kvm) => assert_eq!(kvm.api_version().unwrap(), 12),
            Err(KvmError::NoKvm(_)) => {}
            Err(other) => panic!("unexpected KVM open error: {other:?}"),
        }
    }
}
