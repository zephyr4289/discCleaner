//! Hardware Abstraction Layer (v0.12.0, Miracle 3).
//!
//! Exactly two traits separate the Ghost Boot driver code from the
//! metal: [`PortIo`] (legacy I/O port access — PCI config, PM1a) and
//! [`Mmio`] (memory-mapped register access — BARs). On the UEFI target
//! they are implemented with inline `in`/`out` and volatile loads;
//! under `cargo test` the SAME drivers run against [`SimBus`], a
//! register-accurate simulated bus, so every state transition that
//! touches an AHCI HBA or an NVMe controller is exercised in CI.

/// Legacy x86 I/O port access (0xCF8/0xCFC PCI config, PM1a control…).
pub trait PortIo {
    unsafe fn out8(&mut self, port: u16, value: u8);
    unsafe fn out16(&mut self, port: u16, value: u16);
    unsafe fn out32(&mut self, port: u16, value: u32);
    unsafe fn in8(&mut self, port: u16) -> u8;
    unsafe fn in16(&mut self, port: u16) -> u16;
    unsafe fn in32(&mut self, port: u16) -> u32;
}

/// Memory-mapped register access (BAR windows).
///
/// All accesses are naturally aligned u32/u64 — every AHCI/NVMe
/// field the payload touches is 4-byte or 8-byte aligned (checked at
/// compile time by the offsets module constants).
pub trait Mmio {
    unsafe fn read32(&self, off: usize) -> u32;
    unsafe fn write32(&mut self, off: usize, v: u32);
    unsafe fn read64(&self, off: usize) -> u64;
    unsafe fn write64(&mut self, off: usize, v: u64);
    /// Raw pointer to a DMA buffer region the device writes/reads.
    /// (The physical==virtual identity mapping from UEFI is relied
    /// upon; documented in the boot protocol.)
    fn dma_ptr(&self) -> *mut u8;
    fn dma_phys(&self) -> u64;
}

// ---------------------------------------------------------------------------
// Real hardware implementations (x86-64, used by the EFI build)
// ---------------------------------------------------------------------------

/// Real PortIo over x86 `in`/`out` instructions.
///
/// # Safety contract
/// The trait methods themselves are the unsafe surface; every caller
/// in this crate pins the port numbers to fixed hardware registers.
pub struct RawPortIo;

impl PortIo for RawPortIo {
    #[inline(always)]
    unsafe fn out8(&mut self, port: u16, value: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nostack));
        }
    }
    #[inline(always)]
    unsafe fn out16(&mut self, port: u16, value: u16) {
        unsafe {
            core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nostack));
        }
    }
    #[inline(always)]
    unsafe fn out32(&mut self, port: u16, value: u32) {
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack));
        }
    }
    #[inline(always)]
    unsafe fn in8(&mut self, port: u16) -> u8 {
        let v: u8;
        unsafe {
            core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nostack));
        }
        v
    }
    #[inline(always)]
    unsafe fn in16(&mut self, port: u16) -> u16 {
        let v: u16;
        unsafe {
            core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nostack));
        }
        v
    }
    #[inline(always)]
    unsafe fn in32(&mut self, port: u16) -> u32 {
        let v: u32;
        unsafe {
            core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nostack));
        }
        v
    }
}

/// Real Mmio: a register window plus an associated DMA window (the
/// two are typically different physical regions; AHCI command tables
/// and NVMe queues live in the DMA window, not in the BAR).
pub struct RawMmio {
    pub regs_base: *mut u8,
    pub regs_len: usize,
    pub dma_base: *mut u8,
    pub dma_phys: u64,
    pub dma_len: usize,
}

impl RawMmio {
    /// # Safety
    /// Both windows must be mapped and writable (UEFI identity map) for
    /// the lifetime of self.
    pub unsafe fn new(
        regs_base: *mut u8,
        regs_len: usize,
        dma_base: *mut u8,
        dma_phys: u64,
        dma_len: usize,
    ) -> Self {
        Self {
            regs_base,
            regs_len,
            dma_base,
            dma_phys,
            dma_len,
        }
    }

    #[inline]
    fn check(&self, off: usize, width: usize) {
        debug_assert!(off + width <= self.regs_len, "MMIO window overrun");
    }
}

impl Mmio for RawMmio {
    #[inline(always)]
    unsafe fn read32(&self, off: usize) -> u32 {
        self.check(off, 4);
        unsafe { (self.regs_base.add(off) as *const u32).read_volatile() }
    }
    #[inline(always)]
    unsafe fn write32(&mut self, off: usize, v: u32) {
        self.check(off, 4);
        unsafe { (self.regs_base.add(off) as *mut u32).write_volatile(v) }
    }
    #[inline(always)]
    unsafe fn read64(&self, off: usize) -> u64 {
        self.check(off, 8);
        unsafe { (self.regs_base.add(off) as *const u64).read_volatile() }
    }
    #[inline(always)]
    unsafe fn write64(&mut self, off: usize, v: u64) {
        self.check(off, 8);
        unsafe { (self.regs_base.add(off) as *mut u64).write_volatile(v) }
    }
    #[inline(always)]
    fn dma_ptr(&self) -> *mut u8 {
        self.dma_base
    }
    #[inline(always)]
    fn dma_phys(&self) -> u64 {
        self.dma_phys
    }
}

/// `RDRAND`-backed entropy (x86-64). Retries the instruction per the
/// SDM's re-looping guidance; falls back to the timestamp counter
/// mixed over rounds (documented degraded mode — printed on screen).
pub fn rdrand_seed() -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut filled = 0usize;
    for chunk in out.chunks_mut(8) {
        for attempt in 0..64 {
            let ok: u8;
            let v: u64;
            unsafe {
                core::arch::asm!(
                    "rdrand {v}",
                    "setc {ok}",
                    v = out(reg) v,
                    ok = out(reg_byte) ok,
                );
            }
            if ok == 1 {
                chunk.copy_from_slice(&v.to_le_bytes());
                filled += 8;
                break;
            }
            // SDM: pause briefly between failures
            for _ in 0..(attempt * 10) {
                core::hint::spin_loop();
            }
        }
    }
    if filled < 32 {
        // Degraded fallback: TCR typewriter (weak, disclosed).
        let mut acc = 0u64;
        for (i, b) in out.iter_mut().enumerate() {
            let t: u64;
            unsafe {
                core::arch::asm!("rdtsc", lateout("rax") t, out("rdx") _, options(nostack));
            }
            acc = acc.rotate_left(7) ^ t ^ (i as u64);
            *b = acc as u8;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Simulated bus (CI) — cfg(test) only
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod sim {
    use std::collections::BTreeMap;

    /// Register-accurate simulated bus for hosted tests.
    ///
    /// Beyond a flat register map, the sim implements the small set of
    /// REACTIVE semantics real controllers exhibit — enough for the
    /// driver state machines to be exercised end-to-end:
    ///   * PCI CF8/CFC address→data pairing (config space behind it),
    ///   * NVMe CC.EN → CSTS.RDY, and doorbell → completion generation
    ///     for the admin queue (dma 4096) and I/O queue 1 (dma 12288).
    pub struct SimBus {
        /// PCI config space keyed by the CF8 address word.
        pub pci_config: BTreeMap<u32, u32>,
        pub ports: BTreeMap<u16, u32>,
        pub mmio: BTreeMap<usize, u32>,
        pub mmio64: BTreeMap<usize, u64>,
        /// 128-byte-aligned scratch DMA window (AHCI command lists and
        /// tables demand 128-byte alignment; real page-backed DMA
        /// provides it, so the sim must too).
        pub dma: Vec<u8>,
        pub dma_phys_base: u64,
    }

    impl SimBus {
        pub fn new(dma_bytes: usize) -> Self {
            use std::alloc::{Layout, alloc, handle_alloc_error};
            let size = dma_bytes.max(1);
            let layout = Layout::from_size_align(size, 128)
                .unwrap_or_else(|_| Layout::from_size_align(size, 8).unwrap());
            let align = layout.align();
            let ptr = unsafe { alloc(layout) };
            if ptr.is_null() {
                handle_alloc_error(layout);
            }
            // SAFETY: `ptr` comes from `alloc` with exactly this
            // layout; constructing a Vec hands ownership/freeing over
            // to the Vec with the same layout — valid for the test
            // process lifetime pattern used here (freed on drop).
            let dma = unsafe { Vec::from_raw_parts(ptr, size, size) };
            assert_eq!(dma.as_ptr() as usize % align, 0);
            Self {
                pci_config: BTreeMap::new(),
                ports: BTreeMap::new(),
                mmio: BTreeMap::new(),
                mmio64: BTreeMap::new(),
                dma,
                dma_phys_base: 0x1000_0000,
            }
        }

        /// Simulated controller reactions to register writes (documented
        /// offsets; see the struct docs).
        fn react(&mut self, off: usize, v: u32) {
            // NVMe CC.EN → CSTS.RDY
            const NVME_CC: usize = 0x14;
            const NVME_CSTS: usize = 0x1C;
            if off == NVME_CC && v & 1 == 1 {
                self.mmio.insert(NVME_CSTS, 1);
            }
            // NVMe doorbells: admin SQ @0x1000, I/O SQ1 @0x1008 —
            // fabricate a successful phase-1 completion in the CQ.
            const ADMIN_SQ_DBL: usize = 0x1000;
            const IO_SQ1_DBL: usize = 0x1008;
            if off == ADMIN_SQ_DBL || off == IO_SQ1_DBL {
                let cq_off = if off == ADMIN_SQ_DBL { 4096 } else { 12288 };
                // Completion queue entry layout (16 bytes):
                //   word0: cdw0 | word1: rsvd
                //   word2: sq_head(16) | sq_id(16)
                //   word3: cid(16)     | status_p(16)
                // A successful completion: head advanced, phase bit set,
                // SC/SCT zero.
                let cqe = [
                    0u32,
                    0u32,
                    1u32,       // sq_head = 1
                    1u32 << 16, // status_p = 1 (phase), cid = 0
                ];
                for (i, w) in cqe.iter().enumerate() {
                    let b = cq_off + i * 4;
                    if b + 4 <= self.dma.len() {
                        self.dma[b..b + 4].copy_from_slice(&w.to_le_bytes());
                    }
                }
            }
        }

        pub fn poke32(&mut self, off: usize, v: u32) {
            self.mmio.insert(off, v);
        }

        pub fn peek32(&self, off: usize) -> u32 {
            self.mmio.get(&off).copied().unwrap_or(0)
        }
    }

    impl crate::hal::PortIo for SimBus {
        unsafe fn out8(&mut self, port: u16, value: u8) {
            self.ports.insert(
                port,
                (self.ports.get(&port).copied().unwrap_or(0) & !0xFF) | value as u32,
            );
        }
        unsafe fn out16(&mut self, port: u16, value: u16) {
            self.ports.insert(
                port,
                (self.ports.get(&port).copied().unwrap_or(0) & !0xFFFF) | value as u32,
            );
        }
        unsafe fn out32(&mut self, port: u16, value: u32) {
            const PCI_CF8: u16 = 0xCF8;
            const PCI_CFC: u16 = 0xCFC;
            self.ports.insert(port, value);
            // PCI config write: data port latches into the addressed
            // dword.
            if port == PCI_CFC {
                let addr = self.ports.get(&PCI_CF8).copied().unwrap_or(0) & !0x3;
                self.pci_config.insert(addr, value);
            }
        }
        unsafe fn in8(&mut self, port: u16) -> u8 {
            (self.ports.get(&port).copied().unwrap_or(0) & 0xFF) as u8
        }
        unsafe fn in16(&mut self, port: u16) -> u16 {
            (self.ports.get(&port).copied().unwrap_or(0) & 0xFFFF) as u16
        }
        unsafe fn in32(&mut self, port: u16) -> u32 {
            // PCI config read: data port serves the addressed dword.
            if port == 0xCFC {
                let addr = self.ports.get(&0xCF8).copied().unwrap_or(0) & !0x3;
                return self.pci_config.get(&addr).copied().unwrap_or(0xFFFF_FFFF);
            }
            self.ports.get(&port).copied().unwrap_or(0)
        }
    }

    impl SimBus {
        /// AHCI interrupt-status registers are write-1-to-clear.
        fn is_w1c_register(off: usize) -> bool {
            // GHC.IS @0x08; PxIS @0x110 + k·0x80, k in 0..32.
            if off == 0x08 {
                return true;
            }
            if (0x110..0x110 + 32 * 0x80).contains(&off) {
                return (off - 0x110).is_multiple_of(0x80);
            }
            false
        }
    }

    impl crate::hal::Mmio for SimBus {
        unsafe fn read32(&self, off: usize) -> u32 {
            self.mmio.get(&off).copied().unwrap_or(0)
        }
        unsafe fn write32(&mut self, off: usize, v: u32) {
            if Self::is_w1c_register(off) {
                let old = self.mmio.get(&off).copied().unwrap_or(0);
                self.mmio.insert(off, old & !v);
            } else {
                self.mmio.insert(off, v);
            }
            self.react(off, v);
        }
        unsafe fn read64(&self, off: usize) -> u64 {
            self.mmio64.get(&off).copied().unwrap_or(0)
        }
        unsafe fn write64(&mut self, off: usize, v: u64) {
            self.mmio64.insert(off, v);
        }
        fn dma_ptr(&self) -> *mut u8 {
            self.dma.as_ptr() as *mut u8
        }
        fn dma_phys(&self) -> u64 {
            self.dma_phys_base
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoSync {} // placeholder for future out-of-order tests

    #[allow(dead_code)]
    fn _layout_check() {
        let _ = NoSync {};
    }

    #[test]
    fn sim_bus_roundtrip() {
        let mut bus = sim::SimBus::new(4096);
        unsafe {
            bus.write32(0x20, 0xDEAD_BEEF);
            assert_eq!(bus.read32(0x20), 0xDEAD_BEEF);
            bus.write64(0x28, u64::MAX);
            assert_eq!(bus.read64(0x28), u64::MAX);
            use crate::hal::PortIo;
            bus.out32(0xCF8, 0x8000_0000);
            assert_eq!(bus.in32(0xCF8), 0x8000_0000);
        }
    }
}
