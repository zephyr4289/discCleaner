//! NVMe 1.x controller driver (v0.12.0, Miracle 3).
//!
//! Zero-kernel driver: controller registers over BAR0, admin queue
//! pair on dedicated DMA pages, Identify Controller/Namespace, I/O
//! queue creation, Write (0x01) with PRP scatter, and Format NVM
//! (0x80) with user-data / cryptographic erase — the controller-side
//! purge that matches dc-nvme's hosted ladder.

use crate::hal::Mmio;

// Controller registers (BAR0)
pub const REG_CAP: usize = 0x00; // r64: MQES[0:15] CQES[52:55] DSTRD[32:35] TO[24:31]
pub const REG_VS: usize = 0x08;
pub const REG_CC: usize = 0x14;
pub const REG_CSTS: usize = 0x1C;
pub const REG_NSSR: usize = 0x20;
pub const REG_AQA: usize = 0x24;
pub const REG_ASQ: usize = 0x28; // r64
pub const REG_ACQ: usize = 0x30; // r64
pub const REG_SQ0_TDBL: usize = 0x1000; // admin SQ doorbell (stride 4<<DSTRD)

pub const CC_EN: u32 = 1 << 0;
pub const CC_CSS: u32 = 0 << 4; // NVM command set
pub const CC_MPS_SHIFT: u32 = 7; // memory page size = 1 << (12+MPS)
pub const CC_IOCQES_SHIFT: u32 = 20;
pub const CC_IOSQES_SHIFT: u32 = 16;

pub const CSTS_RDY: u32 = 1 << 0;
pub const CSTS_CFS: u32 = 1 << 1;

// Opcodes
pub const OP_ADMIN_DELETE_SQ: u8 = 0x00;
pub const OP_ADMIN_CREATE_SQ: u8 = 0x01;
pub const OP_ADMIN_GET_LOG: u8 = 0x02;
pub const OP_ADMIN_DELETE_CQ: u8 = 0x04;
pub const OP_ADMIN_CREATE_CQ: u8 = 0x05;
pub const OP_ADMIN_IDENTIFY: u8 = 0x06;
pub const OP_ADMIN_ABORT: u8 = 0x08;
pub const OP_ADMIN_SET_FEATURES: u8 = 0x09;
pub const OP_ADMIN_GET_FEATURES: u8 = 0x0A;
pub const OP_ADMIN_FORMAT_NVM: u8 = 0x80;
pub const OP_ADMIN_SANITIZE: u8 = 0x84;
pub const OP_IO_WRITE: u8 = 0x01;
pub const OP_IO_READ: u8 = 0x02;
pub const OP_IO_DSM: u8 = 0x09;

// Identify CNS values
pub const CNS_NAMESPACE: u32 = 0x00;
pub const CNS_CONTROLLER: u32 = 0x01;

// Format NVM SES (sanitize erase settings) — matches dc-nvme ladder
pub const SES_NO_CHANGE: u32 = 0b000 << 9;
pub const SES_USER_DATA_ERASE: u32 = 0b001 << 9;
pub const SES_CRYPTO_ERASE: u32 = 0b010 << 9;

/// Errors from the driver.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NvmeError {
    ControllerNotReady,
    EnableTimeout,
    DoorbellInvalid,
    CommandTimeout,
    BadStatus(u16),
    NoNamespace,
    PrpOverflow,
}

/// Admin/IO submission queue entry (64 bytes).
#[repr(C, align(64))]
pub struct SubmissionEntry {
    pub cdw0: u32, // opcode | FUSE | PSDT | CID
    pub nsid: u32,
    _rsvd: u64,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl SubmissionEntry {
    pub fn zeroed() -> Self {
        Self {
            cdw0: 0,
            nsid: 0,
            _rsvd: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }
}

/// Completion queue entry (16 bytes).
#[repr(C, align(16))]
pub struct CompletionEntry {
    pub cdw0: u32,
    pub rsvd: u32,
    pub sq_head: u16,
    pub sq_id: u16,
    pub cid: u16,
    pub status_p: u16, // phase bit = 1<<0; SC<<1 | SCT<<9
}

impl CompletionEntry {
    /// Hosted-test constructor (the field is public for CI simulation
    /// only; the driver never constructs completions on hardware).
    #[cfg(test)]
    pub fn sim(cdw0: u32, sq_head: u16, sq_id: u16, cid: u16, status_p: u16) -> Self {
        Self {
            cdw0,
            rsvd: 0,
            sq_head,
            sq_id,
            cid,
            status_p,
        }
    }
}

/// The driver. Queue pages live in the DMA window; the admin pair uses
/// two dedicated pages (4 KB each), the I/O pair two more.
pub struct Nvme<M: Mmio> {
    pub mmio: M,
    /// Base offsets within the DMA window.
    pub admin_sq_off: usize,
    pub admin_cq_off: usize,
    pub io_sq_off: usize,
    pub io_cq_off: usize,
    pub data_off: usize,
    pub q_depth: u32,
    pub dstrd: u32,
    pub nsid: u32,
    pub lba_count: u64,
    pub lba_size: u32,
}

impl<M: Mmio> Nvme<M> {
    /// Full controller bring-up: reset → CC enable → CSTS.RDY → admin
    /// queues → Identify (namespace 1) → I/O queue pair.
    pub fn init(mut mmio: M, dma_window_kb: usize) -> Result<Self, NvmeError> {
        let cap = unsafe { mmio.read64(REG_CAP) };
        let mqes = (cap as u32 & 0xFFFF) as u32 + 1;
        let dstrd = ((cap >> 32) as u32) & 0xF;
        // Page-aligned queue placement in the DMA window.
        let admin_sq_off = 0;
        let admin_cq_off = 4096;
        let io_sq_off = 8192;
        let io_cq_off = 12288;
        let data_off = 16384;
        debug_assert!(dma_window_kb * 1024 >= data_off + 4096);
        let q_depth = mqes.min(64).max(2);

        // Zero the four queue pages.
        let ptr = mmio.dma_ptr() as *mut u8;
        unsafe {
            for i in 0..(data_off - admin_sq_off) {
                *ptr.add(i) = 0;
            }
        }

        let sq_phys = mmio.dma_phys() + admin_sq_off as u64;
        let cq_phys = mmio.dma_phys() + admin_cq_off as u64;
        let aqa = ((q_depth - 1) << 16) | (q_depth - 1);
        unsafe {
            mmio.write32(REG_AQA, aqa);
            mmio.write64(REG_ASQ, sq_phys);
            mmio.write64(REG_ACQ, cq_phys);
            // CC: enable, MPS=0 (4 KiB pages), CQES/IOQES = 4 bytes… wait
            // CQES must match the 16-byte completion entries: 4 → 1<<(4)?
            // CC.CQES is a power-of-two exponent: 16 bytes = 2^4 → 4.
            mmio.write32(
                REG_CC,
                CC_EN
                    | CC_CSS
                    | (0 << CC_MPS_SHIFT)
                    | (4 << CC_IOCQES_SHIFT)
                    | (6 << CC_IOSQES_SHIFT),
            );
        }

        // Wait for CSTS.RDY.
        for _ in 0..5_000_000 {
            let csts = unsafe { mmio.read32(REG_CSTS) };
            if csts & CSTS_CFS != 0 {
                return Err(NvmeError::ControllerNotReady);
            }
            if csts & CSTS_RDY != 0 {
                break;
            }
        }
        if unsafe { mmio.read32(REG_CSTS) } & CSTS_RDY == 0 {
            return Err(NvmeError::EnableTimeout);
        }

        let mut drv = Self {
            mmio,
            admin_sq_off,
            admin_cq_off,
            io_sq_off,
            io_cq_off,
            data_off,
            q_depth,
            dstrd,
            nsid: 0,
            lba_count: 0,
            lba_size: 512,
        };

        // Identify namespace 1: data buffer at data_off.
        let mut identify = SubmissionEntry::zeroed();
        identify.cdw0 = (OP_ADMIN_IDENTIFY as u32) | (1 << 16); // CID 1
        identify.nsid = 1;
        identify.cdw10 = CNS_NAMESPACE;
        identify.prp1 = drv.mmio.dma_phys() + drv.data_off as u64;
        let (sc, _) = drv.admin_cmd(&identify, |m| {
            // sim hook: mark completion with phase toggle
            let _ = m;
        })?;
        if sc != 0 {
            return Err(NvmeError::BadStatus(sc));
        }
        // Parse the Identify Namespace structure from the data page.
        drv.parse_identify_ns();
        if drv.lba_count == 0 {
            return Err(NvmeError::NoNamespace);
        }

        // Create the I/O queue pair (QID 1).
        let io_sq_phys = drv.mmio.dma_phys() + drv.io_sq_off as u64;
        let io_cq_phys = drv.mmio.dma_phys() + drv.io_cq_off as u64;
        let mut create_cq = SubmissionEntry::zeroed();
        create_cq.cdw0 = (OP_ADMIN_CREATE_CQ as u32) | (2 << 16);
        create_cq.prp1 = io_cq_phys;
        create_cq.cdw10 = ((drv.q_depth - 1) << 16) | 1; // QID 1
        create_cq.cdw11 = 1; // interrupt enable (phys contiguous)
        let (sc, _) = drv.admin_cmd(&create_cq, |m| {
            let _ = m;
        })?;
        if sc != 0 {
            return Err(NvmeError::BadStatus(sc));
        }
        let mut create_sq = SubmissionEntry::zeroed();
        create_sq.cdw0 = (OP_ADMIN_CREATE_SQ as u32) | (3 << 16);
        create_sq.prp1 = io_sq_phys;
        create_sq.cdw10 = ((drv.q_depth - 1) << 16) | 1; // QID 1
        create_sq.cdw11 = 1 << 0; // physically contiguous
        let (sc, _) = drv.admin_cmd(&create_sq, |m| {
            let _ = m;
        })?;
        if sc != 0 {
            return Err(NvmeError::BadStatus(sc));
        }
        Ok(drv)
    }

    fn parse_identify_ns(&mut self) {
        let ptr = self.mmio.dma_ptr() as *mut u8;
        let page = unsafe { ptr.add(self.data_off) };
        unsafe {
            // Identify Namespace: NSZE at dword 0; NLBAF (count) at
            // byte 4; LBAF[n].LBADS (size exponent) at 26 + 2n.
            let nlbaf = (*page.add(4) & 0xF) as usize;
            let exp = *page.add(26 + 2 * nlbaf) as u32;
            self.lba_size = 1u32 << exp.max(9);
            let lo = (page as *const u32).read_volatile();
            let hi = (page.add(4) as *const u32).read_volatile();
            self.lba_count = ((hi as u64) << 32) | lo as u64;
        }
    }

    fn admin_cmd(
        &mut self,
        cmd: &SubmissionEntry,
        mut poll: impl FnMut(&mut M),
    ) -> Result<(u16, u32), NvmeError> {
        // Place at admin SQ tail 0, ring doorbell, await completion.
        let sq = self.mmio.dma_ptr() as *mut SubmissionEntry;
        unsafe {
            *sq = SubmissionEntry {
                cdw0: cmd.cdw0,
                nsid: cmd.nsid,
                _rsvd: 0,
                mptr: cmd.mptr,
                prp1: cmd.prp1,
                prp2: cmd.prp2,
                cdw10: cmd.cdw10,
                cdw11: cmd.cdw11,
                cdw12: cmd.cdw12,
                cdw13: cmd.cdw13,
                cdw14: cmd.cdw14,
                cdw15: cmd.cdw15,
            };
        }
        let dbl = REG_SQ0_TDBL;
        unsafe {
            self.mmio.write32(dbl, 1);
        }
        for _ in 0..5_000_000 {
            poll(&mut self.mmio);
            // The completion entry appears at admin CQ head 0 with the
            // phase bit toggled (initial phase = 0 → completion sets 1).
            let cqe = unsafe {
                (self.mmio.dma_ptr() as *mut CompletionEntry)
                    .add(self.admin_cq_off / core::mem::size_of::<CompletionEntry>())
            };
            let c = unsafe { cqe.read_volatile() };
            if c.status_p & 1 == 1 {
                let sc = (c.status_p >> 1) & 0xFF;
                let sct = (c.status_p >> 9) & 0x7;
                let code = (sct << 8) | sc;
                return Ok((code as u16, c.cdw0));
            }
        }
        Err(NvmeError::CommandTimeout)
    }

    /// Issue an I/O Write (op 0x01) of `nlb` blocks at `slba`; data at
    /// the DMA data page (single PRP — chunked by the wipe engine).
    pub fn io_write(
        &mut self,
        slba: u64,
        nlb: u32,
        mut poll: impl FnMut(&mut M),
    ) -> Result<(), NvmeError> {
        let mut cmd = SubmissionEntry::zeroed();
        cmd.cdw0 = (OP_IO_WRITE as u32) | (1 << 16);
        cmd.nsid = self.nsid;
        cmd.prp1 = self.mmio.dma_phys() + self.data_off as u64;
        cmd.cdw10 = (slba & 0xFFFF_FFFF) as u32;
        cmd.cdw11 = (slba >> 32) as u32;
        cmd.cdw12 = (nlb - 1) & 0xFFFF; // NLB zero-based
        // I/O QID 1 submission doorbell: 0x1000 + 2·(4 << DSTRD).
        let stride = 4u32 << self.dstrd;
        let sq = unsafe {
            (self.mmio.dma_ptr() as *mut SubmissionEntry)
                .add(self.io_sq_off / core::mem::size_of::<SubmissionEntry>())
        };
        unsafe {
            *sq = SubmissionEntry {
                cdw0: cmd.cdw0,
                nsid: cmd.nsid,
                _rsvd: 0,
                mptr: cmd.mptr,
                prp1: cmd.prp1,
                prp2: cmd.prp2,
                cdw10: cmd.cdw10,
                cdw11: cmd.cdw11,
                cdw12: cmd.cdw12,
                cdw13: cmd.cdw13,
                cdw14: cmd.cdw14,
                cdw15: cmd.cdw15,
            };
        }
        unsafe {
            self.mmio.write32(REG_SQ0_TDBL + (2 * stride) as usize, 1);
        }
        for _ in 0..5_000_000 {
            poll(&mut self.mmio);
            let cqe = unsafe {
                (self.mmio.dma_ptr() as *mut CompletionEntry)
                    .add(self.io_cq_off / core::mem::size_of::<CompletionEntry>())
            };
            let c = unsafe { cqe.read_volatile() };
            if c.status_p & 1 == 1 {
                let sc = (c.status_p >> 1) & 0xFF;
                let sct = (c.status_p >> 9) & 0x7;
                if sc != 0 || sct != 0 {
                    return Err(NvmeError::BadStatus(((sct << 8) | sc) as u16));
                }
                return Ok(());
            }
        }
        Err(NvmeError::CommandTimeout)
    }

    /// Format NVM with the given sanitize-erase setting. Non-immediate
    /// (blocking) — the Ghost waits: the whole point is the media is
    /// sanitized before power-off.
    pub fn format_nvm(&mut self, ses: u32, mut poll: impl FnMut(&mut M)) -> Result<(), NvmeError> {
        let mut cmd = SubmissionEntry::zeroed();
        cmd.cdw0 = (OP_ADMIN_FORMAT_NVM as u32) | (9 << 16);
        cmd.nsid = self.nsid;
        cmd.cdw10 = ses >> 9; // SES lives in cdw10 bits 9-11
        let (sc, _) = self.admin_cmd(&cmd, |m| poll(m))?;
        if sc != 0 {
            return Err(NvmeError::BadStatus(sc));
        }
        Ok(())
    }

    /// Sanitize admin command (0x84) — modern controllers.
    pub fn sanitize(&mut self, sanact: u32, mut poll: impl FnMut(&mut M)) -> Result<(), NvmeError> {
        let mut cmd = SubmissionEntry::zeroed();
        cmd.cdw0 = (OP_ADMIN_SANITIZE as u32) | (10 << 16);
        cmd.nsid = self.nsid;
        cmd.cdw10 = sanact; // SANACT bits 0-3
        let (sc, _) = self.admin_cmd(&cmd, |m| poll(m))?;
        if sc != 0 {
            return Err(NvmeError::BadStatus(sc));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::sim::SimBus;

    /// Simulated NVMe controller: CAP with 64-entry queues, DSTRD 0.
    /// Completion mechanics live in the poll hook (hosted side).
    fn sim_nvme() -> SimBus {
        let mut bus = SimBus::new(64 * 1024);
        bus.poke32(REG_CAP, 63); // MQES=63 (+1 → 64), DSTRD=0
        // CAP is 64-bit; poke64 too
        bus.mmio64.insert(REG_CAP, 63);
        bus.poke32(REG_CSTS, 0);
        bus
    }

    #[test]
    fn full_init_identify_and_io_write() {
        let mut bus = sim_nvme();
        // Seed the identify data page BEFORE init: NSZE = 100000,
        // NLBAF = 0, LBAF0 exponent 9 (512 B).
        unsafe {
            let p = bus.dma.as_mut_ptr().add(16384);
            (p as *mut u32).write_volatile(100_000);
            *p.add(4) = 0; // NLBAF = 0
            *p.add(26) = 9; // LBAF0 LBADS = 9 → 512 B
        }
        let mut d = Nvme::init(bus, 64).expect("controller init with namespace");
        assert_eq!(d.lba_count, 100_000);
        assert_eq!(d.lba_size, 512);

        // Simulate the I/O completion: poll hook writes a phase-set CQ
        // entry at the I/O completion queue.
        let mut completed = false;
        d.io_write(500, 8, |m| {
            if !completed {
                let cqe = unsafe {
                    (m.dma_ptr() as *mut CompletionEntry)
                        .add(12288 / core::mem::size_of::<CompletionEntry>())
                };
                unsafe {
                    core::ptr::write_volatile(
                        cqe,
                        CompletionEntry {
                            cdw0: 0,
                            rsvd: 0,
                            sq_head: 1,
                            sq_id: 1,
                            cid: 1,
                            status_p: 1, // phase=1, SC=0, SCT=0
                        },
                    );
                }
                completed = true;
            }
        })
        .expect("I/O write must complete in sim");
        assert!(completed);
    }

    #[test]
    fn format_nvm_crypto_erase() {
        let mut bus = SimBus::new(64 * 1024);
        bus.mmio64.insert(REG_CAP, 63);
        // Pre-seed namespace data.
        unsafe {
            let p = bus.dma.as_mut_ptr().add(16384);
            (p as *mut u32).write_volatile(1000);
            *p.add(4) = 0;
            *p.add(26) = 9;
        }
        let mut d = Nvme::init(bus, 64).unwrap();
        let ok = d.format_nvm(SES_CRYPTO_ERASE, |m| {
            // admin completion: phase 1, SC 0
            let cqe = unsafe { (m.dma_ptr() as *mut CompletionEntry).add(0) };
            unsafe {
                core::ptr::write_volatile(
                    cqe,
                    CompletionEntry {
                        cdw0: 0,
                        rsvd: 0,
                        sq_head: 1,
                        sq_id: 0,
                        cid: 9,
                        status_p: 1,
                    },
                );
            }
        });
        ok.expect("Format NVM crypto erase must complete");
    }

    #[test]
    fn bad_status_surfaces() {
        let mut bus = SimBus::new(64 * 1024);
        bus.mmio64.insert(REG_CAP, 63);
        unsafe {
            let p = bus.dma.as_mut_ptr().add(16384);
            (p as *mut u32).write_volatile(1000);
            *p.add(4) = 0;
            *p.add(26) = 9;
        }
        let mut d = Nvme::init(bus, 64).unwrap();
        let err = d
            .format_nvm(SES_CRYPTO_ERASE, |m| {
                // Overwrite the ADMIN completion entry (dma offset 4096)
                // with a failing status: SC = 0x0B.
                let cqe = unsafe {
                    (m.dma_ptr() as *mut CompletionEntry)
                        .add(4096 / core::mem::size_of::<CompletionEntry>())
                };
                unsafe {
                    core::ptr::write_volatile(
                        cqe,
                        CompletionEntry::sim(0, 1, 0, 9, 1 | (0x0B << 1)),
                    );
                }
            })
            .unwrap_err();
        assert!(matches!(err, NvmeError::BadStatus(0x0B)));
    }
}
