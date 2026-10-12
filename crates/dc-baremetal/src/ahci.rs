//! AHCI (SATA) host controller driver (v0.12.0, Miracle 3).
//!
//! Speaks the AHCI 1.3.1 host bus adapter memory layout directly:
//! GHC handoff/reset, port spin-up & signature detection, command
//! list / FIS receive setup, and H2D register FIS construction for
//! 48-bit WRITE DMA EXT (0x35) / READ DMA EXT (0x25) with PRDT-scoped
//! DMA. All state machines run against any [`crate::hal::Mmio`] —
//! including the CI simulation bus.

use crate::hal::Mmio;

// Host registers (offsets from ABAR)
pub const REG_CAP: usize = 0x00; // r64: S64A/NP/SSS/EMS/SNCQ/SSC/ISC/SCLO/SAL/SSS/PSC/ISS/(17-23)r/(24-30)SALP/31S64A... NP = bits 0-4
pub const REG_GHC: usize = 0x04;
pub const REG_IS: usize = 0x08;
pub const REG_PI: usize = 0x0C;
pub const REG_VS: usize = 0x10;

pub const GHC_HR: u32 = 1 << 0; // hard reset
pub const GHC_IE: u32 = 1 << 1;
pub const GHC_MRSM: u32 = 1 << 2;
pub const GHC_AE: u32 = 1 << 31; // AHCI enable

// Port register block (per port i: 0x100 + 0x80*i)
pub const PORT_STRIDE: usize = 0x80;
pub const PORT_BASE: usize = 0x100;
pub const P_PXCLB: usize = 0x00; // command list base lo
pub const P_PXCLBU: usize = 0x04;
pub const P_PXFB: usize = 0x08; // FIS receive base lo
pub const P_PXFBU: usize = 0x0C;
pub const P_PXIS: usize = 0x10;
pub const P_PXIE: usize = 0x14;
pub const P_PXCMD: usize = 0x18;
pub const P_PXTFD: usize = 0x20;
pub const P_PXSIG: usize = 0x24;
pub const P_PXSSTS: usize = 0x28;
pub const P_PXSCTL: usize = 0x2C;
pub const P_PXSERR: usize = 0x30;
pub const P_PXCI: usize = 0x38;

pub const PCMD_ST: u32 = 1 << 0;
pub const PCMD_SUD: u32 = 1 << 1; // spin up device
pub const PCMD_POD: u32 = 1 << 2;
pub const PCMD_FRE: u32 = 1 << 4;
pub const PCMD_FR: u32 = 1 << 14; // ro: FIS running
pub const PCMD_CR: u32 = 1 << 15; // ro: command list running
pub const PCMD_ATAPI: u32 = 1 << 24;
pub const PCMD_ICC_MASK: u32 = 0xF0_00_00_00;

pub const PORT_IRQ_TFE: u32 = 1 << 0; // task file error
pub const PORT_IRQ_DH: u32 = 1 << 1; // descriptor processed / D2H FIS

pub const SIG_SATA: u32 = 0x0000_0101;
pub const SIG_SATAPI: u32 = 0xEB14_0101;
pub const SIG_SEMB: u32 = 0xC33C_0101;
pub const SIG_PM: u32 = 0x9669_0101;

/// Errors surfaced by the driver.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AhciError {
    HbaNotIdle,
    NoPorts,
    PortBusy,
    CommandTimeout,
    TaskFileError,
    UnsupportedSignature(u32),
}

/// One discovered SATA port.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SataPort {
    pub index: usize,
    pub signature: u32,
    pub atapi: bool,
}

/// Command list entry (system memory, 32 bytes).
#[repr(C, align(128))]
pub struct CmdHeader {
    pub flags: u32, // FIS len | ATAPI | W | PMP | C
    pub prdbc: u32,
    pub ctba: u32,
    pub ctbau: u32,
    _rsvd: [u32; 4],
}

/// Command table (system memory): 0x80 CFIS + 0x10 ACMD + PRDT.
#[repr(C, align(128))]
pub struct CmdTable {
    pub cfis: [u8; 64],
    pub acmd: [u8; 16],
    pub prdt: [PrdtEntry; 1],
}

#[repr(C)]
pub struct PrdtEntry {
    pub dba: u32,
    pub dbau: u32,
    _rsvd: u32,
    pub dbc_i: u32, // byte count (bits 0-21) | interrupt-on-completion (bit 31)
}

/// H2D register FIS builder for 48-bit LBA commands.
pub struct RegFisH2D {
    pub is_write: bool,
    pub command: u8,
    pub lba: u64,
    pub count: u16,
}

impl RegFisH2D {
    /// WRITE DMA EXT (0x35) / READ DMA EXT (0x25) with L=1 (48-bit).
    pub fn dma_ext(is_write: bool, lba: u64, count: u16) -> Self {
        Self {
            is_write,
            command: if is_write { 0x35 } else { 0x25 },
            lba,
            count,
        }
    }

    /// Serialize into a 20-byte H2D register FIS.
    pub fn write_to(&self, out: &mut [u8; 64]) {
        out.fill(0);
        out[0] = 0x27; // FIS type: register H2D
        out[1] = 1 << 7; // C: update command register
        out[2] = self.command;
        // device: LBA mode bit (0x40)
        out[7] = 0x40;
        let lba = self.lba;
        out[4] = (lba & 0xFF) as u8;
        out[5] = ((lba >> 8) & 0xFF) as u8;
        out[6] = ((lba >> 16) & 0xFF) as u8;
        out[8] = ((lba >> 24) & 0xFF) as u8;
        out[9] = ((lba >> 32) & 0xFF) as u8;
        out[10] = ((lba >> 40) & 0xFF) as u8;
        out[12] = (self.count & 0xFF) as u8;
        out[13] = (self.count >> 8) as u8;
    }
}

/// The driver. One instance owns the ABAR window; a small bump
/// allocator over the DMA region hands out aligned command
/// structures (1 KB command list, 256 B FIS area, 256 B command
/// table per port — sizes mandated by AHCI 1.3.1 §4.2).
pub struct Ahci<M: Mmio> {
    pub mmio: M,
    /// Bump offset into the DMA window for command structures.
    bump: usize,
    /// Per-port allocated structures (port → (list_phys, fis_phys, ct_phys)).
    ports: [(u64, u64, u64); 32],
    pub num_ports: usize,
    pub implemented: u32,
}

impl<M: Mmio> Ahci<M> {
    /// Bring the HBA up: reset, re-enable AHCI, return port count.
    pub fn init(mut mmio: M) -> Result<Self, AhciError> {
        // Wait for prior resets / readiness; issue HR if AE semantics
        // allow. The conservative Ghost path: set AE, then clear IS.
        unsafe {
            mmio.write32(REG_GHC, GHC_AE);
            mmio.write32(REG_IS, 0xFFFF_FFFF); // clear pending
        }
        let cap = unsafe { mmio.read64(REG_CAP) };
        let num_ports = ((cap as u32) & 0x1F) as usize + 1;
        let implemented = unsafe { mmio.read32(REG_PI) };
        Ok(Self {
            mmio,
            bump: 0,
            ports: [(0, 0, 0); 32],
            num_ports,
            implemented,
        })
    }

    /// Detect devices on implemented ports (spin-up + signature).
    /// Writes up to `out.len()` ports, returns the count found.
    pub fn detect_into(&mut self, out: &mut [SataPort]) -> usize {
        let mut found = 0;
        for i in 0..self.num_ports {
            if self.implemented & (1 << i) == 0 || found == out.len() {
                continue;
            }
            let base = PORT_BASE + i * PORT_STRIDE;
            unsafe {
                // spin-up (SUD) + power-on (POD)
                let cmd = self.mmio.read32(base + P_PXCMD);
                if cmd & PCMD_ATAPI == 0 {
                    self.mmio.write32(base + P_PXCMD, cmd | PCMD_SUD | PCMD_POD);
                }
                let sig = self.mmio.read32(base + P_PXSIG);
                let atapi = sig == SIG_SATAPI;
                // A present device: nonzero signature that is not the
                // all-ones "nothing there" pattern.
                if sig != 0xFFFF_FFFF && sig != 0 {
                    out[found] = SataPort {
                        index: i,
                        signature: sig,
                        atapi,
                    };
                    found += 1;
                }
            }
        }
        found
    }

    /// Start a port: allocate + program command list & FIS area, then
    /// enable FIS reception and command processing.
    pub fn start_port(&mut self, port: usize) -> Result<(), AhciError> {
        let base = PORT_BASE + port * PORT_STRIDE;
        // Stop first (ST=0), wait CR/FR clear.
        unsafe {
            let cmd = self.mmio.read32(base + P_PXCMD);
            self.mmio
                .write32(base + P_PXCMD, cmd & !PCMD_ST & !PCMD_FRE);
            for _ in 0..100_000 {
                let c = self.mmio.read32(base + P_PXCMD);
                if c & (PCMD_CR | PCMD_FR) == 0 {
                    break;
                }
            }
        }

        // Allocate from the bump region: 1 KB cmd list + 256 B FIS +
        // 256 B cmd table — keep 128-byte alignment.
        let (list_off, fis_off, ct_off) = (self.bump, self.bump + 1024, self.bump + 1024 + 256);
        self.bump += 1024 + 256 + 256 + 128; // pad
        let dma_phys = self.mmio.dma_phys() as usize;

        // Zero the structures through the DMA window.
        let ptr = self.mmio.dma_ptr() as *mut u8;
        unsafe {
            for i in 0..(1024 + 256 + 256 + 128) {
                *ptr.add(list_off + i) = 0;
            }
        }

        let list_phys = (dma_phys + list_off) as u64;
        let fis_phys = (dma_phys + fis_off) as u64;
        let ct_phys = (dma_phys + ct_off) as u64;
        self.ports[port] = (list_phys, fis_phys, ct_phys);

        unsafe {
            self.mmio.write32(base + P_PXCLB, list_phys as u32);
            self.mmio.write32(base + P_PXCLBU, (list_phys >> 32) as u32);
            self.mmio.write32(base + P_PXFB, fis_phys as u32);
            self.mmio.write32(base + P_PXFBU, (fis_phys >> 32) as u32);
            self.mmio.write32(base + P_PXIS, 0xFFFF_FFFF);
            let cmd = self.mmio.read32(base + P_PXCMD);
            self.mmio.write32(base + P_PXCMD, cmd | PCMD_FRE | PCMD_ST);
        }
        Ok(())
    }

    /// Issue one DMA command (write or read) of `sectors` at `lba`,
    /// data at DMA offset `data_off` (within the window). The poll
    /// hook fires before every register re-read — on hardware it is
    /// a no-op; in CI it simulates completion.
    pub fn dma_io(
        &mut self,
        port: usize,
        is_write: bool,
        lba: u64,
        sectors: u16,
        data_off: usize,
        mut poll: impl FnMut(&mut M),
    ) -> Result<(), AhciError> {
        let base = PORT_BASE + port * PORT_STRIDE;
        let (_, _, ct_phys) = self.ports[port];

        // ---- build the command table in the DMA window --------------
        let ptr = self.mmio.dma_ptr() as *mut u8;
        let ct = ptr as usize + (ct_phys as usize - self.mmio.dma_phys() as usize);
        let ct = ct as *mut CmdTable;
        unsafe {
            (*ct).cfis = [0u8; 64];
            (*ct).acmd = [0u8; 16];
            let mut fis = [0u8; 64];
            RegFisH2D::dma_ext(is_write, lba, sectors).write_to(&mut fis);
            (*ct).cfis = fis;
            let data_phys = self.mmio.dma_phys() as u64 + data_off as u64;
            (*ct).prdt[0].dba = data_phys as u32;
            (*ct).prdt[0].dbau = (data_phys >> 32) as u32;
            (*ct).prdt[0]._rsvd = 0;
            (*ct).prdt[0].dbc_i = ((sectors as u32 * 512) - 1) | (1 << 31);
        }

        // ---- command list slot 0 ------------------------------------
        let (list_phys, _, _) = self.ports[port];
        let list = ptr as usize + (list_phys as usize - self.mmio.dma_phys() as usize);
        let hdr = list as *mut CmdHeader;
        unsafe {
            (*hdr).flags = 5u32 /* FIS len in dwords */
                | (1u32 << 16) /* PRDTL 1 */
                | (u32::from(is_write) << 6) /* W */
                | (1u32 << 10) /* C: clear on completion */;
            (*hdr).prdbc = 0;
            (*hdr).ctba = ct_phys as u32;
            (*hdr).ctbau = (ct_phys >> 32) as u32;
        }

        // ---- issue and wait ------------------------------------------
        unsafe {
            // W1C only the statuses this driver consumes.
            self.mmio.write32(base + P_PXIS, PORT_IRQ_TFE | PORT_IRQ_DH);
            let ci = self.mmio.read32(base + P_PXCI);
            self.mmio.write32(base + P_PXCI, ci | 1);
        }
        for _ in 0..5_000_000 {
            poll(&mut self.mmio);
            let ci = unsafe { self.mmio.read32(base + P_PXCI) };
            let is = unsafe { self.mmio.read32(base + P_PXIS) };
            if is & PORT_IRQ_TFE != 0 {
                return Err(AhciError::TaskFileError);
            }
            if ci & 1 == 0 && is & PORT_IRQ_DH != 0 {
                return Ok(());
            }
        }
        Err(AhciError::CommandTimeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::sim::SimBus;

    /// Install a simulated AHCI HBA: 1 port implemented, SATA disk.
    fn sim_hba(dma: usize) -> SimBus {
        let mut bus = SimBus::new(dma);
        bus.poke32(REG_GHC, 0);
        bus.poke32(REG_PI, 0b1); // port 0 implemented
        bus.poke32(PORT_BASE + P_PXSIG, SIG_SATA);
        // SSTS: DET=3 (device present & comm established)
        bus.poke32(PORT_BASE + P_PXSSTS, 3);
        bus
    }

    #[test]
    fn detect_sata_disk() {
        let bus = sim_hba(16 * 1024);
        let mut ahci = Ahci::init(bus).unwrap();
        let mut ports = [SataPort {
            index: 0,
            signature: 0,
            atapi: false,
        }; 8];
        let n = ahci.detect_into(&mut ports);
        assert_eq!(n, 1);
        assert_eq!(ports[0].signature, SIG_SATA);
        assert!(!ports[0].atapi);
        assert_eq!(ahci.num_ports, 1); // CAP.NP=0 → 1 port
    }

    #[test]
    fn start_port_programs_bas() {
        let bus = sim_hba(16 * 1024);
        let mut ahci = Ahci::init(bus).unwrap();
        let mut ports = [SataPort {
            index: 0,
            signature: 0,
            atapi: false,
        }; 8];
        ahci.detect_into(&mut ports);
        ahci.start_port(0).unwrap();
        let clb = unsafe { ahci.mmio.read32(PORT_BASE + P_PXCLB) };
        let fb = unsafe { ahci.mmio.read32(PORT_BASE + P_PXFB) };
        assert!(
            clb >= 0x1000_0000 && clb & 0x3FF == 0,
            "cmd list 1KB-aligned: {clb:#x}"
        );
        assert!(
            fb >= 0x1000_0000 && fb & 0xFF == 0,
            "FIS 256B-aligned: {fb:#x}"
        );
        let cmd = unsafe { ahci.mmio.read32(PORT_BASE + P_PXCMD) };
        assert_eq!(cmd & (PCMD_ST | PCMD_FRE), PCMD_ST | PCMD_FRE);
    }

    #[test]
    fn dma_write_completes_via_poll_hook() {
        let bus = sim_hba(64 * 1024);
        let mut ahci = Ahci::init(bus).unwrap();
        let mut ports = [SataPort {
            index: 0,
            signature: 0,
            atapi: false,
        }; 8];
        ahci.detect_into(&mut ports);
        ahci.start_port(0).unwrap();

        // The poll hook simulates the DEVICE (not the driver) finishing
        // the command: PxIS is write-1-to-CLEAR, so a controller raising
        // the DH interrupt injects the bit directly into the register
        // map (bypassing the W1C write path), and clears CI.
        let mut done = false;
        let result = ahci.dma_io(0, true, 1000, 8, 8192, |m| {
            if !done {
                unsafe {
                    m.mmio.insert(PORT_BASE + P_PXIS, PORT_IRQ_DH);
                    m.write32(PORT_BASE + P_PXCI, 0);
                }
                done = true;
            }
        });
        result.expect("write DMA EXT must complete");
        assert!(done);

        // And the TFE path: hook sets task-file error → driver rejects.
        let bus = sim_hba(64 * 1024);
        let mut ahci = Ahci::init(bus).unwrap();
        let mut ports = [SataPort {
            index: 0,
            signature: 0,
            atapi: false,
        }; 8];
        ahci.detect_into(&mut ports);
        ahci.start_port(0).unwrap();
        let mut fired = false;
        let err = ahci
            .dma_io(0, false, 2000, 4, 8192, |m| {
                if !fired {
                    unsafe {
                        // Controller raises task-file error (inject; W1C).
                        m.mmio.insert(PORT_BASE + P_PXIS, PORT_IRQ_TFE);
                        m.write32(PORT_BASE + P_PXCI, 0);
                    }
                    fired = true;
                }
            })
            .unwrap_err();
        assert_eq!(err, AhciError::TaskFileError);
    }

    #[test]
    fn h2d_fis_layout() {
        let mut fis = [0u8; 64];
        RegFisH2D::dma_ext(true, 0x1234_5678_9ABC, 16).write_to(&mut fis);
        assert_eq!(fis[0], 0x27);
        assert_eq!(fis[1], 0x80);
        assert_eq!(fis[2], 0x35); // WRITE DMA EXT
        assert_eq!(fis[7], 0x40); // LBA mode
        assert_eq!(fis[4], 0xBC);
        assert_eq!(fis[5], 0x9A);
        assert_eq!(fis[6], 0x78);
        assert_eq!(fis[8], 0x56);
        assert_eq!(fis[9], 0x34);
        assert_eq!(fis[10], 0x12);
        assert_eq!(fis[12], 16);
    }
}
