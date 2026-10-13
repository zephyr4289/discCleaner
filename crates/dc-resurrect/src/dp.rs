//! ARM Debug Port abstraction shared by the SWD and JTAG-DP engines.
//!
//! Register model follows ARM ADIv5:
//!
//! * DP registers (offset selects A[3:2]): `0x00` DPIDR/ABORT, `0x04`
//!   CTRL/STAT (and TARGETSEL in bank 2), `0x08` SELECT, `0x0C` RDBUFF.
//! * MEM-AP registers: `0x00` CSW, `0x04` TAR, `0x0C` DRW, `0xFC` IDR.
//!
//! Posting semantics differ per transport (SWD returns DP-read data in the
//! same packet, AP reads are posted through RDBUFF; JTAG-DP posts everything
//! through the 35-bit scan), so each engine implements [`DpPort`] and the
//! common [`MemAp`] logic — power-up handshake, bank select, TAR/DRW with
//! auto-increment — is written once.

use crate::hal::LinkError;

/// DP register byte offsets (low nibble encodes A[3:2] as offset>>2).
pub mod dp_reg {
    /// DPIDR (read) / ABORT (write).
    pub const DPIDR_OR_ABORT: u8 = 0x00;
    /// CTRL/STAT.
    pub const CTRL_STAT: u8 = 0x04;
    /// SELECT.
    pub const SELECT: u8 = 0x08;
    /// RDBUFF — posted read result.
    pub const RDBUFF: u8 = 0x0C;
}

/// MEM-AP register offsets.
pub mod ap_reg {
    /// Transfer size / increment control.
    pub const CSW: u8 = 0x00;
    /// Transfer address.
    pub const TAR: u8 = 0x04;
    /// Data read/write.
    pub const DRW: u8 = 0x0C;
    /// Identification.
    pub const IDR: u8 = 0xFC;
}

/// CTRL/STAT bits (ADIv5).
pub mod ctrl_stat {
    pub const CSYSPWRUPREQ: u32 = 1 << 28;
    pub const CSYSPWRUPACK: u32 = 1 << 27;
    pub const CDBGPWRUPREQ: u32 = 1 << 26;
    pub const CDBGPWRUPACK: u32 = 1 << 25;
    pub const CSTICKYERR: u32 = 1 << 5;
    /// ABORT write-1-to-clear bits.
    pub const STKERRCLR: u32 = 1 << 1;
    pub const ORUNCLR: u32 = 1 << 3;
}

/// CSW: 32-bit transfers, auto-increment TAR (classic AHB-AP value).
pub const CSW_32BIT_AUTOINC: u32 = 0x2300_0042;

/// A physical Debug Port. Implementations speak SWD packets or 35-bit
/// JTAG-DP scans; both present this one face to [`MemAp`].
pub trait DpPort {
    /// Read a DP register (offset 0x00/0x04/0x08/0x0C).
    fn dp_read(&mut self, addr: u8) -> Result<u32, LinkError>;
    /// Write a DP register.
    fn dp_write(&mut self, addr: u8, value: u32) -> Result<(), LinkError>;
    /// Read an AP register (posted reads resolved internally).
    fn ap_read(&mut self, addr: u8) -> Result<u32, LinkError>;
    /// Write an AP register.
    fn ap_write(&mut self, addr: u8, value: u32) -> Result<(), LinkError>;
    /// Read the DPIDR (implementation detail of each port).
    fn dpidr(&mut self) -> Result<u32, LinkError> {
        self.dp_read(dp_reg::DPIDR_OR_ABORT)
    }
}

/// A MEM-AP (memory access port) on top of a [`DpPort`].
///
/// Handles: AP selection + bank switching via SELECT, system/debug power-up
/// handshake, CSW configuration, and block transfers through TAR/DRW with
/// auto-increment.
pub struct MemAp<'a, P: DpPort> {
    dp: &'a mut P,
    apsel: u8,
    bank: u8,
    /// Number of power-up polls before giving up.
    pub powerup_polls: u32,
}

impl<'a, P: DpPort> MemAp<'a, P> {
    pub fn new(dp: &'a mut P, apsel: u8) -> Self {
        MemAp {
            dp,
            apsel,
            bank: 0xFF,
            powerup_polls: 256,
        }
    }

    fn set_bank(&mut self, bank: u8) -> Result<(), LinkError> {
        if self.bank != bank {
            let sel = ((self.apsel as u32) << 24) | bank as u32;
            self.dp.dp_write(dp_reg::SELECT, sel)?;
            self.bank = bank;
        }
        Ok(())
    }

    /// Bring system + debug power domains up and verify both ACK.
    pub fn power_up(&mut self) -> Result<(), LinkError> {
        let req = ctrl_stat::CSYSPWRUPREQ | ctrl_stat::CDBGPWRUPREQ;
        self.set_bank(0)?;
        self.dp.dp_write(dp_reg::CTRL_STAT, req)?;
        let want = ctrl_stat::CSYSPWRUPACK | ctrl_stat::CDBGPWRUPACK;
        for _ in 0..self.powerup_polls {
            let st = self.dp.dp_read(dp_reg::CTRL_STAT)?;
            if (st & want) == want {
                return Ok(());
            }
        }
        Err(LinkError::Fault("power-up handshake never ACKed"))
    }

    /// Read the AP IDR — identifies the MEM-AP instance.
    pub fn idr(&mut self) -> Result<u32, LinkError> {
        self.set_bank(0x0F)?;
        self.dp.ap_read(ap_reg::IDR)
    }

    /// Configure CSW for 32-bit auto-increment access.
    fn configure(&mut self) -> Result<(), LinkError> {
        self.set_bank(0)?;
        self.dp.ap_write(ap_reg::CSW, CSW_32BIT_AUTOINC)
    }

    /// Single 32-bit memory read.
    pub fn read32(&mut self, addr: u32) -> Result<u32, LinkError> {
        self.configure()?;
        self.dp.ap_write(ap_reg::TAR, addr)?;
        self.dp.ap_read(ap_reg::DRW)
    }

    /// Single 32-bit memory write.
    pub fn write32(&mut self, addr: u32, value: u32) -> Result<(), LinkError> {
        self.configure()?;
        self.dp.ap_write(ap_reg::TAR, addr)?;
        self.dp.ap_write(ap_reg::DRW, value)
    }

    /// Block read with TAR auto-increment.
    pub fn read_block32(&mut self, addr: u32, out: &mut [u32]) -> Result<(), LinkError> {
        if out.is_empty() {
            return Ok(());
        }
        self.configure()?;
        self.dp.ap_write(ap_reg::TAR, addr)?;
        // TAR auto-increment is only guaranteed within 1 KiB windows
        // (ADIv5), so re-set TAR when we cross a boundary.
        let mut a = addr;
        for (i, slot) in out.iter_mut().enumerate() {
            if i > 0 && (a & 0x3FF) == 0 {
                self.dp.ap_write(ap_reg::TAR, a)?;
            }
            *slot = self.dp.ap_read(ap_reg::DRW)?;
            a = a.wrapping_add(4);
        }
        Ok(())
    }

    /// Block write with TAR auto-increment.
    pub fn write_block32(&mut self, addr: u32, data: &[u32]) -> Result<(), LinkError> {
        if data.is_empty() {
            return Ok(());
        }
        self.configure()?;
        self.dp.ap_write(ap_reg::TAR, addr)?;
        let mut a = addr;
        for (i, &w) in data.iter().enumerate() {
            if i > 0 && (a & 0x3FF) == 0 {
                self.dp.ap_write(ap_reg::TAR, a)?;
            }
            self.dp.ap_write(ap_reg::DRW, w)?;
            a = a.wrapping_add(4);
        }
        Ok(())
    }

    /// Halt the core through the debug block (vendor-modeled register:
    /// write 1 to DBG_HALT).
    pub fn halt_core(&mut self, dbg_base: u32) -> Result<(), LinkError> {
        self.write32(dbg_base, 1)
    }

    /// Jump the core to an entry point (DBG_JUMP, Thumb bit honored).
    pub fn jump_core(&mut self, dbg_base: u32, entry: u32) -> Result<(), LinkError> {
        self.write32(dbg_base + 0x04, entry)
    }

    /// Read the core status word (DBG_STATS).
    pub fn core_status(&mut self, dbg_base: u32) -> Result<u32, LinkError> {
        self.read32(dbg_base + 0x08)
    }
}
