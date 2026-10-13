//! Storage-lane interception: the gate, the per-lane targets, and
//! the direct command path.
//!
//! Physically the interceptor sits between the host root complex
//! and the storage targets: every PCIe/SATA lane of the targets is
//! routed through the FPGA pins. Three gate states per lane:
//!
//! ```text
//!   BYPASS    traffic flows host ↔ target untouched (normal ops)
//!   GATED     the payload drives the target directly; the host
//!             side is held in hot-reset / electrical idle — the
//!             host cannot observe or inject anything
//!   LATCHED   one-way after completion: every write transaction is
//!             refused at the gate (read-only audit path stays up)
//! ```
//!
//! [`LaneGate`] is the register-level driver; [`Target`] is the
//! discovered per-lane identity; [`LaneDriver`] issues the direct
//! commands (erase / write / read / wear) the sanitizer uses.

use crate::hal::Mmio;
use crate::hal::{lane_cmd, lane_stat, regs};

/// Maximum lanes one interceptor core gates.
pub const MAX_LANES: usize = 4;

/// A discovered storage target behind one lane.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Target {
    /// Lane index (0..MAX_LANES).
    pub lane: u32,
    /// IDENTIFY word returned by the target.
    pub identity: u32,
}

/// Lane gate register driver (per-interceptor).
pub struct LaneGate<'a> {
    mmio: &'a mut dyn Mmio,
}

impl<'a> LaneGate<'a> {
    pub fn new(mmio: &'a mut dyn Mmio) -> Self {
        Self { mmio }
    }

    /// Gate `lanes` (bitmask, 1 = gated for sanitization).
    pub fn gate(&mut self, lanes: u32) {
        self.mmio.write32(regs::LANE_GATE, lanes);
    }

    /// Read the target-present bitmap.
    pub fn present(&self) -> u32 {
        self.mmio.read32(regs::LANE_PRESENT)
    }

    /// Latch the gate closed (one-way, post-completion).
    pub fn latch(&mut self) {
        self.mmio.write32(regs::LANE_LATCH, 1);
    }

    /// Whether the latch is engaged.
    pub fn latched(&self) -> bool {
        self.mmio.read32(regs::LANE_LATCH) != 0
    }

    /// IDENTIFY every present lane, ungated (discovery is passive).
    pub fn enumerate(&mut self) -> [Option<Target>; MAX_LANES] {
        let present = self.present();
        let mut out = [None; MAX_LANES];
        for (lane, slot) in out.iter_mut().enumerate() {
            if (present >> lane) & 1 == 1 {
                let identity = self.command(lane as u32, lane_cmd::IDENTIFY, 0, 0);
                if let Some(word) = identity {
                    *slot = Some(Target {
                        lane: lane as u32,
                        identity: word,
                    });
                }
            }
        }
        out
    }

    /// Run one lane command; returns the LANE_DATA word on OK.
    fn command(&mut self, lane: u32, cmd: u32, addr: u32, data: u32) -> Option<u32> {
        self.mmio.write32(regs::LANE_SELECT, lane & 0xF);
        self.mmio.write32(regs::LANE_ADDR, addr);
        self.mmio.write32(regs::LANE_DATA, data);
        self.mmio.write32(regs::LANE_CMD, cmd);
        let stat = self.mmio.read32(regs::LANE_STAT);
        if stat & lane_stat::OK != 0 {
            Some(self.mmio.read32(regs::LANE_DATA))
        } else {
            None
        }
    }
}

/// The direct command path used by the sanitizer (lane gated).
pub struct LaneDriver<'a> {
    mmio: &'a mut dyn Mmio,
}

impl<'a> LaneDriver<'a> {
    pub fn new(mmio: &'a mut dyn Mmio) -> Self {
        Self { mmio }
    }

    /// Block-erase the addressed window on the selected lane.
    pub fn erase(&mut self, lane: u32, addr: u32) -> bool {
        self.raw(lane, lane_cmd::ERASE, addr, 0)
    }

    /// Write one data word to the addressed window.
    pub fn write(&mut self, lane: u32, addr: u32, data: u32) -> bool {
        self.raw(lane, lane_cmd::WRITE, addr, data)
    }

    /// Read one word from the addressed window.
    pub fn read(&mut self, lane: u32, addr: u32) -> Option<u32> {
        self.mmio.write32(regs::LANE_SELECT, lane & 0xF);
        self.mmio.write32(regs::LANE_ADDR, addr);
        self.mmio.write32(regs::LANE_CMD, lane_cmd::READ);
        let stat = self.mmio.read32(regs::LANE_STAT);
        if stat & lane_stat::OK != 0 {
            Some(self.mmio.read32(regs::LANE_DATA))
        } else {
            None
        }
    }

    /// Read the lane's erase-pulse (wear) counter.
    pub fn wear(&mut self, lane: u32) -> Option<u32> {
        self.mmio.write32(regs::LANE_SELECT, lane & 0xF);
        self.mmio.write32(regs::LANE_CMD, lane_cmd::WEAR);
        let stat = self.mmio.read32(regs::LANE_STAT);
        if stat & lane_stat::OK != 0 {
            Some(self.mmio.read32(regs::LANE_DATA))
        } else {
            None
        }
    }

    fn raw(&mut self, lane: u32, cmd: u32, addr: u32, data: u32) -> bool {
        self.mmio.write32(regs::LANE_SELECT, lane & 0xF);
        self.mmio.write32(regs::LANE_ADDR, addr);
        self.mmio.write32(regs::LANE_DATA, data);
        self.mmio.write32(regs::LANE_CMD, cmd);
        self.mmio.read32(regs::LANE_STAT) & lane_stat::OK != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::SimBoard;

    #[test]
    fn enumeration_finds_only_present_lanes() {
        let mut board = SimBoard::new();
        board.attach_target(0);
        board.attach_target(3);
        let mut gate = LaneGate::new(&mut board);
        let targets = gate.enumerate();
        assert!(targets[0].is_some());
        assert!(targets[3].is_some());
        assert_eq!(targets[0].unwrap().identity & 0xF000_0000, 0);
        assert!(targets[1].is_none());
        assert!(targets[2].is_none());
    }

    #[test]
    fn ungated_erase_is_refused_gated_succeeds() {
        let mut board = SimBoard::new();
        board.attach_target(0);
        {
            let mut drv = LaneDriver::new(&mut board);
            assert!(!drv.erase(0, 10), "bypass lane refuses direct writes");
        }
        board.write32(regs::LANE_GATE, 1 << 0);
        let mut drv = LaneDriver::new(&mut board);
        assert!(drv.erase(0, 10));
        assert_eq!(drv.read(0, 10), Some(0));
    }

    #[test]
    fn wear_counter_tracks_erase_pulses() {
        let mut board = SimBoard::new();
        board.attach_target(1);
        board.write32(regs::LANE_GATE, 1 << 1);
        let mut drv = LaneDriver::new(&mut board);
        for i in 0..5 {
            assert!(drv.erase(1, i));
        }
        assert_eq!(drv.wear(1), Some(5));
    }
}
