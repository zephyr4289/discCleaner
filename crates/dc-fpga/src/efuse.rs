//! The one-way eFuse bank.
//!
//! An eFuse is a physical metal link you destroy by forcing
//! current through it — anti-fuse or laser-cut variants have the
//! same property: **the transition is one-way and microscopically
//! visible**. A blown completion fuse is the silicon-level analogue
//! of a wax seal: it cannot be forged after the fact by any
//! software on any die, and a lab with a microscope can confirm it
//! decades later, powered or not.
//!
//! Bit allocation in the 32-bit bank (word offset `regs::EFUSE`):
//!
//! | bits | meaning |
//! |------|---------|
//! | 0..=27 | per-target completion fuse (one per enumerated lane) |
//! | 28 | FAULT fuse — the run ended in the fault path (never with COMPLETE) |
//! | 29 | VERIFIED fuse — self-verification passed on all targets |
//! | 30 | COMPLETE fuse — the root of destruction ran to the end |
//! | 31 | reserved (must stay 0) |
//!
//! The FAULT bit is blown on the fault path *instead of* COMPLETE:
//! an auditor reading the bank can distinguish "finished" from
//! "failed" — and a failed board is a board somebody must
//! physically re-inspect.

use crate::hal::Mmio;
use crate::hal::regs;

/// Bit positions in the fuse word.
pub mod bits {
    /// First per-target fuse bit (lane 0).
    pub const TARGET_BASE: u32 = 0;
    /// The run ended in the fault path.
    pub const FAULT: u32 = 28;
    /// Self-verification passed on all targets.
    pub const VERIFIED: u32 = 29;
    /// The root of destruction completed.
    pub const COMPLETE: u32 = 30;
}

/// Total usable fuse bits (31; bit 31 reserved).
pub const FUSE_MASK: u32 = 0x7FFF_FFFF;

/// The bank model. Real silicon burns links; the model is honest
/// about the one-way property (bits only ever accumulate).
#[derive(Debug, Clone, PartialEq)]
pub struct EfuseBank {
    word: u32,
}

impl Default for EfuseBank {
    fn default() -> Self {
        Self::new()
    }
}

impl EfuseBank {
    pub const fn new() -> Self {
        Self { word: 0 }
    }

    /// Current fuse word.
    pub const fn word(&self) -> u32 {
        self.word
    }

    /// Burn (OR-in) a mask. Physics: one-way — burning cannot clear.
    pub fn burn_mask(&mut self, mask: u32) {
        self.word |= mask & FUSE_MASK;
    }

    /// Blow the per-target completion fuse for lane `i`.
    pub fn burn_target(&mut self, lane: u32) {
        let l = if lane > 27 { 27 } else { lane };
        self.burn_mask(1 << (bits::TARGET_BASE + l));
    }

    /// Blow the fault fuse (fault path only).
    pub fn burn_fault(&mut self) {
        self.burn_mask(1 << bits::FAULT);
    }

    /// Blow the verification-passed fuse.
    pub fn burn_verified(&mut self) {
        self.burn_mask(1 << bits::VERIFIED);
    }

    /// Blow the completion fuse — the root-of-destruction seal.
    pub fn burn_complete(&mut self) {
        self.burn_mask(1 << bits::COMPLETE);
    }

    /// Did the run complete (COMPLETE set, FAULT clear)?
    pub const fn completed(&self) -> bool {
        (self.word & (1 << bits::COMPLETE)) != 0 && (self.word & (1 << bits::FAULT)) == 0
    }

    /// Did the run fault (FAULT set)?
    pub const fn faulted(&self) -> bool {
        (self.word & (1 << bits::FAULT)) != 0
    }

    /// Is target `lane`'s completion fuse blown?
    pub fn target_burned(&self, lane: u32) -> bool {
        (self.word & (1 << (bits::TARGET_BASE + lane.min(27)))) != 0
    }

    /// Count of blown per-target fuses (bits 0..=27).
    pub fn burned_target_count(&self) -> u32 {
        (self.word & 0x0FFF_FFFF).count_ones()
    }

    /// Read the bank over MMIO.
    pub fn read(mmio: &mut dyn Mmio) -> Self {
        Self {
            word: mmio.read32(regs::EFUSE) & FUSE_MASK,
        }
    }

    /// Burn a mask over MMIO (real silicon path).
    pub fn burn(mmio: &mut dyn Mmio, mask: u32) {
        mmio.write32(regs::EFUSE, mask & FUSE_MASK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuses_only_accumulate() {
        let mut f = EfuseBank::new();
        assert_eq!(f.word(), 0);
        f.burn_target(0);
        f.burn_target(0); // idempotent
        assert_eq!(f.word(), 1);
        f.burn_mask(0b1110);
        // "Clearing" by writing the old value does nothing.
        f.burn_mask(1);
        assert_eq!(f.word(), 0b1111);
    }

    #[test]
    fn completion_requires_complete_and_no_fault() {
        let mut f = EfuseBank::new();
        f.burn_complete();
        assert!(f.completed());
        assert!(!f.faulted());
        // A board that faulted never reads as completed.
        let mut g = EfuseBank::new();
        g.burn_fault();
        g.burn_complete(); // even if buggy code blew both
        assert!(!g.completed());
        assert!(g.faulted());
    }

    #[test]
    fn target_fuses_are_independent_bits() {
        let mut f = EfuseBank::new();
        for lane in 0..4u32 {
            assert!(!f.target_burned(lane));
        }
        f.burn_target(2);
        assert!(!f.target_burned(0));
        assert!(f.target_burned(2));
        assert_eq!(f.burned_target_count(), 1);
        f.burn_target(0);
        f.burn_target(1);
        assert_eq!(f.burned_target_count(), 3);
    }

    #[test]
    fn reserved_bit_is_never_burnable() {
        let mut f = EfuseBank::new();
        f.burn_mask(0xFFFF_FFFF);
        assert_eq!(f.word() & 0x8000_0000, 0, "reserved bit stays 0");
        // FAULT was blown along with everything: NOT completed —
        // a faulted board must never read as done, even by accident.
        assert!(!f.completed());
        assert!(f.faulted());
        // Burning everything EXCEPT fault does read as completed.
        let mut g = EfuseBank::new();
        g.burn_mask(FUSE_MASK & !(1 << bits::FAULT));
        assert!(g.completed());
    }

    #[test]
    fn mmio_bank_roundtrip() {
        let mut board = crate::hal::SimBoard::new();
        let f = EfuseBank::read(&mut board);
        assert_eq!(f.word(), 0);
        EfuseBank::burn(&mut board, 1 << bits::COMPLETE);
        let f = EfuseBank::read(&mut board);
        assert!(f.completed());
    }
}
