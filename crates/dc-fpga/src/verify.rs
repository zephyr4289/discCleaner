//! Self-verification: readback classification and the
//! zero-dependency transcript digest.
//!
//! Before the completion fuse burns, every enumerated target is
//! read back through the gate and classified. The classifier
//! answers one question per word: **is this consistent with an
//! erased surface?** (zero word, or the declared final pattern).
//! Any leftover classified-data word blocks completion — the fuse
//! never lies.
//!
//! The transcript digest is a 64-bit FNV-1a chain over every read
//! word and lane — no allocation, no dependencies, one register's
//! worth of state: exactly the kind of arithmetic an open softcore
//! can run cycle-deterministically and an auditor can replay.

use crate::hal::Mmio;
use crate::lane::{LaneDriver, MAX_LANES, Target};
/// FNV-1a 64-bit constants.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Running FNV-1a digest (the transcript hash).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Digest(u64);

impl Default for Digest {
    fn default() -> Self {
        Self(FNV_OFFSET)
    }
}

impl Digest {
    pub fn new() -> Self {
        Self(FNV_OFFSET)
    }

    /// Absorb one word.
    pub fn update(&mut self, word: u32) {
        self.0 ^= word as u64;
        self.0 = self.0.wrapping_mul(FNV_PRIME);
    }

    /// Absorb a lane marker (binds word streams to their lane).
    pub fn update_lane(&mut self, lane: u32) {
        self.update(0x4C41_4E45 /* "LANE" */);
        self.update(lane);
        self.update(0x5447_4554 /* "TGET" */);
    }

    /// Final digest value.
    pub const fn finalize(&self) -> u64 {
        self.0
    }
}

/// Classification of one readback word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordClass {
    /// Erased (zero) — the expected post-erasure state.
    Zero,
    /// The declared final pattern word.
    Pattern(u32),
    /// Leftover classified data — verification failure.
    Residue,
}

impl WordClass {
    pub fn is_ok(&self) -> bool {
        matches!(self, WordClass::Zero | WordClass::Pattern(_))
    }
}

/// Classify one readback word against the expected final pattern
/// (`None` → pure-zero surface expected).
pub fn classify(word: u32, pattern: Option<u32>) -> WordClass {
    if word == 0 {
        WordClass::Zero
    } else if pattern == Some(word) {
        WordClass::Pattern(word)
    } else {
        WordClass::Residue
    }
}

/// Per-target verification outcome.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LaneVerdict {
    pub lane: u32,
    /// Words read.
    pub words_read: u32,
    /// Residue words found (must be 0 to pass).
    pub residue_words: u32,
    /// Transcript digest at the end of this lane's readback.
    pub digest: u64,
    /// Erase pulses the target booked for this run.
    pub wear: u32,
}

impl LaneVerdict {
    pub fn passed(&self) -> bool {
        self.residue_words == 0 && self.words_read > 0
    }
}

/// Fixed-capacity verdict list (no_std: no allocator, ever).
pub type Verdicts = [Option<LaneVerdict>; MAX_LANES];

/// Read one lane back through the gate and verify it.
///
/// `words` is the address window count to check; `pattern` is the
/// expected non-zero final pattern word, if any.
pub fn verify_lane(
    mmio: &mut dyn Mmio,
    target: &Target,
    words: u32,
    pattern: Option<u32>,
) -> LaneVerdict {
    let mut drv = LaneDriver::new(mmio);
    let mut digest = Digest::new();
    digest.update_lane(target.lane);
    let mut residue = 0u32;
    let mut read = 0u32;
    for addr in 0..words {
        match drv.read(target.lane, addr) {
            Some(word) => {
                read += 1;
                digest.update(word);
                if !classify(word, pattern).is_ok() {
                    residue += 1;
                }
            }
            None => {
                // Read failure IS residue: unverifiable ≠ verified.
                residue += 1;
            }
        }
    }
    LaneVerdict {
        lane: target.lane,
        words_read: read,
        residue_words: residue,
        digest: digest.finalize(),
        wear: drv.wear(target.lane).unwrap_or(0),
    }
}

/// Verify every target; all must pass (fixed-capacity, no_std).
pub fn verify_all(
    mmio: &mut dyn Mmio,
    targets: &[Option<Target>; MAX_LANES],
    words: u32,
    pattern: Option<u32>,
) -> Verdicts {
    let mut out: Verdicts = [None; MAX_LANES];
    for (slot, t) in targets.iter().enumerate() {
        if let Some(t) = t {
            out[slot] = Some(verify_lane(mmio, t, words, pattern));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::SimBoard;
    use crate::lane::LaneGate;

    #[test]
    fn fnv_basis_and_step_arithmetic() {
        // Empty digest = FNV offset basis (the one published constant).
        assert_eq!(Digest::new().finalize(), FNV_OFFSET);
        // One word step: h = (basis ^ w) * prime, mod 2^64 — computed
        // with the SAME published constants, independently of Digest.
        let w = 0xA5A5_5A5Au32;
        let expect = (FNV_OFFSET ^ w as u64).wrapping_mul(FNV_PRIME);
        let mut d = Digest::new();
        d.update(w);
        assert_eq!(d.finalize(), expect);
        // Order sensitivity: words in a different order differ.
        let mut a = Digest::new();
        a.update(1);
        a.update(2);
        let mut b = Digest::new();
        b.update(2);
        b.update(1);
        assert_ne!(a.finalize(), b.finalize());
        // Avalanche: one-bit input change, big output change.
        let mut x = Digest::new();
        x.update(0x0000_0000);
        let mut y = Digest::new();
        y.update(0x0000_0001);
        assert_ne!(x.finalize(), y.finalize());
    }

    #[test]
    fn classification_separates_states() {
        assert_eq!(classify(0, None), WordClass::Zero);
        assert_eq!(classify(0, Some(0xA5A5A5A5)), WordClass::Zero);
        assert_eq!(
            classify(0xA5A5A5A5, Some(0xA5A5A5A5)),
            WordClass::Pattern(0xA5A5A5A5)
        );
        assert_eq!(classify(0xDEADBEEF, None), WordClass::Residue);
        assert_eq!(classify(0xDEADBEEF, Some(0xA5A5A5A5)), WordClass::Residue);
    }

    #[test]
    fn erased_lane_passes_leftover_data_fails() {
        let mut board = SimBoard::new();
        board.attach_target(0);
        board.attach_target(1);
        board.write32(crate::hal::regs::LANE_GATE, 0b11);
        let targets = {
            let mut gate = LaneGate::new(&mut board);
            gate.enumerate()
        };
        // Erase lane 0 fully; leave lane 1 alone.
        {
            let mut drv = LaneDriver::new(&mut board);
            for addr in 0..256u32 {
                assert!(drv.erase(0, addr));
            }
        }
        let verdicts = verify_all(&mut board, &targets, 256, None);
        let v0 = verdicts[0].expect("lane 0 verdict");
        let v1 = verdicts[1].expect("lane 1 verdict");
        assert!(v0.passed(), "erased lane passes: {v0:?}");
        assert!(!v1.passed(), "leftover data lane fails: {v1:?}");
        assert_eq!(v1.residue_words, 256);
        // The erased lane saw 256 erase pulses.
        assert_eq!(v0.wear, 256);
    }

    #[test]
    fn patterned_surface_passes_only_with_the_declared_pattern() {
        let mut board = SimBoard::new();
        board.attach_target(2);
        board.write32(crate::hal::regs::LANE_GATE, 1 << 2);
        // Write the pattern word everywhere (the "final pass"
        // surface: e.g. a fixed DoD-style filler).
        {
            let mut drv = LaneDriver::new(&mut board);
            for addr in 0..256u32 {
                assert!(drv.write(2, addr, 0xA5A5_5A5A));
            }
        }
        let mut targets = [None; MAX_LANES];
        targets[2] = Some(Target {
            lane: 2,
            identity: 0,
        });
        // Right pattern → passes.
        let v = verify_all(&mut board, &targets, 256, Some(0xA5A5_5A5A));
        assert!(v[2].as_ref().expect("verdict").passed());
        // Wrong pattern → every word is residue.
        let v2 = verify_all(&mut board, &targets, 256, Some(0x1313_1313));
        assert!(!v2[2].as_ref().expect("verdict").passed());
        assert_eq!(v2[2].as_ref().unwrap().residue_words, 256);
    }

    #[test]
    fn digests_bind_lane_and_content() {
        let mut board = SimBoard::new();
        board.attach_target(0);
        board.write32(crate::hal::regs::LANE_GATE, 1 << 0);
        let t0 = Target {
            lane: 0,
            identity: 0,
        };
        let a = verify_lane(&mut board, &t0, 8, None);
        // Same lane read again: deterministic digest.
        let b = verify_lane(&mut board, &t0, 8, None);
        assert_eq!(a.digest, b.digest);
        // Change one word: digest changes (content binding).
        {
            let mut drv = LaneDriver::new(&mut board);
            drv.write(0, 3, 1);
        }
        let c = verify_lane(&mut board, &t0, 8, None);
        assert_ne!(a.digest, c.digest);
    }
}
