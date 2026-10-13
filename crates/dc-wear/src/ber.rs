//! Raw bit error rate (RBER) distributions vs P/E cycling.
//!
//! Before ECC hides everything, the raw bit error rate of a flash
//! channel is the cleanest endurance signal there is: it climbs as a
//! power law in P/E cycles, orders of magnitude before the ECC wall
//! is reached. A channel that was "erased" by an FTL shortcut keeps
//! its day-one RBER — indistinguishable from a drive that was never
//! touched. A channel that genuinely ran thousands of erase pulses
//! cannot pretend otherwise.
//!
//! The model (fitted across the SLC endurance literature):
//!
//! ```text
//!   RBER(N) = r0 + a · (N / N_end)^b
//! ```
//!
//! with r0 ≈ 1e-6 (fresh media floor), a ≈ 3e-4, b ≈ 2 — i.e. RBER
//! grows quadratically through the cycling budget. [`BerModel`]
//! evaluates and *inverts* the law (observed RBER → implied P/E
//! cycles), and [`BerTally`] accumulates the empirical counts a
//! verification readback actually observes.

use serde::{Deserialize, Serialize};

/// The empirical RBER endurance law.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BerModel {
    /// Fresh-media floor (day-one RBER).
    pub r0: f64,
    /// Scale at the endurance budget.
    pub a: f64,
    /// Power-law exponent.
    pub b: f64,
    /// Rated endurance budget, P/E cycles.
    pub n_end: u64,
}

impl Default for BerModel {
    fn default() -> Self {
        // SLC-class defaults: 1e-6 floor rising to ~3e-4 at 100k cycles.
        Self {
            r0: 1e-6,
            a: 3e-4,
            b: 2.0,
            n_end: 100_000,
        }
    }
}

impl BerModel {
    /// Predicted RBER after `cycles` P/E cycles.
    pub fn rber(&self, cycles: u64) -> f64 {
        let x = (cycles.min(self.n_end) as f64) / (self.n_end as f64);
        self.r0 + self.a * x.powf(self.b)
    }

    /// Invert: the P/E cycles an observed RBER implies (bisection —
    /// the law is strictly monotone in its operating range).
    pub fn implied_cycles(&self, observed_rber: f64) -> u64 {
        if observed_rber <= self.r0 {
            return 0;
        }
        let (mut lo, mut hi) = (0u64, self.n_end);
        // Monotone bisection over the cycle budget.
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            if self.rber(mid) < observed_rber {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Is an observed RBER statistically distinguishable from the
    /// fresh-media floor, given the read sample size? (Wilson-style
    /// sanity: k errors in n bits, floor p0.) A fresh-looking RBER
    /// on a supposedly cycled channel is FTL-shortcut evidence.
    pub fn looks_fresh(&self, errors: u64, bits_read: u64) -> bool {
        if bits_read == 0 {
            return true;
        }
        let rber = errors as f64 / bits_read as f64;
        // Two-sigma-ish band over the floor for the sample size.
        let band = 2.0 * (self.r0 * (1.0 - self.r0) / bits_read as f64).sqrt();
        rber <= self.r0 + band
    }
}

/// Empirical BER tally for one channel.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BerTally {
    pub bits_read: u64,
    pub bit_errors: u64,
    /// Read-retry events observed during the reads (Vth estimator feed).
    pub read_retries: u64,
}

impl BerTally {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one readback window's observation into the tally.
    pub fn observe(&mut self, bits: u64, errors: u64, retries: u64) {
        self.bits_read += bits;
        self.bit_errors += errors;
        self.read_retries += retries;
    }

    pub fn rber(&self) -> f64 {
        if self.bits_read == 0 {
            0.0
        } else {
            self.bit_errors as f64 / self.bits_read as f64
        }
    }

    /// Read-retry rate per 1000 reads (windows read = the read unit).
    pub fn retry_rate_per_1k(&self, reads: u64) -> f64 {
        if reads == 0 {
            0.0
        } else {
            (self.read_retries as f64 / reads as f64) * 1000.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rber_grows_as_a_power_law() {
        let m = BerModel::default();
        let fresh = m.rber(0);
        assert!((fresh - 1e-6).abs() < 1e-12);
        let r10k = m.rber(10_000);
        let r100k = m.rber(100_000);
        // Quadratic in the cycling fraction x = N/N_end: at 10% of
        // budget RBER is ~4x the floor; at 100% it is ~75x the 10k
        // point.
        assert!(r10k > fresh * 3.0, "r10k={r10k}");
        assert!(r100k > r10k * 50.0, "r100k/r10k = {}", r100k / r10k);
        assert!(r100k < 1e-3, "still under the ECC wall");
    }

    #[test]
    fn inversion_round_trips() {
        let m = BerModel::default();
        for n in [0u64, 1, 100, 5_000, 50_000, 99_999] {
            let r = m.rber(n);
            let back = m.implied_cycles(r);
            let tol = 2.0 + n as f64 * 0.01;
            assert!((back as f64 - n as f64).abs() <= tol, "N={n} → {back}");
        }
        // Below-floor observations clamp to zero.
        assert_eq!(m.implied_cycles(1e-9), 0);
    }

    #[test]
    fn freshness_detection_sees_through_sample_noise() {
        let m = BerModel::default();
        // 1 GiB read of truly fresh media: expect ~ r0*bits ≈ 8531
        // errors at 1e-6; a cycled channel shows 10x that.
        let bits = 1u64 << 30;
        let fresh_errors = (1e-6 * bits as f64) as u64;
        assert!(m.looks_fresh(fresh_errors, bits), "floor-level is fresh");
        let cycled_errors = fresh_errors * 20;
        assert!(
            !m.looks_fresh(cycled_errors, bits),
            "20x floor is not fresh"
        );
        // Degenerate: no reads read nothing.
        assert!(m.looks_fresh(0, 0));
    }

    #[test]
    fn tally_accumulates_and_computes() {
        let mut t = BerTally::new();
        t.observe(4096 * 8, 3, 1);
        t.observe(4096 * 8, 5, 2);
        assert_eq!(t.bits_read, 2 * 4096 * 8);
        assert_eq!(t.bit_errors, 8);
        assert_eq!(t.read_retries, 3);
        let rber = t.rber();
        assert!((rber - 8.0 / (2.0 * 4096.0 * 8.0)).abs() < 1e-18);
        assert_eq!(t.retry_rate_per_1k(2), 1500.0); // 3 retries / 2 reads
    }

    #[test]
    fn empty_tally_is_safe() {
        let t = BerTally::new();
        assert_eq!(t.rber(), 0.0);
        assert_eq!(t.retry_rate_per_1k(0), 0.0);
    }
}
