//! Threshold-voltage (Vth) distribution modeling and shift estimation.
//!
//! A floating-gate cell's charge state IS its threshold voltage: the
//! gate voltage at which the channel turns on. A fresh, erased cell
//! (SLC) sits in a tight Gaussian around Vth ≈ −1 V; a programmed
//! cell sits near +2 V. Every program/erase cycle does two things
//! to those populations:
//!
//! 1. **Mean shift** — charge trapped in the tunnel oxide screens
//!    the floating gate, so the erased distribution walks positive
//!    (and the programmed distribution walks with it). After N cycles
//!    the shift follows the classic power law
//!    ΔVth(N) ≈ ΔV₀ · N^α  with α ≈ 0.3–0.5 for SiO₂ tunnel oxides.
//! 2. **σ-widening** — trap occupancy is per-cell stochastic, so the
//!    distributions smear: read margins shrink, read-retry events
//!    multiply.
//!
//!    Both are analog charge-state facts. The FTL can lie about
//!    blocks; it cannot untrap charge.
//!
//!    ## Estimation from observables
//!
//!    Raw per-cell Vth is not directly visible to software, but the
//!    controller's own compensation is: when a read of a stressed block
//!    needs **read-retry** (a shifted-Vth recovery re-read with adjusted
//!    reference voltages), that retry count per K reads is a monotone
//!    observable of distribution overlap. [`VthEstimator`] converts
//!    read-retry statistics into a bounded ΔVth estimate via the
//!    Gaussian overlap integral, inverting the standard Q-function.

use serde::{Deserialize, Serialize};

/// One Vth distribution (a single programmed-level population).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VthDistribution {
    /// Mean threshold voltage, volts.
    pub mean_v: f64,
    /// Standard deviation, volts.
    pub sigma_v: f64,
}

impl VthDistribution {
    pub const fn new(mean_v: f64, sigma_v: f64) -> Self {
        Self { mean_v, sigma_v }
    }

    /// Overlap coefficient with another distribution: the fraction
    /// of cells the two populations share (0 = disjoint, 1 =
    /// identical). Read-retry rates track this overlap.
    pub fn overlap_with(&self, other: &VthDistribution) -> f64 {
        // For two Gaussians the overlapping coefficient is
        // 2·Φ(−|μ1−μ2| / (2σ̄)) with σ̄ the RMS of the two sigmas
        // (exact for equal variances, tight upper bound otherwise).
        let sigma_bar = ((self.sigma_v.powi(2) + other.sigma_v.powi(2)) / 2.0).sqrt();
        if sigma_bar <= 0.0 {
            return if (self.mean_v - other.mean_v).abs() < f64::EPSILON {
                1.0
            } else {
                0.0
            };
        }
        2.0 * gaussian_cdf(-(self.mean_v - other.mean_v).abs() / (2.0 * sigma_bar))
    }

    /// Shift this distribution (mean += dmean, sigma widened by
    /// the multiplicative factor).
    pub fn shifted(&self, dmean: f64, widen: f64) -> Self {
        Self::new(self.mean_v + dmean, self.sigma_v * widen)
    }
}

/// The canonical empirical wear law: ΔVth(N) = dv0 · N^α.
///
/// Defaults fitted to the SLC endurance literature: ΔV₀ ≈ 40 mV of
/// trapped-charge screening after one full P/E cycle at the oxide
/// fields dc applies, α ≈ 0.35.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WearLaw {
    /// Single-cycle shift constant, volts.
    pub dv0_v: f64,
    /// Power-law exponent (0.3–0.5 for tunnel-oxide trapping).
    pub alpha: f64,
}

impl Default for WearLaw {
    fn default() -> Self {
        Self {
            dv0_v: 0.04,
            alpha: 0.35,
        }
    }
}

impl WearLaw {
    /// Predicted mean Vth shift after `cycles` P/E cycles.
    pub fn shift_v(&self, cycles: u64) -> f64 {
        if cycles == 0 {
            0.0
        } else {
            self.dv0_v * (cycles as f64).powf(self.alpha)
        }
    }

    /// Predicted σ-widening factor after `cycles` (linear-in-log
    /// growth, bounded): σ(N) = σ0 · (1 + w·N^β), β = 0.5.
    pub fn widen_factor(&self, cycles: u64, w: f64) -> f64 {
        1.0 + w * (cycles as f64).sqrt()
    }

    /// Invert the law: how many P/E cycles does an observed ΔVth
    /// represent? (The certificate's "how hard did we hit it" bound.)
    pub fn cycles_for_shift(&self, observed_shift_v: f64) -> u64 {
        if observed_shift_v <= 0.0 || self.dv0_v <= 0.0 {
            return 0;
        }
        ((observed_shift_v / self.dv0_v).powf(1.0 / self.alpha)).round() as u64
    }
}

/// Standard normal CDF (Zelen & Severo's Abramowitz-Stegun 26.2.17,
/// |ε| < 7.5e-8 — plenty for wear inference).
pub fn gaussian_cdf(x: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.2316419 * x.abs());
    let poly = t
        * (0.319381530
            + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));
    let pdf = (-0.5 * x * x).exp() / (2.0 * std::f64::consts::PI).sqrt();
    let cdf = 1.0 - pdf * poly;
    if x >= 0.0 { cdf } else { 1.0 - cdf }
}

/// ΔVth estimator: read-retry statistics → threshold-voltage shift.
///
/// Read-retry events per read are the controller's confession that
/// the read reference no longer sits between the (shifted)
/// distributions. Given the retry RATE per 1e3 reads and the
/// pre-stress distribution pair, the overlap that would produce
/// that rate implies a mean shift; [`Self::estimate`] returns the
/// shift that best reproduces the observed retry rate.
#[derive(Debug, Clone)]
pub struct VthEstimator {
    /// The fresh erased-level distribution (baseline reference).
    pub erased: VthDistribution,
    /// The fresh programmed-level distribution (baseline reference).
    pub programmed: VthDistribution,
    pub law: WearLaw,
}

impl VthEstimator {
    pub fn new(erased: VthDistribution, programmed: VthDistribution) -> Self {
        Self {
            erased,
            programmed,
            law: WearLaw::default(),
        }
    }

    /// Estimate (ΔVth mean shift, σ-widening) from an observed
    /// read-retry rate per 1000 reads.
    ///
    /// Model: retry rate ≈ k · overlap(erased', programmed') where
    /// the stressed distributions are the fresh ones shifted by ΔVth
    /// and widened; k = 1000 calibration constant (a retry can only
    /// fire when the populations genuinely overlap). The estimate is
    /// the shift that reproduces the observed rate, found by a
    /// bisection over the physically meaningful range — monotone by
    /// construction, so bisection is exact to the tolerance.
    pub fn estimate(&self, retries_per_1k_reads: f64) -> EstimatedVthShift {
        // Fresh overlap (some baseline retries even on day one).
        let base_overlap = self.erased.overlap_with(&self.programmed);
        // Widen with cycles by the law's default coupling.
        let lo = 0.0f64; // volts
        let hi = 3.0f64; // volts (a dead cell)
        let f = |shift: f64| -> f64 {
            // Widening tracks the same cycle count as the shift.
            let cycles = self.law.cycles_for_shift(shift);
            let w = self.law.widen_factor(cycles.max(1), 0.08);
            let e = self.erased.shifted(shift, w);
            let p = self.programmed.shifted(shift, w);
            // Retries fire on the INCREASED overlap over baseline.
            let inc = (e.overlap_with(&p) - base_overlap).max(0.0);
            inc * 1000.0
        };
        // Bisect: f is monotone increasing in shift.
        let mut lo_v = lo;
        let mut hi_v = hi;
        if f(lo) >= retries_per_1k_reads {
            return EstimatedVthShift {
                shift_v: 0.0,
                widen_factor: 1.0,
                implied_cycles: 0,
            };
        }
        if f(hi) <= retries_per_1k_reads {
            return EstimatedVthShift {
                shift_v: hi,
                widen_factor: self
                    .law
                    .widen_factor(self.law.cycles_for_shift(hi).max(1), 0.08),
                implied_cycles: self.law.cycles_for_shift(hi),
            };
        }
        for _ in 0..60 {
            let mid = (lo_v + hi_v) / 2.0;
            if f(mid) < retries_per_1k_reads {
                lo_v = mid;
            } else {
                hi_v = mid;
            }
        }
        let shift = (lo_v + hi_v) / 2.0;
        let cycles = self.law.cycles_for_shift(shift);
        EstimatedVthShift {
            shift_v: shift,
            widen_factor: self.law.widen_factor(cycles.max(1), 0.08),
            implied_cycles: cycles,
        }
    }
}

/// The estimator's output.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EstimatedVthShift {
    /// Mean Vth shift, volts.
    pub shift_v: f64,
    /// σ-widening factor (1.0 = unworn).
    pub widen_factor: f64,
    /// P/E cycles the wear law says this shift implies.
    pub implied_cycles: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slc_pair() -> (VthDistribution, VthDistribution) {
        (
            VthDistribution::new(-1.0, 0.12),
            VthDistribution::new(2.0, 0.20),
        )
    }

    #[test]
    fn fresh_populations_barely_overlap() {
        let (e, p) = slc_pair();
        // 3 V apart with ~0.2 V sigmas: overlap ~ 0.
        assert!(e.overlap_with(&p) < 1e-9);
    }

    #[test]
    fn identical_populations_fully_overlap() {
        let a = VthDistribution::new(0.5, 0.1);
        assert!((a.overlap_with(&a) - 1.0).abs() < 1e-6);
        let b = VthDistribution::new(0.5, 0.3);
        assert!(
            (a.overlap_with(&b) - 1.0).abs() < 1e-6,
            "same mean always overlaps"
        );
    }

    #[test]
    fn wear_law_is_monotone_and_invertible() {
        let law = WearLaw::default();
        let mut last = 0.0;
        for n in [1u64, 10, 100, 1_000, 10_000] {
            let s = law.shift_v(n);
            assert!(s > last, "monotone in cycles");
            last = s;
        }
        // Round trip: shift(N) → cycles_for_shift ≈ N.
        for n in [10u64, 1000, 5000] {
            let s = law.shift_v(n);
            let back = law.cycles_for_shift(s);
            let rel = (back as f64 - n as f64).abs() / n as f64;
            assert!(rel < 0.02, "round trip N={n}: {back}");
        }
        assert_eq!(law.shift_v(0), 0.0);
    }

    #[test]
    fn retry_rate_maps_to_shift_and_cycles() {
        let (e, p) = slc_pair();
        let est = VthEstimator::new(e, p);
        // Fresh media: ~0 retries → ~0 shift.
        let fresh = est.estimate(0.0);
        assert!(fresh.shift_v < 0.05);
        assert_eq!(fresh.implied_cycles, 0);
        // Heavily cycled: many retries → large shift, many cycles.
        let worn = est.estimate(120.0); // 12% of reads need retry
        assert!(worn.shift_v > 0.5, "shift={}", worn.shift_v);
        assert!(worn.implied_cycles > 1000, "cycles={}", worn.implied_cycles);
        assert!(worn.widen_factor > 1.0);
        // Monotone: more retries never means less shift.
        let mid = est.estimate(20.0);
        assert!(mid.shift_v < worn.shift_v && mid.shift_v > fresh.shift_v);
    }

    #[test]
    fn gaussian_cdf_matches_known_values() {
        assert!((gaussian_cdf(0.0) - 0.5).abs() < 1e-9);
        assert!((gaussian_cdf(1.96) - 0.975).abs() < 1e-4);
        assert!((gaussian_cdf(-1.96) - 0.025).abs() < 1e-4);
        assert!((gaussian_cdf(6.0) - 1.0).abs() < 1e-9);
        assert!(gaussian_cdf(-6.0) > 0.0);
    }

    #[test]
    fn widening_shrinks_the_margin() {
        let (e, p) = slc_pair();
        let w = 2.0; // doubled σ
        let e2 = e.shifted(0.5, w);
        let p2 = p.shifted(0.5, w);
        // Same shift applied to both; widened populations overlap more.
        assert!(e2.overlap_with(&p2) > e.overlap_with(&p));
    }
}
