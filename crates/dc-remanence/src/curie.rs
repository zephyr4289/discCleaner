//! # Curie-dither: thermal & magnetic domain randomization.
//!
//! The annihilation engine's second weapon. The ladder smashes the
//! guard bands with hard fields; the dither finishes the job at the
//! soft edges and — critically — destroys the *transition-boundary*
//! forensics (the positions of the old recording's NRZ edges, which
//! density-modulation attacks read).
//!
//! ## Physics
//!
//! **Néel-Brown thermal activation.** A grain with coercivity
//! `H_c` under applied field `H` flips with probability
//!
//! ```text
//! P_switch(H, H_c) = 1                          if H ≥ H_c           (hard switch)
//!                  = exp(−κ · (1 − H/H_c))       if H < H_c           (thermal)
//! ```
//!
//! during one write pass, where `κ` is the activation factor
//! (~energy barrier / k_B T at the write timescale). Near the
//! bubble edge — where `H` is just under the grain's `H_c` — the
//! thermal branch still fires with healthy probability, which is
//! exactly what repeated dither passes exploit.
//!
//! **Alternating flux.** The dither pattern writes polarity
//! `π_k = ±1` inverted every `period` cells, with a per-pass random
//! phase and per-cell jitter, at elevated current. Each pass, a
//! grain that fires its switch re-aligns with the *current*
//! polarity; because the polarity comb alternates (and the phase is
//! re-rolled per pass), the grain's final orientation after `K`
//! passes is statistically independent of both its old state and
//! the comb itself. Old-domain retention decays geometrically:
//!
//! ```text
//! retention after K passes = Π_k (1 − p_k)
//! correlation with old orientation ≈ Π_k (1 − p_k)·(alternation factors)
//! ```
//!
//! **Transition-boundary scrambling.** Writing a maximum-density
//! alternating pattern plants a fresh transition comb everywhere;
//! the autocorrelation of the guard-band signal at the OLD bit
//! period `T_old` is driven to zero because the dominant surviving
//! spatial frequency is the dither period `T_d << T_old`.

use crate::SimRng;
/// Relative field excess over coercivity that guarantees a hard
/// switch (threshold branch of the Néel-Brown model).
pub const HARD_SWITCH_MARGIN: f64 = 0.05;

/// Néel-Brown activation factor per write pass at write timescales.
///
/// `κ = E_barrier / (k_B T)` evaluated over the ~10 ns field
/// dwell of a write event for typical CoCrPt barriers
/// (E_barrier ≈ 45 k_B T room-temperature stability, divided by
/// the dwell-time attempt count). Chosen so that a grain at 90% of
/// its coercivity still switches with ~30% probability per pass —
/// consistent with measured write-error-rate tails.
pub const KAPPA_NEL_BROWN: f64 = 12.0;

/// The Curie-dither waveform configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurieDither {
    /// Spatial period of the polarity comb, in cells (2 = maximum
    /// transition density).
    pub period_cells: usize,
    /// Write-current bias during dithering (elevated).
    pub bias: f64,
    /// Number of full passes over the track.
    pub passes: usize,
    /// Per-pass phase re-rolling (random phase per pass).
    pub reroll_phase: bool,
    /// Per-cell polarity jitter fraction (0..1) — transition-position
    /// scrambling.
    pub jitter: f64,
}

impl Default for CurieDither {
    fn default() -> Self {
        Self {
            period_cells: 2,
            bias: 0.55,
            passes: 24,
            reroll_phase: true,
            jitter: 0.5,
        }
    }
}

impl CurieDither {
    /// Validate the waveform.
    pub fn validate(&self) -> Result<(), String> {
        if self.period_cells < 2 {
            return Err("dither period must be at least 2 cells (alternating)".into());
        }
        if self.passes == 0 {
            return Err("a dither of zero passes randomizes nothing".into());
        }
        if !(0.0..=1.0).contains(&self.jitter) {
            return Err("jitter fraction must lie in [0,1]".into());
        }
        Ok(())
    }

    /// The polarity comb for one pass: cell index → ±1.
    ///
    /// `phase` shifts the comb's starting cell; with
    /// `reroll_phase` the caller draws a fresh phase per pass from
    /// the RNG.
    pub fn polarity_pass(&self, cells: usize, phase: usize) -> Vec<f64> {
        (0..cells)
            .map(|i| {
                if ((i + phase) / self.period_cells).is_multiple_of(2) {
                    1.0
                } else {
                    -1.0
                }
            })
            .collect()
    }

    /// Draw a random pass phase.
    pub fn roll_phase(&self, rng: &mut SimRng) -> usize {
        rng.below(self.period_cells.max(2) as u64) as usize
    }
}

/// Néel-Brown switching probability for one write pass.
///
/// `field` is the local write field in gap-field units, `hc` the
/// grain coercivity in the same units.
pub fn switch_probability(field: f64, hc: f64) -> f64 {
    if !field.is_finite() || field <= 0.0 {
        return 0.0;
    }
    if field >= hc * (1.0 + HARD_SWITCH_MARGIN) {
        1.0
    } else if field >= hc {
        // Between hard threshold and coercivity: near-certain.
        0.98
    } else {
        (-KAPPA_NEL_BROWN * (1.0 - field / hc)).exp()
    }
}

/// Expected old-domain retention after `k` dither passes at
/// per-pass switch probability `p` with alternating re-orientation.
///
/// Retention here is the *correlation* of the grain's final
/// orientation with its old orientation: each pass multiplies by
/// `(1 − p)` (it survived unswitched), and a switch under an
/// alternating comb re-aligns it to an orientation whose expected
/// correlation with the old state is zero (fresh ±1 draw).
pub fn retention_after_passes(p: f64, passes: usize) -> f64 {
    (1.0 - p.clamp(0.0, 1.0)).powi(passes as i32)
}

/// Jittered transition-position map for one dither pass.
///
/// Returns per-cell positions (in cell units) of the comb
/// transitions after applying the jitter fraction — used to prove
/// the old-period autocorrelation is scrambled even if the comb
/// itself is known.
pub fn jittered_transitions(
    cells: usize,
    period: usize,
    jitter: f64,
    rng: &mut SimRng,
) -> Vec<f64> {
    let mut out = Vec::new();
    let mut next = period as f64;
    while next < cells as f64 {
        let jitter_amt = (rng.next_f64() * 2.0 - 1.0) * jitter;
        out.push(next + jitter_amt);
        next += period as f64;
    }
    out
}

/// Autocorrelation of a real signal at lag `lag` (normalized).
///
/// Used in the certificate's transition-forensics check: the
/// post-treatment guard-band sequence must show no residual
/// correlation at the old bit period.
pub fn autocorrelation_at_lag(signal: &[f64], lag: usize) -> f64 {
    if signal.len() <= lag || lag == 0 {
        return 0.0;
    }
    let n = signal.len() - lag;
    let mean = signal.iter().sum::<f64>() / signal.len() as f64;
    let mut num = 0.0;
    let mut den = 0.0;
    for i in 0..n {
        let a = signal[i] - mean;
        let b = signal[i + lag] - mean;
        num += a * b;
    }
    for v in signal {
        den += (v - mean) * (v - mean);
    }
    if den <= f64::EPSILON { 0.0 } else { num / den }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_probability_branches() {
        // Hard switch above the margin threshold.
        assert_eq!(switch_probability(1.2, 0.6), 1.0);
        // Thermal branch below coercivity: bounded by exp(-κ) and
        // rising towards 1 as field approaches Hc.
        let p_low = switch_probability(0.3, 0.6);
        let p_high = switch_probability(0.55, 0.6);
        assert!(p_low > 0.0 && p_low < 0.02, "far field p = {p_low}");
        assert!(p_high > p_low);
        assert!(p_high <= 1.0);
        // Zero field never switches.
        assert_eq!(switch_probability(0.0, 0.6), 0.0);
    }

    #[test]
    fn retention_decays_geometrically() {
        let p = 0.3;
        assert!((retention_after_passes(p, 1) - 0.7).abs() < 1e-12);
        let r10 = retention_after_passes(p, 10);
        let r20 = retention_after_passes(p, 20);
        assert!(r10 > 1e-4 && r10 < 0.04);
        assert!((r20 - r10 * r10).abs() < 1e-12, "geometric decay");
        assert!(retention_after_passes(1.0, 1) < 1e-12);
    }

    #[test]
    fn dither_comb_alternates() {
        let d = CurieDither::default();
        let comb = d.polarity_pass(8, 0);
        assert_eq!(comb, vec![1.0, 1.0, -1.0, -1.0, 1.0, 1.0, -1.0, -1.0]);
        let phased = d.polarity_pass(8, 1);
        assert_eq!(phased[0], 1.0);
        assert_ne!(phased, comb);
        assert!(d.validate().is_ok());
    }

    #[test]
    fn dither_validation_rejects_degenerate_waveforms() {
        assert!(
            CurieDither {
                period_cells: 1,
                ..CurieDither::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CurieDither {
                passes: 0,
                ..CurieDither::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CurieDither {
                jitter: 1.5,
                ..CurieDither::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn jittered_transitions_stay_in_neighborhood() {
        let mut rng = SimRng::new(11);
        let ts = jittered_transitions(64, 4, 0.5, &mut rng);
        assert!(!ts.is_empty());
        // All transitions within ±1 cell of their nominal comb slot.
        for (k, t) in ts.iter().enumerate() {
            let nominal = (k + 1) as f64 * 4.0;
            assert!((t - nominal).abs() <= 1.0, "t={t} vs {nominal}");
        }
    }

    #[test]
    fn autocorrelation_detects_periodicity_and_noise() {
        // Pure alternating signal: strong negative correlation at lag 1.
        let sig: Vec<f64> = (0..64)
            .map(|i| if i % 2 == 0 { 1.0 } else { -1.0 })
            .collect();
        assert!(autocorrelation_at_lag(&sig, 1) < -0.9);
        // White noise: near-zero correlation at any lag (long window
        // keeps the sampling error small).
        let mut rng = SimRng::new(3);
        let noise: Vec<f64> = (0..4096).map(|_| rng.next_normal()).collect();
        assert!(autocorrelation_at_lag(&noise, 4).abs() < 0.06);
        assert!(autocorrelation_at_lag(&noise, 8).abs() < 0.06);
    }
}
