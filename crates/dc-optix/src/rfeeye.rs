//! # Readback verification: RF eye pattern & push-pull collapse.
//!
//! The verification instrument replays the drive's own read path
//! over the annihilated disc — the same signals a forensics lab
//! would capture:
//!
//! * **HF RF eye pattern** — the photodiode high-frequency signal
//!   as the spot crosses marks and lands. The eye height is
//!   `I₀·(R_max − R_min)`, the eye width the timing margin at the
//!   slicer threshold. A destroyed layer shows a flat line: the
//!   eye is CLOSED to the noise floor.
//! * **Push-pull tracking signal** — the quadrature photodiode
//!   difference that locks the spot in the groove. Annihilation
//!   heat slumps the groove walls; the push-pull amplitude decays
//!   with the residual groove height, and the servo loses its
//!   error term.
//! * **Jitter** — the timing dispersion of the recovered mark
//!   edges: with contrast gone, the slicer fires on pure noise
//!   (jitter at the channel-clock scale).
//!
//! All signals are read with photodiode shot + electronics noise
//! (σ = 1% of the full-scale return, the calibrated-reader
//! best case — we give the adversary the quietest instrument).

use crate::SimRng;
use crate::layer::LayerStack;
/// Normalized read-path noise (fraction of full-scale return).
pub const READ_SIGMA: f64 = 0.01;

/// Per-zone eye analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EyeZoneReport {
    pub zone: usize,
    /// Eye height (normalized return): R_max − R_min.
    pub eye_height: f64,
    /// Eye height against the noise floor (σ = 0.01): the eye is
    /// closed below 2σ.
    pub eye_open: bool,
    /// Reflectivity modulation ΔR/R.
    pub modulation: f64,
    /// Mean photodiode return (normalized).
    pub mean_return: f64,
}

/// The overall readback analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReadbackReport {
    pub zones: Vec<EyeZoneReport>,
    /// Worst (largest) residual modulation across zones.
    pub worst_modulation: f64,
    /// Push-pull amplitude vs fresh media (0..1).
    pub push_pull_ratio: f64,
    /// Mark-edge jitter vs the channel bit clock (0..1; 0.5 =
    /// uniform random — pure noise).
    pub jitter: f64,
    /// Forensics read-recovery success rate (0.5 = chance).
    pub read_recovery_rate: f64,
    /// Sample count read per zone.
    pub samples: usize,
}

/// Analyze the readback of an annihilated (or fresh) stack.
pub fn analyze(stack: &LayerStack, rng: &mut SimRng) -> ReadbackReport {
    let mut zones = Vec::with_capacity(stack.zones);
    let mut worst = 0.0_f64;
    for z in 0..stack.zones {
        let zone = &stack.cells[z];
        // Eye height: the TRUE separation of the mark/land
        // reflectivity populations (the calibrated-reader case —
        // the slicer sees the population means, not the sampled
        // extremes). The noisy sample contributes the mean return.
        let mut rmin = f64::INFINITY;
        let mut rmax = f64::NEG_INFINITY;
        let mut sum = 0.0;
        let mut n = 0usize;
        for c in zone.iter().step_by((zone.len() / 64).max(1)) {
            rmin = rmin.min(c.reflectivity);
            rmax = rmax.max(c.reflectivity);
            sum += c.reflectivity + READ_SIGMA * rng.next_normal();
            n += 1;
        }
        let modulation = stack.zone_modulation(z).unwrap_or(0.0);
        let eye = (rmax - rmin).max(0.0);
        let mean = if n > 0 { sum / n as f64 } else { 0.0 };
        worst = worst.max(modulation);
        zones.push(EyeZoneReport {
            zone: z,
            eye_height: eye,
            eye_open: eye > 2.0 * READ_SIGMA,
            modulation,
            mean_return: mean,
        });
    }
    // Push-pull: mean groove vs the fresh-media reference (0.95).
    let push_pull = (stack.mean_groove() / 0.95).clamp(0.0, 1.0);
    // Jitter: timing dispersion ∝ noise / contrast slope; with the
    // contrast gone the slicer output is uniform noise (0.5).
    let contrast = worst.max(1e-9);
    let jitter = (READ_SIGMA / (0.35 * contrast)).clamp(0.0, 0.5);
    ReadbackReport {
        zones,
        worst_modulation: worst,
        push_pull_ratio: push_pull,
        jitter,
        read_recovery_rate: stack.read_recovery_rate(),
        samples: 64,
    }
}

impl ReadbackReport {
    /// The destruction verdict: every eye closed, modulation
    /// below the read threshold, push-pull collapsed, recovery at
    /// chance.
    pub fn destroyed(&self) -> bool {
        self.zones.iter().all(|z| !z.eye_open)
            && self.worst_modulation < 0.05
            && self.push_pull_ratio < 0.15
            && (self.read_recovery_rate - 0.5).abs() < 0.05
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{LayerStack, MediaType};

    #[test]
    fn fresh_disc_shows_wide_open_eyes() {
        let mut rng = SimRng::new(1);
        let stack = LayerStack::new(MediaType::PhaseChange, 4, 8, 32);
        let r = analyze(&stack, &mut rng);
        assert!(r.zones.iter().all(|z| z.eye_open));
        assert!(r.worst_modulation > 0.5);
        assert!(r.push_pull_ratio > 0.85);
        assert!(r.read_recovery_rate > 0.99);
        assert!(!r.destroyed());
    }

    #[test]
    fn annihilated_disc_reads_as_noise() {
        let mut rng = SimRng::new(2);
        let mut stack = LayerStack::new(MediaType::PhaseChange, 4, 8, 32);
        let threshold = MediaType::PhaseChange.annihilate_dose();
        for z in 0..stack.zones {
            let n = stack.sectors_per_zone * stack.cells_per_sector;
            for idx in 0..n {
                stack.deposit(z, idx, threshold * 2.0).unwrap();
            }
        }
        let r = analyze(&stack, &mut rng);
        assert!(r.zones.iter().all(|z| !z.eye_open), "all eyes closed");
        assert!(r.worst_modulation < 0.05);
        assert!(r.push_pull_ratio < 0.15);
        assert!(
            (r.read_recovery_rate - 0.5).abs() < 0.05,
            "recovery {}",
            r.read_recovery_rate
        );
        assert!(r.destroyed());
    }

    #[test]
    fn partial_destruction_is_detected() {
        // Only zone 0 destroyed: the verdict must refuse.
        let mut rng = SimRng::new(3);
        let mut stack = LayerStack::new(MediaType::OrganicDye, 4, 4, 16);
        let threshold = MediaType::OrganicDye.annihilate_dose();
        let n = stack.sectors_per_zone * stack.cells_per_sector;
        for idx in 0..n {
            stack.deposit(0, idx, threshold * 2.0).unwrap();
        }
        let r = analyze(&stack, &mut rng);
        assert!(!r.destroyed());
        assert!(r.zones[0].modulation < 0.05);
        assert!(r.zones[1].modulation > 0.3);
    }

    #[test]
    fn jitter_and_push_pull_degrade_together() {
        let mut rng = SimRng::new(4);
        let fresh = LayerStack::new(MediaType::GlassyCarbon, 2, 4, 16);
        let r_fresh = analyze(&fresh, &mut rng);
        assert!(r_fresh.jitter < 0.2);

        let mut dead = LayerStack::new(MediaType::GlassyCarbon, 2, 4, 16);
        let threshold = MediaType::GlassyCarbon.annihilate_dose();
        for z in 0..dead.zones {
            let n = dead.sectors_per_zone * dead.cells_per_sector;
            for idx in 0..n {
                dead.deposit(z, idx, threshold * 2.0).unwrap();
            }
        }
        let r_dead = analyze(&dead, &mut rng);
        assert!(r_dead.jitter >= 0.49, "slicer fires on pure noise");
        assert!(r_dead.push_pull_ratio < r_fresh.push_pull_ratio);
    }
}
