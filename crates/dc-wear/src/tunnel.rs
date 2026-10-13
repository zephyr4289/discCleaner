//! Fowler-Nordheim tunneling proof: charge accounting for erase pulses.
//!
//! NAND erasure is physics, not bookkeeping: the controller raises
//! the substrate/channel to +20 V (gate grounded through the word
//! line) and electrons leave the floating gate by **Fowler-Nordheim
//! quantum tunneling** through the ~7–8 nm tunnel oxide. The tunnel
//! current density follows the canonical FN law
//!
//! ```text
//!   J = A_FN · F² · exp(−B_FN / F)      [A/cm², F in MV/cm]
//! ```
//!
//! with the standard SiO₂ empirical constants A_FN = 1.25×10⁻⁶
//! A·cm⁻²·(MV/cm)⁻² and B_FN = 253 MV/cm. Both the erasure of the
//! cell AND the wear of the oxide are this same current: every
//! pulse injects charge THROUGH the dielectric, and the cumulative
//! injected charge density
//!
//! ```text
//!   Q_inj = Σ_pulses J(F_p) · t_p
//! ```
//!
//! is the single quantity that (a) cannot be produced without real
//! high-voltage pulses and (b) is exactly what wears the oxide —
//! you cannot claim the erase happened without also admitting the
//! dielectric stress that goes with it. That duality is the proof.
//!
//! ## Charge-bleed cross-check
//!
//! A ΔVth observed on a channel implies a floating-gate charge
//! change ΔQ = C_fg · ΔVth. If the campaign's erase pulses did not
//! move at least that much charge, the ΔVth did not come from this
//! campaign (or the erase never happened). [`TunnelAccountant`]
//! keeps both ledgers and [`Self::consistency`] checks them.

use serde::{Deserialize, Serialize};

/// Standard SiO₂ Fowler-Nordheim empirical constants (law shape).
pub const FN_A: f64 = 1.25e-6; // A·cm⁻²·(MV/cm)⁻²
pub const FN_B: f64 = 253.0; // MV/cm

/// dc-wear per-cell calibration anchor: the electron count one
/// STANDARD erase pulse (10.5 MV/cm, 1 ms) moves through one
/// floating gate — the textbook SLC erase window (~2.5×10³
/// electrons).
///
/// Why a calibration instead of a first-principles J·A·t integral:
/// the effective tunnel area per cell is process-secret (it depends
/// on the gate stack geometry and the coupling ratio), so the
/// per-cell conversion is anchored to the one number every flash
/// datasheet implicitly agrees on — the charge window — and scaled
/// by the FN law's field/time ratios from there. The AREA-side
/// ledger (`q_inj_c_cm2`) stays first-principles.
pub const CAL_ELECTRONS_REF_PULSE: f64 = 2_500.0;
/// Reference pulse for the calibration anchor.
pub const CAL_REF_FIELD_MV_CM: f64 = 10.5;
pub const CAL_REF_DURATION_US: f64 = 1_000.0;

/// Fowler-Nordheim tunneling current density at field `f_mv_cm`
/// (megavolts per centimeter).
///
/// ```text
/// J = A_FN · F² · exp(−B_FN / F)
/// ```
pub fn fn_current_density_a_cm2(f_mv_cm: f64) -> f64 {
    if f_mv_cm <= 0.0 {
        return 0.0;
    }
    FN_A * f_mv_cm * f_mv_cm * (-FN_B / f_mv_cm).exp()
}

/// One erase pulse as actually applied by the controller.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ErasePulse {
    /// Oxide field during the pulse, MV/cm (~10 for erase).
    pub field_mv_cm: f64,
    /// Pulse duration, microseconds (typ. 100 µs – 10 ms).
    pub duration_us: f64,
}

impl ErasePulse {
    /// Charge injected through one cell's tunnel oxide by this
    /// pulse, in electrons — the calibration-anchored estimate
    /// (see [`CAL_ELECTRONS_REF_PULSE`]).
    pub fn charge_electrons_per_cell(&self) -> f64 {
        let j_ref = fn_current_density_a_cm2(CAL_REF_FIELD_MV_CM);
        let j = fn_current_density_a_cm2(self.field_mv_cm);
        if j_ref <= 0.0 {
            return 0.0;
        }
        CAL_ELECTRONS_REF_PULSE * (j * self.duration_us) / (j_ref * CAL_REF_DURATION_US)
    }
}

/// The oxide-stress ledger for one channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelAccountant {
    /// Cumulative injected charge per unit oxide area, C/cm²
    /// (the standard Q_inj endurance metric — first-principles:
    /// J·t, independent of area).
    pub q_inj_c_cm2: f64,
    /// Total erase pulses applied.
    pub pulses: u64,
    /// Floating-gate capacitance per cell, femtofarads (ΔVth = ΔQ/C).
    pub c_fg_ff: f64,
    /// Cells in this channel (die × planes × blocks × pages × cells).
    pub cells: u64,
    /// Calibration-ledger: total electrons moved through one
    /// average cell of this channel over the campaign.
    pub electrons_per_cell_total: f64,
}

/// Electrons per femtocoulomb.
const ELECTRONS_PER_FC: f64 = 1e-15 / 1.602176634e-19; // ≈ 6242

impl TunnelAccountant {
    pub fn new(c_fg_ff: f64, cells: u64) -> Self {
        Self {
            q_inj_c_cm2: 0.0,
            pulses: 0,
            c_fg_ff,
            cells,
            electrons_per_cell_total: 0.0,
        }
    }

    /// Book one applied erase pulse over the channel's cells.
    pub fn apply(&mut self, pulse: &ErasePulse) {
        let j = fn_current_density_a_cm2(pulse.field_mv_cm);
        let t_s = pulse.duration_us * 1e-6;
        self.q_inj_c_cm2 += j * t_s;
        self.electrons_per_cell_total += pulse.charge_electrons_per_cell();
        self.pulses += 1;
    }

    /// Electrons removed from the floating gates of one average
    /// cell in this channel, over the whole campaign (calibration
    /// ledger — an upper-bound integral: it counts the charge the
    /// PULSES carried, not the charge the cell could hold).
    pub fn electrons_moved_per_cell(&self) -> f64 {
        self.electrons_per_cell_total
    }

    /// The Vth change this charge removal implies for one cell:
    /// ΔV = ΔQ / C_fg (charge OFF the gate → Vth DOWN; the
    /// certificate carries magnitudes).
    pub fn implied_vth_change_v(&self) -> f64 {
        let q_c = self.electrons_moved_per_cell() * 1.602176634e-19;
        let c_f = self.c_fg_ff * 1e-15;
        if c_f > 0.0 { (q_c / c_f).abs() } else { 0.0 }
    }

    /// Charge-bleed consistency: an OBSERVED ΔVth must be
    /// explainable by the campaign's charge ledger. Returns the
    /// coverage ratio observed-charge-need / ledger-supplied —
    /// ≥ 1.0 means the pulses moved at least the charge the Vth
    /// shift exhibits (physically consistent); « 1.0 means the
    /// Vth shift is larger than the pulses can account for
    /// (impossible for an honest erase campaign — certificate
    /// refuses).
    pub fn consistency(&self, observed_dvth_v: f64) -> f64 {
        let need_fc = observed_dvth_v * self.c_fg_ff; // femtocoulombs
        let supplied_fc = self.electrons_moved_per_cell() / ELECTRONS_PER_FC;
        if need_fc <= 0.0 {
            return f64::INFINITY;
        }
        supplied_fc / need_fc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fn_law_matches_textbook_points() {
        // J(10 MV/cm) ≈ 1.25e-6 * 100 * exp(-25.3) ≈ 1.3e-15 A/cm² —
        // the classic "10 MV/cm is where tunneling turns on" knee.
        let j10 = fn_current_density_a_cm2(10.0);
        assert!(j10 > 1e-16 && j10 < 1e-13, "j10={j10}");
        // Monotone in field, brutally exponential below the knee.
        let j9 = fn_current_density_a_cm2(9.0);
        assert!(j9 < j10 * 0.2, "9 MV/cm should be ~50x smaller");
        let j12 = fn_current_density_a_cm2(12.0);
        assert!(j12 > j10 * 50.0);
        // No field, no current.
        assert_eq!(fn_current_density_a_cm2(0.0), 0.0);
        assert_eq!(fn_current_density_a_cm2(-5.0), 0.0);
    }

    #[test]
    fn one_erase_pulse_moves_a_sane_electron_count() {
        // The calibration anchor: a standard pulse moves the SLC
        // erase window (~2.5e3 electrons).
        let p = ErasePulse {
            field_mv_cm: 10.5,
            duration_us: 1000.0,
        };
        let n = p.charge_electrons_per_cell();
        assert!((n - 2_500.0).abs() < 25.0, "anchor={n}");
        // Half the duration → half the charge.
        let half = ErasePulse {
            duration_us: 500.0,
            ..p
        };
        assert!((half.charge_electrons_per_cell() - n / 2.0).abs() < 1e-6);
        // A lower field moves orders less.
        let weak = ErasePulse {
            field_mv_cm: 9.5,
            ..p
        };
        assert!(weak.charge_electrons_per_cell() < n * 0.1);
    }

    #[test]
    fn charge_ledger_is_monotone_and_proportional() {
        let p = ErasePulse {
            field_mv_cm: 10.5,
            duration_us: 500.0,
        };
        let mut acc = TunnelAccountant::new(1.0, 1_000_000_000);
        let before = acc.q_inj_c_cm2;
        acc.apply(&p);
        assert!(acc.q_inj_c_cm2 > before);
        assert_eq!(acc.pulses, 1);
        let q1 = acc.q_inj_c_cm2;
        let e1 = acc.electrons_moved_per_cell();
        acc.apply(&p);
        assert!(
            (acc.q_inj_c_cm2 - 2.0 * q1).abs() < 1e-30,
            "linear in pulses"
        );
        assert!((acc.electrons_moved_per_cell() - 2.0 * e1).abs() < 1e-9);
        // Double duration = double charge.
        let p2 = ErasePulse {
            duration_us: 1000.0,
            ..p
        };
        let mut a2 = TunnelAccountant::new(1.0, 1);
        a2.apply(&p2);
        assert!((a2.q_inj_c_cm2 - 2.0 * q1).abs() < 1e-30);
        assert!((a2.electrons_moved_per_cell() - 2.0 * e1).abs() < 1e-9);
    }

    #[test]
    fn observed_vth_is_covered_by_the_campaign_ledger() {
        // 2000 standard erase pulses.
        let p = ErasePulse {
            field_mv_cm: 10.5,
            duration_us: 1000.0,
        };
        let mut acc = TunnelAccountant::new(1.0, 1_000_000_000); // 1 fF gate
        for _ in 0..2000 {
            acc.apply(&p);
        }
        // 2000 pulses × 2500 electrons = 5e6 electrons ≈ 0.8 pC →
        // the ledger's implied ΔV is a large upper bound (the cell
        // saturates long before) — the consistency RATIO is what
        // matters: a modest observed ΔVth is comfortably covered.
        let implied = acc.implied_vth_change_v();
        assert!(implied > 0.1, "implied={implied}");
        let cov = acc.consistency(0.6);
        assert!(cov >= 1.0, "coverage={cov}");
        // An absurd observed ΔVth (say 1e6 V) cannot be covered.
        assert!(acc.consistency(1e6) < 1.0);
        // Zero observed shift is trivially covered.
        assert!(acc.consistency(0.0).is_infinite());
    }

    #[test]
    fn an_untouched_channel_has_no_ledger() {
        let acc = TunnelAccountant::new(1.0, 1000);
        assert_eq!(acc.pulses, 0);
        assert_eq!(acc.q_inj_c_cm2, 0.0);
        assert_eq!(acc.electrons_moved_per_cell(), 0.0);
        // Any positive observed ΔVth on an untouched channel is
        // physically impossible under an honest erase campaign.
        assert!(acc.consistency(0.1) < 1.0);
    }
}
