//! # The optical pickup unit (OPU): laser diode & CLV servo model.
//!
//! The OPU is a closed-loop precision instrument:
//!
//! * **Laser diode** — nominal write power `P_w` (class-dependent:
//!   ~7 mW CD-R write, ~10 mW BD write), PWM-modulated under the
//!   write strategy. The vendor diagnostic channel exposes duty
//!   and drive-current gain; at 100% duty the beam is continuous
//!   wave (CW) at `P = P_w · current_pct/100`.
//! * **CLV servo** — the disc spins so the beam's *linear*
//!   velocity `v = ω(r)·r` stays constant across the spiral (the
//!   channel-bit clock demands it). Energy deposited per unit
//!   track length is
//!
//!   ```text
//!   E/L = P · t / L = P / v
//!   ```
//!
//!   — so the annihilation strategy parks the servo at the MINIMUM
//!   viable velocity and the MAXIMUM viable power: the exact
//!   inverse of the drive's own write strategy.
//!
//! [`Opu`] computes the per-cell dose in normalized destruction
//! units:
//!
//! ```text
//! dose(cell) = (P/P_w) · (v_w/v) · duty · focus_coupling
//! ```
//!
//! with `v_w` the nominal write velocity and `focus_coupling` the
//! energy fraction surviving the protective substrate offset
//! (defocus spreads the spot; `exp(−(Δz/σ_f)²)`).

use crate::OptixError;
/// The optical pickup unit state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Opu {
    /// Nominal write power (mW).
    pub nominal_write_mw: f64,
    /// Nominal write linear velocity (m/s).
    pub nominal_write_mps: f64,
    /// Applied PWM duty (0..=1).
    pub duty: f64,
    /// Applied diode current (fraction of nominal, e.g. 2.8).
    pub current_gain: f64,
    /// Applied CLV (m/s).
    pub clv_mps: f64,
    /// Applied focus offset (µm).
    pub focus_offset_um: f64,
    /// Focus coupling width (µm) — spot energy survival of defocus.
    pub focus_sigma_um: f64,
}

impl Default for Opu {
    fn default() -> Self {
        Self {
            nominal_write_mw: 10.0,
            nominal_write_mps: 4.917, // BD 1× CLV
            duty: 1.0,
            current_gain: 2.8,
            clv_mps: 1.2, // parked at the spindle floor
            focus_offset_um: 0.0,
            focus_sigma_um: 1.4,
        }
    }
}

impl Opu {
    /// Effective beam power (mW).
    pub fn effective_power_mw(&self) -> f64 {
        self.nominal_write_mw * self.current_gain * self.duty
    }

    /// Energy per unit track length relative to the nominal write
    /// strategy — the annihilation gain.
    pub fn energy_gain(&self) -> f64 {
        (self.current_gain * self.duty) * (self.nominal_write_mps / self.clv_mps)
    }

    /// Focus coupling fraction for the applied offset.
    pub fn focus_coupling(&self) -> f64 {
        (-(self.focus_offset_um / self.focus_sigma_um).powi(2)).exp()
    }

    /// Dose in normalized destruction units delivered to one cell
    /// of exposure time `t_cell_ms` (the time the spot dwells on
    /// the cell at the parked CLV).
    ///
    /// Normalization: dose 1.0 = the energy a nominal write pulse
    /// delivers to one mark. The media thresholds in
    /// [`crate::layer`] are expressed against this unit.
    pub fn cell_dose(&self, t_cell_ms: f64) -> f64 {
        // Dose 1.0 = one nominal write pulse on one mark: nominal
        // current, nominal write velocity, on-focus. The
        // annihilation dose scales each factor independently:
        // current gain × duty × focus coupling × dwell ratio
        // (t/t_w = v_w/v at fixed mark length — the CLV factor
        // enters here, NOT a second time via energy_gain).
        self.current_gain * self.duty * self.focus_coupling() * (t_cell_ms / Self::NOMINAL_MARK_MS)
    }

    /// Dwell time per cell (ms) at the current CLV for a cell of
    /// `cell_len_um` micrometres.
    ///
    /// `t = L/v` with `v` in µm/ms at the given m/s (1 m/s =
    /// 1000 µm/ms), so a 0.15 µm cell at 1.2 m/s dwells 125 ns.
    pub fn dwell_ms(&self, cell_len_um: f64) -> f64 {
        cell_len_um / (self.clv_mps * 1000.0)
    }

    /// Nominal mark exposure time (ms) at write velocity: a 0.15 µm
    /// mark at 4.917 m/s = 30.5 ns.
    pub const NOMINAL_MARK_MS: f64 = 3.05e-5;

    /// Validate the OPU state.
    pub fn validate(&self) -> Result<(), OptixError> {
        if !(0.0..=1.0).contains(&self.duty) {
            return Err(OptixError::Physics(format!(
                "PWM duty {} outside 0..=1",
                self.duty
            )));
        }
        if self.current_gain <= 0.0 || self.current_gain > 3.5 {
            return Err(OptixError::Physics(format!(
                "current gain {} outside the vendor shelf 0..=3.5",
                self.current_gain
            )));
        }
        if self.clv_mps <= 0.0 || self.clv_mps > 20.0 {
            return Err(OptixError::Physics(format!(
                "CLV {} m/s outside 0..20",
                self.clv_mps
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parked_velocity_and_overdrive_multiply_the_dose() {
        let opu = Opu::default();
        // 2.8× current at 1/4.1-th of write velocity.
        let gain = opu.energy_gain();
        assert!((gain - 2.8 * (4.917 / 1.2)).abs() < 1e-9, "gain = {gain}");
        assert!(gain > 10.0, "the annihilation gain must be ≫ 1");
    }

    #[test]
    fn defocus_spreads_and_loses_energy() {
        let mut opu = Opu::default();
        let c0 = opu.focus_coupling();
        assert!((c0 - 1.0).abs() < 1e-12);
        opu.focus_offset_um = 1.4;
        let c1 = opu.focus_coupling();
        assert!((c1 - (-1.0f64).exp()).abs() < 1e-12, "one σ → 1/e");
        opu.focus_offset_um = 4.0;
        assert!(opu.focus_coupling() < 0.02, "way off focus kills the beam");
    }

    #[test]
    fn dwell_time_follows_the_clv() {
        let opu = Opu::default();
        // 0.15 µm cell at 1.2 m/s: t = 125 ns = 1.25e-4 ms.
        let t = opu.dwell_ms(0.15);
        assert!((t - 1.25e-4).abs() < 1e-10, "dwell = {t} ms");
        // The dose model uses the RATIO to the nominal mark time,
        // so the absolute ns-scale values cancel correctly (the
        // constant is rounded, hence the 1% tolerance).
        let dose = opu.cell_dose(t);
        assert!((dose - opu.energy_gain()).abs() < 0.05, "dose = {dose}");
    }

    #[test]
    fn opu_validation_rejects_insane_states() {
        let mut opu = Opu::default();
        assert!(opu.validate().is_ok());
        opu.duty = 1.5;
        assert!(opu.validate().is_err());
        opu.duty = 1.0;
        opu.current_gain = 4.0;
        assert!(opu.validate().is_err());
        opu.current_gain = 2.8;
        opu.clv_mps = 25.0;
        assert!(opu.validate().is_err());
    }
}
