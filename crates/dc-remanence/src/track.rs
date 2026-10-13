//! # Track geometry & the write-bubble fringing model.
//!
//! Modern perpendicular-recording media is organized as concentric
//! data tracks separated by **guard bands**. The write element is
//! narrower than the track pitch so adjacent tracks are not
//! clobbered in normal operation — which is exactly why the guard
//! bands keep a magnetic memory of everything ever written by the
//! fringing field of past writes.
//!
//! ## Physics captured here
//!
//! * **Write bubble width.** A write head magnetizes the region where
//!   its gap field exceeds the media coercivity `H_c`. Gap field
//!   scales with write current, and the field past the pole edge
//!   falls off exponentially (dipole falloff, characteristic length
//!   `λ_fringe` of a few nm). Overdriving the write current raises
//!   the field AND the effective bubble width:
//!
//!   ```text
//!   H(y) = H_gap · (1 + k_I·bias) · exp(−max(0, |y−c| − w₀/2) / λ_fringe)
//!   ```
//!
//!   where `c` is the head center (= track centerline + micro-step
//!   offset), `w₀` the nominal write-element width, `bias` the
//!   write-current bias fraction (0 = nominal, 0.25 = +25% current).
//!
//! * **Original-recording fringe (the MFM target).** The same
//!   falloff shape governs how much of the old bit's magnetization
//!   bleeds into the guard band during the *original* write: a
//!   grain at distance `d` past the write edge retains a fraction
//!   `exp(−d/λ_fringe)` of the saturated value (soft pre-echo of the
//!   pole tip). This is the sub-surface remanence the adversary
//!   reads after a naive overwrite.
//!
//! * **Grain coercivity dispersion.** Thin-film CoCrPt media is
//!   granular; each grain has its own coercivity, modeled as
//!   log-normal around `H_c50`. The switching probability of a grain
//!   under field `H` follows the Néel-Brown thermal activation law
//!   (see [`crate::curie`]) — the dispersion is what makes bubble
//!   edges soft and gives the Curie-dither its grip.

use crate::{RemanenceError, SimRng};

/// Thin-film perpendicular-recording track stack geometry.
///
/// Defaults model a ~2 500 TPI-class drive (112 nm pitch) with a
/// 79 nm write element, i.e. ~33 nm of guard band split between
/// both track edges — the MFM recovery window.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrackGeometry {
    /// Track center-to-center pitch (nm).
    pub track_pitch_nm: f64,
    /// Write-element width at nominal current (nm).
    pub write_width_nm: f64,
    /// Gap-field falloff length past the pole edge (nm).
    pub lambda_fringe_nm: f64,
    /// Median media coercivity (relative units, nominal gap field = 1.0).
    pub hc_median: f64,
    /// Log-normal spread of grain coercivity (sigma of ln Hc).
    pub hc_log_sigma: f64,
    /// Write-current → gap-field gain (field per unit bias).
    pub current_field_gain: f64,
    /// Write-current → bubble-width gain (width growth per unit bias).
    pub current_width_gain: f64,
}

impl Default for TrackGeometry {
    fn default() -> Self {
        Self {
            track_pitch_nm: 112.0,
            write_width_nm: 79.0,
            lambda_fringe_nm: 6.5,
            hc_median: 0.62,
            hc_log_sigma: 0.14,
            current_field_gain: 0.9,
            current_width_gain: 0.18,
        }
    }
}

impl TrackGeometry {
    /// Half of the nominal written core width (nm from centerline).
    pub fn core_half_width_nm(&self) -> f64 {
        self.write_width_nm / 2.0
    }

    /// Guard-band half width: from write edge to the neighboring
    /// track centerline.
    pub fn guard_band_nm(&self) -> f64 {
        (self.track_pitch_nm - self.write_width_nm) / 2.0
    }

    /// Validate the geometry makes physical sense.
    pub fn validate(&self) -> Result<(), RemanenceError> {
        if self.write_width_nm >= self.track_pitch_nm {
            return Err(RemanenceError::Geometry(format!(
                "write width {} nm must stay below track pitch {} nm (guard band would be negative)",
                self.write_width_nm, self.track_pitch_nm
            )));
        }
        if !(self.lambda_fringe_nm.is_finite() && self.lambda_fringe_nm > 0.0) {
            return Err(RemanenceError::Geometry(
                "fringe falloff length must be positive".into(),
            ));
        }
        if !(0.0 < self.hc_median && self.hc_median < 1.0) {
            return Err(RemanenceError::Geometry(format!(
                "coercivity median {} must sit strictly inside (0,1) in gap-field units",
                self.hc_median
            )));
        }
        Ok(())
    }

    /// Effective write-bubble half width under a current bias.
    ///
    /// `bias` is the fractional write-current offset (0 = nominal,
    /// +0.25 = 25% overdrive). The bubble edge moves out
    /// logarithmically with field: solving `H(edge) = H_c50` for
    /// `d` past the pole edge gives
    /// `d = λ · ln(H_gap(bias)/H_c50)` clamped at 0 for
    /// underdriven heads.
    pub fn bubble_half_width_nm(&self, bias: f64) -> f64 {
        let field = self.gap_field(bias);
        let d = self.lambda_fringe_nm * (field / self.hc_median).ln();
        self.core_half_width_nm() + d.max(0.0)
    }

    /// Gap field at the pole edge for a given current bias, in
    /// nominal-gap-field units.
    pub fn gap_field(&self, bias: f64) -> f64 {
        1.0 + self.current_field_gain * bias
    }

    /// Write field at lateral position `y` (nm from track
    /// centerline) when the head is centered at `c` (nm) with
    /// current bias `bias`.
    pub fn write_field_at(&self, y: f64, c: f64, bias: f64) -> f64 {
        let half = self.core_half_width_nm();
        let dist = (y - c).abs() - half;
        let falloff = if dist > 0.0 {
            (-dist / self.lambda_fringe_nm).exp()
        } else {
            1.0
        };
        self.gap_field(bias) * falloff
    }

    /// Fringe remanence fraction of the ORIGINAL recording at
    /// lateral distance `d` past the write edge (nm): the amplitude
    /// of old-bit magnetization left in the guard band.
    pub fn old_fringe_amplitude(&self, y: f64, c: f64) -> f64 {
        let dist = (y - c).abs() - self.core_half_width_nm();
        if dist <= 0.0 {
            1.0
        } else {
            (-(dist / self.lambda_fringe_nm).min(60.0)).exp()
        }
    }

    /// Sample a grain coercivity from the log-normal media
    /// dispersion (relative gap-field units).
    pub fn sample_hc(&self, rng: &mut SimRng) -> f64 {
        // Log-normal: median hc_median, log-spread hc_log_sigma.
        let z = rng.next_normal();
        (self.hc_log_sigma * z).exp() * self.hc_median
    }
}

/// A lateral column of grains at a fixed off-track position.
///
/// The platter simulation (see [`crate::remanence`]) tracks one
/// column per lateral sample point; each column stores the grain
/// coercivity plus per-bit-cell magnetization values.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ColumnSpec {
    /// Lateral position (nm from track centerline; negative = towards
    /// the lower track number).
    pub y_nm: f64,
    /// Grain coercivity in gap-field units.
    pub hc: f64,
}

impl ColumnSpec {
    /// Lateral sampling grid for one track's strip of interest:
    /// from `−(half core + guard + margin)` to `+…`, covering the
    /// written core, both guard bands and one fringe tail beyond the
    /// neighbor centerline.
    ///
    /// The margin exists because overdriven micro-steps (±30% of
    /// pitch) push the bubble center past the neighbor centerline —
    /// the proof must see those columns too.
    pub fn sample_track(geo: &TrackGeometry, resolution_nm: f64, rng: &mut SimRng) -> Vec<Self> {
        let reach = geo.core_half_width_nm() + geo.guard_band_nm() + 0.35 * geo.track_pitch_nm;
        let n = ((2.0 * reach) / resolution_nm).round() as usize;
        (0..=n)
            .map(|i| {
                let y = -reach + i as f64 * resolution_nm;
                Self {
                    y_nm: y,
                    hc: geo.sample_hc(rng),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_band_is_positive_and_bounded() {
        let geo = TrackGeometry::default();
        let g = geo.guard_band_nm();
        assert!(g > 0.0 && g < geo.track_pitch_nm / 2.0 + 1e-9);
        assert!(geo.validate().is_ok());
    }

    #[test]
    fn geometry_validation_rejects_overlapping_tracks() {
        let mut geo = TrackGeometry::default();
        geo.write_width_nm = geo.track_pitch_nm + 1.0;
        assert!(geo.validate().is_err());
    }

    #[test]
    fn overdrive_widens_the_bubble_monotonically() {
        let geo = TrackGeometry::default();
        let w0 = geo.bubble_half_width_nm(0.0);
        let w25 = geo.bubble_half_width_nm(0.25);
        let w50 = geo.bubble_half_width_nm(0.50);
        assert!(w0 > 0.0);
        assert!(w25 > w0, "overdrive must widen the write bubble");
        assert!(w50 > w25);
        // Underdrive must never widen past nominal core.
        assert!(geo.bubble_half_width_nm(-0.5) <= w0 + 1e-12);
    }

    #[test]
    fn bubble_edge_field_equals_coercivity() {
        // Inverting bubble_half_width must land on a point where the
        // local field matches the median coercivity (the definitional
        // equation of the bubble edge).
        let geo = TrackGeometry::default();
        let bias = 0.3;
        let edge = geo.bubble_half_width_nm(bias);
        let field_at_edge = geo.write_field_at(edge, 0.0, bias);
        assert!(
            (field_at_edge - geo.hc_median).abs() < 1e-9,
            "field at bubble edge {field_at_edge} should equal Hc {}",
            geo.hc_median
        );
    }

    #[test]
    fn fringe_amplitude_decays_with_distance() {
        let geo = TrackGeometry::default();
        let a0 = geo.old_fringe_amplitude(geo.core_half_width_nm(), 0.0);
        let a1 = geo.old_fringe_amplitude(geo.core_half_width_nm() + geo.lambda_fringe_nm, 0.0);
        let a2 =
            geo.old_fringe_amplitude(geo.core_half_width_nm() + 2.0 * geo.lambda_fringe_nm, 0.0);
        assert!((a0 - 1.0).abs() < 1e-12);
        assert!((a1 - (-1.0f64).exp()).abs() < 1e-12);
        assert!(a2 < a1 && a1 < a0);
    }

    #[test]
    fn column_grid_covers_neighbor_centerline() {
        let geo = TrackGeometry::default();
        let mut rng = SimRng::new(7);
        let cols = ColumnSpec::sample_track(&geo, 2.0, &mut rng);
        let reach = geo.core_half_width_nm() + geo.guard_band_nm() + 0.35 * geo.track_pitch_nm;
        assert!(cols.first().unwrap().y_nm <= -reach);
        assert!(cols.last().unwrap().y_nm >= reach - 2.0);
        // Grain coercivities must scatter around the median (log-normal).
        let mean_hc: f64 = cols.iter().map(|c| c.hc).sum::<f64>() / cols.len() as f64;
        assert!(mean_hc > 0.5 && mean_hc < 0.8, "sampled Hc mean {mean_hc}");
    }
}
