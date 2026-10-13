//! # The recording layer: dose response & destruction states.
//!
//! The spiral is modeled as a grid of cells (zones × sectors ×
//! cells) — every cell carries a reflectivity state and an
//! accumulated destruction dose (in normalized units: 1.0 = one
//! nominal write pulse per cell).
//!
//! **Media physics** (per [`MediaType`]):
//!
//! * `OrganicDye` (CD-R / DVD-R azo / cyanine / phthalocyanine):
//!   written marks are photobleached regions of the dye. The
//!   destruction mode is **photobleaching to saturation**: dose
//!   `D ≳ 1` forces the ENTIRE cell into the bleached (written
//!   state-like) regime; the mark/land reflectivity contrast
//!   collapses to zero. Bleaching follows
//!   `R(D) = R_land + (R_mark − R_land)·(1 − exp(−D))` — both mark
//!   and land converge to the same bleached reflectivity.
//! * `PhaseChange` (BD-R inorganic, DVD±RW GeSbTe / InAgSbTe): the
//!   layer is a crystalline/aglomerate phase-change alloy. The
//!   destruction mode is **melt-and-quench**: dose `D ≳ 2.5`
//!   raises the local temperature past the melting point, and the
//!   spinning disc's quench rate freezes an amorphous, uniformly
//!   low-reflectivity slurry — marks, lands, grooves, everything.
//! * `GlassyCarbon` (M-DISC inorganic "stone" layer): the
//!   marketing claim is "engraved like rock, readable for a
//!   millennium" — the actual layer is a glassy-carbon / metal
//!   alloy needing **ablation-class** dose `D ≳ 6` to carbonize
//!   and bubble. This is the media that survives shredding-grade
//!   handling — and exactly why the overdrive (energy gain ≳ 11)
//!   is not optional.
//!
//! **Written data.** Cells alternate mark/land per a deterministic
//! pseudo-random bit pattern (the "recorded data" the forensics
//! lab tries to read back); unwritten (land) cells sit at the
//! base reflectivity.

use crate::{OptixError, SimRng};
/// The recording medium family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaType {
    /// Organic dye (CD-R, DVD-R).
    OrganicDye,
    /// Inorganic phase-change alloy (BD-R inorganic, DVD±RW).
    PhaseChange,
    /// Glassy-carbon "stone" layer (M-DISC).
    GlassyCarbon,
}

impl MediaType {
    /// Annihilation dose threshold (normalized units).
    pub fn annihilate_dose(&self) -> f64 {
        match self {
            Self::OrganicDye => 1.0,
            Self::PhaseChange => 2.5,
            Self::GlassyCarbon => 6.0,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::OrganicDye => "organic dye",
            Self::PhaseChange => "phase-change alloy",
            Self::GlassyCarbon => "glassy carbon (M-DISC class)",
        }
    }
}

/// Convergence rate of the destroyed reflectivity saturation (in
/// threshold multiples).
pub const SATURATION_K: f64 = 4.0;

/// Reflectivity endpoints per medium (normalized: substrate = 0).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Reflectivity {
    /// Unwritten land reflectivity.
    pub land: f64,
    /// Written mark reflectivity.
    pub mark: f64,
    /// Fully annihilated (bleached / amorphous / carbonized)
    /// reflectivity.
    pub destroyed: f64,
}

impl Reflectivity {
    pub fn for_media(media: MediaType) -> Self {
        match media {
            MediaType::OrganicDye => Self {
                land: 0.65,
                mark: 0.35,
                destroyed: 0.30,
            },
            MediaType::PhaseChange => Self {
                land: 0.55,
                mark: 0.25,
                destroyed: 0.18,
            },
            MediaType::GlassyCarbon => Self {
                land: 0.45,
                mark: 0.22,
                destroyed: 0.12,
            },
        }
    }
}

/// Per-cell physical state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Cell {
    /// The recorded bit (mark present?) — the data the lab hunts.
    pub bit: bool,
    /// Accumulated destruction dose (normalized).
    pub dose: f64,
    /// Current reflectivity.
    pub reflectivity: f64,
    /// Groove wall height (0..1, drives push-pull signal).
    pub groove: f64,
    /// Annihilated flag (dose crossed the media threshold).
    pub annihilated: bool,
}

/// The full spiral: zones × sectors × cells.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LayerStack {
    pub media: MediaType,
    pub reflectivity: Reflectivity,
    pub zones: usize,
    pub sectors_per_zone: usize,
    pub cells_per_sector: usize,
    /// `cells[zone][sector*cells + cell]`.
    pub cells: Vec<Vec<Cell>>,
}

impl LayerStack {
    /// A written disc: pseudo-random marks, fresh grooves, zero
    /// dose.
    pub fn new(
        media: MediaType,
        zones: usize,
        sectors_per_zone: usize,
        cells_per_sector: usize,
    ) -> Self {
        Self::with_seed(media, zones, sectors_per_zone, cells_per_sector, 0x5EED)
    }

    /// Written disc from an explicit RNG seed.
    pub fn with_seed(
        media: MediaType,
        zones: usize,
        sectors_per_zone: usize,
        cells_per_sector: usize,
        seed: u64,
    ) -> Self {
        let refl = Reflectivity::for_media(media);
        let mut rng = SimRng::new(seed);
        let mut cells = Vec::with_capacity(zones);
        for _z in 0..zones {
            let mut zone = Vec::with_capacity(sectors_per_zone * cells_per_sector);
            for _s in 0..sectors_per_zone * cells_per_sector {
                let bit = rng.next_f64() < 0.5;
                // Fresh groove walls: uniform 0.9..1.0.
                let groove = 0.9 + 0.1 * rng.next_f64();
                zone.push(Cell {
                    bit,
                    dose: 0.0,
                    reflectivity: if bit { refl.mark } else { refl.land },
                    groove,
                    annihilated: false,
                });
            }
            cells.push(zone);
        }
        Self {
            media,
            reflectivity: refl,
            zones,
            sectors_per_zone,
            cells_per_sector,
            cells,
        }
    }

    /// Number of zones in the spiral.
    pub fn zones(&self) -> usize {
        self.zones
    }

    /// Total cell count of the spiral.
    pub fn total_cells(&self) -> usize {
        self.zones * self.sectors_per_zone * self.cells_per_sector
    }

    /// Apply a dose to one cell and update its physical state.
    pub fn deposit(&mut self, zone: usize, idx: usize, dose: f64) -> Result<(), OptixError> {
        let refl = &self.reflectivity;
        let threshold = self.media.annihilate_dose();
        let cell = self
            .cells
            .get_mut(zone)
            .and_then(|z| z.get_mut(idx))
            .ok_or_else(|| {
                OptixError::Physics(format!("cell ({zone}, {idx}) outside the spiral grid"))
            })?;
        cell.dose += dose;
        if cell.dose >= threshold {
            cell.annihilated = true;
            // Saturation approach to the destroyed reflectivity,
            // in units of the threshold multiple (K = 4: two
            // thresholds of overdrive converge the mark/land
            // contrast to the read noise floor).
            let over = ((cell.dose / threshold - 1.0) * SATURATION_K).exp();
            cell.reflectivity = refl.destroyed + (cell.reflectivity - refl.destroyed) / over;
            // Groove walls thermally slump.
            cell.groove *= (-cell.dose / threshold).exp();
        } else {
            // Partial bleaching pulls marks toward the bleached
            // reflectivity (organic media); phase-change heats but
            // stays reversible below threshold.
            if matches!(self.media, MediaType::OrganicDye) {
                let f = 1.0 - (-cell.dose).exp();
                cell.reflectivity += (refl.destroyed - cell.reflectivity) * f * 0.5;
            }
        }
        Ok(())
    }

    /// Per-zone reflectivity modulation ΔR/R (the RF signal's
    /// amplitude source): `(R_max − R_min) / R_mean` over all
    /// cells of the zone.
    pub fn zone_modulation(&self, zone: usize) -> Result<f64, OptixError> {
        let z = self
            .cells
            .get(zone)
            .ok_or_else(|| OptixError::Physics(format!("zone {zone} outside the spiral")))?;
        let mut rmin = f64::INFINITY;
        let mut rmax = f64::NEG_INFINITY;
        let mut sum = 0.0;
        for c in z {
            rmin = rmin.min(c.reflectivity);
            rmax = rmax.max(c.reflectivity);
            sum += c.reflectivity;
        }
        let mean = sum / z.len() as f64;
        if mean <= 0.0 {
            return Ok(0.0);
        }
        Ok((rmax - rmin) / mean)
    }

    /// Fraction of cells annihilated.
    pub fn annihilated_fraction(&self) -> f64 {
        let total = self.total_cells() as f64;
        let done = self
            .cells
            .iter()
            .map(|z| z.iter().filter(|c| c.annihilated).count())
            .sum::<usize>() as f64;
        done / total
    }

    /// Mean groove wall height (push-pull signal source).
    pub fn mean_groove(&self) -> f64 {
        let n = self.total_cells() as f64;
        self.cells
            .iter()
            .map(|z| z.iter().map(|c| c.groove).sum::<f64>())
            .sum::<f64>()
            / n
    }

    /// The read-recovery model: a forensics lab reads the disc and
    /// classifies each cell as mark/land by reflectivity against
    /// the midpoint discriminator; returns the fraction of cells
    /// whose ORIGINAL bit is correctly recovered.
    pub fn read_recovery_rate(&self) -> f64 {
        let mid = (self.reflectivity.land + self.reflectivity.mark) / 2.0;
        let mut correct = 0usize;
        let mut total = 0usize;
        for z in &self.cells {
            for c in z {
                let read_as_mark = c.reflectivity < mid;
                if read_as_mark == c.bit {
                    correct += 1;
                }
                total += 1;
            }
        }
        correct as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_match_the_media_families() {
        assert_eq!(MediaType::OrganicDye.annihilate_dose(), 1.0);
        assert_eq!(MediaType::PhaseChange.annihilate_dose(), 2.5);
        assert_eq!(MediaType::GlassyCarbon.annihilate_dose(), 6.0);
    }

    #[test]
    fn fresh_disc_carries_data_and_full_modulation() {
        let d = LayerStack::new(MediaType::PhaseChange, 4, 8, 16);
        // Fresh modulation: (0.55 − 0.25)/mean ≈ 0.75.
        let m = d.zone_modulation(0).unwrap();
        assert!(m > 0.5 && m < 1.0, "modulation {m}");
        // Readback recovers the data well above chance (perfect,
        // in fact — the discriminator exactly separates marks).
        let r = d.read_recovery_rate();
        assert!(r > 0.99, "fresh readback {r}");
        // Annihilated fraction is zero.
        assert_eq!(d.annihilated_fraction(), 0.0);
        assert!(d.mean_groove() > 0.85);
    }

    #[test]
    fn sub_threshold_dose_partially_bleaches() {
        let mut d = LayerStack::new(MediaType::OrganicDye, 2, 4, 8);
        let before = d.zone_modulation(0).unwrap();
        for idx in 0..d.sectors_per_zone * d.cells_per_sector {
            d.deposit(0, idx, 0.5).unwrap();
        }
        let after = d.zone_modulation(0).unwrap();
        assert!(after < before, "partial dose must reduce contrast");
        assert_eq!(d.annihilated_fraction(), 0.0, "not yet annihilated");
    }

    #[test]
    fn annihilated_cells_converge_to_the_destroyed_state() {
        let mut d = LayerStack::new(MediaType::GlassyCarbon, 2, 4, 8);
        for idx in 0..d.sectors_per_zone * d.cells_per_sector {
            d.deposit(0, idx, 12.0).unwrap(); // 2× the threshold
        }
        assert_eq!(d.annihilated_fraction(), 0.5); // 1 of 2 zones
        let m = d.zone_modulation(0).unwrap();
        assert!(m < 0.05, "modulation {m} must collapse");
        // Readback: zone 0 (annihilated) reads at chance, zone 1
        // (fresh) reads perfectly — the blend lands around 0.75
        // with sampling spread.
        let r = d.read_recovery_rate();
        assert!((0.6..=0.9).contains(&r), "recovery {r}");
        // Grooves slumped.
        let g0: f64 = d.cells[0].iter().map(|c| c.groove).sum::<f64>() / d.cells[0].len() as f64;
        assert!(g0 < 0.2, "groove {g0}");
    }

    #[test]
    fn out_of_grid_deposits_are_refused() {
        let mut d = LayerStack::new(MediaType::PhaseChange, 2, 4, 8);
        assert!(d.deposit(9, 0, 1.0).is_err());
        assert!(d.deposit(0, 9999, 1.0).is_err());
        assert!(d.zone_modulation(9).is_err());
    }

    #[test]
    fn media_families_behave_consistently() {
        for media in [
            MediaType::OrganicDye,
            MediaType::PhaseChange,
            MediaType::GlassyCarbon,
        ] {
            // Large grid: the chance-recovery band tightens as
            // 1/sqrt(n).
            let mut d = LayerStack::new(media, 4, 8, 32);
            let dose = media.annihilate_dose() * 2.0;
            for z in 0..d.zones {
                for idx in 0..d.sectors_per_zone * d.cells_per_sector {
                    d.deposit(z, idx, dose).unwrap();
                }
            }
            assert_eq!(d.annihilated_fraction(), 1.0);
            for z in 0..d.zones {
                assert!(
                    d.zone_modulation(z).unwrap() < 0.05,
                    "{:?} zone {z} modulation",
                    media
                );
            }
            // Recovery at chance ± statistical spread.
            let r = d.read_recovery_rate();
            assert!((0.40..=0.60).contains(&r), "{media:?} recovery {r}");
        }
    }
}
