//! # The platter remanence simulation.
//!
//! One simulated track = a lateral strip of grain columns, each
//! carrying a per-bit-cell magnetization value. The simulation
//! stages:
//!
//! 1. **Original recording** (`write_original`): the old data — a
//!    random ±1 bit sequence per track — is written at the
//!    centerline with nominal current. Track core saturates; the
//!    guard bands receive the fringing pre-echo
//!    (`old_fringe_amplitude`) of each old bit: **this is the
//!    MFM-readable ghost**.
//!
//! 2. **Naive overwrite** (`write_zero_baseline`): the classic
//!    "overwrite with zeros" — a single centerline zero-write at
//!    nominal current. The track core is destroyed but the guard
//!    bands keep the ghost (the myth, reproduced).
//!
//! 3. **dc-remanence treatment** (`apply_treatment`): the
//!    micro-step ladder at overdriven current sweeps the guard
//!    bands with hard fields, then the Curie-dither passes
//!    thermally re-randomize whatever the ladder's soft edge left
//!    behind and scramble the transition comb.
//!
//! 4. **Adversary readback** (`adversary_read`): the MFM model —
//!    off-track reads of guard-band columns (known plaintext),
//!    with the read path's Johnson-Nyquist noise added. Feeds
//!    [`crate::prml::SnrEstimate`] for the certificate.

use crate::curie::{CurieDither, switch_probability};
use crate::microstep::{MicroStepTransport, SimStepTransport, WritePlan};
use crate::prml::ReadFrontEnd;
use crate::track::{ColumnSpec, TrackGeometry};
use crate::{RemanenceError, SimRng};
/// The magnetization state of one track's lateral strip.
///
/// `columns[j][k]` is the magnetization of lateral column `j` at
/// bit-cell `k` (normalized, −1..+1 saturating).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrackState {
    /// Lateral column specs (position + grain coercivity).
    pub columns: Vec<ColumnSpec>,
    /// Per-column, per-cell magnetization.
    pub m: Vec<Vec<f64>>,
    /// The original recording's bit per cell (±1) — kept as the
    /// adversary's known plaintext.
    pub old_bits: Vec<f64>,
}

impl TrackState {
    /// Lateral resolution used for sampling (nm).
    pub fn resolution_nm(&self) -> f64 {
        if self.columns.len() < 2 {
            return 0.0;
        }
        (self.columns[1].y_nm - self.columns[0].y_nm).abs()
    }

    /// Columns whose center lies inside either guard band
    /// (write edge → neighbor centerline).
    pub fn guard_band_columns(&self, geo: &TrackGeometry) -> Vec<usize> {
        let core = geo.core_half_width_nm();
        let edge = core + geo.guard_band_nm();
        self.columns
            .iter()
            .enumerate()
            .filter(|(_, c)| c.y_nm.abs() > core && c.y_nm.abs() < edge)
            .map(|(j, _)| j)
            .collect()
    }
}

/// Build a fresh track strip: per-column coercivities from the media
/// dispersion, magnetization zero-initialized.
pub fn new_track(
    geo: &TrackGeometry,
    cells: usize,
    resolution_nm: f64,
    rng: &mut SimRng,
) -> TrackState {
    let columns = ColumnSpec::sample_track(geo, resolution_nm, rng);
    let old_bits: Vec<f64> = (0..cells)
        .map(|_| if rng.next_f64() < 0.5 { 1.0 } else { -1.0 })
        .collect();
    TrackState {
        m: vec![vec![0.0; cells]; columns.len()],
        columns,
        old_bits,
    }
}

/// Saturation magnetization reached by a hard write, with grain
/// alignment variance (the source of track-edge magnetization
/// variance an MFM maps).
fn saturated_write(polarity: f64, rng: &mut SimRng) -> f64 {
    polarity * (0.85 + 0.15 * rng.next_f64())
}

/// Stage 1 — write the original recording at nominal current.
///
/// Track core: saturated to the old bit polarity. Guard bands:
/// fringing pre-echo of each bit with amplitude falloff — the
/// sub-surface ghost MFM reads after a naive wipe.
pub fn write_original(track: &mut TrackState, geo: &TrackGeometry, rng: &mut SimRng) {
    let cells = track.old_bits.len();
    for (j, col) in track.columns.iter().enumerate() {
        let amp = geo.old_fringe_amplitude(col.y_nm, 0.0);
        if amp <= 1e-4 {
            continue;
        }
        for k in 0..cells {
            track.m[j][k] = track.old_bits[k] * amp * (0.9 + 0.1 * rng.next_f64());
        }
    }
}

/// Stage 2 — the naive overwrite: one centerline zero-write at
/// nominal current (the myth).
///
/// "Writing zeros" means recording the constant 0-symbol — a
/// saturated magnetization direction — at nominal current from the
/// centerline. It hard-switches the track core but leaves the
/// guard-band ghost standing.
pub fn write_zero_baseline(track: &mut TrackState, geo: &TrackGeometry, rng: &mut SimRng) {
    write_pass(track, geo, 0.0, 0.0, &|_| ZERO_SYMBOL, rng);
}

/// The magnetization direction recorded for a logical 0 (the
/// constant overwrite symbol).
const ZERO_SYMBOL: f64 = -1.0;

/// Stage 3 — the full dc-remanence treatment: dither + ladder.
///
/// Order matters for the final state: the Curie-dither runs FIRST
/// (randomizing the soft bubble edges and scrambling the old
/// transition comb), then the ladder's hard zero-writes finish —
/// so every hard-covered column ends in a constant saturated
/// 0-symbol with zero correlation to the previous recording, and
/// soft-edge columns end dither-randomized.
///
/// Returns the executed transport (command log for the
/// certificate).
pub fn apply_treatment(
    track: &mut TrackState,
    geo: &TrackGeometry,
    plan: &WritePlan,
    dither: &CurieDither,
    rng: &mut SimRng,
) -> Result<SimStepTransport, RemanenceError> {
    let mut transport = SimStepTransport::new();
    // 3a. The Curie-dither: alternating elevated-current passes
    //     across the ladder positions.
    for step in &plan.ladder {
        transport
            .step_head(step.offset_frac)
            .map_err(|e| RemanenceError::Simulation(format!("dither step: {e}")))?;
        transport
            .set_write_current_bias(dither.bias)
            .map_err(|e| RemanenceError::Simulation(format!("dither bias: {e}")))?;
        transport
            .write_burst(plan.cells)
            .map_err(|e| RemanenceError::Simulation(format!("dither burst: {e}")))?;
        let c = step.offset_frac * geo.track_pitch_nm;
        for _pass in 0..dither.passes {
            let phase = if dither.reroll_phase {
                dither.roll_phase(rng)
            } else {
                0
            };
            let comb = dither.polarity_pass(track.old_bits.len(), phase);
            write_pass(track, geo, c, dither.bias, &|k| comb[k], rng);
        }
    }
    // 3b. The ladder: hard zero-writes sweep the guard bands and
    //     leave the constant final state.
    for step in &plan.ladder {
        transport
            .step_head(step.offset_frac)
            .map_err(|e| RemanenceError::Simulation(format!("ladder step: {e}")))?;
        transport
            .set_write_current_bias(step.bias)
            .map_err(|e| RemanenceError::Simulation(format!("ladder bias: {e}")))?;
        transport
            .write_burst(plan.cells)
            .map_err(|e| RemanenceError::Simulation(format!("ladder burst: {e}")))?;
        write_pass(
            track,
            geo,
            step.offset_frac * geo.track_pitch_nm,
            step.bias,
            &|_| ZERO_SYMBOL,
            rng,
        );
    }
    Ok(transport)
}

/// One write pass at head center `c` (nm), current `bias`, writing
/// per-cell polarity `π(k)`.
///
/// Every grain column sees the head field at its lateral position;
/// grains that switch re-align to the pass polarity with saturation
/// variance. Grains in the soft edge switch with Néel-Brown
/// probability — repeated passes erode them.
fn write_pass(
    track: &mut TrackState,
    geo: &TrackGeometry,
    c: f64,
    bias: f64,
    polarity: &dyn Fn(usize) -> f64,
    rng: &mut SimRng,
) {
    let cells = track.old_bits.len();
    for (j, col) in track.columns.iter().enumerate() {
        let field = geo.write_field_at(col.y_nm, c, bias);
        let p = switch_probability(field, col.hc);
        if p <= 1e-6 {
            continue;
        }
        for k in 0..cells {
            if p >= 1.0 || rng.next_f64() < p {
                track.m[j][k] = saturated_write(polarity(k), rng);
            }
        }
    }
}

/// Guard-band coverage accounting: per guard-band column, the
/// maximum hard-switch margin achieved by the plan.
///
/// A column counts covered when the ladder's field exceeds its
/// (individual, dispersed) coercivity by the hard-switch margin —
/// or when the dither exposure leaves expected retention below
/// `1e-3`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ColumnCoverage {
    pub y_nm: f64,
    pub hc: f64,
    pub ladder_field: f64,
    pub dither_field: f64,
    pub covered: bool,
}

/// Compute the coverage ledger for every guard-band column.
pub fn coverage_ledger(
    track: &TrackState,
    geo: &TrackGeometry,
    plan: &WritePlan,
    dither: &CurieDither,
) -> Vec<ColumnCoverage> {
    let guard = track.guard_band_columns(geo);
    guard
        .into_iter()
        .map(|j| {
            let col = &track.columns[j];
            let ladder_field = plan.hard_switch_field_at(geo, col.y_nm);
            let dither_field = plan.dither_exposure_at(geo, col.y_nm, dither.bias);
            let hard = ladder_field >= col.hc * (1.0 + crate::curie::HARD_SWITCH_MARGIN);
            // Soft path: dither passes with thermal switch prob p
            // drive retention (1-p)^passes below 1e-3.
            let p = crate::curie::switch_probability(dither_field, col.hc);
            let retention =
                crate::curie::retention_after_passes(p, dither.passes * plan.ladder.len());
            ColumnCoverage {
                y_nm: col.y_nm,
                hc: col.hc,
                ladder_field,
                dither_field,
                covered: hard || retention < 1e-3,
            }
        })
        .collect()
}

/// The MFM adversary model: off-track readback of guard-band
/// columns.
///
/// The adversary's tip integrates one lateral column at a time;
/// the read path adds Johnson-Nyquist noise. We model the
/// best-case adversary: zero instrument noise beyond the thermal
/// floor, perfect tip positioning, known plaintext (`old_bits`),
/// and the ability to pool evidence across columns (the
/// [`crate::prml::AggregateSnr`] estimator is their optimal
/// detector).
pub struct AdversaryRead {
    /// Front end supplying the noise floor.
    pub front_end: ReadFrontEnd,
}

impl AdversaryRead {
    /// Read the columns `j` of a track: one sample vector per
    /// column (column-major), for the aggregate estimator.
    pub fn read_columns_matrix(
        &self,
        track: &TrackState,
        columns: &[usize],
        rng: &mut SimRng,
    ) -> Vec<Vec<f64>> {
        let sigma = self.front_end.noise_sigma();
        let cells = track.old_bits.len();
        columns
            .iter()
            .map(|&j| {
                (0..cells)
                    .map(|k| track.m[j][k] + sigma * rng.next_normal())
                    .collect()
            })
            .collect()
    }

    /// Known-plaintext bit sequence (identical for every column).
    pub fn plaintext_for(&self, track: &TrackState) -> Vec<f64> {
        track.old_bits.clone()
    }
}

/// Transition-boundary forensics ghost: the Pearson correlation
/// between the old recording's edge-energy sequence and the
/// post-treatment guard-band residual's edge-energy sequence.
///
/// Edge energy `E_k = ((x_k − x_{k−1})/2)²` peaks where a
/// transition happened; a surviving ghost correlates the two
/// sequences. A wiped platter shows ~0.
pub fn transition_ghost_correlation(track: &TrackState, columns: &[usize]) -> f64 {
    let cells = track.old_bits.len();
    if cells < 4 || columns.is_empty() {
        return 0.0;
    }
    // Old edge energy (known plaintext).
    let mut e_old = Vec::with_capacity(cells - 1);
    for k in 1..cells {
        let d = (track.old_bits[k] - track.old_bits[k - 1]) / 2.0;
        e_old.push(d * d);
    }
    // Residual (per-column centered) mean edge energy.
    let mut e_res = vec![0.0_f64; cells - 1];
    for &j in columns {
        let mu: f64 = track.m[j].iter().sum::<f64>() / cells as f64;
        for k in 1..cells {
            let a = track.m[j][k] - mu;
            let b = track.m[j][k - 1] - mu;
            let d = (a - b) / 2.0;
            e_res[k - 1] += d * d;
        }
    }
    let n = columns.len() as f64;
    let e_res: Vec<f64> = e_res.iter().map(|v| v / n).collect();
    // Pearson correlation.
    let m_o = e_old.iter().sum::<f64>() / e_old.len() as f64;
    let m_r = e_res.iter().sum::<f64>() / e_res.len() as f64;
    let mut num = 0.0;
    let mut d_o = 0.0;
    let mut d_r = 0.0;
    for i in 0..e_old.len() {
        num += (e_old[i] - m_o) * (e_res[i] - m_r);
        d_o += (e_old[i] - m_o).powi(2);
        d_r += (e_res[i] - m_r).powi(2);
    }
    if d_o <= f64::EPSILON || d_r <= f64::EPSILON {
        return 0.0;
    }
    num / (d_o * d_r).sqrt()
}

/// Post-treatment main-channel readback for the PRML statistics:
/// the read head (centerline, read-width weighted average of the
/// columns) samples the wiped track; PRML LLRs must be noise-like.
pub fn main_channel_readback(
    track: &TrackState,
    geo: &TrackGeometry,
    front_end: &ReadFrontEnd,
    rng: &mut SimRng,
) -> Vec<f64> {
    let read_half = 0.60 * geo.core_half_width_nm();
    let sigma = front_end.noise_sigma();
    let cells = track.old_bits.len();
    let mut out = Vec::with_capacity(cells);
    for k in 0..cells {
        let mut acc = 0.0;
        let mut wsum = 0.0;
        for (j, col) in track.columns.iter().enumerate() {
            if col.y_nm.abs() <= read_half {
                let w = 1.0 - col.y_nm.abs() / read_half; // triangular head sensitivity
                acc += w * track.m[j][k];
                wsum += w;
            }
        }
        let mean = if wsum > 0.0 { acc / wsum } else { 0.0 };
        out.push(mean + sigma * rng.next_normal());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn std_setup() -> (TrackGeometry, usize, f64) {
        (TrackGeometry::default(), 192, 2.0)
    }

    #[test]
    fn original_write_leaves_a_guard_band_ghost() {
        let (geo, cells, res) = std_setup();
        let mut rng = SimRng::new(101);
        let mut track = new_track(&geo, cells, res, &mut rng);
        write_original(&mut track, &geo, &mut rng);
        // Guard-band columns must carry the old-bit fringe.
        let guard = track.guard_band_columns(&geo);
        assert!(!guard.is_empty());
        let amp: f64 = guard
            .iter()
            .map(|&j| track.m[j].iter().map(|v| v.abs()).sum::<f64>() / cells as f64)
            .fold(0.0_f64, f64::max);
        assert!(amp > 0.05, "ghost amplitude {amp} must be MFM-visible");
        // Core is fully saturated.
        let core_amp: f64 = track
            .columns
            .iter()
            .enumerate()
            .filter(|(_, c)| c.y_nm.abs() < geo.core_half_width_nm() * 0.8)
            .map(|(j, _)| track.m[j].iter().map(|v| v.abs()).sum::<f64>() / cells as f64)
            .fold(0.0_f64, f64::max);
        assert!(core_amp > 0.9, "core saturation {core_amp}");
    }

    #[test]
    fn naive_zero_write_keeps_the_ghost() {
        let (geo, cells, res) = std_setup();
        let mut rng = SimRng::new(202);
        let mut track = new_track(&geo, cells, res, &mut rng);
        write_original(&mut track, &geo, &mut rng);
        write_zero_baseline(&mut track, &geo, &mut rng);
        // Adversary still reads the ghost well above the floor.
        let fe = ReadFrontEnd::default();
        let adv = AdversaryRead { front_end: fe };
        let guard = track.guard_band_columns(&geo);
        let z = adv.read_columns_matrix(&track, &guard, &mut rng);
        let b = adv.plaintext_for(&track);
        let est = crate::prml::AggregateSnr::fit(&z, &b);
        // Pooled SNR far above the floor and the detection horizon
        // collapses: the myth reproduced.
        assert!(
            est.pooled_snr_db() > -6.0,
            "naive overwrite pooled ghost {} dB — the myth reproduced",
            est.pooled_snr_db()
        );
        assert!(
            est.detection_horizon_bits(1e-6, 0.99) < (cells as f64),
            "adversary decides within one track"
        );
    }

    #[test]
    fn full_treatment_annihilates_the_ghost() {
        // Full-length track: enough cells for the −20 dB claim to
        // be statistically meaningful (short tracks bottom out at
        // the estimator's own confidence floor).
        let geo = TrackGeometry::default();
        let cells = 4096usize;
        let res = 4.0;
        let mut rng = SimRng::new(303);
        let mut track = new_track(&geo, cells, res, &mut rng);
        write_original(&mut track, &geo, &mut rng);
        let plan = WritePlan::default_plan(cells);
        let dither = CurieDither::default();
        apply_treatment(&mut track, &geo, &plan, &dither, &mut rng).expect("treatment");

        let fe = ReadFrontEnd::default();
        let adv = AdversaryRead { front_end: fe };
        let guard = track.guard_band_columns(&geo);
        let z = adv.read_columns_matrix(&track, &guard, &mut rng);
        let b = adv.plaintext_for(&track);
        let est = crate::prml::AggregateSnr::fit(&z, &b);
        assert!(
            est.per_bit_snr_upper_db() < -20.0,
            "post-treatment aggregate bound {} dB must be < −20 dB",
            est.per_bit_snr_upper_db()
        );
        // The optimal distinguisher's horizon exceeds the track.
        assert!(
            est.detection_horizon_bits(1e-6, 0.99) > cells as f64,
            "horizon {} vs {} cells",
            est.detection_horizon_bits(1e-6, 0.99),
            cells
        );
        // Transition-boundary ghost dead.
        let tgc = transition_ghost_correlation(&track, &guard);
        assert!(tgc.abs() < 0.2, "transition ghost correlation {tgc}");
    }

    #[test]
    fn coverage_ledger_closes_under_the_default_plan() {
        let (geo, cells, res) = std_setup();
        let mut rng = SimRng::new(404);
        let track = new_track(&geo, cells, res, &mut rng);
        let plan = WritePlan::default_plan(cells);
        let dither = CurieDither::default();
        let ledger = coverage_ledger(&track, &geo, &plan, &dither);
        assert!(!ledger.is_empty());
        assert!(
            ledger.iter().all(|c| c.covered),
            "every guard-band column must be covered"
        );
    }

    #[test]
    fn anemic_plan_leaves_uncovered_columns() {
        let (geo, cells, res) = std_setup();
        let mut rng = SimRng::new(505);
        let track = new_track(&geo, cells, res, &mut rng);
        let plan = WritePlan {
            ladder: vec![crate::microstep::StepSpec::new(0.0, 0.0)],
            cells,
        };
        let dither = CurieDither::default();
        let ledger = coverage_ledger(&track, &geo, &plan, &dither);
        assert!(ledger.iter().any(|c| !c.covered));
    }

    #[test]
    fn main_channel_readback_is_noise_like_after_treatment() {
        let (geo, cells, res) = std_setup();
        let mut rng = SimRng::new(606);
        let mut track = new_track(&geo, cells, res, &mut rng);
        write_original(&mut track, &geo, &mut rng);
        let plan = WritePlan::default_plan(cells);
        let dither = CurieDither::default();
        apply_treatment(&mut track, &geo, &plan, &dither, &mut rng).expect("treatment");
        let fe = ReadFrontEnd::default();
        let y = main_channel_readback(&track, &geo, &fe, &mut rng);
        assert_eq!(y.len(), cells);
        // The wiped track reads back as the constant saturated
        // zero-symbol with only noise-scale residuals around it —
        // no old-data structure survives in the readback.
        let mean = y.iter().sum::<f64>() / y.len() as f64;
        assert!(mean < -0.8, "readback mean {mean} must be the zero-symbol");
        let peak_resid = y.iter().map(|v| (v - mean).abs()).fold(0.0_f64, f64::max);
        assert!(
            peak_resid < 0.25,
            "readback residual peak {peak_resid} too hot (noise σ ≈ 0.014)"
        );
    }

    #[test]
    fn treatment_is_deterministic_under_a_fixed_seed() {
        let (geo, cells, res) = std_setup();
        let run = |seed: u64| {
            let mut rng = SimRng::new(seed);
            let mut track = new_track(&geo, cells, res, &mut rng);
            write_original(&mut track, &geo, &mut rng);
            let plan = WritePlan::default_plan(cells);
            let dither = CurieDither::default();
            apply_treatment(&mut track, &geo, &plan, &dither, &mut rng).expect("treatment");
            track
        };
        let a = run(777);
        let b = run(777);
        assert_eq!(a.m, b.m, "same seed must replay identically");
    }
}
