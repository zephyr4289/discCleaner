//! # The Remanence Annihilation Certificate.
//!
//! The court-grade proof that a platter's guard-band sub-surface
//! magnetization was driven below the read path's Johnson-Nyquist
//! thermal floor, making Magnetic-Force-Microscopy recovery
//! uninformative.
//!
//! ## What each track row proves
//!
//! * **Ghost baseline** — what a pooled multi-column MFM adversary
//!   measures on a naive zero-overwrite of the same original
//!   recording (the "overwrite myth" quantified: detection within a
//!   few dozen bits).
//! * **Post-treatment aggregate SNR** — the 99% upper bound on the
//!   adversary's per-bit aggregate SNR across all guard-band
//!   columns (χ²-omnibus bound, sign-mixing safe). The certificate
//!   demands `< −20 dB`.
//! * **Coverage** — every guard-band column hard-switched (or
//!   dither-randomized below 0.1% retention) by the executed
//!   micro-step ladder.
//! * **Transition forensics** — the correlation between the old
//!   recording's edge-energy sequence and the post-treatment
//!   guard-band residual must be statistically zero (no
//!   edge-density ghost of the old recording).
//! * **Detection horizon** — how many bits a Neyman-Pearson
//!   optimal distinguisher needs at the certified SNR
//!   (P_FA = 10⁻⁶, P_D = 99%), vs. how many the track physically
//!   contains. Below the floor the horizon exceeds supply: the
//!   distinguisher cannot reach a decision.
//!
//! `digest` is BLAKE3 over the canonical JSON of the evidence body
//! (everything except the digest itself), signable by the dc-cert
//! hybrid Ed25519 + ML-DSA machinery at the CLI layer.

use crate::curie::CurieDither;
use crate::microstep::{DEFAULT_LADDER, WritePlan};
use crate::prml::{AggregateSnr, ReadFrontEnd, detection_horizon};
use crate::remanence::{
    AdversaryRead, apply_treatment, coverage_ledger, main_channel_readback, new_track,
    transition_ghost_correlation, write_original, write_zero_baseline,
};
use crate::track::TrackGeometry;
use crate::{RemanenceError, SimRng};
use serde::Serialize;
/// Certificate schema tag.
pub const SCHEMA: &str = "discCleaner/remanence-annihilation/1";

/// Target: post-treatment adversary per-bit aggregate SNR upper
/// bound (dB).
pub const SNR_FLOOR_DB: f64 = -20.0;

/// False-alarm budget of the adversary distinguisher.
pub const ADVERSARY_P_FA: f64 = 1e-6;
/// Detection power the adversary aims for.
pub const ADVERSARY_P_D: f64 = 0.99;

/// Per-track verdict row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrackVerdict {
    pub track: usize,
    /// Guard-band columns simulated (the MFM readout width).
    pub guard_columns: usize,
    /// Columns covered by the executed plan.
    pub covered_columns: usize,
    /// Pooled multi-column SNR (dB) after a NAIVE zero-overwrite —
    /// the myth, quantified.
    pub ghost_baseline_pooled_snr_db: f64,
    /// Bits the adversary needs to decide on the NAIVE overwrite
    /// (detection collapses to a handful of bits).
    pub ghost_baseline_horizon_bits: f64,
    /// 99% upper bound (dB) on the post-treatment per-bit aggregate
    /// SNR — the certified number.
    pub residual_snr_upper_db: f64,
    /// χ² omnibus statistic of the post-treatment readback.
    pub residual_chi2: f64,
    /// Centered-residual noise sigma (normalized read units).
    pub residual_sigma: f64,
    /// Bits an optimal distinguisher needs at the certified bound.
    pub detection_horizon_bits: f64,
    /// Bit cells the track physically contains.
    pub available_bits: usize,
    /// Post-treatment transition-boundary ghost correlation.
    pub transition_ghost_corr: f64,
    /// PRML main-channel readback mean after treatment (noise-like
    /// ⇒ ~0).
    pub readback_mean: f64,
    pub passed: bool,
    pub reasons: Vec<String>,
}

/// The Remanence Annihilation Certificate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemanenceCertificate {
    pub schema: String,
    pub device_id: String,
    pub geometry: TrackGeometry,
    pub plan: WritePlan,
    pub dither: CurieDither,
    pub front_end: ReadFrontEnd,
    /// Lateral simulation resolution (nm).
    pub resolution_nm: f64,
    /// Bit cells per track.
    pub cells: usize,
    pub tracks: Vec<TrackVerdict>,
    pub covered_tracks: usize,
    pub total_tracks: usize,
    pub verified: bool,
    pub notes: Vec<String>,
    pub digest: String,
}

impl RemanenceCertificate {
    /// Run the annihilation campaign and assemble the certificate.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        device_id: &str,
        geometry: &TrackGeometry,
        plan: &WritePlan,
        dither: &CurieDither,
        front_end: &ReadFrontEnd,
        tracks: usize,
        cells: usize,
        resolution_nm: f64,
        seed: u64,
    ) -> Result<Self, RemanenceError> {
        geometry.validate()?;
        dither.validate().map_err(RemanenceError::Geometry)?;
        if tracks == 0 || cells == 0 {
            return Err(RemanenceError::Simulation(
                "campaign needs at least one track and one cell".into(),
            ));
        }
        let mut rng = SimRng::new(seed);
        let mut rows = Vec::with_capacity(tracks);
        for t in 0..tracks {
            rows.push(simulate_track(
                t,
                geometry,
                plan,
                dither,
                front_end,
                cells,
                resolution_nm,
                &mut rng,
            ));
        }
        let covered_tracks = rows.iter().filter(|r| r.passed).count();
        let verified = covered_tracks == tracks;
        let mut notes = Vec::new();
        if verified {
            notes.push(format!(
                "all {tracks} tracks: guard-band coverage 100%, certified adversary per-bit aggregate SNR below {SNR_FLOOR_DB} dB"
            ));
            notes.push(format!(
                "adversary model: known-plaintext multi-column MFM read at the Johnson-Nyquist floor ({:.0} K, {:.0} ohm, {:.0} MHz), Neyman-Pearson optimal, chi-square omnibus",
                front_end.temperature_k, front_end.resistance_ohm, front_end.bandwidth_hz / 1e6
            ));
            let worst = rows
                .iter()
                .fold(f64::NEG_INFINITY, |a, r| a.max(r.residual_snr_upper_db));
            let best_baseline = rows.iter().fold(f64::NEG_INFINITY, |a, r| {
                a.max(r.ghost_baseline_pooled_snr_db)
            });
            let quickest = rows
                .iter()
                .fold(f64::INFINITY, |a, r| a.min(r.ghost_baseline_horizon_bits));
            notes.push(format!(
                "worst-track certified bound: {worst:.1} dB (floor {SNR_FLOOR_DB} dB); the same recording under a naive zero-overwrite pools at {best_baseline:.1} dB and falls to the adversary in {quickest:.0} bits"
            ));
        }
        let mut cert = Self {
            schema: SCHEMA.into(),
            device_id: device_id.into(),
            geometry: geometry.clone(),
            plan: plan.clone(),
            dither: dither.clone(),
            front_end: front_end.clone(),
            resolution_nm,
            cells,
            tracks: rows,
            covered_tracks,
            total_tracks: tracks,
            verified,
            notes,
            digest: String::new(),
        };
        cert.digest = cert.compute_digest();
        Ok(cert)
    }

    /// Canonical evidence body (everything the digest binds).
    fn evidence_json(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Body<'a> {
            schema: &'a str,
            device_id: &'a str,
            geometry: &'a TrackGeometry,
            plan: &'a WritePlan,
            dither: &'a CurieDither,
            front_end: &'a ReadFrontEnd,
            resolution_nm: f64,
            cells: usize,
            tracks: &'a [TrackVerdict],
            covered_tracks: usize,
            total_tracks: usize,
            verified: bool,
            notes: &'a [String],
        }
        serde_json::to_vec(&Body {
            schema: &self.schema,
            device_id: &self.device_id,
            geometry: &self.geometry,
            plan: &self.plan,
            dither: &self.dither,
            front_end: &self.front_end,
            resolution_nm: self.resolution_nm,
            cells: self.cells,
            tracks: &self.tracks,
            covered_tracks: self.covered_tracks,
            total_tracks: self.total_tracks,
            verified: self.verified,
            notes: &self.notes,
        })
        .expect("canonical remanence body json")
    }

    /// BLAKE3 over the canonical body.
    pub fn compute_digest(&self) -> String {
        blake3::hash(&self.evidence_json()).to_hex().to_string()
    }

    /// Offline verification: digest coverage + verdict arithmetic
    /// recomputation.
    pub fn verify(&self) -> Result<(), RemanenceError> {
        if self.schema != SCHEMA {
            return Err(RemanenceError::Certificate(format!(
                "unknown schema {} (expected {SCHEMA})",
                self.schema
            )));
        }
        if self.digest != self.compute_digest() {
            return Err(RemanenceError::Certificate(
                "digest does not cover the evidence body — tampered or corrupt".into(),
            ));
        }
        // Recompute verdicts from the raw statistics.
        let mut recomputed_covered = 0usize;
        for row in &self.tracks {
            let coverage = row.covered_columns as f64 / row.guard_columns.max(1) as f64;
            let snr_ok = row.residual_snr_upper_db < SNR_FLOOR_DB;
            let horizon_ok = row.detection_horizon_bits > row.available_bits as f64;
            let should =
                coverage >= 1.0 && snr_ok && horizon_ok && row.transition_ghost_corr.abs() < 0.2;
            if should {
                recomputed_covered += 1;
            }
            if should != row.passed {
                return Err(RemanenceError::Certificate(format!(
                    "track {} verdict does not recompute (passed={} but statistics say {should})",
                    row.track, row.passed
                )));
            }
        }
        if self.covered_tracks != recomputed_covered {
            return Err(RemanenceError::Certificate(
                "covered track count does not recompute".into(),
            ));
        }
        if self.verified != (recomputed_covered == self.total_tracks) {
            return Err(RemanenceError::Certificate(
                "verified flag does not recompute from track verdicts".into(),
            ));
        }
        Ok(())
    }
}

/// Simulate one track end-to-end and produce its verdict row.
fn simulate_track(
    track_idx: usize,
    geo: &TrackGeometry,
    plan: &WritePlan,
    dither: &CurieDither,
    front_end: &ReadFrontEnd,
    cells: usize,
    resolution_nm: f64,
    rng: &mut SimRng,
) -> TrackVerdict {
    // 1. Original recording on a virgin track.
    let mut t = new_track(geo, cells, resolution_nm, rng);
    write_original(&mut t, geo, rng);
    let guard = t.guard_band_columns(geo);
    let adversary = AdversaryRead {
        front_end: front_end.clone(),
    };
    let plaintext = adversary.plaintext_for(&t);

    // 2. Baseline: the naive zero-overwrite ghost (the myth), same
    //    original recording.
    let mut baseline = t.clone();
    write_zero_baseline(&mut baseline, geo, rng);
    let z_b = adversary.read_columns_matrix(&baseline, &guard, rng);
    let est_b = AggregateSnr::fit(&z_b, &plaintext);

    // 3. The full treatment.
    apply_treatment(&mut t, geo, plan, dither, rng).expect("treatment executes");
    let z = adversary.read_columns_matrix(&t, &guard, rng);
    let est = AggregateSnr::fit(&z, &plaintext);

    // 4. Coverage ledger + transition forensics + readback stats.
    let ledger = coverage_ledger(&t, geo, plan, dither);
    let covered_columns = ledger.iter().filter(|c| c.covered).count();
    let transition_corr = transition_ghost_correlation(&t, &guard);
    let readback = main_channel_readback(&t, geo, front_end, rng);
    let readback_mean = readback.iter().sum::<f64>() / readback.len() as f64;

    let horizon = est.detection_horizon_bits(ADVERSARY_P_FA, ADVERSARY_P_D);
    let baseline_horizon = detection_horizon(
        est_b.chi2 / est_b.cells as f64,
        ADVERSARY_P_FA,
        ADVERSARY_P_D,
    );

    let mut reasons = Vec::new();
    let coverage = covered_columns as f64 / ledger.len().max(1) as f64;
    if coverage < 1.0 {
        reasons.push(format!(
            "guard-band coverage {:.1}% — {} columns uncovered (forensic islands)",
            coverage * 100.0,
            ledger.len() - covered_columns
        ));
    }
    if est.per_bit_snr_upper_db() >= SNR_FLOOR_DB {
        reasons.push(format!(
            "residual aggregate SNR bound {:.1} dB ≥ floor {SNR_FLOOR_DB} dB",
            est.per_bit_snr_upper_db()
        ));
    }
    if horizon <= cells as f64 {
        reasons.push(format!(
            "detection horizon {horizon:.0} bits ≤ available {cells} — distinguisher still decides"
        ));
    }
    if transition_corr.abs() >= 0.2 {
        reasons.push(format!(
            "transition ghost correlation {transition_corr:.3} — edge-density ghost survives"
        ));
    }
    TrackVerdict {
        track: track_idx,
        guard_columns: ledger.len(),
        covered_columns,
        ghost_baseline_pooled_snr_db: est_b.pooled_snr_db(),
        ghost_baseline_horizon_bits: baseline_horizon,
        residual_snr_upper_db: est.per_bit_snr_upper_db(),
        residual_chi2: est.chi2,
        residual_sigma: est.sigma,
        detection_horizon_bits: horizon,
        available_bits: cells,
        transition_ghost_corr: transition_corr,
        readback_mean,
        passed: reasons.is_empty(),
        reasons,
    }
}

/// Convenience: the default campaign configuration used by the CLI.
pub struct CampaignDefaults;

impl CampaignDefaults {
    /// Default plan on the default ladder.
    pub fn plan(cells: usize) -> WritePlan {
        WritePlan {
            ladder: DEFAULT_LADDER.to_vec(),
            cells,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prml::{q_function, q_inverse};

    fn run_campaign(tracks: usize, cells: usize, seed: u64) -> RemanenceCertificate {
        RemanenceCertificate::assemble(
            "SIM-REMANENCE-000",
            &TrackGeometry::default(),
            &CampaignDefaults::plan(cells),
            &CurieDither::default(),
            &ReadFrontEnd::default(),
            tracks,
            cells,
            4.0,
            seed,
        )
        .expect("campaign assembles")
    }

    #[test]
    fn honest_campaign_certifies() {
        let cert = run_campaign(3, 4096, 42);
        assert!(cert.verified, "notes: {:?}", cert.notes);
        assert_eq!(cert.covered_tracks, 3);
        for row in &cert.tracks {
            assert!(row.passed);
            // The myth reproduced: naive ghost pools above the floor
            // and detection collapses to a few dozen bits.
            assert!(
                row.ghost_baseline_pooled_snr_db > -6.0,
                "baseline ghost {} dB",
                row.ghost_baseline_pooled_snr_db
            );
            assert!(row.ghost_baseline_horizon_bits < 512.0);
            // The treatment: certified below the floor.
            assert!(row.residual_snr_upper_db < SNR_FLOOR_DB);
            // Horizon exceeds supply.
            assert!(row.detection_horizon_bits > row.available_bits as f64);
            // Transition ghost dead.
            assert!(row.transition_ghost_corr.abs() < 0.2);
        }
        cert.verify().expect("honest certificate verifies");
    }

    #[test]
    fn tampering_with_the_body_breaks_the_digest() {
        let mut cert = run_campaign(2, 4096, 7);
        let original = cert.tracks[0].residual_snr_upper_db;
        cert.tracks[0].residual_snr_upper_db = -60.0; // beautify the physics
        assert!(cert.verify().is_err());
        cert.tracks[0].residual_snr_upper_db = original;
        assert!(cert.verify().is_ok());
    }

    #[test]
    fn anemic_ladder_refuses_to_certify() {
        let geo = TrackGeometry::default();
        let plan = WritePlan {
            ladder: vec![crate::microstep::StepSpec::new(0.0, 0.0)],
            cells: 4096,
        };
        let cert = RemanenceCertificate::assemble(
            "SIM-REMANENCE-REFUSAL",
            &geo,
            &plan,
            &CurieDither::default(),
            &ReadFrontEnd::default(),
            2,
            4096,
            4.0,
            99,
        )
        .expect("campaign assembles");
        assert!(!cert.verified);
        assert!(cert.tracks.iter().any(|r| !r.passed));
        // A refused run is still a valid document.
        cert.verify().expect("integrity holds even on refusal");
    }

    #[test]
    fn campaign_is_deterministic_under_a_fixed_seed() {
        let a = run_campaign(2, 2048, 1234);
        let b = run_campaign(2, 2048, 1234);
        assert_eq!(a.digest, b.digest);
        let c = run_campaign(2, 2048, 1235);
        assert_ne!(a.digest, c.digest);
    }

    #[test]
    fn horizon_math_is_self_consistent() {
        // Cross-check detection_horizon against the direct NP
        // formula at a known SNR.
        let snr = 0.005;
        let n = detection_horizon(snr, ADVERSARY_P_FA, ADVERSARY_P_D);
        // The error exponent of the optimal detector: P_D at n
        // cells is Q(z_fa - sqrt(n·snr)).
        let z_fa = q_inverse(ADVERSARY_P_FA);
        let p_d = q_function(z_fa - (n * snr).sqrt());
        assert!(
            ((p_d - ADVERSARY_P_D).abs() < 1e-3),
            "P_D at horizon = {p_d}, target {ADVERSARY_P_D}"
        );
    }
}
