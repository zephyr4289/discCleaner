//! # The Photobleach Destruction Certificate.
//!
//! The court-grade artifact of the optical annihilation run. It
//! binds:
//!
//! * the **media identity** (type + disc id), the executed vendor
//!   command stream digest, and the OPU weaponization state,
//! * the **per-zone dose ledger** (minimum dose must cross the
//!   media's annihilation threshold in every zone — 100% spiral
//!   coverage, proven per cell),
//! * the **readback evidence**: per-zone RF eye state, worst
//!   residual ΔR/R modulation, push-pull collapse ratio, slicer
//!   jitter, and the forensics read-recovery rate (must sit at
//!   chance),
//! * the **media-type thresholds** the verdicts recompute against.
//!
//! `digest` is BLAKE3 over the canonical JSON of the evidence body
//! (everything except the digest itself), signable by the dc-cert
//! hybrid Ed25519 + ML-DSA machinery at the CLI layer.

use crate::OptixError;
use crate::anneal::{AnnealConfig, AnnealReport, annihilate};
use crate::layer::{LayerStack, MediaType};
use crate::mmc::{DriveLimits, MmcTransport, SimDrive, VendorCommand};
use crate::rfeeye::{ReadbackReport, analyze};
use serde::Serialize;

/// Certificate schema tag.
pub const SCHEMA: &str = "discCleaner/optix-destruction/1";

/// Residual modulation threshold (ΔR/R below this = unreadable).
pub const MODULATION_FLOOR: f64 = 0.05;

/// Push-pull collapse threshold (fraction of fresh amplitude).
pub const PUSH_PULL_FLOOR: f64 = 0.15;

/// Read-recovery band around chance (0.5 ± band).
pub const RECOVERY_BAND: f64 = 0.05;

/// Per-zone verdict row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneVerdict {
    pub zone: usize,
    /// Minimum cell dose in the zone.
    pub min_dose: f64,
    /// Mean cell dose.
    pub mean_dose: f64,
    /// RF eye height (normalized return).
    pub eye_height: f64,
    pub eye_open: bool,
    /// Residual modulation ΔR/R.
    pub modulation: f64,
    pub passed: bool,
    pub reasons: Vec<String>,
}

/// The Photobleach Destruction Certificate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OptixCertificate {
    pub schema: String,
    pub disc_id: String,
    pub media: MediaType,
    /// The media's annihilation threshold (normalized dose).
    pub annihilate_threshold: f64,
    /// The weaponized OPU state.
    pub opu: crate::opu::Opu,
    /// Number of write-long passes.
    pub passes: u32,
    /// Digest over the executed vendor command stream.
    pub command_digest: String,
    /// Per-zone dose + eye evidence.
    pub zones: Vec<ZoneVerdict>,
    /// Spiral coverage (fraction of cells over threshold).
    pub coverage: f64,
    /// Worst residual modulation.
    pub worst_modulation: f64,
    /// Push-pull collapse ratio (vs fresh).
    pub push_pull_ratio: f64,
    /// Slicer jitter (fraction of the bit clock).
    pub jitter: f64,
    /// Forensics read-recovery rate (0.5 = chance).
    pub read_recovery_rate: f64,
    pub verified: bool,
    pub notes: Vec<String>,
    pub digest: String,
}

impl OptixCertificate {
    /// Run the annihilation campaign and assemble the certificate.
    pub fn assemble(
        disc_id: &str,
        media: MediaType,
        config: &AnnealConfig,
        zones: usize,
        sectors_per_zone: usize,
        cells_per_sector: usize,
        seed: u64,
    ) -> Result<Self, OptixError> {
        if zones == 0 || sectors_per_zone == 0 || cells_per_sector == 0 {
            return Err(OptixError::Annihilation(
                "empty spiral grid — nothing to destroy".into(),
            ));
        }
        let stack = LayerStack::with_seed(media, zones, sectors_per_zone, cells_per_sector, seed);
        let mut drive = SimDrive::new(DriveLimits::default(), stack);
        let report: AnnealReport = annihilate(&mut drive, config)?;
        let command_digest = command_stream_digest(drive.command_log());
        let mut rng = crate::SimRng::new(seed ^ 0xC0FFEE);
        let readback: ReadbackReport = analyze(&drive.media, &mut rng);
        Self::from_parts(disc_id, media, config, report, command_digest, readback)
    }

    /// Assemble from already-run parts (used by tests and future
    /// hardware backends).
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        disc_id: &str,
        media: MediaType,
        config: &AnnealConfig,
        report: AnnealReport,
        command_digest: String,
        readback: ReadbackReport,
    ) -> Result<Self, OptixError> {
        let threshold = media.annihilate_dose();
        let mut rows = Vec::with_capacity(report.zone_min_dose.len());
        for (z, ((eye, min_dose), mean_dose)) in readback
            .zones
            .iter()
            .zip(&report.zone_min_dose)
            .zip(&report.zone_mean_dose)
            .enumerate()
        {
            let mut reasons = Vec::new();
            if *min_dose < threshold {
                reasons.push(format!(
                    "min dose {min_dose:.2} < threshold {threshold:.2} — cells survive"
                ));
            }
            if eye.eye_open {
                reasons.push(format!(
                    "RF eye open (height {:.3}) — data pattern still readable",
                    eye.eye_height
                ));
            }
            if eye.modulation >= MODULATION_FLOOR {
                reasons.push(format!(
                    "residual modulation {:.3} ≥ floor {MODULATION_FLOOR}",
                    eye.modulation
                ));
            }
            rows.push(ZoneVerdict {
                zone: z,
                min_dose: *min_dose,
                mean_dose: *mean_dose,
                eye_height: eye.eye_height,
                eye_open: eye.eye_open,
                modulation: eye.modulation,
                passed: reasons.is_empty(),
                reasons,
            });
        }
        let covered_zones = rows.iter().filter(|r| r.passed).count();
        let verified = covered_zones == rows.len()
            && (report.coverage - 1.0).abs() < 1e-12
            && readback.worst_modulation < MODULATION_FLOOR
            && readback.push_pull_ratio < PUSH_PULL_FLOOR
            && (readback.read_recovery_rate - 0.5).abs() < RECOVERY_BAND;
        let mut notes = Vec::new();
        if verified {
            notes.push(format!(
                "spiral coverage 100%: every cell dose ≥ {:.1} ({} {})",
                threshold,
                media.name(),
                if matches!(media, MediaType::GlassyCarbon) {
                    "— the media that survives shredders, not the parked-CW overdrive"
                } else {
                    "destruction threshold"
                }
            ));
            notes.push(format!(
                "worst residual ΔR/R {:.4} (floor {MODULATION_FLOOR}); push-pull at {:.1}% of fresh; read recovery {:.1}% (chance 50%)",
                readback.worst_modulation,
                readback.push_pull_ratio * 100.0,
                readback.read_recovery_rate * 100.0
            ));
            notes.push(format!(
                "OPU: {:.1} mW CW at {:.2} m/s parked CLV — energy gain {:.1}× the write strategy",
                config.opu.effective_power_mw(),
                config.opu.clv_mps,
                config.opu.energy_gain()
            ));
        } else {
            notes.push("run REFUSED — see per-zone reasons".into());
        }
        let mut cert = Self {
            schema: SCHEMA.into(),
            disc_id: disc_id.into(),
            media,
            annihilate_threshold: threshold,
            opu: config.opu.clone(),
            passes: report.passes,
            command_digest,
            zones: rows,
            coverage: report.coverage,
            worst_modulation: readback.worst_modulation,
            push_pull_ratio: readback.push_pull_ratio,
            jitter: readback.jitter,
            read_recovery_rate: readback.read_recovery_rate,
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
            disc_id: &'a str,
            media: MediaType,
            annihilate_threshold: f64,
            opu: &'a crate::opu::Opu,
            passes: u32,
            command_digest: &'a str,
            zones: &'a [ZoneVerdict],
            coverage: f64,
            worst_modulation: f64,
            push_pull_ratio: f64,
            jitter: f64,
            read_recovery_rate: f64,
            verified: bool,
            notes: &'a [String],
        }
        serde_json::to_vec(&Body {
            schema: &self.schema,
            disc_id: &self.disc_id,
            media: self.media,
            annihilate_threshold: self.annihilate_threshold,
            opu: &self.opu,
            passes: self.passes,
            command_digest: &self.command_digest,
            zones: &self.zones,
            coverage: self.coverage,
            worst_modulation: self.worst_modulation,
            push_pull_ratio: self.push_pull_ratio,
            jitter: self.jitter,
            read_recovery_rate: self.read_recovery_rate,
            verified: self.verified,
            notes: &self.notes,
        })
        .expect("canonical optix body json")
    }

    /// BLAKE3 over the canonical body.
    pub fn compute_digest(&self) -> String {
        blake3::hash(&self.evidence_json()).to_hex().to_string()
    }

    /// Offline verification: digest coverage + verdict arithmetic
    /// recomputation from the raw statistics.
    pub fn verify(&self) -> Result<(), OptixError> {
        if self.schema != SCHEMA {
            return Err(OptixError::Certificate(format!(
                "unknown schema {} (expected {SCHEMA})",
                self.schema
            )));
        }
        if self.digest != self.compute_digest() {
            return Err(OptixError::Certificate(
                "digest does not cover the evidence body — tampered or corrupt".into(),
            ));
        }
        let mut recomputed = 0usize;
        for row in &self.zones {
            let should = row.min_dose >= self.annihilate_threshold
                && !row.eye_open
                && row.modulation < MODULATION_FLOOR;
            if should {
                recomputed += 1;
            }
            if should != row.passed {
                return Err(OptixError::Certificate(format!(
                    "zone {} verdict does not recompute (passed={} but statistics say {should})",
                    row.zone, row.passed
                )));
            }
        }
        let recomputed_verified = recomputed == self.zones.len()
            && (self.coverage - 1.0).abs() < 1e-12
            && self.worst_modulation < MODULATION_FLOOR
            && self.push_pull_ratio < PUSH_PULL_FLOOR
            && (self.read_recovery_rate - 0.5).abs() < RECOVERY_BAND;
        if recomputed_verified != self.verified {
            return Err(OptixError::Certificate(
                "verified flag does not recompute from the evidence".into(),
            ));
        }
        Ok(())
    }
}

/// Digest over the executed vendor command stream.
pub fn command_stream_digest(commands: &[VendorCommand]) -> String {
    let json = serde_json::to_vec(commands).expect("command stream json");
    blake3::hash(&json).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(media: MediaType, passes: u32, zones: usize, seed: u64) -> OptixCertificate {
        OptixCertificate::assemble(
            "SIM-OPTIX-000",
            media,
            &AnnealConfig {
                passes,
                ..Default::default()
            },
            zones,
            6,
            16,
            seed,
        )
        .expect("campaign assembles")
    }

    #[test]
    fn honest_campaign_certifies_all_media_families() {
        for media in [
            MediaType::OrganicDye,
            MediaType::PhaseChange,
            MediaType::GlassyCarbon,
        ] {
            let cert = run(media, 3, 6, 42);
            assert!(cert.verified, "{media:?} notes: {:?}", cert.notes);
            assert!((cert.coverage - 1.0).abs() < 1e-12);
            assert!(cert.worst_modulation < MODULATION_FLOOR);
            assert!(cert.push_pull_ratio < PUSH_PULL_FLOOR);
            assert!((cert.read_recovery_rate - 0.5).abs() < RECOVERY_BAND);
            cert.verify().expect("honest certificate verifies");
        }
    }

    #[test]
    fn weak_beam_refuses_to_certify() {
        let mut config = AnnealConfig::default();
        config.opu.current_gain = 0.45;
        let cert = OptixCertificate::assemble(
            "SIM-OPTIX-REFUSAL",
            MediaType::GlassyCarbon,
            &config,
            4,
            4,
            16,
            7,
        )
        .expect("campaign assembles");
        assert!(!cert.verified);
        assert!(cert.coverage < 1.0);
        // A refused run is still a valid document.
        cert.verify().expect("integrity holds on refusal");
    }

    #[test]
    fn single_zone_shortfall_fails_the_whole_certificate() {
        // M-DISC with ONE pass at reduced gain: dose ≈ 0.9 × 4.1
        // ≈ 3.7 against the threshold of 6 — refused.
        let config = AnnealConfig {
            passes: 1,
            opu: crate::opu::Opu {
                current_gain: 0.9,
                ..Default::default()
            },
            ..Default::default()
        };
        let cert = OptixCertificate::assemble(
            "SIM-OPTIX-SHORT",
            MediaType::GlassyCarbon,
            &config,
            1, // single zone
            4,
            8,
            9,
        )
        .expect("campaign assembles");
        // Dose ≈ 0.9 × 4.1 ≈ 3.7 < 6: refused.
        assert!(!cert.verified);
    }

    #[test]
    fn tampering_with_the_body_breaks_the_digest() {
        let mut cert = run(MediaType::PhaseChange, 2, 4, 11);
        let original = cert.zones[0].min_dose;
        cert.zones[0].min_dose = 100.0; // beautify the dose
        assert!(cert.verify().is_err());
        cert.zones[0].min_dose = original;
        assert!(cert.verify().is_ok());
    }

    #[test]
    fn campaign_is_deterministic_under_a_fixed_seed() {
        let a = run(MediaType::PhaseChange, 2, 4, 1234);
        let b = run(MediaType::PhaseChange, 2, 4, 1234);
        assert_eq!(a.digest, b.digest);
        let c = run(MediaType::PhaseChange, 2, 4, 1235);
        assert_ne!(a.digest, c.digest);
    }

    #[test]
    fn command_stream_digest_binds_the_weaponization() {
        let commands = vec![
            VendorCommand::DisableOpc {
                opcode: crate::mmc::opcodes::DISABLE_OPC,
            },
            VendorCommand::LaserOverdrive {
                opcode: crate::mmc::opcodes::LASER_OVERDRIVE,
                duty_pm: 1000,
                current_pct: 280,
            },
        ];
        let d1 = command_stream_digest(&commands);
        let mut other = commands.clone();
        other[1] = VendorCommand::LaserOverdrive {
            opcode: crate::mmc::opcodes::LASER_OVERDRIVE,
            duty_pm: 1000,
            current_pct: 200, // a weaker beam
        };
        assert_ne!(command_stream_digest(&other), d1);
        assert_eq!(command_stream_digest(&commands), d1);
    }
}
