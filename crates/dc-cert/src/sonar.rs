//! Acoustic PUF evidence (v0.12.0, Miracle 2).
//!
//! Embedded into `SanitizationCertificate.sonar` by `dc execute
//! --puf-guard` / `--puf-bind`. Mirrors the structures produced by the
//! `dc-sonar` engine — see that crate for the fingerprinting
//! (challenge-driven seek probes, IIO/hwmon telemetry capture,
//! pairwise-ordering fuzzy extractor).
//!
//! The enrollment digest binds the wipe to the physical chassis of the
//! drive; the guard verification records prove the same physical unit
//! stayed under the write head for the whole run — the rogue-swap
//! detector.

use serde::{Deserialize, Serialize};

/// One guard verification performed during a wipe run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SonarVerificationRecord {
    /// When in the run: "pre", "mid:<pass>", "post".
    pub phase: String,
    /// Fresh challenge used for this probe (hex).
    pub challenge_hex: String,
    pub hamming_distance: usize,
    pub bit_count: usize,
    pub match_threshold: usize,
    pub similarity: f64,
    pub matches: bool,
}

/// Full acoustic PUF binding for a wipe run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SonarPufEvidence {
    /// "sonar-puf/pairwise-order-v1".
    pub scheme: String,
    /// Enrollment fingerprint digest (BLAKE3, hex) — identifies the
    /// physical chassis the wipe was bound to.
    pub enrolled_digest_blake3: String,
    /// Number of enrolled comparison bits.
    pub bit_count: usize,
    /// Enrollment challenge (hex; audit reproducibility).
    pub enrollment_challenge_hex: String,
    /// Telemetry sources the enrollment was built from.
    pub telemetry_sources: Vec<String>,
    /// I/O backend used for probing during the run.
    pub probe_backend: String,
    /// Guard verifications executed during the run (empty when the PUF
    /// was bound but not guarded).
    pub verifications: Vec<SonarVerificationRecord>,
    /// Overall verdict: all guard verifications matched.
    pub all_matched: bool,
}

impl SonarPufEvidence {
    /// Human-readable field lines for the PDF/A archival report.
    pub fn field_lines(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Sonar PUF scheme".to_string(), self.scheme.clone()),
            (
                "Acoustic fingerprint".to_string(),
                self.enrolled_digest_blake3.clone(),
            ),
            ("PUF bit count".to_string(), self.bit_count.to_string()),
            (
                "PUF telemetry".to_string(),
                self.telemetry_sources.join(", "),
            ),
        ];
        for v in &self.verifications {
            lines.push((
                format!("PUF guard @ {}", v.phase),
                format!(
                    "{} of {} bits (threshold {}) — {}",
                    v.hamming_distance,
                    v.bit_count,
                    v.match_threshold,
                    if v.matches { "MATCH" } else { "SWAP DETECTED" }
                ),
            ));
        }
        lines
    }
}
