//! Certificate evidence structures (v0.12.0, Miracle 2).
//!
//! `SonarPufEvidence` binds a wipe to the physical silicon body of
//! the drive: the challenge, the enrolled fingerprint digest, and the
//! verification verdicts observed DURING the wipe (pre / mid / post
//! under `--puf-guard`). An auditor holding the same enrollment
//! re-probes the drive with a fresh challenge and confirms the same
//! physical unit — or proves a rogue swap occurred.

use crate::puf::VerifyOutcome;
use serde::{Deserialize, Serialize};

/// One guard verification performed during a wipe run.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VerificationRecord {
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

impl VerificationRecord {
    pub fn from_outcome(phase: &str, challenge: &[u8; 32], o: &VerifyOutcome) -> Self {
        Self {
            phase: phase.to_string(),
            challenge_hex: hex::encode(challenge),
            hamming_distance: o.hamming_distance,
            bit_count: o.bit_count,
            match_threshold: o.match_threshold,
            similarity: o.similarity,
            matches: o.matches,
        }
    }
}

/// The certificate-embedded acoustic PUF binding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SonarPufEvidence {
    pub scheme: String, // "sonar-puf/pairwise-order-v1"
    /// Enrollment fingerprint digest (BLAKE3, hex) — identifies the
    /// physical chassis the wipe was bound to.
    pub enrolled_digest_blake3: String,
    /// Number of enrolled comparison bits.
    pub bit_count: usize,
    /// Enrollment challenge (audit reproducibility).
    pub enrollment_challenge_hex: String,
    /// Telemetry sources the enrollment was built from.
    pub telemetry_sources: Vec<String>,
    /// I/O backend used for probing during the run.
    pub probe_backend: String,
    /// Guard verifications executed during the run (empty when the
    /// PUF was bound but not guarded).
    pub verifications: Vec<VerificationRecord>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_lines_render() {
        let ev = SonarPufEvidence {
            scheme: "sonar-puf/pairwise-order-v1".into(),
            enrolled_digest_blake3: "ab".repeat(32),
            bit_count: 64,
            enrollment_challenge_hex: "cd".repeat(32),
            telemetry_sources: vec!["iio:device0".into()],
            probe_backend: "file:/dev/sda".into(),
            verifications: vec![VerificationRecord {
                phase: "pre".into(),
                challenge_hex: "ef".repeat(32),
                hamming_distance: 2,
                bit_count: 64,
                match_threshold: 8,
                similarity: 0.97,
                matches: true,
            }],
            all_matched: true,
        };
        let lines = ev.field_lines();
        assert!(lines.iter().any(|(k, _)| k.contains("Sonar PUF scheme")));
        assert!(
            lines
                .iter()
                .any(|(k, v)| k.contains("guard @ pre") && v.contains("MATCH"))
        );
    }
}
