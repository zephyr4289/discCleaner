//! VDF time-lock timeline evidence (v0.12.0, Miracle 1).
//!
//! Embedded into `SanitizationCertificate.vdf` by `dc execute
//! --vdf-lock`. Signature-covered like every other certificate field.
//! Mirrors the structures produced by the `dc-vdf` engine — see that
//! crate for the cryptography (Wesolowski proofs over the RSA
//! unknown-order group, per-pass weave states).
//!
//! An auditor verifies with `dc vdf verify --certificate <cert.json>`:
//! every per-pass Wesolowski link checks in milliseconds, and the
//! chain proves `passes × steps_per_pass` non-parallelizable squarings
//! elapsed between the first and last woven writes — a wall-clock
//! lower bound independent of system clocks, NTP and operator honesty.

use serde::{Deserialize, Serialize};

/// One pass binding: the weave state that keyed the pass's on-media
/// keystream, plus its Wesolowski proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfPassBinding {
    pub pass_index: u8,
    /// Chain state `state_i` (hex, canonical big-endian, width of N).
    pub state: String,
    /// BLAKE3 of the ChaCha20 pass key (`vdf_pass_seed`) — matches the
    /// journal's BeginPass descriptor fingerprint exactly (hex).
    pub seed_fingerprint: String,
    /// Fiat–Shamir challenge prime ℓ_i (hex, 128-bit).
    pub challenge_prime: String,
    /// Wesolowski proof π_i (hex).
    pub proof: String,
    /// Advisory wall-clock note (ms since run start; NOT part of the
    /// mathematical claim).
    pub materialized_after_ms: u64,
}

/// Full time-lock timeline for a woven run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfTimelineEvidence {
    /// "wesolowski-rsa-ufo/v1".
    pub scheme: String,
    /// Modulus N (hex). Factorization destroyed at ceremony time.
    pub modulus_n: String,
    /// Challenge x (hex; BLAKE3 over N ‖ beacon ‖ run material).
    pub challenge_x: String,
    /// Sequential squarings between consecutive pass states.
    pub steps_per_pass: u64,
    /// Optional public beacon anchor (hex) — externally verifiable
    /// start-time lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon: Option<String>,
    pub passes: Vec<VdfPassBinding>,
    /// Measured local squarings/sec (advisory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_squarings_per_second: Option<f64>,
    /// Total squarings performed by the lock.
    pub squarings_done: u64,
}

impl VdfTimelineEvidence {
    /// Human-readable field lines for the PDF/A archival report.
    pub fn field_lines(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("VDF scheme".to_string(), self.scheme.clone()),
            (
                "VDF modulus bits".to_string(),
                (4 * self.modulus_n.trim_start_matches("0x").len() as u64).to_string(),
            ),
            (
                "VDF steps per pass".to_string(),
                self.steps_per_pass.to_string(),
            ),
            (
                "VDF total steps".to_string(),
                (self.steps_per_pass.saturating_mul(self.passes.len() as u64)).to_string(),
            ),
        ];
        if let Some(b) = &self.beacon {
            lines.push(("VDF beacon anchor".to_string(), b.clone()));
        }
        for p in &self.passes {
            lines.push((
                format!("VDF pass {} state", p.pass_index),
                format!(
                    "{}… (proof {}…)",
                    &p.state[..p.state.len().min(16)],
                    &p.proof[..p.proof.len().min(16)]
                ),
            ));
        }
        lines
    }
}
