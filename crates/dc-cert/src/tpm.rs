//! TPM 2.0 remote-attestation evidence (v0.8.0, Vector 1).
//!
//! Carries the verified `TPM2_Quote` bundle into the signed certificate:
//! the PCR values measured by the platform's secure element, the AIK
//! public key that signed the quote, the raw archived quote response for
//! offline replay, and the verification verdict performed at capture
//! time. See `dc-tpm` for the wire protocol implementation.

use serde::{Deserialize, Serialize};

/// The certificate-embedded TPM attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmAttestationEvidence {
    /// Quote freshness nonce (hex).
    pub nonce_hex: String,
    /// PCR selection mask (hex bytes, SHA-256 bank).
    pub pcr_mask_hex: String,
    /// Live PCR values at quote time (hex, selection order).
    pub pcr_values_hex: Vec<String>,
    /// SHA-256 over the concatenated PCR values (what the quote must
    /// contain internally for a genuine measurement).
    pub pcr_digest_hex: String,
    /// Raw TPM2_Quote response — TPMS_ATTEST + TPMT_SIGNATURE exactly as
    /// the secure element returned it (archival replay artifact).
    pub quote_response_hex: String,
    /// AIK public point x (hex, 32 bytes).
    pub aik_x_hex: String,
    /// AIK public point y (hex, 32 bytes).
    pub aik_y_hex: String,
    /// Raw TPMT_PUBLIC template of the AIK (hex).
    pub aik_public_template_hex: String,
    /// TPMS_ATTEST decoded display fields.
    pub attestation: AttestationFields,
    /// ECDSA signature r (hex).
    pub signature_r_hex: String,
    /// ECDSA signature s (hex).
    pub signature_s_hex: String,
    /// TPM monotonic clock at quote time (replay guard).
    pub tpm_clock: u64,
    pub tpm_reset_count: u32,
    pub tpm_restart_count: u32,
    /// True when the full local verification ladder passed before the
    /// bundle was accepted into this certificate (fail-closed upstream).
    pub locally_verified: bool,
}

/// `TPMS_ATTEST` fields for quick audit display.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationFields {
    pub magic_hex: String,
    pub attest_type_hex: String,
    pub qualified_signer_hex: String,
    pub firmware_version: u64,
    pub clock_safe: bool,
}

impl TpmAttestationEvidence {
    /// Defense warnings derived from the attestation.
    pub fn defense_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.locally_verified {
            warnings.push(
                "DEFENSE_WARNING: TPM quote embedded WITHOUT successful local verification — \
                 treat the hardware-attestation claim as void (NIST SP 800-88 Rev 1)."
                    .to_string(),
            );
        }
        if !self.attestation.clock_safe {
            warnings.push(
                "DEFENSE_WARNING: TPM clock reported unsafe (TPMS_CLOCK_INFO.safe == 0) — \
                 clock rollback protection cannot be assumed for this quote."
                    .into(),
            );
        }
        if self.attestation.magic_hex != "FF544347" {
            warnings.push(
                "DEFENSE_WARNING: TPMS_ATTEST magic is not TPM_GENERATED — the structure was \
                 not produced by a genuine TPM."
                    .into(),
            );
        }
        warnings
    }

    /// Certificate field lines (visual PDF front page).
    pub fn field_lines(&self) -> Vec<(String, String)> {
        vec![
            (
                "TPM attestation".into(),
                if self.locally_verified {
                    "TPM2_Quote verified (ECDSA-P256 AIK)".to_string()
                } else {
                    "UNVERIFIED — see defense warnings".to_string()
                },
            ),
            (
                "TPM PCR selection (SHA-256)".into(),
                format!("mask {}", self.pcr_mask_hex),
            ),
            (
                "TPM PCR digest".into(),
                format!(
                    "{}…",
                    &self.pcr_digest_hex[..16.min(self.pcr_digest_hex.len())]
                ),
            ),
            (
                "TPM nonce (freshness)".into(),
                format!("{}…", &self.nonce_hex[..12.min(self.nonce_hex.len())]),
            ),
            (
                "TPM firmware version".into(),
                format!("{:#x}", self.attestation.firmware_version),
            ),
            (
                "TPM clock/reset/restart".into(),
                format!(
                    "{}/{}/{}",
                    self.tpm_clock, self.tpm_reset_count, self.tpm_restart_count
                ),
            ),
            (
                "TPM AIK (P-256)".into(),
                format!("x={}…", &self.aik_x_hex[..12.min(self.aik_x_hex.len())]),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> TpmAttestationEvidence {
        TpmAttestationEvidence {
            nonce_hex: "aabbccddeeff".into(),
            pcr_mask_hex: "ff0f0000".into(),
            pcr_values_hex: vec!["00".repeat(32); 12],
            pcr_digest_hex: "ab".repeat(32),
            quote_response_hex: "00".repeat(64),
            aik_x_hex: "11".repeat(32),
            aik_y_hex: "22".repeat(32),
            aik_public_template_hex: "00".repeat(10),
            attestation: AttestationFields {
                magic_hex: "FF544347".into(),
                attest_type_hex: "8018".into(),
                qualified_signer_hex: "00".repeat(4),
                firmware_version: 0x0001_0002_0003_0004,
                clock_safe: true,
            },
            signature_r_hex: "33".repeat(32),
            signature_s_hex: "44".repeat(32),
            tpm_clock: 4711,
            tpm_reset_count: 3,
            tpm_restart_count: 1,
            locally_verified: true,
        }
    }

    #[test]
    fn verified_evidence_has_no_warnings() {
        let e = evidence();
        assert!(e.defense_warnings().is_empty());
        assert!(
            e.field_lines()
                .iter()
                .any(|(k, v)| k.contains("TPM attestation") && v.contains("verified"))
        );
    }

    #[test]
    fn unverified_or_foreign_attestations_warn() {
        let mut e = evidence();
        e.locally_verified = false;
        assert_eq!(e.defense_warnings().len(), 1);
        e.attestation.clock_safe = false;
        e.attestation.magic_hex = "DEADBEEF".into();
        assert_eq!(e.defense_warnings().len(), 3);
        let lines = e.field_lines();
        assert!(
            lines
                .iter()
                .any(|(k, v)| k.contains("TPM attestation") && v.contains("UNVERIFIED"))
        );
    }
}
