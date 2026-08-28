use crate::signer::{verify_canonical_signature, OperatorKeyPair};
use dc_core::{
    DcError, DeviceIdentity, JournalChainSummary, SanitizationPlan, ToolBuild,
};
use dc_verify::VerificationReport;
use serde::{Deserialize, Serialize};

pub const VERIFICATION_SCHEME_DOC: &str = r#"scheme: chacha20-window-v1
window: W bytes (from plan.window_bytes, default 2097152)
key:    the 32-byte `seed` from the plan (BLAKE3-hash-committed at t0 via plan_hash)
nonce:  12 bytes, little-endian: nonce[0..8] = window_index as u64 LE,
        nonce[8..12] = 0x00000000
blocks: ChaCha20 keystream starting at counter 0, advanced 1 per 64-byte block,
        generated over the full window W (last window of the drive may be
        shorter: keystream is truncated to remaining length, never re-keyed)
data:   keystream XOR zero-buffer == keystream"#;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ExecutionPassReport {
    pub index: u8,
    pub pattern: String,
    pub fast_path_used: bool,
    pub windows_written: u64,
    pub throughput_mib_s: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InterruptionRecord {
    pub at_utc: String,
    pub resumed_utc: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FailureRecord {
    pub at_utc: String,
    pub code: String,
    pub errno: Option<i32>,
    pub op: Option<String>,
    pub at_lba: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ExecutionDetails {
    pub started_utc: String,
    pub finished_utc: String,
    pub duration_mono_ms: u64,
    pub interruptions: Vec<InterruptionRecord>,
    pub failures: Vec<FailureRecord>,
    pub passes: Vec<ExecutionPassReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OperatorDetails {
    pub key_fingerprint_blake3: String,
    pub public_key_ed25519: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignatureDetails {
    pub alg: String, // "Ed25519"
    pub value: String, // Base64
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UnsignedCertificate {
    pub schema: String,
    pub tool: ToolBuild,
    pub verification_scheme_doc: String,
    pub plan: SanitizationPlan,
    pub plan_hash: String,
    pub device: DeviceIdentity,
    pub execution: ExecutionDetails,
    pub verification: VerificationReport,
    pub journal: JournalChainSummary,
    pub operator: OperatorDetails,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SanitizationCertificate {
    pub schema: String,
    pub tool: ToolBuild,
    pub verification_scheme_doc: String,
    pub plan: SanitizationPlan,
    pub plan_hash: String,
    pub device: DeviceIdentity,
    pub execution: ExecutionDetails,
    pub verification: VerificationReport,
    pub journal: JournalChainSummary,
    pub operator: OperatorDetails,
    pub signature: Option<SignatureDetails>,
}

impl SanitizationCertificate {
    pub fn new(
        plan: SanitizationPlan,
        plan_hash: String,
        device: DeviceIdentity,
        execution: ExecutionDetails,
        verification: VerificationReport,
        journal: JournalChainSummary,
        operator_pubkey: String,
        operator_fingerprint: String,
    ) -> Self {
        Self {
            schema: "diskcleaner-cert/1".to_string(),
            tool: ToolBuild::current(),
            verification_scheme_doc: VERIFICATION_SCHEME_DOC.to_string(),
            plan,
            plan_hash,
            device,
            execution,
            verification,
            journal,
            operator: OperatorDetails {
                key_fingerprint_blake3: operator_fingerprint,
                public_key_ed25519: operator_pubkey,
            },
            signature: None,
        }
    }

    /// Extract unsigned payload for canonical JCS serialization.
    pub fn unsigned_payload(&self) -> UnsignedCertificate {
        UnsignedCertificate {
            schema: self.schema.clone(),
            tool: self.tool.clone(),
            verification_scheme_doc: self.verification_scheme_doc.clone(),
            plan: self.plan.clone(),
            plan_hash: self.plan_hash.clone(),
            device: self.device.clone(),
            execution: self.execution.clone(),
            verification: self.verification.clone(),
            journal: self.journal.clone(),
            operator: self.operator.clone(),
        }
    }

    /// Compute canonical JCS bytes of the unsigned certificate.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, DcError> {
        let unsigned = self.unsigned_payload();
        serde_jcs::to_vec(&unsigned).map_err(|e| DcError::Json(e))
    }

    /// Cryptographically sign this certificate with the operator's private key.
    pub fn sign(&mut self, keypair: &OperatorKeyPair) -> Result<(), DcError> {
        self.operator.public_key_ed25519 = keypair.public_key_hex();
        self.operator.key_fingerprint_blake3 = keypair.key_fingerprint_blake3();

        let canonical_bytes = self.canonical_unsigned_bytes()?;
        let sig_base64 = keypair.sign_canonical_bytes(&canonical_bytes);

        self.signature = Some(SignatureDetails {
            alg: "Ed25519".to_string(),
            value: sig_base64,
        });

        Ok(())
    }

    /// Cryptographically verify the digital signature against the public key and canonical bytes.
    pub fn verify_signature(&self) -> Result<bool, DcError> {
        let sig = match &self.signature {
            Some(s) => s,
            None => return Ok(false),
        };

        if sig.alg != "Ed25519" {
            return Err(DcError::CertSigning(format!(
                "Unsupported signature algorithm: {}",
                sig.alg
            )));
        }

        let canonical_bytes = self.canonical_unsigned_bytes()?;
        verify_canonical_signature(&self.operator.public_key_ed25519, &canonical_bytes, &sig.value)
    }

    /// Render human-readable audit text summary.
    pub fn render_summary(&self) -> String {
        format!(
            r#"================================================================================
                    CERTIFICATE OF DATA SANITIZATION
================================================================================
Schema:            {}
Tool:              {} v{} (Build: {})
Device Model:      {}
Device Serial:     {}
Device Bus / Size: {} / {} GiB ({:.2} GB)
Plan Hash:         {}
Mechanism:         Logical Overwrite ({} passes)
Verification:      {} (Mismatches: {})
Stream BLAKE3:     {}
Journal Chain:     {}
Prior Failures:    {}
Operator PubKey:   {}
Signature Valid:   {}
================================================================================"#,
            self.schema,
            self.tool.name,
            self.tool.version,
            self.tool.build_hash,
            self.device.stable.model.as_deref().unwrap_or("Unknown"),
            self.device.stable.serial.as_deref().unwrap_or("Unknown"),
            self.device.stable.bus,
            self.device.stable.size_bytes / (1024 * 1024 * 1024),
            self.device.stable.size_bytes as f64 / 1_000_000_000.0,
            self.plan_hash,
            self.execution.passes.len(),
            self.verification.level,
            self.verification.mismatch_count,
            self.verification.stream_hash_blake3,
            self.journal.chain_head,
            self.execution.failures.len(),
            self.operator.public_key_ed25519,
            if self.verify_signature().unwrap_or(false) {
                "VERIFIED (Ed25519)"
            } else {
                "INVALID OR UNSIGNED"
            }
        )
    }
}
