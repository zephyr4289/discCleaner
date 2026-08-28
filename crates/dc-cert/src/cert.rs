use crate::signer::{verify_canonical_signature, OperatorKeyPair};
use dc_core::{
    DcError, DeviceIdentity, JournalChainSummary, SanitizationPlan, ToolBuild,
};
use dc_verify::VerificationReport;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

pub const VERIFICATION_SCHEME_DOC: &str = r#"scheme: chacha20-window-v1
cipher: ChaCha20 as specified in RFC 8439 §2.4 — 256-bit key, 96-bit
        nonce occupying state words 13–15, 32-bit block counter
        occupying state word 12, state serialized little-endian
        per RFC 8439 §2.3.
window: W bytes (from plan.window_bytes, default 2097152)
key:    the 32-byte `seed` from the plan, used verbatim — no hashing,
        derivation, or transformation of any kind — committed at t0
        via plan_hash.
nonce:  12 bytes: nonce[0..8] = window_index as u64 little-endian,
        nonce[8..12] = 0x00000000
blocks: keystream generated starting at block counter 0, advanced by
        1 per 64-byte block, across the full window W. The final
        window of the device may be shorter than W: its keystream is
        the corresponding prefix of the full window's keystream,
        truncated at the required length. The cipher is never re-keyed
        and the counter is never reset within a window.
data:   keystream XOR zero-buffer == keystream (the bytes written to
        media are the keystream itself)"#;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionPassReport {
    pub index: u8,
    pub pattern: String,
    pub fast_path_used: bool,
    pub windows_written: u64,
    pub throughput_kib_s: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterruptionRecord {
    pub at_utc: String,
    pub resumed_utc: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailureRecord {
    pub at_utc: String,
    pub code: String,
    pub errno: Option<i32>,
    pub op: Option<String>,
    pub at_lba: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionDetails {
    pub started_utc: String,
    pub finished_utc: String,
    pub duration_mono_ms: u64,
    pub interruptions: Vec<InterruptionRecord>,
    pub failures: Vec<FailureRecord>,
    pub passes: Vec<ExecutionPassReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorDetails {
    pub key_fingerprint_blake3: String,
    pub public_key_ed25519: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug)]
pub struct CertVerificationResult {
    pub is_valid: bool,
    pub is_authenticated: bool,
    pub mode: String, // "authenticated" or "integrity-only"
    pub file_blake3: String,
    pub error_detail: Option<String>,
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
        serde_jcs::to_vec(&unsigned).map_err(DcError::Json)
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

    /// Strict parser and anchor verification driver (§5 / Δ63 / Δ65).
    pub fn verify_raw_cert_file(
        raw_bytes: &[u8],
        trusted_fingerprint: Option<&str>,
        trusted_keys_list: Option<&[String]>,
    ) -> CertVerificationResult {
        let file_blake3 = blake3::hash(raw_bytes).to_hex().to_string();

        // 1. Strict parser checks (Δ65)
        if let Err(e) = Self::strict_json_scan(raw_bytes) {
            return CertVerificationResult {
                is_valid: false,
                is_authenticated: false,
                mode: "invalid".to_string(),
                file_blake3,
                error_detail: Some(format!("PARSE_STRICT_ERROR: {}", e)),
            };
        }

        // 2. Deserialize certificate
        let cert: SanitizationCertificate = match serde_json::from_slice(raw_bytes) {
            Ok(c) => c,
            Err(e) => {
                return CertVerificationResult {
                    is_valid: false,
                    is_authenticated: false,
                    mode: "invalid".to_string(),
                    file_blake3,
                    error_detail: Some(format!("DESERIALIZE_ERROR: {}", e)),
                };
            }
        };

        // 3. Forward Schema compatibility check (Δ66)
        if cert.schema != "diskcleaner-cert/1" {
            return CertVerificationResult {
                is_valid: false,
                is_authenticated: false,
                mode: "invalid".to_string(),
                file_blake3,
                error_detail: Some(format!("SCHEMA_VERSION_REFUSAL: Unsupported schema {}", cert.schema)),
            };
        }

        // 4. Verify Digital Signature
        match cert.verify_signature() {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                return CertVerificationResult {
                    is_valid: false,
                    is_authenticated: false,
                    mode: "invalid".to_string(),
                    file_blake3,
                    error_detail: Some("INVALID_SIGNATURE".to_string()),
                };
            }
        }

        // 5. Coherence check: embedded fingerprint == BLAKE3(pubkey) (Δ63 / K119)
        let pubkey_bytes = match hex::decode(&cert.operator.public_key_ed25519) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                return CertVerificationResult {
                    is_valid: false,
                    is_authenticated: false,
                    mode: "invalid".to_string(),
                    file_blake3,
                    error_detail: Some("INVALID_PUBKEY_HEX".to_string()),
                };
            }
        };

        let calculated_fp = blake3::hash(&pubkey_bytes).to_hex().to_string();
        if calculated_fp != cert.operator.key_fingerprint_blake3 {
            return CertVerificationResult {
                is_valid: false,
                is_authenticated: false,
                mode: "invalid".to_string(),
                file_blake3,
                error_detail: Some(format!(
                    "COHERENCE_MISMATCH: Stored fingerprint '{}' != computed '{}'",
                    cert.operator.key_fingerprint_blake3, calculated_fp
                )),
            };
        }

        // 6. Authenticity & Anchor evaluation (Δ63)
        let mut is_authenticated = false;
        if let Some(fp) = trusted_fingerprint {
            if fp == cert.operator.key_fingerprint_blake3 {
                is_authenticated = true;
            } else {
                return CertVerificationResult {
                    is_valid: false,
                    is_authenticated: false,
                    mode: "invalid".to_string(),
                    file_blake3,
                    error_detail: Some(format!(
                        "KEY_MISMATCH: Fingerprint '{}' does not match trusted anchor '{}'",
                        cert.operator.key_fingerprint_blake3, fp
                    )),
                };
            }
        } else if let Some(keys) = trusted_keys_list {
            if keys.iter().any(|k| k.trim() == cert.operator.public_key_ed25519) {
                is_authenticated = true;
            } else {
                return CertVerificationResult {
                    is_valid: false,
                    is_authenticated: false,
                    mode: "invalid".to_string(),
                    file_blake3,
                    error_detail: Some("KEY_MISMATCH: Public key not in trusted keys list".to_string()),
                };
            }
        }

        let mode = if is_authenticated {
            "authenticated".to_string()
        } else {
            "integrity-only".to_string()
        };

        CertVerificationResult {
            is_valid: true,
            is_authenticated,
            mode,
            file_blake3,
            error_detail: None,
        }
    }

    /// Strict parser scanner for duplicate keys, BOM, and depth bounds (Δ65).
    fn strict_json_scan(bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Err("Empty document".to_string());
        }

        // Reject UTF-8 BOM (EF BB BF)
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Err("BOM detected in JSON input (rejected by strict policy)".to_string());
        }

        let s = std::str::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8: {}", e))?;

        // Simple strict tokenizer to catch duplicate keys at any object depth
        let mut seen_keys_stack: Vec<HashSet<String>> = Vec::new();
        let mut chars = s.chars().peekable();
        let mut depth = 0;

        while let Some(&c) = chars.peek() {
            match c {
                '{' => {
                    depth += 1;
                    if depth > 32 {
                        return Err("JSON nesting depth exceeded limit of 32".to_string());
                    }
                    seen_keys_stack.push(HashSet::new());
                    chars.next();
                }
                '}' => {
                    depth = depth.saturating_sub(1);
                    seen_keys_stack.pop();
                    chars.next();
                }
                '"' => {
                    chars.next(); // consume opening quote
                    let mut key_str = String::new();
                    let mut escaped = false;
                    while let Some(ch) = chars.next() {
                        if escaped {
                            key_str.push(ch);
                            escaped = false;
                        } else if ch == '\\' {
                            escaped = true;
                        } else if ch == '"' {
                            break;
                        } else {
                            key_str.push(ch);
                        }
                    }

                    // Check if followed by ':' (meaning it's an object key)
                    while let Some(&next_c) = chars.peek() {
                        if next_c.is_whitespace() {
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    if chars.peek() == Some(&':') {
                        if let Some(current_scope) = seen_keys_stack.last_mut() {
                            if !current_scope.insert(key_str.clone()) {
                                return Err(format!("DUPLICATE_KEY: Duplicate key '{}' detected", key_str));
                            }
                        }
                    }
                }
                _ => {
                    chars.next();
                }
            }
        }

        Ok(())
    }

    /// Render human-readable audit text summary.
    pub fn render_summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push("================================================================================".to_string());
        lines.push("                    CERTIFICATE OF DATA SANITIZATION".to_string());
        lines.push("================================================================================".to_string());
        lines.push(format!("Schema:            {}", self.schema));
        lines.push(format!("Tool:              {} v{} (Build: {})", self.tool.name, self.tool.version, self.tool.build_hash));
        lines.push(format!("Device Model:      {}", self.device.stable.model.as_deref().unwrap_or("Unknown")));
        lines.push(format!("Device Serial:     {}", self.device.stable.serial.as_deref().unwrap_or("Unknown")));
        lines.push(format!("Device Bus / Size: {} / {} GiB ({:.2} GB)", self.device.stable.bus, self.device.stable.size_bytes / (1024 * 1024 * 1024), self.device.stable.size_bytes as f64 / 1_000_000_000.0));
        lines.push(format!("Plan Hash:         {}", self.plan_hash));
        lines.push(format!("Mechanism:         Logical Overwrite ({} passes)", self.execution.passes.len()));

        if self.verification.mismatch_count > 0 {
            lines.push(format!("VERIFICATION:      FAILED ({} mismatches)", self.verification.mismatch_count));
        } else {
            lines.push(format!("Verification:      {} (Mismatches: 0)", self.verification.level));
        }

        lines.push(format!("Stream BLAKE3:     {}", self.verification.stream_hash_blake3));
        lines.push(format!("Journal Chain:     {}", self.journal.chain_head));

        if !self.execution.failures.is_empty() {
            lines.push(format!("Prior Failures:    {} recorded", self.execution.failures.len()));
            for f in &self.execution.failures {
                lines.push(format!("  - {} at {}: {}", f.code, f.at_utc, f.op.as_deref().unwrap_or("")));
            }
        }

        if !self.execution.interruptions.is_empty() {
            lines.push(format!("Interruptions:     {} recorded", self.execution.interruptions.len()));
        }

        if let Some(note) = &self.plan.legacy_note {
            lines.push(format!("\n[!] LEGAL NOTICE:  {}", note));
        }

        lines.push(format!("Operator PubKey:   {}", self.operator.public_key_ed25519));
        lines.push(format!("Key Fingerprint:   {}", self.operator.key_fingerprint_blake3));
        lines.push(format!("Signature Valid:   {}", if self.verify_signature().unwrap_or(false) { "VERIFIED (Ed25519)" } else { "INVALID OR UNSIGNED" }));
        lines.push("================================================================================".to_string());

        lines.join("\n")
    }
}
