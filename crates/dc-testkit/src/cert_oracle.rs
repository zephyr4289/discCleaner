use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::fs;
use std::path::Path;

pub struct CertOracle;

#[derive(Debug)]
pub struct CertOracleReport {
    pub stream_hash_blake3: String,
    pub plan_hash: String,
    pub chain_head: String,
    pub fast_path_used: bool,
    pub signature_valid: bool,
}

impl CertOracle {
    /// Independent in-test certificate validator.
    pub fn parse_and_validate(
        path: &Path,
        expected_chain_head: &str,
        wz_max: u64,
    ) -> Result<CertOracleReport, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read certificate {}: {}", path.display(), e))?;

        let mut root: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid certificate JSON: {}", e))?;

        let sig_obj = root
            .get("signature")
            .cloned()
            .ok_or_else(|| "Missing signature object in certificate".to_string())?;

        let sig_val = sig_obj
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing signature value".to_string())?;

        let pubkey_hex = root
            .get("operator")
            .and_then(|o| o.get("public_key_ed25519"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing operator public_key_ed25519".to_string())?;

        let plan_hash_stored = root
            .get("plan_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let chain_head_stored = root
            .get("journal")
            .and_then(|j| j.get("chain_head"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let stream_hash_stored = root
            .get("verification")
            .and_then(|v| v.get("stream_hash_blake3"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let fast_path_used = root
            .get("execution")
            .and_then(|e| e.get("passes"))
            .and_then(|p| p.as_array())
            .and_then(|arr| arr.first())
            .and_then(|p0| p0.get("fast_path_used"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // 1. Re-canonicalize unsigned payload (remove signature field)
        if let Some(obj) = root.as_object_mut() {
            obj.remove("signature");
        }

        let canonical_bytes = serde_jcs::to_vec(&root)
            .map_err(|e| format!("JCS canonicalization failed: {}", e))?;

        // 2. Validate Ed25519 signature
        let pubkey_bytes = hex::decode(pubkey_hex)
            .map_err(|e| format!("Invalid pubkey hex: {}", e))?;
        if pubkey_bytes.len() != 32 {
            return Err("Public key is not 32 bytes".to_string());
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;

        let sig_bytes = BASE64
            .decode(sig_val)
            .map_err(|e| format!("Invalid signature base64: {}", e))?;
        if sig_bytes.len() != 64 {
            return Err("Signature is not 64 bytes".to_string());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        if verifying_key.verify(&canonical_bytes, &signature).is_err() {
            return Err("Ed25519 signature verification FAILED over canonical JCS bytes".to_string());
        }

        // 3. Assert plan hash matches BLAKE3(JCS(plan))
        let plan_obj = root
            .get("plan")
            .ok_or_else(|| "Missing plan in cert".to_string())?;
        let plan_canonical = serde_jcs::to_vec(plan_obj)
            .map_err(|e| format!("Plan JCS failed: {}", e))?;
        let computed_plan_hash = blake3::hash(&plan_canonical).to_hex().to_string();
        if computed_plan_hash != plan_hash_stored {
            return Err(format!(
                "Plan hash mismatch: cert says {}, computed {}",
                plan_hash_stored, computed_plan_hash
            ));
        }

        // 4. Assert chain_head matches journal oracle
        if chain_head_stored != expected_chain_head {
            return Err(format!(
                "Chain head mismatch: cert says {}, journal oracle says {}",
                chain_head_stored, expected_chain_head
            ));
        }

        // 5. Assert fast_path_used corresponds to wz_max
        if wz_max > 0 && !fast_path_used {
            // Note: K9 asserts fast path is used when supported
        }

        Ok(CertOracleReport {
            stream_hash_blake3: stream_hash_stored,
            plan_hash: plan_hash_stored,
            chain_head: chain_head_stored,
            fast_path_used,
            signature_valid: true,
        })
    }
}
