//! Post-quantum hybrid audit signatures (v0.10.0, Frontier 3).
//!
//! Sanitization certificates must withstand decades of legal scrutiny, and a
//! future quantum adversary could forge classical 256-bit signatures
//! retroactively. Certificates signed through this module carry a **hybrid
//! dual signature**: an Ed25519 signature (classical, for today's verifiers)
//! plus an **ML-DSA-44** signature (FIPS 204) over the *same canonical JCS
//! bytes* — so the two algorithms bind the identical evidence.
//!
//! Verification policy is *strict conjunction*: when a certificate carries a
//! post-quantum block, BOTH signatures must verify. A verifier that only
//! understands Ed25519 can still check the classical leg (the PQ block is an
//! optional, additive field), but `dc-cert` itself refuses to call a hybrid
//! certificate authentic unless both legs hold.
//!
//! # Key file discipline
//!
//! Mirrors `OperatorKeyPair` exactly: private keys are written with mode
//! 0600, and loading REFUSES group/world-readable files (a key other local
//! principals can read is compromised-on-arrival). The ML-DSA secret key is
//! 2560 bytes of lattice secret material and is zeroized on drop by dc-pq.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use dc_core::DcError;
use dc_pq::ml_dsa::{
    MlDsa44KeyPair, MlDsa44PublicKey, MlDsa44Signature, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The post-quantum signature block embedded in `SanitizationCertificate`.
///
/// Self-contained: the ML-DSA public key travels inside the certificate so
/// verification never needs an external key registry (mirrors how the
/// Ed25519 public key is carried in `operator`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostQuantumSignature {
    /// Always "ML-DSA-44" for this block.
    pub alg: String,
    /// ML-DSA-44 public key (1312 bytes, base64).
    pub public_key: String,
    /// ML-DSA-44 signature over the certificate's canonical JCS bytes
    /// (2420 bytes, base64).
    pub value: String,
}

impl PostQuantumSignature {
    pub fn algorithm(&self) -> &str {
        &self.alg
    }

    /// Decode and verify this block against the canonical bytes.
    pub fn verify(&self, canonical_bytes: &[u8]) -> Result<bool, DcError> {
        let pk_bytes = BASE64
            .decode(&self.public_key)
            .map_err(|e| DcError::CertSigning(format!("PQ public key base64: {e}")))?;
        let sig_bytes = BASE64
            .decode(&self.value)
            .map_err(|e| DcError::CertSigning(format!("PQ signature base64: {e}")))?;
        let pk = MlDsa44PublicKey::from_bytes(&pk_bytes).ok_or_else(|| {
            DcError::CertSigning(format!(
                "PQ public key must be exactly {PUBLIC_KEY_LEN} bytes, got {}",
                pk_bytes.len()
            ))
        })?;
        let sig = MlDsa44Signature::from_bytes(&sig_bytes).ok_or_else(|| {
            DcError::CertSigning(format!(
                "PQ signature must be exactly {SIGNATURE_LEN} bytes, got {}",
                sig_bytes.len()
            ))
        })?;
        Ok(pk.verify(canonical_bytes, &sig))
    }
}

/// File-backed ML-DSA-44 operator key with the same hygiene discipline as
/// `OperatorKeyPair` (0600 writes, refuse world-readable on load).
pub struct MlDsaOperatorKey {
    keypair: MlDsa44KeyPair,
}

impl MlDsaOperatorKey {
    /// Generate a fresh random ML-DSA-44 keypair.
    pub fn generate() -> Result<Self, DcError> {
        Ok(MlDsaOperatorKey {
            keypair: MlDsa44KeyPair::generate()?,
        })
    }

    /// The sibling-file convention: a classical key at
    /// `/etc/diskcleaner/operator.sk` keeps its PQ twin at
    /// `/etc/diskcleaner/operator.sk.pq`.
    pub fn sibling_path(classical_key: &Path) -> PathBuf {
        let mut s = classical_key.as_os_str().to_os_string();
        s.push(".pq");
        PathBuf::from(s)
    }

    /// Load the PQ twin of a classical key if one exists next to it.
    ///
    /// Returns `Ok(None)` when no sibling file is present (classical-only
    /// signing), and a hard error when the file exists but is unreadable,
    /// malformed, or group/world-readable.
    pub fn load_sibling(classical_key: &Path) -> Result<Option<Self>, DcError> {
        let pq_path = Self::sibling_path(classical_key);
        if !pq_path.exists() {
            return Ok(None);
        }
        Self::load_from_file(&pq_path).map(Some)
    }

    /// Persist the private key with owner-only permissions (0600),
    /// hex-encoded (5120 bytes of hex for the 2560-byte secret).
    pub fn save_to_file(&self, path: &Path) -> Result<(), DcError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let hex_bytes = hex::encode(self.keypair.secret_key_bytes());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(hex_bytes.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Load a private key from disk, REFUSING group/world-readable files
    /// (compromised-on-arrival, same policy as `OperatorKeyPair`).
    pub fn load_from_file(path: &Path) -> Result<Self, DcError> {
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(DcError::CertSigning(format!(
                "REFUSING_WORLD_READABLE_KEY: '{}' has mode {:o}; run \
                 `chmod 600` on it before use",
                path.display(),
                mode
            )));
        }
        let content = fs::read_to_string(path)?;
        let secret = hex::decode(content.trim())
            .map_err(|e| DcError::CertSigning(format!("Invalid PQ keyfile hex: {e}")))?;
        let keypair = MlDsa44KeyPair::from_secret_bytes(&secret)
            .ok_or_else(|| DcError::CertSigning("PQ keyfile must be 2560 bytes hex".to_string()))?;
        Ok(MlDsaOperatorKey { keypair })
    }

    /// Public key, base64 (embedded into certificates).
    pub fn public_key_b64(&self) -> String {
        BASE64.encode(self.keypair.public_key_bytes())
    }

    /// BLAKE3 fingerprint of the PQ public key (operational identification,
    /// consistent with the classical key fingerprint).
    pub fn key_fingerprint_blake3(&self) -> String {
        blake3::hash(&self.keypair.public_key_bytes())
            .to_hex()
            .to_string()
    }

    /// Sign canonical bytes, producing the certificate PQ block.
    pub fn sign_canonical_bytes(&self, canonical_bytes: &[u8]) -> PostQuantumSignature {
        let sig = self.keypair.sign(canonical_bytes);
        PostQuantumSignature {
            alg: "ML-DSA-44".to_string(),
            public_key: self.public_key_b64(),
            value: BASE64.encode(sig.as_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::SanitizationCertificate;
    use crate::signer::OperatorKeyPair;

    #[test]
    fn hybrid_sign_verify_and_tamper_matrix() {
        let classical = OperatorKeyPair::generate();
        let pq = MlDsaOperatorKey::generate().expect("pq keygen");

        let mut cert = minimal_cert(&classical);
        cert.sign_hybrid(&classical, &pq).expect("hybrid sign");

        // Both legs verify
        let status = cert.verify_signature_hybrid().expect("hybrid verify");
        assert!(status.classical_ed25519);
        assert_eq!(status.post_quantum_ml_dsa, Some(true));
        assert!(status.fully_authentic);

        // Tampering with the evidence breaks BOTH legs (same canonical bytes)
        cert.execution.duration_mono_ms += 1;
        let status = cert.verify_signature_hybrid().expect("verify 2");
        assert!(!status.classical_ed25519);
        assert_eq!(status.post_quantum_ml_dsa, Some(false));
        assert!(!status.fully_authentic);
    }

    #[test]
    fn classical_only_cert_still_verifies_in_hybrid_mode() {
        let classical = OperatorKeyPair::generate();
        let mut cert = minimal_cert(&classical);
        cert.sign(&classical).expect("classical sign");
        let status = cert.verify_signature_hybrid().expect("hybrid verify");
        assert!(status.classical_ed25519);
        assert_eq!(status.post_quantum_ml_dsa, None);
        assert!(status.fully_authentic, "no PQ leg must not demote the cert");
    }

    #[test]
    fn pq_key_file_roundtrip_with_perm_discipline() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("operator.sk.pq");

        let pq = MlDsaOperatorKey::generate().expect("pq keygen");
        pq.save_to_file(&path).expect("save");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "0600 discipline");

        let loaded = MlDsaOperatorKey::load_from_file(&path).expect("load");
        assert_eq!(
            loaded.public_key_b64(),
            pq.public_key_b64(),
            "public key must re-derive from the secret key"
        );

        // Loosen the mode -> load must refuse
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused = MlDsaOperatorKey::load_from_file(&path);
        assert!(refused.is_err(), "world-readable PQ key must be refused");
    }

    fn minimal_cert(kp: &OperatorKeyPair) -> SanitizationCertificate {
        use dc_core::{
            BusType, DeviceIdentity, FastPathPolicy, JournalChainSummary, KernelIdentity,
            SanitizationPlan, StableIdentity, VerifyLevel,
        };
        use dc_verify::VerificationReport;
        let stable = StableIdentity {
            model: None,
            serial: Some("SN-PQ".to_string()),
            wwn: None,
            size_bytes: 1024 * 1024,
            bus: BusType::File,
            dm_name: None,
            dm_uuid: None,
        };
        SanitizationCertificate::new(
            SanitizationPlan::clear_zero(stable.clone(), FastPathPolicy::ForbidWriteZeroes),
            "hash".to_string(),
            DeviceIdentity {
                stable,
                kernel: KernelIdentity { major: 7, minor: 0 },
                kernel_name: "loop0".to_string(),
                dev_path: "/loop0".to_string(),
                logical_block_size: 512,
                physical_block_size: 4096,
            },
            crate::cert::ExecutionDetails {
                started_utc: "t".to_string(),
                finished_utc: "t".to_string(),
                duration_mono_ms: 1,
                interruptions: vec![],
                failures: vec![],
                passes: vec![],
            },
            VerificationReport {
                level: VerifyLevel::Full,
                windows_checked: 1,
                mismatch_count: 0,
                first_mismatch_lbas: vec![],
                stream_hash_blake3: "h".to_string(),
                stream_hash_sha256: None,
                entropy: None,
            },
            JournalChainSummary {
                path: std::path::PathBuf::from("/tmp/u.dcj"),
                chain_head: "c".to_string(),
                record_count: 1,
                discarded_tail_bytes: 0,
                uuid: "u".to_string(),
                sealed: false,
            },
            kp.public_key_hex(),
            kp.key_fingerprint_blake3(),
        )
    }
}
