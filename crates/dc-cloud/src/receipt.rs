//! The cloud sanitization receipt — the signed audit artifact binding the
//! cloud context to the engine's evidence.
//!
//! Design: the engine's `SanitizationCertificate` is immutable once
//! written (it is itself signed over its canonical bytes). The receipt
//! WRAPS it: it references the certificate by file hash (BLAKE3), carries
//! the cloud context (provider/account/volume/KMS/region/AZ), the full
//! phase timeline, and carries its own signatures — classical Ed25519 and,
//! when the operator has an ML-DSA keypair, a post-quantum hybrid
//! co-signature over the same canonical bytes (v0.10.0 Frontier 3
//! applied to cloud evidence).

use crate::CloudContext;
use crate::lifecycle::LifecycleResult;
use dc_cert::{MlDsaOperatorKey, OperatorKeyPair};
use dc_core::DcError;
use serde::{Deserialize, Serialize};

pub const RECEIPT_SCHEMA: &str = "dc.cloud-receipt/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSanitizationReceipt {
    pub schema: String,
    pub cloud: CloudContext,
    pub volume: crate::CloudVolume,
    pub lifecycle: Vec<crate::lifecycle::PhaseRecord>,
    /// The engine certificate this receipt attests, bound by file hash.
    pub certificate: CertificateBinding,
    pub operator: OperatorBinding,
    pub signature: SignatureBlock,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<dc_cert::PostQuantumSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateBinding {
    /// Path on the sanitizer instance at signing time (operational hint —
    /// the cryptographic binding is the hash + signature).
    pub path: Option<String>,
    pub file_blake3: String,
    pub device_serial: Option<String>,
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorBinding {
    pub public_key_ed25519: String,
    pub key_fingerprint_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    pub alg: String,   // "Ed25519"
    pub value: String, // Base64
}

impl CloudSanitizationReceipt {
    /// Canonical (JCS) bytes of the unsigned receipt — what both
    /// signature legs sign.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, DcError> {
        let unsigned = UnsignedReceipt {
            schema: self.schema.clone(),
            cloud: self.cloud.clone(),
            volume: self.volume.clone(),
            lifecycle: self.lifecycle.clone(),
            certificate: self.certificate.clone(),
            operator: self.operator.clone(),
        };
        serde_jcs::to_vec(&unsigned).map_err(DcError::Json)
    }

    /// Sign with Ed25519, plus ML-DSA-44 when a PQ key is supplied
    /// (hybrid dual-signing over the same canonical bytes).
    pub fn sign(
        &mut self,
        classical: &OperatorKeyPair,
        pq: Option<&MlDsaOperatorKey>,
    ) -> Result<(), DcError> {
        let canonical = self.canonical_unsigned_bytes()?;
        self.signature = SignatureBlock {
            alg: "Ed25519".to_string(),
            value: classical.sign_canonical_bytes(&canonical),
        };
        if let Some(pq) = pq {
            self.post_quantum = Some(pq.sign_canonical_bytes(&canonical));
        }
        Ok(())
    }

    /// Verify the classical leg; when a post-quantum leg exists it must
    /// verify as well (strict conjunction).
    pub fn verify(&self) -> Result<bool, DcError> {
        let canonical = self.canonical_unsigned_bytes()?;
        let classical_ok = dc_cert::verify_canonical_signature(
            &self.operator.public_key_ed25519,
            &canonical,
            &self.signature.value,
        )?;
        if !classical_ok {
            return Ok(false);
        }
        if let Some(pq) = &self.post_quantum {
            return pq.verify(&canonical);
        }
        Ok(true)
    }

    /// Build the receipt from a finished lifecycle + the certificate bytes
    /// the engine produced.
    pub fn build(
        result: &LifecycleResult,
        cloud: CloudContext,
        cert_path: Option<&std::path::Path>,
        cert_json: Option<&serde_json::Value>,
        classical: &OperatorKeyPair,
    ) -> Result<Self, DcError> {
        let cert_bytes = match (cert_path, cert_json) {
            (Some(p), _) => std::fs::read(p)?,
            (_, Some(v)) => serde_jcs::to_vec(v).map_err(DcError::Json)?,
            _ => Vec::new(),
        };
        let file_blake3 = if cert_bytes.is_empty() {
            "unsigned-dry-run".to_string()
        } else {
            blake3::hash(&cert_bytes).to_hex().to_string()
        };

        // Pull binding hints out of the certificate JSON when available.
        let (device_serial, profile) = match cert_json {
            Some(v) => (
                v.pointer("/device/stable/serial")
                    .and_then(|s| s.as_str())
                    .map(String::from),
                v.pointer("/plan/profile")
                    .and_then(|s| s.as_str())
                    .map(String::from),
            ),
            None => (None, None),
        };

        Ok(CloudSanitizationReceipt {
            schema: RECEIPT_SCHEMA.to_string(),
            cloud,
            volume: result.volume.clone(),
            lifecycle: result.phases.clone(),
            certificate: CertificateBinding {
                path: cert_path.map(|p| p.display().to_string()),
                file_blake3,
                device_serial,
                profile,
            },
            operator: OperatorBinding {
                public_key_ed25519: classical.public_key_hex(),
                key_fingerprint_blake3: classical.key_fingerprint_blake3(),
            },
            signature: SignatureBlock {
                alg: "Ed25519".to_string(),
                value: String::new(),
            },
            post_quantum: None,
        })
    }
}

/// The unsigned core (what the signatures cover).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedReceipt {
    schema: String,
    cloud: CloudContext,
    volume: crate::CloudVolume,
    lifecycle: Vec<crate::lifecycle::PhaseRecord>,
    certificate: CertificateBinding,
    operator: OperatorBinding,
}
