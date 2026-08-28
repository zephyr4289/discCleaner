use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use dc_core::DcError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use std::fs;
use std::path::Path;

pub struct OperatorKeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl OperatorKeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), DcError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let hex_bytes = hex::encode(self.signing_key.to_bytes());
        fs::write(path, hex_bytes)?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self, DcError> {
        let content = fs::read_to_string(path)?;
        let bytes = hex::decode(content.trim())
            .map_err(|e| DcError::CertSigning(format!("Invalid keyfile hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(DcError::CertSigning("Keyfile must be 32 bytes hex".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&arr);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    pub fn key_fingerprint_blake3(&self) -> String {
        blake3::hash(&self.verifying_key.to_bytes()).to_hex().to_string()
    }

    pub fn sign_canonical_bytes(&self, bytes: &[u8]) -> String {
        let signature = self.signing_key.sign(bytes);
        BASE64.encode(signature.to_bytes())
    }
}

pub fn verify_canonical_signature(
    public_key_hex: &str,
    canonical_bytes: &[u8],
    signature_base64: &str,
) -> Result<bool, DcError> {
    let pubkey_bytes = hex::decode(public_key_hex)
        .map_err(|e| DcError::CertSigning(format!("Invalid public key hex: {}", e)))?;
    if pubkey_bytes.len() != 32 {
        return Err(DcError::CertSigning("Public key must be 32 bytes".to_string()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pubkey_bytes);
    let verifying_key = VerifyingKey::from_bytes(&arr)
        .map_err(|e| DcError::CertSigning(format!("Invalid public key bytes: {}", e)))?;

    let sig_bytes = BASE64
        .decode(signature_base64)
        .map_err(|e| DcError::CertSigning(format!("Invalid signature base64: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(DcError::CertSigning("Signature must be 64 bytes".to_string()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    Ok(verifying_key.verify(canonical_bytes, &signature).is_ok())
}
