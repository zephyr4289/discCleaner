use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use dc_core::DcError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub struct OperatorKeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

/// Operator key material is SECRET: group/other read access is a hard error.
const OPERATOR_KEY_FILE_MODE: u32 = 0o600;

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

    /// Persist the private key with owner-only permissions (0600).
    ///
    /// SECURITY (regression `REG-KEYFILE-PERMS`): key material written via
    /// plain `fs::write` inherits the process umask (often 0644 — world
    /// readable). This path creates the file with mode 0600 and explicitly
    /// re-applies it afterwards so no umask can loosen it.
    pub fn save_to_file(&self, path: &Path) -> Result<(), DcError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let hex_bytes = hex::encode(self.signing_key.to_bytes());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(OPERATOR_KEY_FILE_MODE)
            .open(path)?;
        file.write_all(hex_bytes.as_bytes())?;
        file.sync_all()?;
        // Re-assert permissions in case umask or a pre-existing file mode
        // loosened them.
        fs::set_permissions(path, fs::Permissions::from_mode(OPERATOR_KEY_FILE_MODE))?;
        Ok(())
    }

    /// Load a private key from disk, REFUSING world/group-readable files.
    ///
    /// SECURITY: a key file that other local principals can read is treated
    /// as compromised-on-arrival; the operator must fix the mode first.
    /// (ed25519-dalek's default `zeroize` feature wipes the secret on drop.)
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
