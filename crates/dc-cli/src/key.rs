//! `dc key` — TPM-sealed key custody verbs (v0.9.0, Phase 1b).
//!
//! `seal`   : read a plaintext operator keyfile, hand the bytes to the
//!            machine's TPM 2.0 for PCR-policy sealing, store the sealed
//!            blob (never the plaintext).
//! `unseal` : replay the policy against the LIVE registers; only an
//!            unchanged platform state releases the key.
//! `inspect`: audit a sealed blob's policy offline (no TPM contact).

use crate::{KeyArgs, KeySubcommands};
use dc_core::DcError;
use dc_core::secrets::SecretBuf;
use dc_tpm::{
    SealedKeyBlob, TPM_RM_DEVICE, TpmRmTransport, TpmTransport, pcr_list_to_mask, seal, unseal,
};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct KeyLifecycleVerbs;

impl KeyLifecycleVerbs {
    /// Register a newly generated key into the keyring registry (Δ450, Δ453).
    pub fn register_generated_key(
        registry: &mut dc_cert::KeyringRegistry,
        key_hash: &str,
        identity: &str,
        role: &str,
        timestamp_utc: u64,
    ) {
        registry.register_key(dc_cert::KeyringEntry {
            key_hash: key_hash.to_string(),
            identity: identity.to_string(),
            role: role.to_string(),
            active_from_utc: timestamp_utc,
            superseded_at_utc: None,
            revoked_at_utc: None,
        });
    }

    /// Rotate an existing key to a new key entry bilaterally (Δ450, Δ453).
    pub fn rotate_key(
        registry: &mut dc_cert::KeyringRegistry,
        old_key_hash: &str,
        new_key_entry: dc_cert::KeyringEntry,
        timestamp_utc: u64,
    ) -> Result<(), &'static str> {
        registry.rotate_key_bilateral(old_key_hash, new_key_entry, timestamp_utc)
    }

    /// Revoke a compromised or retired key (Δ452, Δ453).
    pub fn revoke_key(
        registry: &mut dc_cert::KeyringRegistry,
        key_hash: &str,
        timestamp_utc: u64,
    ) -> Result<(), &'static str> {
        registry.revoke_key(key_hash, timestamp_utc)
    }
}

pub fn cmd_key(args: KeyArgs) -> Result<(), DcError> {
    match args.sub {
        KeySubcommands::Seal { key, pcrs, out } => cmd_key_seal(key, pcrs, out),
        KeySubcommands::Unseal { blob, out } => cmd_key_unseal(blob, out),
        KeySubcommands::Inspect { blob } => cmd_key_inspect(blob),
    }
}

fn cmd_key_seal(key: PathBuf, pcrs: Option<String>, out: Option<PathBuf>) -> Result<(), DcError> {
    // Read the plaintext key under strict 0600 discipline — the file bytes
    // ride inside a SecretBuf (mlock + zeroize on drop).
    let plaintext = read_key_secret(&key)?;
    let out_path = out.unwrap_or_else(|| default_blob_path(&key));

    let mut tpm = TpmRmTransport::open()
        .map_err(|e| DcError::Usage(format!("TPM seal: {e} (expected {TPM_RM_DEVICE})")))?;
    let tpm_desc = tpm.describe();
    let mask = match pcrs.as_deref() {
        None | Some("0-11") => dc_tpm::DC_QUOTE_PCR_MASK,
        Some(spec) => pcr_list_to_mask(spec).map_err(|e| DcError::Usage(format!("--pcrs: {e}")))?,
    };

    println!(
        "[KEY] Sealing {} into the platform TPM ({}), policy bound to PCRs {}",
        key.display(),
        tpm_desc,
        dc_tpm::mask_to_pcr_list(mask)
    );
    let blob = seal(&mut tpm, plaintext.expose(), mask)
        .map_err(|e| DcError::CertSigning(format!("TPM seal failed: {e}")))?;

    let blob_json = serde_json::to_string_pretty(&blob)?;
    std::fs::write(&out_path, &blob_json)?;
    // The sealed blob is policy-bound ciphertext; 0600 keeps it away from
    // other local principals anyway (defense in depth).
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600))?;

    println!("[KEY] Sealed blob: {}", out_path.display());
    println!("     Policy digest: {}", blob.policy_hex);
    println!("     Bound PCRs (SHA-256 bank): {}", blob.pcr_list);
    println!(
        "[KEY] The key can only be recovered in this exact platform state — \
         any firmware/kernel/initramfs/binary change refuses the unseal."
    );
    Ok(())
}

fn cmd_key_unseal(blob: PathBuf, out: PathBuf) -> Result<(), DcError> {
    let blob_json = Zeroizing::new(std::fs::read_to_string(&blob)?);
    let blob: SealedKeyBlob = serde_json::from_str(&blob_json)
        .map_err(|e| DcError::Usage(format!("invalid sealed blob '{}': {e}", blob.display())))?;

    let mut tpm = TpmRmTransport::open()
        .map_err(|e| DcError::Usage(format!("TPM unseal: {e} (expected {TPM_RM_DEVICE})")))?;
    println!(
        "[KEY] Replaying PCR policy {} against the live registers...",
        blob.policy_hex
    );
    let secret: SecretBuf = unseal(&mut tpm, &blob)
        .map_err(|e| DcError::CertInvalid(format!("TPM unseal refused: {e}")))?;

    // Write the recovered key with 0600, wipe the hex transcription after.
    let hex_bytes = Zeroizing::new(hex::encode(secret.expose()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&out)?;
    file.write_all(hex_bytes.as_bytes())?;
    file.sync_all()?;
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600))?;

    println!("[KEY] Unsealed (platform state matched): {}", out.display());
    println!(
        "[KEY] WARNING: the plaintext key is on disk NOW — seal it back or \
         shred it after use (`dc key seal` / shred -u)."
    );
    Ok(())
}

fn cmd_key_inspect(blob: PathBuf) -> Result<(), DcError> {
    let blob_json = std::fs::read_to_string(&blob)?;
    let blob: SealedKeyBlob = serde_json::from_str(&blob_json)
        .map_err(|e| DcError::Usage(format!("invalid sealed blob '{}': {e}", blob.display())))?;
    println!("Sealed key blob: {}", blob_display(&blob));
    println!("  Schema:        {}", blob.schema);
    println!("  Policy digest: {}", blob.policy_hex);
    println!("  Bound PCRs:    {} (SHA-256 bank)", blob.pcr_list);
    println!(
        "  Public area:   {} bytes (hex {}...)",
        blob.public_hex.len() / 2,
        &blob.public_hex[..blob.public_hex.len().min(32)]
    );
    println!("  Sealed by:      {}", blob.sealed_by);
    println!("  Created (UTC):  {}", blob.created_utc);
    Ok(())
}

fn blob_display(blob: &SealedKeyBlob) -> String {
    format!(
        "schema={} pcrs={} policy={}",
        blob.schema,
        blob.pcr_list,
        &blob.policy_hex[..blob.policy_hex.len().min(16)]
    )
}

fn read_key_secret(path: &Path) -> Result<SecretBuf, DcError> {
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(DcError::CertSigning(format!(
            "REFUSING_WORLD_READABLE_KEY: '{}' has mode {:o}; run `chmod 600` first",
            path.display(),
            mode
        )));
    }
    let content = Zeroizing::new(std::fs::read_to_string(path)?);
    let bytes = hex::decode(content.trim()).map_err(|e| {
        DcError::CertSigning(format!("invalid keyfile hex '{}': {e}", path.display()))
    })?;
    Ok(SecretBuf::from_vec(bytes))
}

fn default_blob_path(key: &Path) -> PathBuf {
    let mut s = key.as_os_str().to_os_string();
    s.push(".sealed.json");
    PathBuf::from(s)
}
