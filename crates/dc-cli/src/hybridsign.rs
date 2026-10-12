//! Hybrid certificate signing (v0.10.0, Frontier 3 integration).
//!
//! Every certificate-signing site in the CLI funnels through
//! [`sign_certificate`]: when the operator's classical key has an ML-DSA-44
//! sibling file (`<key>.pq`, written by `dc keygen` since v0.10.0), the
//! certificate is dual-signed over the same canonical bytes; otherwise it
//! falls back to classical-only signing, byte-compatible with v0.9.x
//! certificates.

use dc_cert::{MlDsaOperatorKey, OperatorKeyPair, SanitizationCertificate};
use dc_core::DcError;
use std::path::Path;

pub fn sign_certificate(
    cert: &mut SanitizationCertificate,
    keypair: &OperatorKeyPair,
    classical_key_path: Option<&Path>,
) -> Result<(), DcError> {
    if let Some(kp_path) = classical_key_path {
        match MlDsaOperatorKey::load_sibling(kp_path) {
            Ok(Some(pq)) => {
                cert.sign_hybrid(keypair, &pq)?;
                eprintln!(
                    "[+] Certificate hybrid-signed: Ed25519 + ML-DSA-44 (post-quantum audit protection)"
                );
                return Ok(());
            }
            // No sibling: classical-only, fully backward compatible.
            Ok(None) => {}
            Err(e) => return Err(e),
        }
    }
    cert.sign(keypair)
}
