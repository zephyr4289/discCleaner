//! TPM NV-sealed key storage (v0.9.0, Phase 1b).
//!
//! Seals an operator's private key (or any secret <= 128 bytes) inside the
//! motherboard's TPM 2.0, encrypted to a **PCR policy**: `TPM2_Create`
//! under the owner primary hierarchy with an `authPolicy` digest harvested
//! from a TRIAL policy session over the selected platform configuration
//! registers. Unsealing replays the policy against the LIVE registers —
//! `TPM2_Unseal` only releases the plaintext when the machine is in the
//! exact boot state (firmware, kernel, initramfs, dc binary) that sealed it.
//!
//! If the boot integrity or firmware changes — a replaced kernel, a patched
//! BIOS, an evil-maid USB implant — the digest no longer matches and the
//! key stays sealed. No owner password can bypass it: the sealed object is
//! created with `FIXED_TPM | FIXED_PARENT` and **no** `USER_WITH_AUTH`, so
//! the PCR policy is the only door.
//!
//! Memory hygiene: the command buffer carrying the plaintext secret and
//! the response buffer carrying the unsealed plaintext are zeroized
//! immediately after their single use (`REG-SEALRAM-LINGER`).

use crate::constants::*;
use crate::device::{transact_owned, TpmError, TpmTransport};
use crate::structures::{
    encode_create_sealed, encode_flush_context, encode_load, encode_policy_get_digest,
    encode_policy_pcr, encode_start_auth_session, encode_unseal, parse_create_sealed,
    parse_load, parse_pcr_read, parse_policy_digest, parse_start_auth_session, parse_unseal,
    PcrSelectionList,
};
use dc_core::secrets::SecretBuf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// The on-disk artifact: a TPM-sealed private key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedKeyBlob {
    /// Schema discriminator (forward compat for future NV-index layouts).
    pub schema: String,
    /// TPM2B_PRIVATE — parent-wrapped ciphertext (hex).
    pub private_hex: String,
    /// TPM2B_PUBLIC — public template carrying the authPolicy (hex).
    pub public_hex: String,
    /// The authPolicy digest the blob is bound to (hex) — for auditing.
    pub policy_hex: String,
    /// PCR mask (SHA-256 bank) the policy binds to, `pcr_select` layout.
    pub pcr_mask_hex: String,
    /// Human-readable PCR list (e.g. "0,1,2,...,11") for evidence.
    pub pcr_list: String,
    /// Transport that performed the sealing (evidence provenance).
    pub sealed_by: String,
    /// Unix seconds at seal time.
    pub created_utc: u64,
}

impl SealedKeyBlob {
    pub const SCHEMA: &'static str = "dc.tpm-sealed/v1";
}

/// Seal `secret` to the current PCR state of `mask` (SHA-256 bank).
///
/// Ladder: read live PCRs → TRIAL session → PolicyPCR(digest of live
/// values) → PolicyGetDigest → `TPM2_Create` under the owner hierarchy →
/// flush the trial session. Returns the portable sealed blob (the private
/// half never leaves TPM-encrypted form; the plaintext is wiped from the
/// command buffer on return).
pub fn seal<T: TpmTransport>(
    tpm: &mut T,
    secret: &[u8],
    mask: [u8; 4],
) -> Result<SealedKeyBlob, TpmError> {
    if secret.is_empty() || secret.len() > DC_SEALED_SECRET_MAX {
        return Err(TpmError::Policy(format!(
            "sealed secret must be 1..={DC_SEALED_SECRET_MAX} bytes (got {})",
            secret.len()
        )));
    }
    let selection = PcrSelectionList::single_sha256(mask);

    // 1. Live PCR digest for the policy assertion.
    let pcr_digest = current_pcr_digest(tpm, &selection)?;

    // 2. TRIAL session → PolicyPCR → PolicyGetDigest.
    let session = start_session(tpm, TPM_SE_TRIAL)?;
    let policy_digest = run_policy_pcr(tpm, session, &selection, &pcr_digest)?;
    let _ = transact_owned(
        tpm,
        &encode_policy_get_digest(session),
    )?;
    let policy_hex = hex::encode(&policy_digest);

    // 3. Create the sealed object (plaintext rides ONLY in this command
    //    buffer, which is zeroized the moment the TPM answers).
    let mut create_cmd =
        encode_create_sealed(TPM_RH_OWNER, &policy_digest, secret);
    let create_rsp = transact_owned(tpm, &create_cmd);
    create_cmd.zeroize();
    let params = create_rsp?;
    let created = crate::device::wire_result(parse_create_sealed(&params))
        .map_err(|e| TpmError::Wire(format!("TPM2_Create: {e}")))?;

    // 4. Trial session is spent.
    let _ = transact_owned(tpm, &encode_flush_context(session));

    let pcr_list = mask_to_pcr_list(mask);
    Ok(SealedKeyBlob {
        schema: SealedKeyBlob::SCHEMA.to_string(),
        private_hex: hex::encode(&created.private),
        public_hex: hex::encode(&created.public),
        policy_hex,
        pcr_mask_hex: hex::encode(mask),
        pcr_list,
        sealed_by: tpm.describe(),
        created_utc: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

/// Unseal a blob under the CURRENT platform state.
///
/// Ladder: Load (owner hierarchy) → POLICY session → PolicyPCR(digest of
/// live values — fails with `TPM_RC_POLICY_FAIL` on drift) → `TPM2_Unseal`
/// → flush everything. The recovered plaintext is returned inside an
/// `mlock`-pinned, zeroized-on-drop [`SecretBuf`]; every intermediate
/// response buffer is wiped after parsing.
pub fn unseal<T: TpmTransport>(
    tpm: &mut T,
    blob: &SealedKeyBlob,
) -> Result<SecretBuf, TpmError> {
    if blob.schema != SealedKeyBlob::SCHEMA {
        return Err(TpmError::Policy(format!(
            "unknown sealed-blob schema '{}'",
            blob.schema
        )));
    }
    let private = hex::decode(&blob.private_hex)
        .map_err(|e| TpmError::Wire(format!("private blob hex: {e}")))?;
    let public = hex::decode(&blob.public_hex)
        .map_err(|e| TpmError::Wire(format!("public blob hex: {e}")))?;
    let mask = decode_mask(&blob.pcr_mask_hex)?;
    let selection = PcrSelectionList::single_sha256(mask);

    // 1. Load under the owner hierarchy.
    let loaded = crate::device::wire_result(parse_load(&transact_owned(
        tpm,
        &encode_load(TPM_RH_OWNER, &private, &public),
    )?))
    .map_err(|e| TpmError::Wire(format!("TPM2_Load: {e}")))?;

    // 2. POLICY session over the live registers.
    let pcr_digest = current_pcr_digest(tpm, &selection)?;
    let session = start_session(tpm, TPM_SE_POLICY)?;
    let unseal_result = (|| {
        run_policy_pcr(tpm, session, &selection, &pcr_digest)?;
        let mut response = tpm.transact(&encode_unseal(session, loaded.handle))?;
        let params = crate::device::classify_response(&response)?.to_vec();
        response.zeroize();
        let mut plaintext = crate::device::wire_result(parse_unseal(&params))
            .map_err(|e| TpmError::Wire(format!("TPM2_Unseal: {e}")))?;
        let secret = SecretBuf::from_vec(std::mem::take(&mut plaintext));
        plaintext.zeroize();
        Ok(secret)
    })();

    // 3. No trace survives regardless of outcome.
    let _ = transact_owned(tpm, &encode_flush_context(session));
    let _ = transact_owned(tpm, &encode_flush_context(loaded.handle));
    unseal_result
}

// --- helpers ----------------------------------------------------------------

fn start_session<T: TpmTransport>(tpm: &mut T, kind: u16) -> Result<u32, TpmError> {
    // Freshness nonce from the TPM itself (one GetRandom read).
    let entropy = transact_owned(tpm, &crate::structures::encode_get_random(16))?;
    let mut er = crate::wire::Reader::new(&entropy);
    let nonce = er.tpm2b().map_err(crate::device::TpmError::wire)?;
    let params = transact_owned(
        tpm,
        &encode_start_auth_session(kind, if nonce.is_empty() { b"dc" } else { &nonce }),
    )?;
    let started = crate::device::wire_result(parse_start_auth_session(&params))
        .map_err(|e| TpmError::Wire(format!("StartAuthSession: {e}")))?;
    Ok(started.session_handle)
}

fn run_policy_pcr<T: TpmTransport>(
    tpm: &mut T,
    session: u32,
    selection: &PcrSelectionList,
    pcr_digest: &[u8],
) -> Result<Vec<u8>, TpmError> {
    let _ = transact_owned(
        tpm,
        &encode_policy_pcr(session, selection, pcr_digest),
    )?;
    let params = transact_owned(tpm, &encode_policy_get_digest(session))?;
    crate::device::wire_result(parse_policy_digest(&params))
        .map_err(|e| TpmError::Wire(format!("PolicyGetDigest: {e}")))
}

/// SHA-256 over the concatenated selected PCR values (policy input).
fn current_pcr_digest<T: TpmTransport>(
    tpm: &mut T,
    selection: &PcrSelectionList,
) -> Result<Vec<u8>, TpmError> {
    let params = transact_owned(
        tpm,
        &crate::structures::encode_pcr_read(selection),
    )?;
    let read = crate::device::wire_result(parse_pcr_read(&params))
        .map_err(|e| TpmError::Wire(format!("PCR_Read: {e}")))?;
    if read.digests.is_empty() {
        return Err(TpmError::Policy(
            "selected PCRs returned no digests — bank mismatch?".into(),
        ));
    }
    let mut h = Sha256::new();
    for d in &read.digests {
        h.update(d);
    }
    Ok(h.finalize().to_vec())
}

/// "0,1,...,11" rendering of a PCR mask for evidence records.
pub fn mask_to_pcr_list(mask: [u8; 4]) -> String {
    let mut pcrs = Vec::new();
    for pcr in 0..32usize {
        if (mask[pcr / 8] >> (pcr % 8)) & 1 == 1 {
            pcrs.push(pcr.to_string());
        }
    }
    pcrs.join(",")
}

/// Parse a PCR list ("0-7,9,11" or "0,1,2") into a mask — CLI input path.
pub fn pcr_list_to_mask(spec: &str) -> Result<[u8; 4], TpmError> {
    let mut mask = [0u8; 4];
    let mut any = false;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (lo, hi) = if let Some((a, b)) = part.split_once('-') {
            (
                a.trim().parse::<u8>().map_err(|_| bad_pcr_spec(spec))?,
                b.trim().parse::<u8>().map_err(|_| bad_pcr_spec(spec))?,
            )
        } else {
            let n = part.parse::<u8>().map_err(|_| bad_pcr_spec(spec))?;
            (n, n)
        };
        if hi < lo || hi > 23 {
            return Err(bad_pcr_spec(spec));
        }
        for pcr in lo..=hi {
            mask[pcr as usize / 8] |= 1 << (pcr % 8);
            any = true;
        }
    }
    if !any {
        return Err(bad_pcr_spec(spec));
    }
    Ok(mask)
}

fn bad_pcr_spec(spec: &str) -> TpmError {
    TpmError::Policy(format!(
        "invalid PCR spec '{spec}' (expected e.g. '0-11', '0,1,9', ranges within 0-23)"
    ))
}

fn decode_mask(hex_str: &str) -> Result<[u8; 4], TpmError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| TpmError::Wire(format!("pcr mask hex: {e}")))?;
    if bytes.len() != 4 {
        return Err(TpmError::Wire("pcr mask must be 4 bytes".into()));
    }
    let mut mask = [0u8; 4];
    mask.copy_from_slice(&bytes);
    Ok(mask)
}

// ---------------------------------------------------------------------------
// Regression matrix (synthetic TPM — hardware-free oracle)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::TpmTransport;
    use crate::synth::SynthTpm;
    use crate::structures::encode_pcr_extend;

    fn rig() -> SynthTpm {
        let mut tpm = SynthTpm::new();
        // Platform firmware measured PCRs 0/2 + dc measurements in 8-11.
        for (pcr, tag) in [
            (0u32, b"firmware".as_slice()),
            (2u32, b"option-rom".as_slice()),
            (8u32, b"kernel".as_slice()),
            (9u32, b"initramfs".as_slice()),
            (10u32, b"dc-binary".as_slice()),
            (11u32, b"evidence".as_slice()),
        ] {
            let d: [u8; 32] = Sha256::digest(tag).into();
            let _ = tpm.transact(&encode_pcr_extend(pcr, &d)).unwrap();
        }
        tpm
    }

    const MASK: [u8; 4] = [0xFF, 0x0F, 0x00, 0x00]; // PCRs 0-11

    #[test]
    fn seal_unseal_roundtrip_returns_the_plaintext() {
        let mut tpm = rig();
        let secret = b"operator-ed25519-seed-0123456789";
        let blob = seal(&mut tpm, secret, MASK).unwrap();
        assert_eq!(blob.schema, "dc.tpm-sealed/v1");
        assert_eq!(blob.pcr_list, "0,1,2,3,4,5,6,7,8,9,10,11");
        let recovered = unseal(&mut tpm, &blob).unwrap();
        assert_eq!(recovered.expose(), secret);
    }

    #[test]
    fn pcr_drift_after_sealing_refuses_unseal() {
        let mut tpm = rig();
        let blob = seal(&mut tpm, b"seed-material-32-bytes_________", MASK).unwrap();
        // Firmware PCR extended post-seal (BIOS update / evil maid).
        let d: [u8; 32] = Sha256::digest(b"evil-maid").into();
        let _ = tpm.transact(&encode_pcr_extend(2, &d)).unwrap();
        let err = unseal(&mut tpm, &blob).unwrap_err();
        assert!(
            matches!(err, TpmError::ResponseCode { code } if code == TPM_RC_POLICY_FAIL),
            "expected TPM_RC_POLICY_FAIL, got {err}"
        );
    }

    #[test]
    fn oversized_secret_is_refused_client_side() {
        let mut tpm = rig();
        let too_big = vec![0u8; DC_SEALED_SECRET_MAX + 1];
        assert!(matches!(
            seal(&mut tpm, &too_big, MASK),
            Err(TpmError::Policy(_))
        ));
    }

    #[test]
    fn spliced_private_blob_is_refused_by_load_integrity() {
        let mut tpm = rig();
        let blob = seal(&mut tpm, b"seed", MASK).unwrap();
        let mut private = hex::decode(&blob.private_hex).unwrap();
        // Flip one bit inside the ciphertext.
        let last = private.len() - 1;
        private[last] ^= 0x01;
        let mut tampered = blob.clone();
        tampered.private_hex = hex::encode(&private);
        assert!(matches!(
            unseal(&mut tpm, &tampered),
            Err(TpmError::ResponseCode { code: 0x0000_0097 })
        ));
    }

    #[test]
    fn unknown_schema_is_refused_without_touching_the_tpm() {
        let mut tpm = rig();
        let mut blob = seal(&mut tpm, b"seed", MASK).unwrap();
        blob.schema = "dc.tpm-sealed/v0".into();
        assert!(matches!(
            unseal(&mut tpm, &blob),
            Err(TpmError::Policy(_))
        ));
    }

    #[test]
    fn pcr_spec_parser_roundtrip() {
        let mask = pcr_list_to_mask("0-7,8,9-11").unwrap();
        assert_eq!(mask, MASK);
        assert_eq!(mask_to_pcr_list(mask), "0,1,2,3,4,5,6,7,8,9,10,11");
        assert!(pcr_list_to_mask("").is_err());
        assert!(pcr_list_to_mask("24").is_err()); // beyond the SHA-256 bank
        assert!(pcr_list_to_mask("9-3").is_err()); // inverted range
    }
}
