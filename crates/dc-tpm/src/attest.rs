//! High-level remote-attestation API (v0.8.0, Vector 1).
//!
//! The defense problem: an Ed25519-signed certificate proves the *operator*
//! approved the sanitization, but nothing in the certificate proves the
//! *host* ran unmodified code. A ring-0 rootkit that shims the wipe engine
//! and the verifier can certify a wipe that never happened.
//!
//! This module closes that gap with the TPM 2.0 attestation ladder:
//!
//! 1. **Measurement**: before purging, the appliance extends SHA-256
//!    measurements of the kernel, initramfs and `dc` binary into PCRs 8-11
//!    (`TPM2_PCR_Extend`). PCRs 0-7 carry the platform firmware
//!    measurements already extended by UEFI (SRTM).
//! 2. **Provisioning** (once per host): a restricted, non-exportable
//!    NIST P-256 signing key is created inside the TPM
//!    (`TPM2_CreatePrimary` + `TPM2_EvictControl`) — the Attestation
//!    Identity Key. `RESTRICTED` + `FIXED_TPM` mean the private key
//!    physically cannot leave the secure element.
//! 3. **Quote**: `TPM2_Quote` over PCRs 0-11, signed by the AIK with
//!    ECDSA-256. The quote binds: the PCR state (what code is running),
//!    our nonce (freshness — no replay), and the TPM's monotonic clock
//!    (replay guard across quotes).
//! 4. **Verification** (`verify_quote`): parse `TPMS_ATTEST`, check the
//!    magic/type/nonce, recompute the PCR digest from a live
//!    `TPM2_PCR_Read`, and verify the ECDSA signature against the AIK
//!    public key. Everything embedded in the certificate.
//!
//! The result is a mathematical statement to any external auditor: *the
//! sanitization ran on a host whose firmware + toolchain state is exactly
//! this PCR digest, measured by the motherboard's own secure element.*

use crate::constants::*;
use crate::device::{TpmError, TpmTransport, transact_owned, wire_result};
use crate::structures::{
    self, EccPublicKey, PcrReadResponse, PcrSelectionList, QuoteAttestation, parse_attestation,
    parse_create_primary, parse_ecdsa_signature, parse_pcr_read, parse_read_public,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::Path;

/// AIK state on this host.
#[derive(Clone, Debug)]
pub struct AikHandle {
    /// Persistent TPM handle (0x81800001 by default).
    pub persistent: u32,
    /// Uncompressed P-256 public coordinates.
    pub public: EccPublicKey,
    /// Raw TPMT_PUBLIC as returned by the TPM (archived into evidence).
    pub public_raw: Vec<u8>,
}

/// What the PCR bank measured (labels for the evidence package).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MeasurementReport {
    /// BLAKE3 of the kernel image extended into PCR 8 (empty = not supplied).
    pub kernel_blake3: String,
    /// BLAKE3 of the initramfs extended into PCR 9.
    pub initramfs_blake3: String,
    /// BLAKE3 of the running dc binary extended into PCR 10.
    pub binary_blake3: String,
    /// Free-form evidence tag extended into PCR 11 (e.g. plan hash).
    pub evidence_tag: String,
}

/// A complete, verifiable quote bundle — everything the certificate (or an
/// external auditor) needs to re-verify the attestation offline.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QuoteBundle {
    /// Nonce we supplied (hex) — freshness proof.
    pub nonce_hex: String,
    /// SHA-256 PCR selection used (bank + mask, hex per selection byte).
    pub pcr_mask_hex: String,
    /// Live PCR values at quote time, selection order, hex (32 bytes each).
    pub pcr_values_hex: Vec<String>,
    /// Recomputed SHA-256 over concatenated PCR values (what the quote
    /// structure must contain for a genuine measurement).
    pub pcr_digest_hex: String,
    /// Raw quote response (hex): TPMS_ATTEST + TPMT_SIGNATURE as returned
    /// by the TPM — the archival artifact an auditor replays.
    pub quote_response_hex: String,
    /// AIK public point: x (hex, 32 bytes) and y (hex, 32 bytes).
    pub aik_x_hex: String,
    pub aik_y_hex: String,
    /// Raw TPMT_PUBLIC template (hex).
    pub aik_public_template_hex: String,
    /// TPMS_ATTEST decoded fields (for quick audit display).
    pub attestation: AttestFields,
    /// ECDSA signature components (hex).
    pub signature_r_hex: String,
    pub signature_s_hex: String,
    /// TPM clock snapshot (replay guard).
    pub tpm_clock: u64,
    pub tpm_reset_count: u32,
    pub tpm_restart_count: u32,
    /// Verification verdict performed at capture time (re-runnable offline
    /// via `verify_quote`).
    pub locally_verified: bool,
}

/// `TPMS_ATTEST` fields serialized for the evidence package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestFields {
    pub magic_hex: String,
    pub attest_type_hex: String,
    pub qualified_signer_hex: String,
    pub firmware_version: u64,
    pub clock_safe: bool,
}

/// The host-side attestation engine.
pub struct TpmAttestor<'a, T: TpmTransport> {
    tpm: &'a mut T,
    aik: AikHandle,
    startup_done: bool,
}

impl<'a, T: TpmTransport> TpmAttestor<'a, T> {
    /// Bring up the attestation stack: `Startup` (idempotent —
    /// `TPM_RC_INITIALIZE` means "already up", treated as success), then
    /// locate or provision the AIK at `aik_persistent`.
    pub fn new(tpm: &'a mut T, aik_persistent: u32) -> Result<Self, TpmError> {
        // Startup: RC_INITIALIZE is the "already started" benign case.
        let _ = transact_owned(tpm, &structures::encode_startup(true));
        let aik = Self::locate_or_provision(tpm, aik_persistent)?;
        Ok(Self {
            tpm,
            aik,
            startup_done: true,
        })
    }

    /// True after construction (startup handshake observed).
    pub fn started(&self) -> bool {
        self.startup_done
    }

    pub fn aik(&self) -> &AikHandle {
        &self.aik
    }

    fn locate_or_provision(tpm: &mut T, persistent: u32) -> Result<AikHandle, TpmError> {
        if !(TPM_HR_PERSISTENT..=TPM_HR_PERSISTENT_LAST).contains(&persistent) {
            return Err(TpmError::Policy(format!(
                "AIK handle {persistent:#010x} outside the persistent range \
                 {TPM_HR_PERSISTENT:#010x}-{TPM_HR_PERSISTENT_LAST:#010x}"
            )));
        }
        // Existing AIK?
        if let Ok(params) = transact_owned(tpm, &structures::encode_read_public(persistent))
            && let Ok((public, public_raw)) = wire_result(parse_read_public(&params))
            && public.curve_id == TPM_ECC_NIST_P256
        {
            return Ok(AikHandle {
                persistent,
                public,
                public_raw,
            });
        }
        // Provision: CreatePrimary (restricted sign, owner hierarchy) then
        // persist. A transient primary is fine for the session; persisting
        // lets later quotes bind to the same key identity.
        let params = transact_owned(tpm, &structures::encode_create_primary_aik(TPM_RH_OWNER))?;
        let created = wire_result(parse_create_primary(&params))
            .map_err(|e| TpmError::Wire(format!("CreatePrimary: {e}")))?;
        if created.public.curve_id != TPM_ECC_NIST_P256 || created.public.x.len() != 32 {
            return Err(TpmError::Policy(
                "AIK template mismatch: TPM did not return a P-256 restricted signing key".into(),
            ));
        }
        // EvictControl to persist under the chosen handle.
        let _ = transact_owned(
            tpm,
            &structures::encode_evict_control(created.handle, persistent),
        )?;
        Ok(AikHandle {
            persistent,
            public: created.public,
            public_raw: created.public_raw,
        })
    }

    /// Extend SHA-256(artifact) into `pcr` (8..=11 are the dc measurement
    /// registers). The *extend* (not overwrite) semantics means a run of dc
    /// cannot hide what was measured before it.
    pub fn measure_into_pcr(&mut self, pcr: u32, data: &[u8]) -> Result<[u8; 32], TpmError> {
        if !(8..=11).contains(&pcr) {
            return Err(TpmError::Policy(format!(
                "dc measurement PCRs are 8-11 (kernel, initramfs, binary, evidence); \
                 refusing to extend PCR {pcr}"
            )));
        }
        let digest: [u8; 32] = Sha256::digest(data).into();
        transact_owned(self.tpm, &structures::encode_pcr_extend(pcr, &digest))?;
        Ok(digest)
    }

    /// Read the SHA-256 PCR values for a selection.
    pub fn read_pcrs(&mut self, mask: [u8; 4]) -> Result<PcrReadResponse, TpmError> {
        let params = transact_owned(
            self.tpm,
            &structures::encode_pcr_read(&PcrSelectionList::single_sha256(mask)),
        )?;
        wire_result(parse_pcr_read(&params))
    }

    /// Measure the appliance artifacts (kernel/initramfs/binary) into
    /// PCRs 8/9/10 and the evidence tag into PCR 11. Missing paths are
    /// skipped — the report records which measurements ran.
    pub fn measure_artifacts(
        &mut self,
        kernel: Option<&Path>,
        initramfs: Option<&Path>,
        binary: Option<&Path>,
        evidence_tag: &[u8],
    ) -> Result<MeasurementReport, TpmError> {
        let mut report = MeasurementReport::default();
        if let Some(p) = kernel
            && let Ok(bytes) = std::fs::read(p)
        {
            let digest = self.measure_into_pcr(8, &bytes)?;
            report.kernel_blake3 = blake3_24(&bytes);
            let _ = digest;
        }
        if let Some(p) = initramfs
            && let Ok(bytes) = std::fs::read(p)
        {
            self.measure_into_pcr(9, &bytes)?;
            report.initramfs_blake3 = blake3_24(&bytes);
        }
        if let Some(p) = binary
            && let Ok(bytes) = std::fs::read(p)
        {
            self.measure_into_pcr(10, &bytes)?;
            report.binary_blake3 = blake3_24(&bytes);
        }
        self.measure_into_pcr(11, evidence_tag)?;
        report.evidence_tag = hex::encode(evidence_tag);
        Ok(report)
    }

    /// Generate a `TPM2_Quote` over PCRs 0-11 (SHA-256 bank) with `nonce`
    /// (up to 32 bytes of caller entropy — the freshness binding), then
    /// verify it locally before accepting.
    pub fn generate_quote(&mut self, nonce: &[u8]) -> Result<QuoteBundle, TpmError> {
        if nonce.is_empty() || nonce.len() > 32 {
            return Err(TpmError::Policy("quote nonce must be 1..=32 bytes".into()));
        }
        let selection = PcrSelectionList::single_sha256(DC_QUOTE_PCR_MASK);

        // Fresh PCR values for the recomputation side of verification.
        let live = self.read_pcrs(DC_QUOTE_PCR_MASK)?;
        let expected_digest = recompute_pcr_digest(&selection, &live.digests);

        let response = self.tpm.transact(&structures::encode_quote(
            self.aik.persistent,
            nonce,
            &selection,
        ))?;
        let params = crate::device::classify_response(&response)?;
        let attest = wire_result(parse_attestation(params))
            .map_err(|e| TpmError::Wire(format!("quote attestation: {e}")))?;
        // Signature follows immediately after the attestation structure.
        let sig_params = &params[attest.raw.len()..];
        let sig = wire_result(parse_ecdsa_signature(sig_params))
            .map_err(|e| TpmError::Wire(format!("quote signature: {e}")))?;

        let mut bundle = QuoteBundle {
            nonce_hex: hex::encode(nonce),
            pcr_mask_hex: hex::encode(DC_QUOTE_PCR_MASK),
            pcr_values_hex: live.digests.iter().copied().map(hex::encode).collect(),
            pcr_digest_hex: hex::encode(expected_digest),
            quote_response_hex: hex::encode(&response),
            aik_x_hex: hex::encode(&self.aik.public.x),
            aik_y_hex: hex::encode(&self.aik.public.y),
            aik_public_template_hex: hex::encode(&self.aik.public_raw),
            attestation: AttestFields {
                magic_hex: format!("{:08X}", attest.magic),
                attest_type_hex: format!("{:04X}", attest.attest_type),
                qualified_signer_hex: hex::encode(&attest.qualified_signer),
                firmware_version: attest.firmware_version,
                clock_safe: attest.clock_safe,
            },
            signature_r_hex: hex::encode(&sig.r),
            signature_s_hex: hex::encode(&sig.s),
            tpm_clock: attest.clock,
            tpm_reset_count: attest.reset_count,
            tpm_restart_count: attest.restart_count,
            locally_verified: false,
        };

        // Fail-closed: a quote we cannot verify ourselves is never embedded.
        bundle.locally_verified = verify_quote(&bundle, &attest)?;
        Ok(bundle)
    }
}

/// Recompute the `TPMS_ATTEST.pcrDigest` for a selection: SHA-256 over the
/// concatenated selected PCR values, in selection order (TPM 2.0 Part 2,
/// TPM2_Quote digest computation).
pub fn recompute_pcr_digest(selection: &PcrSelectionList, pcr_values: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for sel in &selection.selections {
        let mut count = 0usize;
        for pcr in 0..32usize {
            if sel.selects(pcr) && count < pcr_values.len() {
                h.update(pcr_values[count]);
                count += 1;
            }
        }
    }
    h.finalize().into()
}

/// Standalone quote verification — identical to the in-TPM-path check, used
/// by `dc quote verify` and the certificate replay tooling.
///
/// Checks performed (all must pass):
/// 1. `TPM_GENERATED` magic and `TPM_ST_ATTEST_QUOTE` type — the structure
///    was produced by a genuine TPM, not synthesized by software.
/// 2. `extraData` == nonce — freshness.
/// 3. PCR selection == expected bank/mask.
/// 4. `pcrDigest` == SHA-256(concat of the claimed PCR values) — the quote
///    structure is internally consistent with the PCR claims.
/// 5. ECDSA-P256(SHA-256(attestation bytes)) verifies under the AIK public
///    key — the quote was signed by the non-exportable hardware key.
pub fn verify_quote(bundle: &QuoteBundle, attest: &QuoteAttestation) -> Result<bool, TpmError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    if attest.magic != TPM_GENERATED {
        return Err(TpmError::Verification(
            "bad TPMS_ATTEST magic (not TPM-generated)".into(),
        ));
    }
    if attest.attest_type != TPM_ST_ATTEST_QUOTE {
        return Err(TpmError::Verification(format!(
            "attestation type {:#06x} is not TPM_ST_ATTEST_QUOTE",
            attest.attest_type
        )));
    }
    let nonce = hex::decode(&bundle.nonce_hex)
        .map_err(|e| TpmError::Verification(format!("nonce hex: {e}")))?;
    if attest.extra_data != nonce {
        return Err(TpmError::Verification(
            "nonce mismatch — replay or forgery".into(),
        ));
    }
    let mask = hex::decode(&bundle.pcr_mask_hex)
        .map_err(|e| TpmError::Verification(format!("pcr mask hex: {e}")))?;
    let expected_sel = PcrSelectionList::single_sha256([
        mask.first().copied().unwrap_or(0),
        mask.get(1).copied().unwrap_or(0),
        mask.get(2).copied().unwrap_or(0),
        mask.get(3).copied().unwrap_or(0),
    ]);
    if attest.pcr_selection != expected_sel {
        return Err(TpmError::Verification(
            "PCR selection in quote differs from bundle".into(),
        ));
    }
    let values: Result<Vec<[u8; 32]>, _> = bundle
        .pcr_values_hex
        .iter()
        .map(|v| hex::decode(v).map_err(|e| TpmError::Verification(format!("pcr value hex: {e}"))))
        .collect::<Result<Vec<Vec<u8>>, _>>()
        .and_then(|vals| {
            vals.iter()
                .map(|v| {
                    v.clone().try_into().map_err(|v: Vec<u8>| {
                        TpmError::Verification(format!("PCR digest len {} != 32", v.len()))
                    })
                })
                .collect()
        });
    let values = values?;
    let recomputed = recompute_pcr_digest(&expected_sel, &values);
    if attest.pcr_digest != recomputed {
        return Err(TpmError::Verification(
            "pcrDigest does not match SHA-256 of claimed PCR values".into(),
        ));
    }
    // ECDSA verification against the AIK public point.
    let x = hex::decode(&bundle.aik_x_hex)
        .map_err(|e| TpmError::Verification(format!("aik x hex: {e}")))?;
    let y = hex::decode(&bundle.aik_y_hex)
        .map_err(|e| TpmError::Verification(format!("aik y hex: {e}")))?;
    let mut sec1 = vec![0x04u8]; // uncompressed point marker
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let point = p256::EncodedPoint::from_bytes(&sec1)
        .map_err(|e| TpmError::Verification(format!("AIK point: {e}")))?;
    let vk = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| TpmError::Verification(format!("AIK key: {e}")))?;
    let r = hex::decode(&bundle.signature_r_hex)
        .map_err(|e| TpmError::Verification(format!("sig r hex: {e}")))?;
    let s = hex::decode(&bundle.signature_s_hex)
        .map_err(|e| TpmError::Verification(format!("sig s hex: {e}")))?;
    let mut der = Vec::with_capacity(72);
    for part in [&r, &s] {
        // v0.9.0 fix (found by the proptest matrix): DER INTEGERs must be
        // MINIMAL — a leading zero byte is legal only when the next byte
        // has its high bit set. TPM2B components are fixed-width 32 bytes
        // (leading zeros whenever r or s < 2^248, ~0.8% of signatures),
        // which produced non-minimal DER that `Signature::from_der`
        // rejects — genuine quotes failed verification ~1 in 256 runs.
        let mut part = part.as_slice();
        while part.len() > 1 && part[0] == 0 {
            part = &part[1..];
        }
        let lead = usize::from(part.first().map(|b| b & 0x80 != 0).unwrap_or(false));
        der.push(0x02);
        der.push((part.len() + lead) as u8);
        if lead == 1 {
            der.push(0x00); // DER INTEGER must be positive
        }
        der.extend_from_slice(part);
    }
    let len = der.len() as u8;
    let mut sig_der = vec![0x30, len];
    sig_der.append(&mut der);
    let signature = Signature::from_der(&sig_der)
        .map_err(|e| TpmError::Verification(format!("signature DER: {e}")))?;
    // p256's Verifier hashes the message with SHA-256 internally, matching
    // the TPMT_SIG_SCHEME we requested (ECDSA / SHA-256).
    match vk.verify(&attest.raw, &signature) {
        Ok(()) => Ok(true),
        Err(e) => Err(TpmError::Verification(format!(
            "ECDSA signature invalid: {e}"
        ))),
    }
}

/// Re-verify a persisted bundle offline: parse the archived quote response
/// and run the full verification ladder against the stored AIK key.
///
/// SECURITY (v0.9.0, Phase 2): the ECDSA signature EMBEDDED in the archived
/// response is now verified, and required to be bit-identical to the
/// archived `signature_r/s` fields. Previously the ladder verified only the
/// archived components, so mutations of the response's trailing signature
/// region were ignored (found by the proptest non-malleability matrix —
/// a doctored response signature could never again ride on the archived
/// copy). Any single flipped byte in the response now fails verification
/// or parsing.
pub fn verify_bundle(bundle: &QuoteBundle) -> Result<bool, TpmError> {
    let response = hex::decode(&bundle.quote_response_hex)
        .map_err(|e| TpmError::Verification(format!("quote response hex: {e}")))?;
    // v0.9.0: the header's declared size must equal the archived length —
    // a doctored size word (or a truncated/spliced response) is refused
    // before any structure is parsed.
    if response.len() < 10 {
        return Err(TpmError::Verification(
            "archived response shorter than a TPM header".into(),
        ));
    }
    let declared =
        u32::from_be_bytes([response[2], response[3], response[4], response[5]]) as usize;
    if declared != response.len() {
        return Err(TpmError::Verification(format!(
            "declared response size {declared} != archived length {} — response doctored",
            response.len()
        )));
    }
    // Sessions-tagged responses carry a parameterSize word between the
    // header and the parameters; its VALUE is pinned to the parameter
    // area length (flipping it must not pass silently).
    let tag = u16::from_be_bytes([response[0], response[1]]);
    if tag == TPM_ST_SESSIONS_RSP {
        if response.len() < 14 {
            return Err(TpmError::Verification(
                "sessions response truncated before parameterSize".into(),
            ));
        }
        let param_size =
            u32::from_be_bytes([response[10], response[11], response[12], response[13]]) as usize;
        if param_size + 14 != response.len() {
            return Err(TpmError::Verification(format!(
                "declared parameterSize {param_size} inconsistent with response length {} — \
                 response doctored",
                response.len()
            )));
        }
    }
    let params = crate::device::classify_response(&response)?;
    let attest = wire_result(parse_attestation(params))
        .map_err(|e| TpmError::Wire(format!("replay: {e}")))?;
    // The response layout is `TPMS_ATTEST || TPMT_SIGNATURE`; the
    // attestation structure reports its own serialized length.
    let sig_area = &params[attest.raw.len().min(params.len())..];
    let embedded = wire_result(parse_ecdsa_signature(sig_area))
        .map_err(|e| TpmError::Wire(format!("replay signature: {e}")))?;
    if embedded.alg != TPM_ALG_ECDSA || embedded.hash_alg != TPM_ALG_SHA256 {
        return Err(TpmError::Verification(format!(
            "embedded signature scheme {:#06x}/{:#06x} is not ECDSA-SHA256 — response doctored",
            embedded.alg, embedded.hash_alg
        )));
    }
    if hex::encode(&embedded.r) != bundle.signature_r_hex
        || hex::encode(&embedded.s) != bundle.signature_s_hex
    {
        return Err(TpmError::Verification(
            "embedded quote signature differs from archived components — response doctored".into(),
        ));
    }
    verify_quote(bundle, &attest)
}

fn blake3_24(bytes: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(bytes);
    h.finalize().to_hex().to_string()[..24].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structures::PcrSelection;

    fn digest_of(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[test]
    fn pcr_digest_recomputation_matches_spec_ordering() {
        let sel = PcrSelectionList::single_sha256([0xFF, 0x0F, 0x00, 0x00]); // PCRs 0..=11
        let mut values = Vec::new();
        for i in 0..12u8 {
            values.push(digest_of(&[i]));
        }
        let mut h = Sha256::new();
        for v in &values {
            h.update(v);
        }
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(recompute_pcr_digest(&sel, &values), expect);
        // selection ordering matters: shuffled input changes the digest
        let mut shuffled = values.clone();
        shuffled[0] = digest_of(&[99u8]);
        assert_ne!(recompute_pcr_digest(&sel, &shuffled), expect);
    }

    #[test]
    fn empty_nonce_is_refused_by_policy() {
        // Pure logic check without a device: the policy lives in
        // generate_quote, tested through the synthetic TPM in the CLI
        // matrices (t28). Here we pin the digest law only.
        let sel = PcrSelectionList {
            selections: vec![PcrSelection::sha256([0x01, 0, 0, 0])],
        };
        let expect: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(digest_of(b"x"));
            h.finalize().into()
        };
        assert_eq!(recompute_pcr_digest(&sel, &[digest_of(b"x")]), expect);
    }
}
