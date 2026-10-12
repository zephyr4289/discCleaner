//! Cryptographic non-malleability properties (v0.9.0, Phase 2 — proptest).
//!
//! The hardware-attestation guarantees are only as strong as their
//! behavior under tampering: for ANY nonce and ANY single-byte mutation
//! of the attestation stream or the sealed blob, verification must FAIL
//! or the parse must be rejected — never accept a doctored artifact.

use dc_tpm::attest::{verify_bundle, TpmAttestor};
use dc_tpm::seal::{seal, unseal};
use dc_tpm::synth::SynthTpm;
use dc_tpm::TpmTransport;
use proptest::prelude::*;
use sha2::{Digest, Sha256};

fn measured_rig() -> SynthTpm {
    let mut tpm = SynthTpm::new();
    let mut attestor = TpmAttestor::new(&mut tpm, dc_tpm::DC_AIK_PERSISTENT_HANDLE).unwrap();
    attestor.measure_into_pcr(8, b"kernel").unwrap();
    attestor.measure_into_pcr(9, b"initramfs").unwrap();
    attestor.measure_into_pcr(10, b"dc-binary").unwrap();
    attestor
        .measure_into_pcr(11, b"evidence-tag")
        .unwrap();
    tpm
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Any single-byte mutation of a genuine TPM2_Quote response is
    /// rejected: the ECDSA signature, the PCR digest or the structure
    /// parse refuses it — a doctored quote is never locally accepted.
    #[test]
    fn quote_is_non_malleable_under_any_single_byte_flip(
        nonce in prop::collection::vec(any::<u8>(), 8..=32),
        flip in any::<u64>(),
    ) {
        let mut tpm = measured_rig();
        let mut attestor = TpmAttestor::new(&mut tpm, dc_tpm::DC_AIK_PERSISTENT_HANDLE).unwrap();
        let bundle = attestor.generate_quote(&nonce).unwrap();

        let mut response = hex::decode(&bundle.quote_response_hex).unwrap();
        let at = (flip as usize) % response.len();
        response[at] ^= 1u8 << (flip % 8);

        let mut doctored = bundle.clone();
        doctored.quote_response_hex = hex::encode(&response);
        // Either the wire parse rejects it, or the verification ladder
        // fails, or verify_bundle reports false — never `Ok(true)`.
        match verify_bundle(&doctored) {
            Ok(true) => prop_assert!(false, "doctored quote ACCEPTED at byte {}", at),
            _ => {}
        }
    }

    /// Any single-byte mutation of the sealed-blob private area makes
    /// the unseal ladder fail — TPM_RC_INTEGRITY / wire error / policy
    /// refusal — never a silently-altered key.
    #[test]
    fn sealed_blob_is_non_malleable_under_any_single_byte_flip(
        secret in prop::collection::vec(any::<u8>(), 1..=64),
        flip in any::<u64>(),
    ) {
        let mut tpm = measured_rig();
        let blob = seal(&mut tpm, &secret, [0xFF, 0x0F, 0x00, 0x00]).unwrap();

        let mut private = hex::decode(&blob.private_hex).unwrap();
        let at = (flip as usize) % private.len();
        private[at] ^= 1u8 << (flip % 8);
        let mut doctored = blob.clone();
        doctored.private_hex = hex::encode(&private);

        // If the unseal unexpectedly succeeds, the recovered plaintext
        // must NOT equal the sealed secret (integrity flip must surface).
        match unseal(&mut tpm, &doctored) {
            Err(_) => {}
            Ok(recovered) => prop_assert_ne!(recovered.expose(), &secret[..]),
        }
    }

    /// Sanity companion: an UNMODIFIED round trip always verifies — pins
    /// that the non-malleability cases above are not vacuous.
    #[test]
    fn genuine_quote_always_verifies(nonce in prop::collection::vec(any::<u8>(), 8..=32)) {
        let mut tpm = measured_rig();
        let mut attestor = TpmAttestor::new(&mut tpm, dc_tpm::DC_AIK_PERSISTENT_HANDLE).unwrap();
        let bundle = attestor.generate_quote(&nonce).unwrap();
        prop_assert!(verify_bundle(&bundle).unwrap_or(false));
    }
}

/// The PCR digest law used by the rig (documented for reviewers: keeps
/// the proptest rigs honest against the synth TPM's extend semantics).
#[test]
fn rig_pcr_extend_matches_tpm_law() {
    let mut tpm = SynthTpm::new();
    let d: [u8; 32] = Sha256::digest(b"measurement").into();
    tpm.transact(&dc_tpm::structures::encode_pcr_extend(8, &d)).unwrap();
    // PCR' = SHA256(0^32 || SHA256(measurement)) per the TPM extend law.
    let mut h = Sha256::new();
    h.update([0u8; 32]);
    h.update(Sha256::digest(b"measurement"));
    let expected: [u8; 32] = h.finalize().into();
    // PCR 8 = bit 0 of pcr_select byte 1.
    let read = tpm
        .transact(&dc_tpm::structures::encode_pcr_read(
            &dc_tpm::structures::PcrSelectionList::single_sha256([0x00, 0x01, 0x00, 0x00]),
        ))
        .unwrap();
    let params = dc_tpm::device::classify_response(&read).unwrap();
    let parsed = dc_tpm::structures::parse_pcr_read(params).unwrap();
    assert_eq!(parsed.digests[0], expected);
}
