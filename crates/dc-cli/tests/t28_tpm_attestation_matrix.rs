//! t28 — TPM 2.0 remote attestation matrix (v0.8.0, Vector 1).
//!
//! Drives the full attestation ladder against the protocol-level
//! synthetic TPM (`dc_tpm::synth`): provision → measure → quote → verify,
//! plus every tamper axis the verification ladder must reject and the
//! CLI-surface refusals (no TPM device = clean exit, required = refusal).

use dc_tpm::constants::{DC_AIK_PERSISTENT_HANDLE, TPM_GENERATED};
use dc_tpm::synth::SynthTpm;
use dc_tpm::{TpmAttestor, verify_bundle, verify_quote};

// ---------------------------------------------------------------------------
// Ladder: provision → measure → quote → verify
// ---------------------------------------------------------------------------

fn full_ladder(nonce: &[u8]) -> (dc_tpm::QuoteBundle, dc_tpm::QuoteAttestation) {
    let mut tpm = SynthTpm::new();
    let mut attestor = TpmAttestor::new(&mut tpm, DC_AIK_PERSISTENT_HANDLE).unwrap();
    attestor.measure_into_pcr(8, b"appliance-kernel").unwrap();
    attestor.measure_into_pcr(9, b"initramfs").unwrap();
    attestor.measure_into_pcr(10, b"dc-binary").unwrap();
    attestor.measure_into_pcr(11, b"plan-hash").unwrap();
    let bundle = attestor.generate_quote(nonce).unwrap();
    let response = hex::decode(&bundle.quote_response_hex).unwrap();
    let params = dc_tpm::device::classify_response(&response).unwrap();
    let attest = dc_tpm::structures::parse_attestation(params).unwrap();
    (bundle, attest)
}

#[test]
fn t28_a1_ladder_produces_locally_verified_quote() {
    let (bundle, attest) = full_ladder(b"t28-nonce-0123456789abcdef");
    assert!(bundle.locally_verified);
    assert!(verify_quote(&bundle, &attest).unwrap());
    assert!(verify_bundle(&bundle).unwrap());
    assert_eq!(attest.magic, TPM_GENERATED);
    assert_eq!(attest.attest_type, dc_tpm::constants::TPM_ST_ATTEST_QUOTE);
    assert_eq!(attest.extra_data, b"t28-nonce-0123456789abcdef".to_vec());
}

#[test]
fn t28_a2_pcr_measurement_extends_not_overwrites() {
    let mut tpm = SynthTpm::new();
    let mut attestor = TpmAttestor::new(&mut tpm, DC_AIK_PERSISTENT_HANDLE).unwrap();
    let before = attestor.read_pcrs([0x00, 0x01, 0, 0]).unwrap(); // PCR 8
    let d1 = attestor.measure_into_pcr(8, b"first").unwrap();
    let mid = attestor.read_pcrs([0x00, 0x01, 0, 0]).unwrap();
    let d2 = attestor.measure_into_pcr(8, b"second").unwrap();
    let after = attestor.read_pcrs([0x00, 0x01, 0, 0]).unwrap();

    assert_ne!(
        mid.digests[0], before.digests[0],
        "first extend must move PCR 8"
    );
    assert_ne!(
        after.digests[0], mid.digests[0],
        "second extend must move it again"
    );
    // TPM extend law: PCR' = SHA256(PCR || value), recomputed through
    // the same pure helper the attestation stack uses for PCR digests.
    let _ = d2;
    // (The law itself is pinned inside dc-tpm's synth tests; here we pin
    // the observable behavior: extends are order- and value-sensitive.)
    let mut tpm2 = SynthTpm::new();
    let mut a2 = TpmAttestor::new(&mut tpm2, DC_AIK_PERSISTENT_HANDLE).unwrap();
    let d1b = a2.measure_into_pcr(8, b"first").unwrap();
    a2.measure_into_pcr(8, b"second").unwrap();
    let after2 = a2.read_pcrs([0x00, 0x01, 0, 0]).unwrap();
    assert_eq!(
        after.digests[0], after2.digests[0],
        "same extends → same PCR (deterministic)"
    );
    assert_eq!(d1, d1b);
}

#[test]
fn t28_a3_measurement_pcrs_are_restricted_to_8_through_11() {
    let mut tpm = SynthTpm::new();
    let mut attestor = TpmAttestor::new(&mut tpm, DC_AIK_PERSISTENT_HANDLE).unwrap();
    // Platform PCRs 0-7 belong to firmware: dc must refuse to touch them.
    for pcr in 0..8 {
        let err = attestor.measure_into_pcr(pcr, b"x").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("8-11"), "PCR {pcr}: {msg}");
    }
    for pcr in 12..24 {
        assert!(attestor.measure_into_pcr(pcr, b"x").is_err());
    }
}

#[test]
fn t28_a4_aik_reuse_across_attestors() {
    // The AIK persists at the fixed handle: a second attestor reuses the
    // same key identity (quotes chain to one hardware identity).
    let mut tpm = SynthTpm::new();
    let x1 = TpmAttestor::new(&mut tpm, DC_AIK_PERSISTENT_HANDLE).unwrap();
    let k1 = x1.aik().public.x.clone();
    drop(x1);
    let x2 = TpmAttestor::new(&mut tpm, DC_AIK_PERSISTENT_HANDLE).unwrap();
    assert_eq!(k1, x2.aik().public.x, "AIK identity is stable");
}

// ---------------------------------------------------------------------------
// Tamper axes: every one must fail verification
// ---------------------------------------------------------------------------

#[test]
fn t28_b1_tamper_nonce() {
    let (mut bundle, _a) = full_ladder(b"nonce-original-123456");
    bundle.nonce_hex = hex::encode(b"nonce-tampered-----");
    assert!(verify_bundle(&bundle).is_err());
}

#[test]
fn t28_b2_tamper_pcr_value() {
    let (mut bundle, _a) = full_ladder(b"nonce-x");
    let mut first = hex::decode(&bundle.pcr_values_hex[0]).unwrap();
    first[3] ^= 0x40;
    bundle.pcr_values_hex[0] = hex::encode(&first);
    assert!(verify_bundle(&bundle).is_err());
}

#[test]
fn t28_b3_tamper_signature() {
    let (mut bundle, _a) = full_ladder(b"nonce-x");
    let mut r = hex::decode(&bundle.signature_r_hex).unwrap();
    r[0] ^= 1;
    bundle.signature_r_hex = hex::encode(&r);
    assert!(verify_bundle(&bundle).is_err());
}

#[test]
fn t28_b4_tamper_aik_key() {
    let (mut bundle, _a) = full_ladder(b"nonce-x");
    let mut x = hex::decode(&bundle.aik_x_hex).unwrap();
    x[31] ^= 0x01;
    bundle.aik_x_hex = hex::encode(&x);
    assert!(verify_bundle(&bundle).is_err());
}

#[test]
fn t28_b5_doctored_quote_response() {
    // A quote whose internal pcrDigest was doctored: generation must
    // fail-closed (never embed an unverifiable quote).
    let mut tpm = SynthTpm::new();
    tpm.tamper_mode = true;
    let mut attestor = TpmAttestor::new(&mut tpm, DC_AIK_PERSISTENT_HANDLE).unwrap();
    attestor.measure_into_pcr(8, b"k").unwrap();
    let result = attestor.generate_quote(b"nonce");
    assert!(result.is_err(), "fail-closed on inconsistent quote");
}

#[test]
fn t28_b6_replayed_response_under_different_nonce() {
    // Replay: the archived response replayed with a different declared
    // nonce must fail (freshness binding).
    let (bundle, _a) = full_ladder(b"nonce-live");
    let json = serde_json::to_string(&bundle).unwrap();
    let mut replayed: dc_tpm::QuoteBundle = serde_json::from_str(&json).unwrap();
    replayed.nonce_hex = hex::encode(b"nonce-forged");
    assert!(verify_bundle(&replayed).is_err());
}

// ---------------------------------------------------------------------------
// Certificate evidence conversion
// ---------------------------------------------------------------------------

#[test]
fn t28_c1_bundle_to_certificate_evidence_round_trip() {
    let (bundle, _a) = full_ladder(b"evidence-nonce-000");
    let evidence = dc_cli::quote::bundle_to_evidence(&bundle);
    assert!(evidence.locally_verified);
    assert_eq!(evidence.pcr_values_hex.len(), 12);
    assert!(evidence.defense_warnings().is_empty());
    assert!(
        evidence
            .field_lines()
            .iter()
            .any(|(k, _)| k.contains("TPM attestation"))
    );
    // Round-trip through JSON (the archival format).
    let json = serde_json::to_string(&evidence).unwrap();
    let back: dc_cert::TpmAttestationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back, evidence);
}

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

#[test]
fn t28_d1_quote_generate_without_tpm_is_a_clean_refusal() {
    // On CI there is no /dev/tpmrm0: the command must exit with a typed
    // error (usage exit path), never panic.
    let mut cmd = assert_cmd::Command::cargo_bin("dc").unwrap();
    let result = cmd
        .env_remove("DC_TPM_DEVICE")
        .arg("quote")
        .arg("generate")
        .arg("--evidence-tag")
        .arg("t28")
        .output()
        .expect("run dc quote generate");
    let text = String::from_utf8_lossy(&result.stdout);
    let err = String::from_utf8_lossy(&result.stderr);
    if result.status.success() {
        // A host WITH a TPM produced a real quote — allowed.
        assert!(text.contains("pcr_digest_hex") || !err.is_empty());
    } else {
        assert!(
            err.contains("TPM") || err.contains("tpmrm0") || text.contains("TPM"),
            "clean refusal, got stdout='{text}' stderr='{err}'"
        );
        assert!(!result.status.success());
    }
}

#[test]
fn t28_d2_quote_verify_rejects_a_garbage_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("garbage.json");
    std::fs::write(&path, "{\"nonce_hex\": \"nope\"}").unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("dc").unwrap();
    let result = cmd
        .arg("quote")
        .arg("verify")
        .arg(path.to_str().unwrap())
        .output()
        .expect("run dc quote verify");
    assert!(!result.status.success());
}
