//! v0.11.0 frontier integration tests: ZK receipts, CXL sanitization and
//! the formal layer.
//!
//! * `dc zk` library path: seeded ceremony → prove → verify (+ tamper
//!   rejection) — the CLI smoke (setup/prove/verify subcommands) shares
//!   exactly these calls.
//! * `dc cxl --mock` lifecycle via the CLI binary (assert_cmd).
//! * `dc formal check` + `dc formal verify-model` via the CLI binary.

use dc_zk::{
    ComplianceStatement, ComplianceWitness, ProvingKey, VerifyingKey, ZkReceipt, ZkRng,
    audit_root_of, prove_compliance, setup, verify_receipt, vk_commitment_of, vk_fingerprint,
};

fn fixture_statement_witness() -> (ComplianceStatement, ComplianceWitness) {
    let w = ComplianceWitness {
        serial: {
            let mut s = [0u8; 16];
            s[..15].copy_from_slice(b"ZK-INTEGRATION1");
            s
        },
        block_root: dc_zk::Fr::from_hash(b"integration-block-root"),
        passes: 2,
        verified_blocks: 64,
        total_blocks: 64,
        sanitize_success: true,
        operator_secret: dc_zk::Fr::from_hash(b"operator-secret-integration"),
        nonce: dc_zk::Fr::from_hash(b"nonce-integration"),
    };
    let stmt = ComplianceStatement {
        profile_hash: dc_zk::Fr::from_hash(b"nist-800-88-purge"),
        tenant_id: dc_zk::Fr::from_hash(b"tenant-alpha"),
        ts: dc_zk::Fr::from_hash(&1_790_000_000u64.to_be_bytes()),
        vk_commitment: vk_commitment_of(&w.operator_secret, &w.nonce),
        audit_root: dc_zk::Fr::ZERO,
    };
    let stmt = ComplianceStatement {
        audit_root: audit_root_of(&w, &stmt),
        ..stmt
    };
    (stmt, w)
}

/// Full-circuit Groth16 latency — run in release:
/// `cargo test -p dc-cli --release --test v011_frontiers -- --ignored`
#[test]
#[ignore = "expensive: full-circuit setup+prove; run in release"]
fn zk_prove_and_verify_roundtrip() {
    let (stmt, w) = fixture_statement_witness();
    let mut rng = ZkRng::from_seed(b"v011-integration");
    let circuit = dc_zk::compliance_circuit();
    let (pk, _vk): (ProvingKey, VerifyingKey) = setup(&circuit, dc_zk::CIRCUIT_ID, &mut rng);
    let receipt = prove_compliance(&pk, &stmt, &w, &mut rng, None, None)
        .expect("compliant witness must prove");
    let result = verify_receipt(&_vk, &receipt);
    assert!(result.is_valid, "receipt must verify: {:?}", result.error);
    assert!(result.vk_fingerprint_matches);
}

/// Full-circuit Groth16 latency — run in release:
/// `cargo test -p dc-cli --release --test v011_frontiers -- --ignored`
#[test]
#[ignore = "expensive: full-circuit setup+prove; run in release"]
fn zk_wrong_setup_rejected() {
    let (stmt, w) = fixture_statement_witness();
    let mut rng = ZkRng::from_seed(b"v011-integration-a");
    let circuit = dc_zk::compliance_circuit();
    let (pk, _vk) = setup(&circuit, dc_zk::CIRCUIT_ID, &mut rng);
    let receipt = prove_compliance(&pk, &stmt, &w, &mut rng, None, None).unwrap();
    // a DIFFERENT ceremony cannot verify the receipt
    let mut rng2 = ZkRng::from_seed(b"v011-integration-b");
    let (_pk2, vk2) = setup(&circuit, dc_zk::CIRCUIT_ID, &mut rng2);
    let result = verify_receipt(&vk2, &receipt);
    assert!(!result.is_valid, "receipt under another setup must fail");
    assert!(!result.vk_fingerprint_matches);
}

/// Full-circuit Groth16 latency — run in release:
/// `cargo test -p dc-cli --release --test v011_frontiers -- --ignored`
#[test]
#[ignore = "expensive: full-circuit setup+prove; run in release"]
fn zk_receipt_json_roundtrip_and_fingerprint_binding() {
    let (stmt, w) = fixture_statement_witness();
    let mut rng = ZkRng::from_seed(b"v011-ser");
    let circuit = dc_zk::compliance_circuit();
    let (pk, vk) = setup(&circuit, dc_zk::CIRCUIT_ID, &mut rng);
    let receipt =
        prove_compliance(&pk, &stmt, &w, &mut rng, Some("cert.json".into()), None).unwrap();
    let s = serde_json::to_string(&receipt).unwrap();
    let back: ZkReceipt = serde_json::from_str(&s).unwrap();
    assert_eq!(back, receipt);
    assert_eq!(receipt.vk_fingerprint, vk_fingerprint(&vk));
    // tampered statement must not verify
    let mut bad = back.clone();
    bad.statement.tenant_id = hex::encode(dc_zk::Fr::from_hash(b"tenant-beta").to_be_bytes());
    assert!(!verify_receipt(&vk, &bad).is_valid);
}

#[test]
fn cxl_mock_lifecycle_via_cli() {
    use assert_cmd::Command;
    let tmp = tempfile::tempdir().unwrap();
    let evidence = tmp.path().join("cxl-evidence.json");
    Command::cargo_bin("diskcleaner")
        .unwrap()
        .args([
            "cxl",
            "sanitize",
            "mem0",
            "--mock",
            "--evidence-out",
            evidence.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "return code:    0x0000 (Success)",
        ))
        .stdout(predicates::str::contains("all zero: true"));
    let data = std::fs::read_to_string(evidence).unwrap();
    let ev: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!(ev["opcode"], 0x4400);
    assert_eq!(ev["command"], "sanitize");
    assert_eq!(ev["return_code"], 0);
    assert_eq!(ev["media"]["all_zero"], true);
}

#[test]
fn cxl_erase_mock_via_cli() {
    use assert_cmd::Command;
    Command::cargo_bin("diskcleaner")
        .unwrap()
        .args(["cxl", "erase", "mem0", "--mock"])
        .assert()
        .success()
        .stdout(predicates::str::contains("secure-erase (opcode 0x4401)"))
        .stdout(predicates::str::contains("all zero: true"));
}

#[test]
fn formal_check_via_cli() {
    use assert_cmd::Command;
    Command::cargo_bin("diskcleaner")
        .unwrap()
        .args(["formal", "check", "--depth", "7"])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "all invariants hold (exhaustive at this depth)",
        ));
}

#[test]
fn formal_verify_model_via_cli() {
    use assert_cmd::Command;
    Command::cargo_bin("diskcleaner")
        .unwrap()
        .args(["formal", "verify-model", "--windows", "10"])
        .assert()
        .success()
        .stdout(predicates::str::contains("refinement HOLDS"));
}
