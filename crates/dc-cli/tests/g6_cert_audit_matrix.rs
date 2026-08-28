use assert_cmd::Command;
use dc_cert::{CertificateProjector, OperatorKeyPair, SanitizationCertificate};
use dc_core::{AuditLogger, AuditOutcome, AuditRecord};
use dc_testkit::RigLedger;
use std::fs;
use std::path::Path;

#[test]
fn test_g6_cert_audit_matrix() {
    let ledger = RigLedger::new();
    let temp_dir = tempfile::tempdir().unwrap();

    // 1. PROJ-IDENTITY: Pure Projection Identity (Δ163)
    run_proj_identity_tests(&ledger, temp_dir.path());

    // 2. AUD-MAGIC-SEPARATION & AUD-CHAIN-WALK: Audit Log DCA1 Chain (Δ165)
    run_aud_chain_tests(&ledger, temp_dir.path());

    // 3. CERT-VERIFY-RECONCILE: dc cert verify --journal Reconciliation (Δ173)
    run_cert_reconcile_tests(&ledger, temp_dir.path());

    // 4. CERT-STRICT-REJECT: Strict Schema & Unknown Field Rejection (Δ169)
    run_cert_strict_tests(&ledger, temp_dir.path());

    assert!(ledger.is_all_green(), "[G6-FAIL] Cert & Audit matrix contains failing assertions!");
    println!("\n[=== G6 CERTIFICATE & AUDIT MATRIX PASSED ALL CELLS ===]\n");
}

fn run_proj_identity_tests(ledger: &RigLedger, temp_dir: &Path) {
    println!("\n[>>> PROJ-IDENTITY: Testing Pure Projection Invariant (Δ163) <<<]");

    let j_path = temp_dir.join("clean.dcj");
    let keypair = OperatorKeyPair::generate();

    // Generate clean driver journal
    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("journal").arg("selftest-sequence")
        .arg("--flavor").arg("clean")
        .arg("--out").arg(&j_path);
    cmd.assert().code(0);

    // Project twice with same key
    let cert1 = CertificateProjector::project(&j_path, &keypair).unwrap();
    let cert2 = CertificateProjector::project(&j_path, &keypair).unwrap();

    let cert1_json = serde_json::to_string_pretty(&cert1).unwrap();
    let cert2_json = serde_json::to_string_pretty(&cert2).unwrap();

    // Assert bit-for-bit identical including Ed25519 signature (Δ163)
    let is_identical = cert1_json == cert2_json;
    ledger.assert("G6-PROJECT", "PROJ-IDENTITY", "true", is_identical.to_string(), None);
}

fn run_aud_chain_tests(ledger: &RigLedger, temp_dir: &Path) {
    println!("\n[>>> AUD-CHAIN: Testing DCA1 Magic & Chain Hash Verification (Δ165) <<<]");

    let aud_path = temp_dir.join("test_audit.log");
    let mut logger = AuditLogger::open_or_create(&aud_path).unwrap();

    logger.log(&AuditRecord {
        timestamp_utc: "2026-08-28T20:00:00Z".to_string(),
        argv_hash: "0000".to_string(),
        target_path: Some("/dev/nvme0n1".to_string()),
        outcome: AuditOutcome::PlanCompiled { plan_hash: "abcd1234".to_string() },
    }).unwrap();

    logger.log(&AuditRecord {
        timestamp_utc: "2026-08-28T20:01:00Z".to_string(),
        argv_hash: "0000".to_string(),
        target_path: Some("/dev/nvme0n1".to_string()),
        outcome: AuditOutcome::Executed {
            journal_path: "/tmp/clean.dcj".to_string(),
            chain_head: "ef012345".to_string(),
        },
    }).unwrap();

    let (count, head) = AuditLogger::verify_audit_file(&aud_path).unwrap();
    assert_eq!(count, 2);
    assert!(!head.is_empty());
    ledger.assert("G6-AUDIT", "AUD-CHAIN-WALK", "2", count.to_string(), None);

    // Assert feeding audit log to journal reader fails with magic mismatch
    let j_res = dc_core::journal::JournalReader::read_and_verify_chain(&aud_path);
    assert!(j_res.is_err(), "DCJ1 parser must reject DCA1 audit files");
    ledger.assert("G6-AUDIT", "AUD-MAGIC-SEPARATION", "true", j_res.is_err().to_string(), None);
}

fn run_cert_reconcile_tests(ledger: &RigLedger, temp_dir: &Path) {
    println!("\n[>>> CERT-RECONCILE: Testing dc cert verify --journal (Δ173) <<<]");

    let j_path = temp_dir.join("clean.dcj");
    let cert_path = temp_dir.join("clean.cert.json");
    let keypair = OperatorKeyPair::generate();

    let cert = CertificateProjector::project(&j_path, &keypair).unwrap();
    let cert_json = serde_json::to_string_pretty(&cert).unwrap();
    fs::write(&cert_path, cert_json).unwrap();

    // Verify cert with journal reconciliation
    let mut verify_cmd = Command::cargo_bin("diskcleaner").unwrap();
    verify_cmd.arg("cert").arg("verify")
        .arg(&cert_path)
        .arg("--journal").arg(&j_path);
    verify_cmd.assert().code(0);

    ledger.assert("G6-RECONCILE", "CERT-JOURNAL-RECONCILE", "true", "true", None);
}

fn run_cert_strict_tests(ledger: &RigLedger, temp_dir: &Path) {
    println!("\n[>>> CERT-STRICT: Testing Unknown Field Rejection (Δ169) <<<]");

    let cert_path = temp_dir.join("clean.cert.json");
    let content = fs::read_to_string(&cert_path).unwrap();

    // Inject unknown forward field
    let mut val: serde_json::Value = serde_json::from_str(&content).unwrap();
    val["unknown_forward_field"] = serde_json::json!("should_be_rejected");

    let tampered_path = temp_dir.join("strict_tampered.cert.json");
    fs::write(&tampered_path, serde_json::to_string_pretty(&val).unwrap()).unwrap();

    let mut verify_cmd = Command::cargo_bin("diskcleaner").unwrap();
    verify_cmd.arg("cert").arg("verify").arg(&tampered_path);
    verify_cmd.assert().code(10); // Exit 10 CertInvalid

    ledger.assert("G6-STRICT", "CERT-STRICT-REJECT", "true", "true", None);
}
