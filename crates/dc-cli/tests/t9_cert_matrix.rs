use assert_cmd::Command;
use dc_cert::OperatorKeyPair;
use dc_testkit::{
    CertForge, DioProbe, Janitor, KnownAnswerTests, LoopDevice, SentinelManager,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t9_certificate_verification_matrix() {
    // Pure unit and file-surgery tests run without root privileges!
    run_f0_prelude();
    run_f1_canonical_semantics();
    run_f2_authenticity_and_anchors();
    run_f3_parser_adversarial();
    run_f5_schema_hygiene();

    if !is_root() {
        eprintln!("[SKIP] T9 E2E live wipe cell requires root privileges (EUID 0). Pure certificate cells passed.");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // E2E live generation and verify
    run_t9_e2e_live_cycle(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T9 CERTIFICATE VERIFICATION & ANTI-FORGERY SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_f0_prelude() {
    println!("\n[>>> F0 PRELUDE: Testing RFC 8032, RFC 8785 & BLAKE3 Known Answer Tests <<<]");

    KnownAnswerTests::verify_rfc8032_ed25519_kat()
        .expect("[F0-ED25519] RFC 8032 KAT failed!");

    KnownAnswerTests::verify_rfc8785_jcs_examples()
        .expect("[F0-JCS] RFC 8785 JCS canonicalization failed!");

    KnownAnswerTests::verify_blake3_kat()
        .expect("[F0-BLAKE3] BLAKE3 KAT failed!");

    println!("  [✓] F0 PASSED: RFC 8032 Ed25519, RFC 8785 JCS, and BLAKE3 KATs verified.");
}

fn stage_test_cert() -> (String, OperatorKeyPair, PathBuf) {
    let keypair = OperatorKeyPair::generate();
    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("base.cert.json");

    let identity = dc_core::DeviceIdentity {
        stable: dc_core::StableIdentity {
            model: Some("EnterpriseNVMe".to_string()),
            serial: Some("SN-TEST-999".to_string()),
            wwn: None,
            size_bytes: 64 * 1024 * 1024,
            bus: dc_core::BusType::Nvme,
            dm_name: None,
            dm_uuid: None,
        },
        kernel: dc_core::KernelIdentity { major: 259, minor: 0 },
        kernel_name: "nvme0n1".to_string(),
        dev_path: "/dev/nvme0n1".to_string(),
        logical_block_size: 512,
        physical_block_size: 4096,
    };

    let plan = dc_core::SanitizationPlan::clear_zero(identity.stable.clone(), dc_core::FastPathPolicy::PreferWriteZeroes);
    let plan_hash = plan.compute_plan_hash().unwrap();

    let mut cert = dc_cert::SanitizationCertificate::new(
        plan,
        plan_hash,
        identity,
        dc_cert::ExecutionDetails {
            started_utc: "2026-08-28T22:00:00Z".to_string(),
            finished_utc: "2026-08-28T22:05:00Z".to_string(),
            duration_mono_ms: 300000,
            interruptions: vec![],
            failures: vec![],
            passes: vec![dc_cert::ExecutionPassReport {
                index: 0,
                pattern: "Zero".to_string(),
                fast_path_used: true,
                windows_written: 32,
                throughput_kib_s: 2500000,
            }],
        },
        dc_verify::VerificationReport {
            level: dc_core::VerifyLevel::Full,
            windows_checked: 32,
            mismatch_count: 0,
            first_mismatch_lbas: vec![],
            stream_hash_blake3: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            stream_hash_sha256: None,
            entropy: None,
        },
        dc_core::JournalChainSummary {
            path: PathBuf::from("/tmp/test.dcj"),
            chain_head: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            record_count: 4,
            discarded_tail_bytes: 0,
            uuid: "test-uuid-t9".to_string(),
            sealed: true,
        },
        keypair.public_key_hex(),
        keypair.key_fingerprint_blake3(),
    );

    cert.sign(&keypair).unwrap();
    let json_str = serde_json::to_string_pretty(&cert).unwrap();
    fs::write(&cert_path, &json_str).unwrap();

    (json_str, keypair, cert_path)
}

fn run_f1_canonical_semantics() {
    println!("\n[>>> F1: Testing Canonical Semantics vs Encoding Aliases (Δ62) <<<]");
    let (json_str, _op_key, cert_path) = stage_test_cert();
    let temp_dir = cert_path.parent().unwrap();

    // 1. E-REORDER: Reordering JSON keys MUST VALIDATE (Exit 0)
    let reordered = CertForge::reorder_keys(&json_str).unwrap();
    let reordered_path = temp_dir.join("reordered.cert.json");
    fs::write(&reordered_path, reordered).unwrap();

    let mut cmd_reorder = Command::cargo_bin("diskcleaner").unwrap();
    cmd_reorder.arg("cert").arg("verify").arg(&reordered_path);
    cmd_reorder.assert().code(0);
    println!("  [✓] E-REORDER: Key-reordered JSON validly verified (signature protects canonical form).");

    // 2. F-VALUE: Changing serial number MUST FAIL (Exit 10)
    let tampered_val = json_str.replacen("SN-TEST-999", "SN-FORGED-666", 1);
    let tampered_path = temp_dir.join("tampered_val.cert.json");
    fs::write(&tampered_path, tampered_val).unwrap();

    let mut cmd_tamper = Command::cargo_bin("diskcleaner").unwrap();
    cmd_tamper.arg("cert").arg("verify").arg(&tampered_path);
    cmd_tamper.assert().code(10);
    println!("  [✓] F-VALUE: Modified serial number cleanly refused with exit code 10.");

    // 3. F-STREAMHASH: Changing stream digest MUST FAIL (Exit 10)
    let tampered_hash = json_str.replacen("e3b0c442", "deadbeef", 1);
    let hash_path = temp_dir.join("tampered_hash.cert.json");
    fs::write(&hash_path, tampered_hash).unwrap();

    let mut cmd_hash = Command::cargo_bin("diskcleaner").unwrap();
    cmd_hash.arg("cert").arg("verify").arg(&hash_path);
    cmd_hash.assert().code(10);
    println!("  [✓] F-STREAMHASH: Modified stream hash cleanly refused with exit code 10.");
}

fn run_f2_authenticity_and_anchors() {
    println!("\n[>>> F2: Testing Trust Anchors & Authenticity (Δ63) <<<]");
    let (json_str, op_key, cert_path) = stage_test_cert();
    let temp_dir = cert_path.parent().unwrap();

    let attack_key = OperatorKeyPair::generate();

    // 1. F-REKEY-UNANCHORED: Attack key re-sign -> VALID (INTEGRITY-ONLY)
    let attack_cert = CertForge::re_sign_with_attack_key(&json_str, &attack_key).unwrap();
    let attack_path = temp_dir.join("attack_cert.cert.json");
    fs::write(&attack_path, &attack_cert).unwrap();

    let mut cmd_unanchored = Command::cargo_bin("diskcleaner").unwrap();
    cmd_unanchored.arg("cert").arg("verify").arg(&attack_path);
    let out = cmd_unanchored.assert().code(0).get_output().stdout.clone();
    let stdout = String::from_utf8_lossy(&out);
    assert!(stdout.contains("INTEGRITY-ONLY"), "[F-REKEY-UNANCHORED] Missing integrity-only label!");
    println!("  [✓] F-REKEY-UNANCHORED: Forged cert without anchor labeled as INTEGRITY-ONLY.");

    // 2. F-REKEY-ANCHORED: Attack key re-sign with operator fingerprint -> MUST REFUSE (Exit 10)
    let mut cmd_anchored = Command::cargo_bin("diskcleaner").unwrap();
    cmd_anchored.arg("cert").arg("verify")
        .arg(&attack_path)
        .arg("--fingerprint").arg(op_key.key_fingerprint_blake3());
    cmd_anchored.assert().code(10);
    println!("  [✓] F-REKEY-ANCHORED: Forged cert refused against operator fingerprint with exit code 10.");

    // 3. ANCHOR-REQUIRED: Unanchored valid cert with --require-anchor -> MUST REFUSE (Exit 10)
    let mut cmd_req = Command::cargo_bin("diskcleaner").unwrap();
    cmd_req.arg("cert").arg("verify")
        .arg(&cert_path)
        .arg("--require-anchor");
    cmd_req.assert().code(10);
    println!("  [✓] ANCHOR-REQUIRED: Unanchored cert refused when --require-anchor is passed.");

    // 4. F-FINGERPRINT-SWAP: Swapped fingerprint with stale value -> MUST REFUSE (Exit 10)
    let fake_fp_cert = CertForge::swap_fingerprint(&json_str, "0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let fp_path = temp_dir.join("fake_fp.cert.json");
    fs::write(&fp_path, fake_fp_cert).unwrap();

    let mut cmd_fp = Command::cargo_bin("diskcleaner").unwrap();
    cmd_fp.arg("cert").arg("verify").arg(&fp_path);
    cmd_fp.assert().code(10);
    println!("  [✓] F-FINGERPRINT-SWAP: Stale fingerprint caught by coherence check with exit code 10.");
}

fn run_f3_parser_adversarial() {
    println!("\n[>>> F3: Testing Strict Parser Defense (Δ65) <<<]");
    let (json_str, _op_key, cert_path) = stage_test_cert();
    let temp_dir = cert_path.parent().unwrap();

    // 1. Duplicate key -> MUST REFUSE (Exit 10)
    let dup_cert = CertForge::add_duplicate_key(&json_str);
    let dup_path = temp_dir.join("dup.cert.json");
    fs::write(&dup_path, dup_cert).unwrap();

    let mut cmd_dup = Command::cargo_bin("diskcleaner").unwrap();
    cmd_dup.arg("cert").arg("verify").arg(&dup_path);
    cmd_dup.assert().code(10);
    println!("  [✓] DUP-KEY: Duplicate JSON keys refused by tokenizer pre-scan with exit code 10.");

    // 2. UTF-8 BOM -> MUST REFUSE (Exit 10)
    let bom_cert = CertForge::add_bom(json_str.as_bytes());
    let bom_path = temp_dir.join("bom.cert.json");
    fs::write(&bom_path, bom_cert).unwrap();

    let mut cmd_bom = Command::cargo_bin("diskcleaner").unwrap();
    cmd_bom.arg("cert").arg("verify").arg(&bom_path);
    cmd_bom.assert().code(10);
    println!("  [✓] BOM: UTF-8 BOM prefix refused by strict scanner with exit code 10.");

    // 3. Trailing document -> MUST REFUSE (Exit 10)
    let trailing_cert = CertForge::add_trailing_doc(&json_str);
    let trailing_path = temp_dir.join("trailing.cert.json");
    fs::write(&trailing_path, trailing_cert).unwrap();

    let mut cmd_trailing = Command::cargo_bin("diskcleaner").unwrap();
    cmd_trailing.arg("cert").arg("verify").arg(&trailing_path);
    cmd_trailing.assert().code(10);
    println!("  [✓] TRAILING-DOC: Trailing second document refused with exit code 10.");
}

fn run_f5_schema_hygiene() {
    println!("\n[>>> F5: Testing Schema & Crypto Hygiene (Δ66) <<<]");
    let (json_str, _op_key, cert_path) = stage_test_cert();
    let temp_dir = cert_path.parent().unwrap();

    // Future schema "diskcleaner-cert/2" -> MUST REFUSE (Exit 10)
    let schema2_cert = json_str.replacen("diskcleaner-cert/1", "diskcleaner-cert/2", 1);
    let schema2_path = temp_dir.join("schema2.cert.json");
    fs::write(&schema2_path, schema2_cert).unwrap();

    let mut cmd_schema2 = Command::cargo_bin("diskcleaner").unwrap();
    cmd_schema2.arg("cert").arg("verify").arg(&schema2_path);
    cmd_schema2.assert().code(10);
    println!("  [✓] V-SCHEMA2: Unsupported forward schema refused with exit code 10.");
}

fn run_t9_e2e_live_cycle(scratch_dir: &Path) {
    println!("\n[>>> T9 LIVE: Testing End-to-End Execution, Signing & Show <<<]");
    let run_dir = scratch_dir.join(format!("t9_live_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing.raw");
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    let key_path = run_dir.join("operator.key");
    let mut keygen = Command::cargo_bin("diskcleaner").unwrap();
    keygen.arg("keygen").arg("--out").arg(&key_path);
    keygen.assert().code(0);

    let out_dir = run_dir.join("output_cert");
    let _ = fs::create_dir_all(&out_dir);

    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--key").arg(&key_path)
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    exec_cmd.assert().code(0);

    let cert_path = find_single_file_with_ext(&out_dir, "cert.json").unwrap();
    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();

    // 1. Show command
    let mut show_cmd = Command::cargo_bin("diskcleaner").unwrap();
    show_cmd.arg("cert").arg("show").arg(&cert_path);
    let out = show_cmd.assert().code(0).get_output().stdout.clone();
    let stdout = String::from_utf8_lossy(&out);
    assert!(stdout.contains("CERTIFICATE OF DATA SANITIZATION"));
    println!("  [✓] dc cert show correctly rendered certificate details.");

    // 2. Reconcile verify with journal
    let mut verify_cmd = Command::cargo_bin("diskcleaner").unwrap();
    verify_cmd.arg("cert").arg("verify")
        .arg(&cert_path)
        .arg("--journal").arg(&journal_path);
    verify_cmd.assert().code(0);
    println!("  [✓] dc cert verify reconciled cleanly against live journal file.");
}

fn find_single_file_with_ext(dir: &Path, ext: &str) -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = p.file_name()?.to_string_lossy().to_string();
            if name.ends_with(ext) {
                return Some(p);
            }
        }
    }
    None
}
