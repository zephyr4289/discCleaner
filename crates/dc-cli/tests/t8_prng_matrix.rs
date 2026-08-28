use assert_cmd::Command;
use dc_testkit::{
    CleanroomPRNG, DioProbe, GoldenVectors, Janitor, KnownAnswerTests, LoopDevice,
    SentinelManager,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t8_prng_verification_matrix() {
    // F0, F1: Pure unit tests run without root privileges!
    run_f0_prelude();
    run_f1_golden_vectors();
    run_f5_flag_validation();

    if !is_root() {
        eprintln!("[SKIP] T8 E2E integration cells require root privileges (EUID 0). Pure math cells passed.");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // F4: E2E Acceptance (Cert-Only Cleanroom Reproduction)
    run_f4_e2e_reproduction(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T8 PRNG CHAIN-OF-TRUST SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_f0_prelude() {
    println!("\n[>>> F0 PRELUDE: Testing RFC 8439 & BLAKE3 Known Answer Tests <<<]");

    // F0.1 & F0.4: RFC 8439 Block Vector through ChaCha20Ref and chacha20 crate dependency
    KnownAnswerTests::verify_rfc8439_block_vector()
        .expect("[F0-RFC] RFC 8439 KAT verification failed!");

    // F0.3: BLAKE3 official KAT
    KnownAnswerTests::verify_blake3_kat()
        .expect("[F0-BLAKE3] BLAKE3 KAT verification failed!");

    println!("  [✓] F0 PASSED: RFC 8439 and BLAKE3 official KATs verified.");
}

fn run_f1_golden_vectors() {
    println!("\n[>>> F1: Testing Golden Vectors & Invariant Families <<<]");

    // V-BASIC
    GoldenVectors::verify_basic_vectors()
        .expect("[V-BASIC] Basic vector checks failed!");

    // V-PAIRS (u64 2^32 boundary collision test)
    GoldenVectors::verify_u64_boundary_pairs()
        .expect("[V-PAIRS] 2^32 boundary inequality check failed!");

    // V-SHORT (truncation prefix property)
    GoldenVectors::verify_short_window_truncation()
        .expect("[V-SHORT] Short window truncation prefix check failed!");

    // V-CROSSW (cross-W invariance)
    GoldenVectors::verify_cross_w_invariance()
        .expect("[V-CROSSW] Cross-W invariance check failed!");

    println!("  [✓] F1 PASSED: Golden vector families and mathematical invariants verified.");
}

fn run_f5_flag_validation() {
    println!("\n[>>> F5: Testing CLI --seed Validation Rules <<<]");

    // 1. Non-hex seed -> Exit 8
    let mut cmd_nonhex = Command::cargo_bin("diskcleaner").unwrap();
    cmd_nonhex.arg("plan")
        .arg("--target").arg("/dev/null")
        .arg("--profile").arg("clear-random")
        .arg("--seed").arg("ZZZZ_NOT_HEX_DATA_ZZZZ_NOT_HEX_DATA_ZZZZ_NOT_HEX_DATA_ZZZZ_NOT_HEX_DA");
    cmd_nonhex.assert().code(8);

    // 2. Wrong length seed (31 bytes / 62 hex) -> Exit 8
    let mut cmd_len = Command::cargo_bin("diskcleaner").unwrap();
    cmd_len.arg("plan")
        .arg("--target").arg("/dev/null")
        .arg("--profile").arg("clear-random")
        .arg("--seed").arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd");
    cmd_len.assert().code(8);

    // 3. --seed with clear-zero profile -> Exit 8
    let mut cmd_zero = Command::cargo_bin("diskcleaner").unwrap();
    cmd_zero.arg("plan")
        .arg("--target").arg("/dev/null")
        .arg("--profile").arg("clear-zero")
        .arg("--seed").arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    cmd_zero.assert().code(8);

    println!("  [✓] F5 PASSED: --seed validation rules cleanly enforced with exit code 8.");
}

fn run_f4_e2e_reproduction(scratch_dir: &Path) {
    println!("\n[>>> F4: Testing E2E Cert-Only Cleanroom Reproduction (A2 Moat) <<<]");

    let run_dir = scratch_dir.join(format!("t8_e2e_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing.raw");
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    let fixed_seed_hex = "4242424242424242424242424242424242424242424242424242424242424242";
    let plan_path = run_dir.join("plan_random.json");

    // 1. Compile Plan with explicit seed
    let mut plan_cmd = Command::cargo_bin("diskcleaner").unwrap();
    plan_cmd.arg("plan")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-random")
        .arg("--seed").arg(fixed_seed_hex)
        .arg("--out").arg(&plan_path);
    plan_cmd.assert().code(0);

    // 2. Execute plan
    let out_dir = run_dir.join("output_cert");
    let _ = fs::create_dir_all(&out_dir);

    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--plan").arg(&plan_path)
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    exec_cmd.assert().code(0);

    let cert_path = find_single_file_with_ext(&out_dir, "cert.json")
        .expect("Certificate not found after execution");

    // 3. E2E-A: Cleanroom independent cert-only reproduction!
    let cert_match = CleanroomPRNG::verify_certificate_reproduction(&cert_path)
        .expect("[E2E-A] Cleanroom reproduction failed on valid certificate!");
    assert!(cert_match, "[E2E-A] Stream hash did not match cleanroom re-derivation!");
    println!("  [✓] E2E-A: Cleanroom successfully re-derived exact media digest from certificate alone.");

    // 4. E2E-NEG: Tamper seed in copy of certificate -> MUST DETECT MISMATCH (Oracle's teeth)
    let tampered_cert_path = run_dir.join("tampered_cert.json");
    let cert_content = fs::read_to_string(&cert_path).unwrap();
    let mut cert_json: serde_json::Value = serde_json::from_str(&cert_content).unwrap();

    if let Some(s) = cert_json.pointer_mut("/plan/mechanism/passes/0/pattern/DeterministicRandom/seed") {
        *s = serde_json::Value::String("9999999999999999999999999999999999999999999999999999999999999999".to_string());
    }
    fs::write(&tampered_cert_path, serde_json::to_string_pretty(&cert_json).unwrap()).unwrap();

    let neg_result = CleanroomPRNG::verify_certificate_reproduction(&tampered_cert_path);
    assert!(neg_result.is_err(), "[E2E-NEG] Cleanroom failed to detect tampered seed!");
    println!("  [✓] E2E-NEG: Cleanroom detected tampered seed mismatch (oracle teeth confirmed).");

    // 5. E2E-SCHEME: Unknown scheme -> Refusal
    if let Some(s) = cert_json.pointer_mut("/plan/mechanism/passes/0/pattern/DeterministicRandom/scheme") {
        *s = serde_json::Value::String("chacha20-window-v2".to_string());
    }
    let unknown_cert_path = run_dir.join("unknown_scheme_cert.json");
    fs::write(&unknown_cert_path, serde_json::to_string_pretty(&cert_json).unwrap()).unwrap();

    let scheme_result = CleanroomPRNG::verify_certificate_reproduction(&unknown_cert_path);
    assert!(
        scheme_result.unwrap_err().contains("UNKNOWN_SCHEME"),
        "[E2E-SCHEME] Cleanroom failed to refuse unknown scheme!"
    );
    println!("  [✓] E2E-SCHEME: Cleanroom cleanly refused unknown scheme string.");
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
