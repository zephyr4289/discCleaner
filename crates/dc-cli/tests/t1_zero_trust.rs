use assert_cmd::Command;
use dc_testkit::{
    ArtifactsDumper, AuditOracle, CertOracle, DioProbe, EnvironmentFingerprint, Janitor,
    JournalOracle, LoopDevice, SentinelManager,
};
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

// Global mutex to serialize loop tests
static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t1_zero_trust_matrix() {
    if !is_root() {
        eprintln!("[SKIP] T1 integration test requires root privileges (EUID 0) to attach loop devices.");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => {
            panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e);
        }
    };

    println!("[+] Verified scratch directory with real O_DIRECT: {}", scratch_dir.display());

    // Clean prior runs
    let reclaimed = Janitor::sweep_leaked_loops(&scratch_dir);
    if !reclaimed.is_empty() {
        println!("[+] Janitor reclaimed leaked loop devices: {:?}", reclaimed);
    }

    // 1. Run Pre-flight Negative Tests (N1 & N2)
    run_negative_tests(&scratch_dir);

    // 2. Cell: T1.core (1 GiB, 512B lbs, default auto/uring engine)
    run_t1_cell(
        "T1.core",
        &scratch_dir,
        1024 * 1024 * 1024,
        512,
        "auto",
        false,
    );

    // 3. Cell: T1.tail512 (1 GiB + 1536 B short final window)
    run_t1_cell(
        "T1.tail512",
        &scratch_dir,
        1024 * 1024 * 1024 + 1536,
        512,
        "auto",
        false,
    );

    // 4. Cell: T1.sync (Sync engine forced + --no-write-zeroes)
    run_t1_cell(
        "T1.sync",
        &scratch_dir,
        1024 * 1024 * 1024 + 1536,
        512,
        "sync",
        true,
    );

    // 5. Cell: T1.4kn (4Kn lbs geometry)
    run_t1_cell(
        "T1.4kn",
        &scratch_dir,
        1024 * 1024 * 1024 + 12288,
        4096,
        "auto",
        false,
    );

    println!("\n[=== T1 ZERO-TRUST TEST SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_t1_cell(
    cell_name: &str,
    scratch_dir: &Path,
    size_bytes: u64,
    lbs: u32,
    engine: &str,
    no_write_zeroes: bool,
) {
    println!("\n[>>> RUNNING CELL: {} (Size: {} B, LBS: {} B, Engine: {}) <<<]", cell_name, size_bytes, lbs, engine);

    let test_run_dir = scratch_dir.join(format!("t1_run_{}_{}", cell_name, std::process::id()));
    let _ = fs::create_dir_all(&test_run_dir);

    let backing_path = test_run_dir.join("backing.raw");

    // Phase A5: Sentinel pre-fill (0xA5)
    SentinelManager::fill_sentinel(&backing_path, size_bytes)
        .unwrap_or_else(|e| panic!("[A5-FILL] {}", e));

    // Phase A6: Acquire loop device
    let loop_dev = LoopDevice::create_and_attach(&backing_path, size_bytes, lbs)
        .unwrap_or_else(|e| panic!("[A6-ATTACH] {}", e));

    println!("  [+] Attached loop device: {}", loop_dev.dev_path.display());

    // Phase A8: Sentinel pre-check through loop
    SentinelManager::verify_sentinel_pre_check(&loop_dev.dev_path, size_bytes)
        .unwrap_or_else(|e| panic!("[A8-SPOT] {}", e));

    // Phase A9: Record Fingerprint
    let fingerprint = EnvironmentFingerprint::collect(
        loop_dev.minor,
        loop_dev.logical_block_size,
        loop_dev.physical_block_size,
        loop_dev.size_bytes,
        loop_dev.write_zeroes_max_bytes,
        scratch_dir,
    );
    let _ = fs::write(
        test_run_dir.join("fingerprint.json"),
        serde_json::to_string_pretty(&fingerprint).unwrap(),
    );

    // Phase B1: Execute diskcleaner
    let out_dir = test_run_dir.join("output");
    let _ = fs::create_dir_all(&out_dir);

    let loop_name = format!("loop{}", loop_dev.minor);
    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--profile")
        .arg("clear-zero")
        .arg("--engine")
        .arg(engine)
        .arg("--serial-confirm")
        .arg(&loop_name)
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1");

    if no_write_zeroes {
        cmd.arg("--no-write-zeroes");
    }

    let assert_res = cmd.assert();
    let output = assert_res.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        let dump_path = ArtifactsDumper::dump_failure_bundle(
            cell_name,
            &test_run_dir,
            &backing_path,
            &stdout,
            &stderr,
            None,
        );
        panic!(
            "[B4-EXIT] Execution failed with exit code {:?}. Failure bundle preserved at: {}",
            output.status.code(),
            dump_path.display()
        );
    }

    // Phase C1: Journal Oracle
    let total_windows = (size_bytes + (2 * 1024 * 1024) - 1) / (2 * 1024 * 1024);
    let journal_path = find_single_file_with_ext(&out_dir, "dcj")
        .unwrap_or_else(|| panic!("[C1-JOURNAL] Journal file not found in {}", out_dir.display()));

    let journal_report = JournalOracle::parse_and_validate(&journal_path, total_windows)
        .unwrap_or_else(|e| {
            let dump = ArtifactsDumper::dump_failure_bundle(cell_name, &test_run_dir, &backing_path, &stdout, &stderr, None);
            panic!("[C1-CHAIN] {} (Dump: {})", e, dump.display())
        });

    // Phase C2: Cert Oracle
    let cert_path = find_single_file_with_ext(&out_dir, "json")
        .unwrap_or_else(|| panic!("[C2-CERT] Certificate file not found in {}", out_dir.display()));

    let cert_report = CertOracle::parse_and_validate(
        &cert_path,
        &journal_report.chain_head,
        loop_dev.write_zeroes_max_bytes,
    )
    .unwrap_or_else(|e| {
        let dump = ArtifactsDumper::dump_failure_bundle(cell_name, &test_run_dir, &backing_path, &stdout, &stderr, None);
        panic!("[C2-CERT] {} (Dump: {})", e, dump.display())
    });

    // Phase C3: Media Oracle (Sequential O_DIRECT of backing file)
    let media_result = SentinelManager::verify_zero_media_oracle(&backing_path, size_bytes)
        .unwrap_or_else(|e| {
            let dump = ArtifactsDumper::dump_failure_bundle(cell_name, &test_run_dir, &backing_path, &stdout, &stderr, None);
            panic!("[C3-MEDIA] {} (Dump: {})", e, dump.display())
        });

    if !media_result.all_zeros {
        let dump = ArtifactsDumper::dump_failure_bundle(
            cell_name,
            &test_run_dir,
            &backing_path,
            &stdout,
            &stderr,
            media_result.first_mismatch_offset,
        );
        panic!(
            "[C3-MEMCMP] Non-zero byte 0x{:02X} found at offset {}! (Dump: {})",
            media_result.first_mismatch_byte.unwrap_or(0),
            media_result.first_mismatch_offset.unwrap_or(0),
            dump.display()
        );
    }

    // Phase C3: Triple Hash Oracle
    assert_eq!(
        media_result.harness_stream_hash, cert_report.stream_hash_blake3,
        "[C3-HASH] Harness stream hash does not match cert stream hash!"
    );
    assert_eq!(
        media_result.harness_stream_hash, media_result.expected_zeros_hash,
        "[C3-HASH] Harness stream hash does not match independent zero hash!"
    );

    // Phase C4: Dual-view cross-check
    SentinelManager::verify_dual_view_cross_check(&loop_dev.dev_path, size_bytes)
        .unwrap_or_else(|e| {
            let dump = ArtifactsDumper::dump_failure_bundle(cell_name, &test_run_dir, &backing_path, &stdout, &stderr, None);
            panic!("[C4-VIEW] {} (Dump: {})", e, dump.display())
        });

    println!("  [✓] Cell {} PASSED: All 16 Kill-Obligations Satisfied.", cell_name);
}

fn run_negative_tests(scratch_dir: &Path) {
    println!("\n[>>> RUNNING NEGATIVE CELLS (N1 & N2) <<<]");

    let test_dir = scratch_dir.join(format!("t1_neg_{}", std::process::id()));
    let _ = fs::create_dir_all(&test_dir);
    let backing = test_dir.join("neg_backing.raw");

    SentinelManager::fill_sentinel(&backing, 1024 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 1024 * 1024 * 1024, 512).unwrap();

    // N1: Wrong token -> exit 8, sentinel intact
    let mut cmd1 = Command::cargo_bin("diskcleaner").unwrap();
    cmd1.arg("execute")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--profile")
        .arg("clear-zero")
        .arg("--serial-confirm")
        .arg("WRONG_CONFIRM_TOKEN")
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&test_dir)
        .arg("--no-progress");

    cmd1.assert().code(8);

    // Verify sentinel still untouched
    SentinelManager::verify_sentinel_pre_check(&loop_dev.dev_path, 1024 * 1024 * 1024)
        .expect("[N1-CHECK] Sentinel was modified after confirmation mismatch!");
    println!("  [✓] N1 PASSED: Wrong confirmation token refused without writing.");

    // N2: Omit --allow-loop -> exit 2 (LOOP refusal), sentinel intact
    let loop_name = format!("loop{}", loop_dev.minor);
    let mut cmd2 = Command::cargo_bin("diskcleaner").unwrap();
    cmd2.arg("execute")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--profile")
        .arg("clear-zero")
        .arg("--serial-confirm")
        .arg(&loop_name)
        .arg("--out-dir")
        .arg(&test_dir)
        .arg("--no-progress");

    cmd2.assert().code(2);

    SentinelManager::verify_sentinel_pre_check(&loop_dev.dev_path, 1024 * 1024 * 1024)
        .expect("[N2-CHECK] Sentinel was modified when --allow-loop was omitted!");
    println!("  [✓] N2 PASSED: Loop device correctly refused without --allow-loop flag.");
}

fn find_single_file_with_ext(dir: &Path, ext: &str) -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some(ext) {
                return Some(p);
            }
        }
    }
    None
}
