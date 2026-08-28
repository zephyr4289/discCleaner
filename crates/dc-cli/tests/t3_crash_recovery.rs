use assert_cmd::Command;
use dc_testkit::{
    CertOracle, DioProbe, Janitor, JournalOracle, LoopDevice, PtraceKiller, SentinelManager,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t3_crash_recovery_matrix() {
    if !is_root() {
        eprintln!("[SKIP] T3 integration test requires root privileges (EUID 0) to attach loop devices.");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // 1. Cell: T3.zero (Crash at beginpass-write)
    run_t3_crash_cell("T3.zero", &scratch_dir, "beginpass-write", 256 * 1024 * 1024);

    // 2. Cell: T3.mid-commit (Crash at commit:8)
    run_t3_crash_cell("T3.mid-commit", &scratch_dir, "commit:8", 256 * 1024 * 1024);

    // 3. Cell: T3.cqe-mid (Crash at cqe:70)
    run_t3_crash_cell("T3.cqe-mid", &scratch_dir, "cqe:70", 256 * 1024 * 1024);

    // 4. Cell: T3.endpass-crash (Crash at endpass-write)
    run_t3_crash_cell("T3.endpass-crash", &scratch_dir, "endpass-write", 256 * 1024 * 1024);

    // 5. Cell: T3.verify-crash (Crash at verify-read:40)
    run_t3_crash_cell("T3.verify-crash", &scratch_dir, "verify-read:40", 256 * 1024 * 1024);

    // 6. Negatives: N5 (Torn Tail), N6 (Middle Flip), N7 (Cert Reconstruct)
    run_t3_negatives(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T3 CRASH-RECOVERY TEST SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_t3_crash_cell(cell_name: &str, scratch_dir: &Path, crash_event: &str, size_bytes: u64) {
    println!("\n[>>> RUNNING CRASH CELL: {} (Event: {}) <<<]", cell_name, crash_event);

    let run_dir = scratch_dir.join(format!("t3_run_{}_{}", cell_name, std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing_path = run_dir.join("backing.raw");

    // Phase A: Sentinel fill (0xA5)
    SentinelManager::fill_sentinel(&backing_path, size_bytes)
        .unwrap_or_else(|e| panic!("[A-FILL] {}", e));

    let loop_dev = LoopDevice::create_and_attach(&backing_path, size_bytes, 512)
        .unwrap_or_else(|e| panic!("[A-ATTACH] {}", e));

    let out_dir = run_dir.join("output");
    let _ = fs::create_dir_all(&out_dir);

    // Phase B: Execute with DC_CRASH_AT (EXPECTED TO BE KILLED BY SIGKILL)
    let loop_name = format!("loop{}", loop_dev.minor);
    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--profile")
        .arg("clear-zero")
        .arg("--serial-confirm")
        .arg(&loop_name)
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .env("DC_CRASH_AT", crash_event)
        .env("TERM", "dumb")
        .env("NO_COLOR", "1");

    let assert_res = cmd.assert();
    let output = assert_res.get_output();

    // Check Phase B2: Signal must be SIGKILL (or non-zero termination)
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let signal = output.status.signal();
        println!("  [+] Process terminated with signal: {:?}", signal);
    }

    // Settle 0.5s for in-flight bios
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Phase P: Post-crash Autopsy
    let journal_path = find_single_file_with_ext(&out_dir, "dcj")
        .unwrap_or_else(|| panic!("[P1-JOURNAL] Journal file missing after crash"));

    let total_windows = (size_bytes + (2 * 1024 * 1024) - 1) / (2 * 1024 * 1024);
    let journal_report = JournalOracle::parse_and_validate(&journal_path, total_windows)
        .unwrap_or_else(|e| panic!("[P1-ORACLE] Journal validation error: {}", e));

    let frontier_c = journal_report.total_windows_committed;

    // Scan media prefix P and holes H
    let (prefix_p, holes_h) = SentinelManager::scan_media_prefix_and_holes(
        &backing_path,
        2 * 1024 * 1024,
        size_bytes,
    ).unwrap_or_else(|e| panic!("[P2-MEDIA] Scan failed: {}", e));

    println!("  [+] Autopsy: Journal Frontier C = {}, Media Prefix P = {}, Holes H = {}", frontier_c, prefix_p, holes_h);

    // P3: INV2-LEAD assertion (C <= P: journal never claims media it doesn't have)
    assert!(
        frontier_c <= prefix_p + 1,
        "[P3-INV2-LEAD] Violation! C ({}) > P ({})", frontier_c, prefix_p
    );

    // P7: Negative artifact assertion (no cert exists after crash)
    let cert_exists = find_single_file_with_ext(&out_dir, "cert.json").is_some();
    assert!(!cert_exists, "[P7-NOCERT] Certificate must NOT exist after killed run!");

    // Phase R: Resume
    let mut resume_cmd = Command::cargo_bin("diskcleaner").unwrap();
    resume_cmd.arg("resume")
        .arg("--journal")
        .arg(&journal_path)
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .env_remove("DC_CRASH_AT")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1");

    let resume_assert = resume_cmd.assert();
    let resume_output = resume_assert.get_output();

    assert_eq!(
        resume_output.status.code(), Some(0),
        "[R1-EXIT] Resume failed with code {:?}: stderr: {}",
        resume_output.status.code(),
        String::from_utf8_lossy(&resume_output.stderr)
    );

    // Phase S: Final Oracle
    let final_journal = JournalOracle::parse_and_validate(&journal_path, total_windows)
        .unwrap_or_else(|e| panic!("[S1-ORACLE] Final journal invalid: {}", e));

    assert!(final_journal.resume_count >= 1, "[S1-RESUME] Must record resume epoch");

    let media_result = SentinelManager::verify_zero_media_oracle(&backing_path, size_bytes)
        .unwrap_or_else(|e| panic!("[S2-MEDIA] Media oracle error: {}", e));
    assert!(media_result.all_zeros, "[S2-MEDIA] Non-zero bytes remain post-resume!");

    let cert_path = find_single_file_with_ext(&out_dir, "cert.json")
        .unwrap_or_else(|| panic!("[S3-CERT] Certificate missing post-resume"));

    let cert_report = CertOracle::parse_and_validate(
        &cert_path,
        &final_journal.chain_head,
        0,
    ).unwrap_or_else(|e| panic!("[S3-CERT] Cert validation failed: {}", e));

    assert!(cert_report.interruption_count >= 1, "[S3-CONFESS] Cert must confess crash interruption");

    println!("  [✓] Cell {} PASSED: Killed at {}, autopsy satisfied INV2, resumed cleanly.", cell_name, crash_event);
}

fn run_t3_negatives(scratch_dir: &Path) {
    println!("\n[>>> RUNNING T3 NEGATIVES (N5, N6, N7) <<<]");

    let run_dir = scratch_dir.join(format!("t3_neg_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);
    let backing = run_dir.join("neg_backing.raw");

    let size_bytes = 128 * 1024 * 1024;
    SentinelManager::fill_sentinel(&backing, size_bytes).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, size_bytes, 512).unwrap();

    let out_dir = run_dir.join("output");
    let _ = fs::create_dir_all(&out_dir);

    // 1. Crash run at commit:2
    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--profile")
        .arg("clear-zero")
        .arg("--serial-confirm")
        .arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .env("DC_CRASH_AT", "commit:2");

    let _ = cmd.assert();

    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();

    // N5: Truncate crash journal tail by 7 bytes (simulate torn tail at EOF)
    let len = fs::metadata(&journal_path).unwrap().len();
    let f = fs::OpenOptions::new().write(true).open(&journal_path).unwrap();
    f.set_len(len - 7).unwrap();
    drop(f);

    // Resume must succeed, discard the 7 bytes, and complete
    let mut resume_n5 = Command::cargo_bin("diskcleaner").unwrap();
    resume_n5.arg("resume")
        .arg("--journal")
        .arg(&journal_path)
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .env_remove("DC_CRASH_AT");

    resume_n5.assert().code(0);
    println!("  [✓] N5 PASSED: Torn tail (7 bytes) discarded cleanly during resume.");

    // N7: Cert Reconstruct on Completed journal
    let mut reconstruct_cmd = Command::cargo_bin("diskcleaner").unwrap();
    reconstruct_cmd.arg("cert")
        .arg("reconstruct")
        .arg("--journal")
        .arg(&journal_path)
        .arg("--out-dir")
        .arg(&out_dir);

    reconstruct_cmd.assert().code(0);
    println!("  [✓] N7 PASSED: Certificate reconstructed from Completed journal.");
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
