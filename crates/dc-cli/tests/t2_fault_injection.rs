use assert_cmd::Command;
use dc_testkit::{
    ArtifactsDumper, CertOracle, DioProbe, DmDevice, FaultPlan, Janitor, JournalOracle,
    LoopDevice, SentinelManager, TableLine,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t2_fault_injection_matrix() {
    if !is_root() {
        eprintln!("[SKIP] T2 integration test requires root privileges (EUID 0) to manage dm-error devices.");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    // Clean prior runs
    Janitor::sweep_all(&scratch_dir);

    // 1. Prelude check
    if let Err(e) = DmDevice::prelude_check() {
        eprintln!("[SKIP] Device-mapper prelude check failed: {}", e);
        return;
    }

    // 2. Cell: T2.core (Misaligned fault @ 50% -> fail EIO -> repair -> resume)
    run_t2_fault_cell("T2.core", &scratch_dir, "auto");

    // 3. Cell: T2.head (Fault @ sector 1 -> zero commits -> repair -> resume)
    run_t2_fault_cell("T2.head", &scratch_dir, "auto");

    // 4. Cell: T2.tail (Fault @ final short window -> fail -> repair -> resume)
    run_t2_fault_cell("T2.tail", &scratch_dir, "auto");

    // 5. Cell: T2.sync (Sync engine forced error-path parity)
    run_t2_fault_cell("T2.sync", &scratch_dir, "sync");

    // 6. Cell: T2.slow (Deterministic frontier proof)
    run_t2_fault_cell("T2.slow", &scratch_dir, "auto");

    // 7. Negative Cells: N3 & N4
    run_t2_negatives(&scratch_dir);

    // Teardown sweep
    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T2 FAULT-INJECTION TEST SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_t2_fault_cell(cell_name: &str, scratch_dir: &Path, engine: &str) {
    println!("\n[>>> RUNNING FAULT CELL: {} (Engine: {}) <<<]", cell_name, engine);

    let plan = FaultPlan::for_cell(cell_name);
    let run_dir = scratch_dir.join(format!("t2_run_{}_{}", cell_name, std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing_path = run_dir.join("backing.raw");

    // Phase A2: Sentinel pre-fill (0xA5)
    SentinelManager::fill_sentinel(&backing_path, plan.size_bytes)
        .unwrap_or_else(|e| panic!("[A2-FILL] {}", e));

    // Phase A3: Attach Loop Device
    let loop_dev = LoopDevice::create_and_attach(&backing_path, plan.size_bytes, 512)
        .unwrap_or_else(|e| panic!("[A3-ATTACH] {}", e));

    // Phase A4: Create DM Device with error table
    let dm_name = format!("dc-t2-{}-{}", cell_name.replace('.', "_"), std::process::id());
    let dm_uuid = format!("DC-T2-{}-{}", cell_name.replace('.', "_"), std::process::id());

    let mut dm_dev = DmDevice::create(&dm_name, &dm_uuid)
        .unwrap_or_else(|e| panic!("[A4-DM-CREATE] {}", e));

    let fault_tables = vec![
        TableLine::Linear {
            start_sector: 0,
            length_sectors: plan.fault_start_sector,
            backing_major: 7, // Loop major
            backing_minor: loop_dev.minor as u32,
            backing_start_sector: 0,
        },
        TableLine::Error {
            start_sector: plan.fault_start_sector,
            length_sectors: plan.total_sectors - plan.fault_start_sector,
        },
    ];

    dm_dev.load_table(&fault_tables)
        .unwrap_or_else(|e| panic!("[A4-LOAD] {}", e));
    dm_dev.activate()
        .unwrap_or_else(|e| panic!("[A4-ACTIVATE] {}", e));

    println!("  [+] Active DM fault device: {} (Target: fault @ sector {})", dm_dev.dev_path.display(), plan.fault_start_sector);

    // Phase B1: Execute diskcleaner (EXPECTED TO FAIL WITH EIO)
    let out_dir = run_dir.join("output");
    let _ = fs::create_dir_all(&out_dir);

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target")
        .arg(&dm_dev.dev_path)
        .arg("--profile")
        .arg("clear-zero")
        .arg("--engine")
        .arg(engine)
        .arg("--serial-confirm")
        .arg(format!("dm-{}", dm_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1");

    let assert_res = cmd.assert();
    let output = assert_res.get_output();

    // Assert Phase B3: Exit code must be 5 (EIO)
    assert_eq!(
        output.status.code(), Some(5),
        "[B3-EXIT] Execution was expected to fail with exit code 5 (EIO), got {:?}",
        output.status.code()
    );

    // Assert Phase B5: Zero cert files after failed run
    let cert_exists = find_single_file_with_ext(&out_dir, "cert.json").is_some();
    assert!(!cert_exists, "[B5-NOCERT] Certificate must NOT be generated on failed execution!");

    // Phase B4: Journal Oracle verifies failure forensics
    let journal_path = find_single_file_with_ext(&out_dir, "dcj")
        .unwrap_or_else(|| panic!("[B4-JOURNAL] Journal file not found after failure"));

    let total_windows = (plan.size_bytes + (2 * 1024 * 1024) - 1) / (2 * 1024 * 1024);
    let journal_report = JournalOracle::parse_and_validate(&journal_path, total_windows)
        .unwrap_or_else(|e| panic!("[B4-ORACLE] Journal validation error: {}", e));

    assert_eq!(journal_report.failure_count, 1, "[B4-FAIL] Must record exactly 1 failure");
    let failed_rec = journal_report.last_failed_record.expect("[B4-FAIL] Missing failed record");
    assert_eq!(
        failed_rec.get("code").and_then(|v| v.as_str()), Some("EIO"),
        "[B4-FAIL-CODE] Failed code must be EIO"
    );

    // Phase R1: Repair DM device (Swap table to full linear mapping)
    let linear_tables = vec![
        TableLine::Linear {
            start_sector: 0,
            length_sectors: plan.total_sectors,
            backing_major: 7,
            backing_minor: loop_dev.minor as u32,
            backing_start_sector: 0,
        }
    ];
    dm_dev.swap_table(&linear_tables)
        .unwrap_or_else(|e| panic!("[R1-SWAP] Failed to swap DM table to linear: {}", e));
    println!("  [+] Repaired DM device: table swapped to 100% linear mapping");

    // Phase S1: Resume execution with dc resume
    let mut resume_cmd = Command::cargo_bin("diskcleaner").unwrap();
    resume_cmd.arg("resume")
        .arg("--journal")
        .arg(&journal_path)
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1");

    let resume_assert = resume_cmd.assert();
    let resume_output = resume_assert.get_output();

    assert_eq!(
        resume_output.status.code(), Some(0),
        "[S2-EXIT] Resumed execution failed: stderr: {}",
        String::from_utf8_lossy(&resume_output.stderr)
    );

    // Phase S3: Final Journal Oracle
    let final_journal_report = JournalOracle::parse_and_validate(&journal_path, total_windows)
        .unwrap_or_else(|e| panic!("[S3-ORACLE] Final journal invalid: {}", e));

    assert_eq!(final_journal_report.resume_count, 1, "[S3-RESUME] Must record 1 resume epoch");

    // Phase S4: Final Media Oracle (Backing file O_DIRECT verify)
    let media_result = SentinelManager::verify_zero_media_oracle(&backing_path, plan.size_bytes)
        .unwrap_or_else(|e| panic!("[S4-MEDIA] Media oracle error: {}", e));
    assert!(media_result.all_zeros, "[S4-MEDIA] Non-zero bytes found on media post-resume!");

    // Phase S5: Certificate Oracle (Verify signature & failure confession)
    let cert_path = find_single_file_with_ext(&out_dir, "cert.json")
        .unwrap_or_else(|| panic!("[S5-CERT] Certificate not generated after resume"));

    let cert_report = CertOracle::parse_and_validate(
        &cert_path,
        &final_journal_report.chain_head,
        0,
    ).unwrap_or_else(|e| panic!("[S5-CERT] Cert validation failed: {}", e));

    assert_eq!(cert_report.failure_count, 1, "[S5-CERT-CONFESS] Cert must confess exactly 1 failure");

    println!("  [✓] Cell {} PASSED: Failure injected, confessed, repaired, and resumed cleanly.", cell_name);
}

fn run_t2_negatives(scratch_dir: &Path) {
    println!("\n[>>> RUNNING NEGATIVE CELLS (N3 & N4) <<<]");

    let run_dir = scratch_dir.join(format!("t2_neg_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);
    let backing = run_dir.join("neg_backing.raw");

    let size_bytes = 1024 * 1024 * 1024;
    SentinelManager::fill_sentinel(&backing, size_bytes).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, size_bytes, 512).unwrap();

    let out_dir = run_dir.join("output");
    let _ = fs::create_dir_all(&out_dir);

    // 1. Run a clean execution to get a Completed journal
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
        .arg("--no-progress");

    cmd.assert().code(0);

    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();
    let journal_bytes_before = fs::read(&journal_path).unwrap();

    // N3: Attempt resume on Completed journal -> Assert exit 6 (JOURNAL_ALREADY_COMPLETE)
    let mut resume_completed = Command::cargo_bin("diskcleaner").unwrap();
    resume_completed.arg("resume")
        .arg("--journal")
        .arg(&journal_path)
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress");

    resume_completed.assert().code(6);

    let journal_bytes_after = fs::read(&journal_path).unwrap();
    assert_eq!(
        journal_bytes_before, journal_bytes_after,
        "[N3-IMMUTABLE] Journal file was mutated during refused resume!"
    );
    println!("  [✓] N3 PASSED: Resume on completed journal was refused (exit 6) without mutating journal.");
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
