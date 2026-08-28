use assert_cmd::Command;
use dc_testkit::{
    DioProbe, EnduranceLedger, GenBench, HardwareManifest, Janitor, LoopDevice, ManifestDrive,
    ScaleOracle, SentinelManager, TestIdentityReader,
};
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t10_hardware_verification_matrix() {
    // 1. T10.prelude: Pure host benchmark and manifest validation (runs unprivileged)
    run_t10_prelude_pure();

    if !is_root() {
        eprintln!("[SKIP] T10 E2E scale and verify cells require root privileges (EUID 0). Prelude passed.");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // 2. T10.verify: Adoption of the orphan subcommand `dc verify --journal`
    run_t10_verify_orphan_adoption(&scratch_dir);

    // 3. T10.scale & T10.media: Stratified cleanroom scale verification
    run_t10_scale_and_media(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T10 BARE-METAL THROUGHPUT & TRUTH SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_t10_prelude_pure() {
    println!("\n[>>> T10 PRELUDE: Testing Host GenBench & Manifest Pinning (Δ76, Δ78) <<<]");

    // 1. Host GenBench capacity
    let bench = GenBench::benchmark(100);
    println!(
        "  [✓] GenBench: Single-Core {:.2} GiB/s, Host Total {:.2} GiB/s across {} threads.",
        bench.single_core_gib_s, bench.estimated_host_capacity_gib_s, bench.num_threads
    );
    assert!(bench.single_core_gib_s > 0.01);

    // 2. Hardware Manifest Pinning (Δ78)
    let manifest = HardwareManifest {
        drives: vec![ManifestDrive {
            serial: "SACRIFICIAL-NVME-001".to_string(),
            model: "Samsung SSD 980 PRO 1TB".to_string(),
            size_bytes: 1_000_000_000_000,
            tbw_rated_tb: 600,
        }],
    };

    // Valid drive in manifest
    assert!(manifest.verify_manifest_pinning("SACRIFICIAL-NVME-001").is_ok());

    // Host boot disk NOT in manifest -> MUST REFUSE (Guardian safety)
    let boot_disk_attempt = manifest.verify_manifest_pinning("HOST-BOOT-DRIVE-SDA-000");
    assert!(boot_disk_attempt.is_err(), "[MANIFEST-FAIL] Allowed unlisted host boot disk!");
    println!("  [✓] Hardware Manifest: Unlisted host boot disks strictly refused.");

    // 3. Endurance Ledger (Δ76)
    let temp_dir = tempfile::tempdir().unwrap();
    let ledger_path = temp_dir.path().join("endurance.json");
    let mut ledger = EnduranceLedger::load_or_init(&ledger_path, "SACRIFICIAL-NVME-001");

    let drive = manifest.verify_manifest_pinning("SACRIFICIAL-NVME-001").unwrap();
    assert!(ledger.check_budget(drive).is_ok());

    // Simulate 700 TB written (exceeding 80% of 600 TBW)
    ledger.cumulative_bytes_written = 500_000_000_000_000;
    assert!(ledger.check_budget(drive).is_err(), "[ENDURANCE-FAIL] Allowed run on exhausted drive!");
    println!("  [✓] Endurance Ledger: Wear budget limit (>80% TBW) cleanly halts execution.");
}

fn run_t10_verify_orphan_adoption(scratch_dir: &Path) {
    println!("\n[>>> T10.verify: Adopting Orphaned `dc verify --journal` (Δ75) <<<]");

    let run_dir = scratch_dir.join(format!("t10_verify_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing.raw");
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    let key_path = run_dir.join("operator.key");
    let mut keygen = Command::cargo_bin("diskcleaner").unwrap();
    keygen.arg("keygen").arg("--out").arg(&key_path);
    keygen.assert().code(0);

    let out_dir = run_dir.join("output");
    let _ = fs::create_dir_all(&out_dir);

    let fixed_seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let plan_path = run_dir.join("plan.json");

    let mut plan_cmd = Command::cargo_bin("diskcleaner").unwrap();
    plan_cmd.arg("plan")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-random")
        .arg("--seed").arg(fixed_seed)
        .arg("--out").arg(&plan_path);
    plan_cmd.assert().code(0);

    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--plan").arg(&plan_path)
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--key").arg(&key_path)
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    exec_cmd.assert().code(0);

    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();

    // 1. First run: Clean verification from journal -> MUST EXIT 0
    let mut verify_clean = Command::cargo_bin("diskcleaner").unwrap();
    verify_clean.arg("verify")
        .arg("--journal").arg(&journal_path)
        .arg("--target").arg(&loop_dev.dev_path);
    verify_clean.assert().code(0);
    println!("  [✓] dc verify --journal passed cleanly on verified wiped disk.");

    // 2. Plant 4 KiB corruption at LBA 1024 (Offset 512 KiB)
    let mut f = fs::OpenOptions::new().write(true).open(&loop_dev.dev_path).unwrap();
    f.seek(SeekFrom::Start(512 * 1024)).unwrap();
    f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    f.sync_all().unwrap();
    drop(f);

    // 3. Second run: Verification on tampered disk -> MUST EXIT 4 and locate mismatch
    let mut verify_tampered = Command::cargo_bin("diskcleaner").unwrap();
    verify_tampered.arg("verify")
        .arg("--journal").arg(&journal_path)
        .arg("--target").arg(&loop_dev.dev_path);

    let output = verify_tampered.assert().code(4).get_output().stderr.clone();
    let stderr = String::from_utf8_lossy(&output);
    assert!(stderr.contains("Verification failed"), "[VERIFY-FAIL] Did not report verification failure!");

    println!("  [✓] dc verify --journal successfully caught planted corruption; exited with code 4.");
}

fn run_t10_scale_and_media(scratch_dir: &Path) {
    println!("\n[>>> T10.scale & T10.media: Testing Stratified Scale Verification <<<]");

    let run_dir = scratch_dir.join(format!("t10_scale_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing_scale.raw");
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("output_scale");
    let _ = fs::create_dir_all(&out_dir);

    let fixed_seed = [0x77u8; 32];
    let fixed_seed_hex = hex::encode(fixed_seed);
    let plan_path = run_dir.join("plan_scale.json");

    let mut plan_cmd = Command::cargo_bin("diskcleaner").unwrap();
    plan_cmd.arg("plan")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-random")
        .arg("--seed").arg(&fixed_seed_hex)
        .arg("--out").arg(&plan_path);
    plan_cmd.assert().code(0);

    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--plan").arg(&plan_path)
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    exec_cmd.assert().code(0);

    // Stratified scale verification
    let scale_res = ScaleOracle::verify_stratified_windows(
        Path::new(&loop_dev.dev_path),
        &fixed_seed,
        64 * 1024 * 1024,
        2 * 1024 * 1024,
    ).expect("[SCALE-FAIL] Stratified cleanroom scale check failed!");

    assert!(scale_res);
    println!("  [✓] T10.scale: Stratified cleanroom memory verification passed across all windows.");
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
