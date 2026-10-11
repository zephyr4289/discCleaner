//! T14 FLEET PARALLEL + HARDWARE PURGE MATRIX
//! ===========================================
//! Root-gated integration suite for the fleet-grade execution features:
//! - Parallel multi-device wiping (the wall-clock multiplier feature)
//! - All-or-nothing batch arming (REG-MULTI-ARM-ALLORNOTHING full version)
//! - Sampled verification through the real CLI (REG-SAMPLED-VERIFY-CLI)
//! - Hardware purge guards on non-NVMe media (REG-PURGE-NVME-ONLY)
//! - Engine benchmark safety contract (REG-BENCH-SAFETY)
//!
//! Layer: real CLI binary over real loop devices, mirroring T11's rig.

use assert_cmd::Command;
use dc_testkit::{DioProbe, Janitor, LoopDevice, SentinelManager};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn find_all_files_with_ext(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file() && p.extension().map(|x| x == ext).unwrap_or(false) {
                out.push(p);
            }
        }
    }
    out
}

fn is_all_zero(path: &Path) -> bool {
    // Sampled zero check: first/last MiB + middle offset.
    let len = fs::metadata(path).unwrap().len();
    let mut f = fs::File::open(path).unwrap();
    use std::io::{Read, Seek};
    let mut probe = |off: u64| -> bool {
        let mut buf = vec![0u8; 64 * 1024];
        f.seek(std::io::SeekFrom::Start(
            off.min(len.saturating_sub(buf.len() as u64)),
        ))
        .unwrap();
        f.read_exact(&mut buf).is_ok() && buf.iter().all(|&b| b == 0)
    };
    probe(0) && probe(len / 2) && probe(len.saturating_sub(64 * 1024))
}

#[test]
fn test_t14_fleet_parallel_and_purge_matrix() {
    if !is_root() {
        eprintln!("[SKIP] T14 fleet parallel matrix requires root privileges (EUID 0).");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };
    Janitor::sweep_all(&scratch_dir);

    run_f1_parallel_batch_wipe(&scratch_dir);
    run_f2_all_or_nothing_precheck(&scratch_dir);
    run_f3_multi_dry_run(&scratch_dir);
    run_f4_token_mismatch_aborts_batch(&scratch_dir);
    run_f5_sampled_verify_cli(&scratch_dir);
    run_f6_purge_guards(&scratch_dir);
    run_f7_bench_safety(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T14 FLEET PARALLEL + PURGE SUITE PASSED ALL MATRIX CELLS ===]\n");
}

/// F1: two devices wiped in ONE invocation come back zeroed, each with its own
/// journal and certificate, exit 0, and a batch summary listing both.
fn run_f1_parallel_batch_wipe(scratch_dir: &Path) {
    println!("\n[>>> F1: Parallel multi-device batch wipe <<<]");
    let run_dir = scratch_dir.join(format!("t14_f1_{}", std::process::id()));
    fs::create_dir_all(&run_dir).unwrap();

    let backing_a = run_dir.join("a.raw");
    let backing_b = run_dir.join("b.raw");
    SentinelManager::fill_sentinel(&backing_a, 32 * 1024 * 1024).unwrap();
    SentinelManager::fill_sentinel(&backing_b, 32 * 1024 * 1024).unwrap();
    let loop_a = LoopDevice::create_and_attach(&backing_a, 32 * 1024 * 1024, 512).unwrap();
    let loop_b = LoopDevice::create_and_attach(&backing_b, 32 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let out = Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("execute")
        .arg("--target")
        .arg(&loop_a.dev_path)
        .arg("--target")
        .arg(&loop_b.dev_path)
        .arg("--profile")
        .arg("nist-clear")
        .arg("--serial-confirm")
        .arg(format!("loop{},loop{}", loop_a.minor, loop_b.minor))
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(stdout.contains("BATCH SANITIZATION SUMMARY"), "{}", stdout);

    let journals = find_all_files_with_ext(&out_dir, "dcj");
    let certs = find_all_files_with_ext(&out_dir, "json")
        .into_iter()
        .filter(|p| p.to_string_lossy().contains(".cert."))
        .collect::<Vec<_>>();
    assert_eq!(journals.len(), 2, "one journal per device");
    assert_eq!(certs.len(), 2, "one certificate per device");

    assert!(is_all_zero(&backing_a), "device A must read back zeroed");
    assert!(is_all_zero(&backing_b), "device B must read back zeroed");
    println!("  [✓] F1: 2 devices wiped in one invocation; 2 journals + 2 certs; both zeroed.");
}

/// F2 (REG-MULTI-ARM-ALLORNOTHING): a batch containing one unprobable target
/// refuses BEFORE any device is armed — the first device's sentinel survives.
fn run_f2_all_or_nothing_precheck(scratch_dir: &Path) {
    println!("\n[>>> F2: REG-MULTI-ARM-ALLORNOTHING (batch precheck) <<<]");
    let run_dir = scratch_dir.join(format!("t14_f2_{}", std::process::id()));
    fs::create_dir_all(&run_dir).unwrap();

    let backing = run_dir.join("a.raw");
    SentinelManager::fill_sentinel(&backing, 32 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 32 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let out = Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("execute")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--target")
        .arg("/dev/nonexistent-disk-zz")
        .arg("--profile")
        .arg("nist-clear")
        .arg("--serial-confirm")
        .arg(format!("loop{},whatever", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .assert();

    assert_eq!(
        out.get_output().status.code(),
        Some(2),
        "batch with an unprobable target must refuse with the Guardian exit code"
    );
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(
        stderr.contains("BATCH ABORTED"),
        "stderr must explain the all-or-nothing abort: {}",
        stderr
    );

    let journals = find_all_files_with_ext(&out_dir, "dcj");
    assert!(
        journals.is_empty(),
        "no journal may exist after batch abort"
    );
    assert!(
        !is_all_zero(&backing),
        "the surviving device must NOT have been touched"
    );
    println!("  [✓] F2: bad target aborts the batch; good device sentinel intact, no journal.");
}

/// F3: multi-device dry run lists every target and creates no journals.
fn run_f3_multi_dry_run(scratch_dir: &Path) {
    println!("\n[>>> F3: Multi-device dry run <<<]");
    let run_dir = scratch_dir.join(format!("t14_f3_{}", std::process::id()));
    fs::create_dir_all(&run_dir).unwrap();

    let backing = run_dir.join("a.raw");
    SentinelManager::fill_sentinel(&backing, 16 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 16 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let out = Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("execute")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--target")
        .arg(&loop_dev.dev_path) // same device twice is legal for dry-run listing
        .arg("--profile")
        .arg("certin-goi")
        .arg("--allow-loop")
        .arg("--dry-run")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(stdout.contains("DRY RUN"), "{}", stdout);
    assert!(stdout.contains("Devices in batch: 2"), "{}", stdout);
    assert!(stdout.contains("Passes Count:      3"), "{}", stdout);
    assert!(
        find_all_files_with_ext(&out_dir, "dcj").is_empty(),
        "dry runs create no journals"
    );
    println!("  [✓] F3: dry run lists both targets, no journal created.");
}

/// F4: a wrong token in --serial-confirm aborts the whole batch BEFORE
/// arming — sentinels intact on every device.
fn run_f4_token_mismatch_aborts_batch(scratch_dir: &Path) {
    println!("\n[>>> F4: Batch confirmation mismatch aborts <<<]");
    let run_dir = scratch_dir.join(format!("t14_f4_{}", std::process::id()));
    fs::create_dir_all(&run_dir).unwrap();

    let backing = run_dir.join("a.raw");
    SentinelManager::fill_sentinel(&backing, 16 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 16 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let out = Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("execute")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--profile")
        .arg("nist-clear")
        .arg("--serial-confirm")
        .arg("WRONG-TOKEN")
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .assert();

    assert_eq!(
        out.get_output().status.code(),
        Some(1),
        "token mismatch is a usage error"
    );
    assert!(
        find_all_files_with_ext(&out_dir, "dcj").is_empty(),
        "no journal after confirmation mismatch"
    );
    assert!(!is_all_zero(&backing), "device untouched after mismatch");
    println!("  [✓] F4: confirmation mismatch aborts before arming; sentinel intact.");
}

/// F5 (REG-SAMPLED-VERIFY-CLI): --verify sample:N journals a machine-stable
/// tag and the certificate carries the sampling level.
fn run_f5_sampled_verify_cli(scratch_dir: &Path) {
    println!("\n[>>> F5: REG-SAMPLED-VERIFY-CLI <<<]");
    let run_dir = scratch_dir.join(format!("t14_f5_{}", std::process::id()));
    fs::create_dir_all(&run_dir).unwrap();

    let backing = run_dir.join("a.raw");
    SentinelManager::fill_sentinel(&backing, 16 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 16 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("execute")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--profile")
        .arg("nist-clear")
        .arg("--verify")
        .arg("sample:4")
        .arg("--serial-confirm")
        .arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .assert()
        .success();

    let journals = find_all_files_with_ext(&out_dir, "dcj");
    assert_eq!(journals.len(), 1);
    let journal_bytes = fs::read(&journals[0]).unwrap();
    let text = String::from_utf8_lossy(&journal_bytes);
    assert!(
        text.contains("sample:4"),
        "journal must record the machine-stable sampled tag"
    );

    let certs: Vec<_> = find_all_files_with_ext(&out_dir, "json")
        .into_iter()
        .filter(|p| p.to_string_lossy().contains(".cert."))
        .collect();
    assert_eq!(certs.len(), 1);
    let cert: serde_json::Value = serde_json::from_slice(&fs::read(&certs[0]).unwrap()).unwrap();
    assert_eq!(
        cert["plan"]["verification"],
        serde_json::json!({"sampled": {"stride": 4}})
    );
    assert!(cert["verification"]["level"]["sampled"]["stride"] == 4);
    assert!(
        is_all_zero(&backing),
        "wipe still physically completes under sampled verification"
    );
    println!("  [✓] F5: sample:4 journaled + certified; media zeroed.");
}

/// F6 (REG-PURGE-NVME-ONLY): hardware purge refuses loop (non-NVMe) targets
/// fail-closed, and non-root-visible refusal codes.
fn run_f6_purge_guards(scratch_dir: &Path) {
    println!("\n[>>> F6: REG-PURGE-NVME-ONLY (loop target) <<<]");
    let run_dir = scratch_dir.join(format!("t14_f6_{}", std::process::id()));
    fs::create_dir_all(&run_dir).unwrap();

    let backing = run_dir.join("a.raw");
    SentinelManager::fill_sentinel(&backing, 16 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 16 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let out = Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("purge")
        .arg("--target")
        .arg(&loop_dev.dev_path)
        .arg("--serial-confirm")
        .arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .assert();

    assert_eq!(
        out.get_output().status.code(),
        Some(2),
        "purge on non-NVMe is a Guardian refusal"
    );
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(
        stderr.contains("PURGE_NVME_ONLY") || stderr.contains("bus"),
        "stderr must name the NVMe-only purge ladder: {}",
        stderr
    );
    assert!(
        find_all_files_with_ext(&out_dir, "dcj").is_empty(),
        "no journal from a refused purge"
    );
    assert!(!is_all_zero(&backing), "device untouched by refused purge");
    println!("  [✓] F6: purge refuses non-NVMe media fail-closed; sentinel intact.");
}

/// F7 (REG-BENCH-SAFETY): bench refuses device nodes and completes on files.
fn run_f7_bench_safety(scratch_dir: &Path) {
    println!("\n[>>> F7: REG-BENCH-SAFETY <<<]");
    let run_dir = scratch_dir.join(format!("t14_f7_{}", std::process::id()));
    fs::create_dir_all(&run_dir).unwrap();

    // Bench on a loop DEVICE node must be refused...
    let backing = run_dir.join("a.raw");
    SentinelManager::fill_sentinel(&backing, 16 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 16 * 1024 * 1024, 512).unwrap();

    Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("bench")
        .arg("--file")
        .arg(&loop_dev.dev_path)
        .assert()
        .failure();

    // ...and bench on a regular file must produce throughput numbers.
    let bench_file = run_dir.join("bench.raw");
    fs::write(&bench_file, vec![0u8; 8 * 1024 * 1024]).unwrap();
    let out = Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("bench")
        .arg("--file")
        .arg(&bench_file)
        .arg("--size-mib")
        .arg("8")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(stdout.contains("MiB/s"), "{}", stdout);
    assert!(
        stdout.contains("nist-clear"),
        "ETA table present: {}",
        stdout
    );
    println!("  [✓] F7: bench refuses devices, reports MiB/s + ETA table on files.");
}
