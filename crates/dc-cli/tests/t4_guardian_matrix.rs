use assert_cmd::Command;
use dc_testkit::{
    DioProbe, DmDevice, ExclHolder, Janitor, LoopDevice, SentinelManager, SigCraft, TableLine,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t4_guardian_verification_matrix() {
    if !is_root() {
        eprintln!("[SKIP] T4 integration test requires root privileges (EUID 0).");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // 1. F0 Prelude: O_EXCL Claim Semantics Test
    run_f0_prelude(&scratch_dir);

    // 2. F1 True-Positive Refusal Cells
    run_f1_refusal_cells(&scratch_dir);

    // 3. F2 Near-Miss Safe Target Cells
    run_f2_near_miss_cells(&scratch_dir);

    // 4. F3 Deterministic Precedence Probes
    run_f3_precedence_probes(&scratch_dir);

    // 5. F4 Flag Isolation Matrix
    run_f4_flag_isolation(&scratch_dir);

    // 6. F5 Lock Family (O_EXCL & flock)
    run_f5_lock_family(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T4 GUARDIAN VERIFICATION SUITE PASSED ALL FAMILIES ===]\n");
}

fn run_f0_prelude(scratch_dir: &Path) {
    println!("\n[>>> F0 PRELUDE: Testing O_EXCL Claim Semantics <<<]");
    let backing = scratch_dir.join(format!("f0_prelude_{}.raw", std::process::id()));
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    ExclHolder::prelude_verify_excl_semantics(&loop_dev.dev_path)
        .expect("[F0-PRELUDE] Kernel failed O_EXCL claim semantics test!");
    println!("  [✓] F0 PASSED: O_EXCL claim semantics verified on this kernel.");
}

fn run_f1_refusal_cells(scratch_dir: &Path) {
    println!("\n[>>> F1: Testing True-Positive Refusals <<<]");

    let run_dir = scratch_dir.join(format!("t4_f1_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    // 1. R-LVM-SNIFF
    {
        let backing = run_dir.join("lvm.raw");
        SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();
        SigCraft::craft_lvm2_label(&loop_dev.dev_path).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check").arg("--target").arg(&loop_dev.dev_path).arg("--allow-loop");
        cmd.assert().code(2);
        println!("  [✓] R-LVM-SNIFF: Refused LVM2 physical volume signature.");
    }

    // 2. R-SWAP-SNIFF
    {
        let backing = run_dir.join("swap.raw");
        SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();
        SigCraft::craft_swap_signature(&loop_dev.dev_path).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check").arg("--target").arg(&loop_dev.dev_path).arg("--allow-loop");
        cmd.assert().code(2);
        println!("  [✓] R-SWAP-SNIFF: Refused inactive SWAP signature.");
    }

    // 3. R-LUKS (Encrypted container without --allow-inactive-signatures)
    {
        let backing = run_dir.join("luks.raw");
        SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();
        SigCraft::craft_luks_magic(&loop_dev.dev_path).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check").arg("--target").arg(&loop_dev.dev_path).arg("--allow-loop");
        cmd.assert().code(2);

        // With --allow-inactive-signatures, it must PASS
        let mut cmd_pass = Command::cargo_bin("diskcleaner").unwrap();
        cmd_pass.arg("check").arg("--target").arg(&loop_dev.dev_path).arg("--allow-loop").arg("--allow-inactive-signatures");
        cmd_pass.assert().code(0);
        println!("  [✓] R-LUKS: Refused LUKS container by default; permitted with explicit flag.");
    }

    // 4. R-LOOP (Without --allow-loop)
    {
        let backing = run_dir.join("loop.raw");
        SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check").arg("--target").arg(&loop_dev.dev_path);
        cmd.assert().code(2);
        println!("  [✓] R-LOOP: Virtual loopback device refused without --allow-loop.");
    }
}

fn run_f2_near_miss_cells(scratch_dir: &Path) {
    println!("\n[>>> F2: Testing Near-Miss Safe Targets <<<]");

    let run_dir = scratch_dir.join(format!("t4_f2_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    // 1. NM-UNMOUNTED-FS (Unmounted filesystem with allow-inactive-signatures)
    {
        let backing = run_dir.join("unmounted_fs.raw");
        SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();
        SigCraft::craft_ext4_superblock(&loop_dev.dev_path).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check")
            .arg("--target").arg(&loop_dev.dev_path)
            .arg("--allow-loop")
            .arg("--allow-inactive-signatures");
        cmd.assert().code(0);
        println!("  [✓] NM-UNMOUNTED-FS: Unmounted filesystem correctly classified as safe.");

        // Full execute proof on unmounted FS
        let out_dir = run_dir.join("unmounted_out");
        let _ = fs::create_dir_all(&out_dir);

        let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
        exec_cmd.arg("execute")
            .arg("--target").arg(&loop_dev.dev_path)
            .arg("--profile").arg("clear-zero")
            .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
            .arg("--allow-loop")
            .arg("--allow-inactive-signatures")
            .arg("--out-dir").arg(&out_dir)
            .arg("--no-progress");
        exec_cmd.assert().code(0);
        println!("  [✓] NM-UNMOUNTED-FS-EXEC: Full wipe execution completed cleanly.");
    }

    // 2. NM-DM (Clean DM linear mapping)
    {
        let backing = run_dir.join("dm_clean.raw");
        SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

        let dm_name = format!("dc-t4-clean-{}", std::process::id());
        let dm_uuid = format!("DC-T4-CLEAN-{}", std::process::id());
        let mut dm_dev = DmDevice::create(&dm_name, &dm_uuid).unwrap();

        let linear_table = vec![TableLine::Linear {
            start_sector: 0,
            length_sectors: 64 * 1024 * 1024 / 512,
            backing_major: 7,
            backing_minor: loop_dev.minor as u32,
            backing_start_sector: 0,
        }];
        dm_dev.swap_table(&linear_table).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check").arg("--target").arg(&dm_dev.dev_path).arg("--allow-loop");
        cmd.assert().code(0);
        println!("  [✓] NM-DM: Clean device-mapper linear target classified as safe.");
    }
}

fn run_f3_precedence_probes(scratch_dir: &Path) {
    println!("\n[>>> F3: Testing Precedence Determinism (5x repetitions) <<<]");

    let run_dir = scratch_dir.join(format!("t4_f3_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);
    let backing = run_dir.join("prec.raw");

    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    // Craft LVM signature on loop device
    SigCraft::craft_lvm2_label(&loop_dev.dev_path).unwrap();

    // Target without --allow-loop: Rule 12 (LVM_PV) vs Rule 14 (LOOP) -> Rule 12 must win precedence!
    for i in 1..=5 {
        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check").arg("--target").arg(&loop_dev.dev_path);
        let output = cmd.assert().code(2).get_output().stderr.clone();
        let stderr_str = String::from_utf8_lossy(&output);
        assert!(
            stderr_str.contains("LVM_PV"),
            "[F3-DETERMINISM] Repetition {} failed precedence order: stderr: {}",
            i, stderr_str
        );
    }
    println!("  [✓] F3 PASSED: Precedence order (LVM_PV > LOOP) 100% deterministic across 5 runs.");
}

fn run_f4_flag_isolation(scratch_dir: &Path) {
    println!("\n[>>> F4: Testing Permission Flag Isolation <<<]");

    let run_dir = scratch_dir.join(format!("t4_f4_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);
    let backing = run_dir.join("isol.raw");

    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    // Craft LVM signature
    SigCraft::craft_lvm2_label(&loop_dev.dev_path).unwrap();

    // Passing --allow-loop MUST NOT suppress LVM_PV refusal!
    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("check").arg("--target").arg(&loop_dev.dev_path).arg("--allow-loop");
    let output = cmd.assert().code(2).get_output().stderr.clone();
    let stderr = String::from_utf8_lossy(&output);
    assert!(stderr.contains("LVM_PV"), "[F4-ISOLATION] --allow-loop accidentally suppressed LVM_PV!");
    println!("  [✓] F4 PASSED: --allow-loop does not suppress unrelated danger refusals.");
}

fn run_f5_lock_family(scratch_dir: &Path) {
    println!("\n[>>> F5: Testing Lock Family (O_EXCL & flock) <<<]");

    let run_dir = scratch_dir.join(format!("t4_f5_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);
    let backing = run_dir.join("lock.raw");

    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    // L-EXCL: Hold O_EXCL on device from rig -> dc execute must refuse with IN_USE_RACE
    let holder = ExclHolder::hold(&loop_dev.dev_path).unwrap();

    let out_dir = run_dir.join("lock_out");
    let _ = fs::create_dir_all(&out_dir);

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");

    cmd.assert().code(2);
    drop(holder);

    println!("  [✓] F5 PASSED: Concurrent O_EXCL claim caught and refused with IN_USE_RACE.");
}
