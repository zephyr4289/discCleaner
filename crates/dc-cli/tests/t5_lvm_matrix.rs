use assert_cmd::Command;
use dc_testkit::{
    CertOracle, DioProbe, Janitor, JournalOracle, LoopDevice, LvmSandbox, SentinelManager,
    SigCraft, UevFire,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn is_lvm_available() -> bool {
    std::process::Command::new("lvm")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn test_t5_lvm_verification_matrix() {
    if !is_root() {
        eprintln!("[SKIP] T5 integration test requires root privileges (EUID 0).");
        return;
    }

    if !is_lvm_available() {
        eprintln!("[SKIP] lvm2 command not found in PATH on this runner. Skipping real-LVM cells.");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    let lvm_sandbox = match LvmSandbox::create(&scratch_dir) {
        Ok(s) => s,
        Err(e) => panic!("[ENV-FAIL] LVM sandbox creation failed: {}", e),
    };

    // 1. T5.prelude: Fencing & uevent change trigger proof
    run_t5_prelude(&scratch_dir, &lvm_sandbox);

    // 2. Active Family (HAS_HOLDERS)
    run_active_lvm_cells(&scratch_dir, &lvm_sandbox);

    // 3. Advisory Family (LVM_PV & --allow-member)
    run_advisory_lvm_cells(&scratch_dir, &lvm_sandbox);

    // 4. Near-Miss Lookalike
    run_near_miss_cells(&scratch_dir);

    // 5. Flag Isolation Matrix
    run_flag_isolation_cells(&scratch_dir, &lvm_sandbox);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T5 REAL-LVM VERIFICATION SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_t5_prelude(scratch_dir: &Path, lvm: &LvmSandbox) {
    println!("\n[>>> T5 PRELUDE: Testing LVM Sandbox & Uevent Fencing <<<]");
    let backing = scratch_dir.join(format!("t5_prelude_{}.raw", std::process::id()));
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    let loop_name = format!("loop{}", loop_dev.minor);
    let dev_path = PathBuf::from(&loop_dev.dev_path);

    lvm.pvcreate(&dev_path).unwrap();
    let vg_name = format!("dct5-pre-{}", loop_dev.minor);
    lvm.vgcreate(&vg_name, &[&dev_path]).unwrap();

    // Fire kernel uevent change on loop device
    UevFire::fire_change_event(&loop_name).unwrap();

    // Host udev must not auto-activate the foreign system_id VG
    let holder_check = dc_probe::LayerStackDetector::has_holders(&loop_name);
    assert!(!holder_check, "[PRELUDE] Host auto-activated foreign test VG!");

    lvm.vgremove(&vg_name).unwrap();
    println!("  [✓] T5 PRELUDE PASSED: LVM sandbox and uevent fencing verified.");
}

fn run_active_lvm_cells(scratch_dir: &Path, lvm: &LvmSandbox) {
    println!("\n[>>> T5 ACTIVE FAMILY: Testing Real Active LVM Holders <<<]");

    let run_dir = scratch_dir.join(format!("t5_act_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    // 1. A-PV-DISK (Whole disk PV with active LV)
    {
        let backing = run_dir.join("pv_disk.raw");
        SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();
        let dev_path = PathBuf::from(&loop_dev.dev_path);

        lvm.pvcreate(&dev_path).unwrap();
        let vg_name = format!("dct5-vg-{}", loop_dev.minor);
        lvm.vgcreate(&vg_name, &[&dev_path]).unwrap();
        lvm.lvcreate(&vg_name, "lv0", 32).unwrap();
        lvm.vgchange_ay(&vg_name).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check").arg("--target").arg(&loop_dev.dev_path).arg("--allow-loop");
        let output = cmd.assert().code(2).get_output().stderr.clone();
        let stderr = String::from_utf8_lossy(&output);
        assert!(stderr.contains("HAS_HOLDERS"), "[A-PV-DISK] Expected HAS_HOLDERS, got: {}", stderr);

        lvm.vgremove(&vg_name).unwrap();
        println!("  [✓] A-PV-DISK: Active LVM LV detected via HAS_HOLDERS.");
    }

    // 2. A-SPAN (Spanning VG over 2 loops, target loopA)
    {
        let backing_a = run_dir.join("span_a.raw");
        let backing_b = run_dir.join("span_b.raw");
        SentinelManager::fill_sentinel(&backing_a, 64 * 1024 * 1024).unwrap();
        SentinelManager::fill_sentinel(&backing_b, 64 * 1024 * 1024).unwrap();

        let loop_a = LoopDevice::create_and_attach(&backing_a, 64 * 1024 * 1024, 512).unwrap();
        let loop_b = LoopDevice::create_and_attach(&backing_b, 64 * 1024 * 1024, 512).unwrap();

        let dev_a = PathBuf::from(&loop_a.dev_path);
        let dev_b = PathBuf::from(&loop_b.dev_path);

        lvm.pvcreate(&dev_a).unwrap();
        lvm.pvcreate(&dev_b).unwrap();

        let vg_name = format!("dct5-span-{}", loop_a.minor);
        lvm.vgcreate(&vg_name, &[&dev_a, &dev_b]).unwrap();
        lvm.lvcreate(&vg_name, "lv_span", 80).unwrap(); // 80 MiB spans both 64 MiB loops
        lvm.vgchange_ay(&vg_name).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check").arg("--target").arg(&loop_a.dev_path).arg("--allow-loop");
        let output = cmd.assert().code(2).get_output().stderr.clone();
        let stderr = String::from_utf8_lossy(&output);
        assert!(stderr.contains("HAS_HOLDERS"), "[A-SPAN] Expected HAS_HOLDERS, got: {}", stderr);

        lvm.vgremove(&vg_name).unwrap();
        println!("  [✓] A-SPAN: Spanning multi-disk LV refused with HAS_HOLDERS.");
    }
}

fn run_advisory_lvm_cells(scratch_dir: &Path, lvm: &LvmSandbox) {
    println!("\n[>>> T5 ADVISORY FAMILY: Testing Inactive PVs and --allow-member <<<]");

    let run_dir = scratch_dir.join(format!("t5_adv_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    // 1. I-PLAIN (Real pvcreate without active VG)
    {
        let backing = run_dir.join("i_plain.raw");
        SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();
        let dev_path = PathBuf::from(&loop_dev.dev_path);

        lvm.pvcreate(&dev_path).unwrap();

        // Check without --allow-member -> MUST REFUSE with LVM_PV
        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("check").arg("--target").arg(&loop_dev.dev_path).arg("--allow-loop");
        let output = cmd.assert().code(2).get_output().stderr.clone();
        let stderr = String::from_utf8_lossy(&output);
        assert!(stderr.contains("LVM_PV"), "[I-PLAIN] Expected LVM_PV, got: {}", stderr);

        // Check WITH --allow-member -> MUST PASS
        let mut cmd_pass = Command::cargo_bin("diskcleaner").unwrap();
        cmd_pass.arg("check")
            .arg("--target").arg(&loop_dev.dev_path)
            .arg("--allow-loop")
            .arg("--allow-member");
        cmd_pass.assert().code(0);
        println!("  [✓] I-PLAIN: Inactive PV refused by default; allowed with --allow-member.");
    }

    // 2. I-SPAN (Inactive spanning VG + full execute leg with --allow-member)
    {
        let backing_a = run_dir.join("ispan_a.raw");
        let backing_b = run_dir.join("ispan_b.raw");
        SentinelManager::fill_sentinel(&backing_a, 64 * 1024 * 1024).unwrap();
        SentinelManager::fill_sentinel(&backing_b, 64 * 1024 * 1024).unwrap();

        let loop_a = LoopDevice::create_and_attach(&backing_a, 64 * 1024 * 1024, 512).unwrap();
        let loop_b = LoopDevice::create_and_attach(&backing_b, 64 * 1024 * 1024, 512).unwrap();

        let dev_a = PathBuf::from(&loop_a.dev_path);
        let dev_b = PathBuf::from(&loop_b.dev_path);

        lvm.pvcreate(&dev_a).unwrap();
        lvm.pvcreate(&dev_b).unwrap();

        let vg_name = format!("dct5-ispan-{}", loop_a.minor);
        lvm.vgcreate(&vg_name, &[&dev_a, &dev_b]).unwrap();
        lvm.lvcreate(&vg_name, "lv_ispan", 80).unwrap();
        lvm.vgchange_an(&vg_name).unwrap(); // Inactive

        let out_dir = run_dir.join("ispan_out");
        let _ = fs::create_dir_all(&out_dir);

        // Full wipe of loop_a with --allow-member
        let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
        exec_cmd.arg("execute")
            .arg("--target").arg(&loop_a.dev_path)
            .arg("--profile").arg("clear-zero")
            .arg("--serial-confirm").arg(format!("loop{}", loop_a.minor))
            .arg("--allow-loop")
            .arg("--allow-member")
            .arg("--out-dir").arg(&out_dir)
            .arg("--no-progress");
        exec_cmd.assert().code(0);

        // Loop A wiped -> sentinel oracle passes
        let media_res = SentinelManager::verify_zero_media_oracle(&backing_a, 64 * 1024 * 1024).unwrap();
        assert!(media_res.all_zeros, "[I-SPAN] Loop A media not fully zeroed!");

        // Loop B must remain untouched and still refuse LVM_PV
        let mut check_b = Command::cargo_bin("diskcleaner").unwrap();
        check_b.arg("check").arg("--target").arg(&loop_b.dev_path).arg("--allow-loop");
        check_b.assert().code(2);

        println!("  [✓] I-SPAN: Surgical wipe of member disk completed; partner member intact.");
    }
}

fn run_near_miss_cells(scratch_dir: &Path) {
    println!("\n[>>> T5 NEAR-MISS: Testing LVM Lookalike Signatures <<<]");
    let run_dir = scratch_dir.join(format!("t5_nm_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    // NM-LOOKALIKE (LABELONE present, but invalid LVM2 001 type field)
    let backing = run_dir.join("lookalike.raw");
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    // Write corrupted label with LABELONE but bad type
    let mut file = fs::OpenOptions::new().write(true).open(&loop_dev.dev_path).unwrap();
    use std::io::{Seek, SeekFrom, Write};
    file.seek(SeekFrom::Start(512)).unwrap();
    file.write_all(b"LABELONE_FAKE_DATA_NOT_LVM_HEADER").unwrap();
    drop(file);

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("check")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--allow-loop")
        .arg("--allow-inactive-signatures");
    cmd.assert().code(0);
    println!("  [✓] NM-LOOKALIKE: False LVM label lookalike correctly classified as CLEAN.");
}

fn run_flag_isolation_cells(scratch_dir: &Path, lvm: &LvmSandbox) {
    println!("\n[>>> T5 FLAG ISOLATION: --allow-member Demotes ONLY Advisory Classes <<<]");
    let run_dir = scratch_dir.join(format!("t5_fiso_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    // F-ISO-1: Active VG + --allow-member -> MUST STILL REFUSE HAS_HOLDERS
    let backing = run_dir.join("fiso.raw");
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();
    let dev_path = PathBuf::from(&loop_dev.dev_path);

    lvm.pvcreate(&dev_path).unwrap();
    let vg_name = format!("dct5-fiso-{}", loop_dev.minor);
    lvm.vgcreate(&vg_name, &[&dev_path]).unwrap();
    lvm.lvcreate(&vg_name, "lv_fiso", 32).unwrap();
    lvm.vgchange_ay(&vg_name).unwrap();

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("check")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--allow-loop")
        .arg("--allow-member"); // Must NOT suppress HAS_HOLDERS!
    let output = cmd.assert().code(2).get_output().stderr.clone();
    let stderr = String::from_utf8_lossy(&output);
    assert!(
        stderr.contains("HAS_HOLDERS"),
        "[F-ISO-1] --allow-member accidentally suppressed HAS_HOLDERS!"
    );

    lvm.vgremove(&vg_name).unwrap();
    println!("  [✓] F-ISO-1 PASSED: --allow-member does NOT suppress active HAS_HOLDERS.");
}
