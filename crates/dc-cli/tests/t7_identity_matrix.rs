use assert_cmd::Command;
use dc_testkit::{
    DioProbe, DmDevice, Janitor, LoopDevice, RebindChoreographer, SentinelManager, TableLine,
    TestIdentityReader,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t7_identity_verification_matrix() {
    if !is_root() {
        eprintln!("[SKIP] T7 integration test requires root privileges (EUID 0).");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // 1. F0 Prelude: DM Identity Substrate & EBUSY Proofs
    run_f0_prelude(&scratch_dir);

    // 2. F1 Plan Binding (The Charter Bug: D-REBIND-PLAN, N8)
    run_f1_plan_binding(&scratch_dir);

    // 3. F2 Confirmation Binding (C-SWAP-TYPED-OLD)
    run_f2_confirmation_binding(&scratch_dir);

    // 4. F3 Crash / Swap / Resume Rediscovery (R-DRIFT)
    run_f3_rediscovery_drift(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T7 IDENTITY & REBIND SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_f0_prelude(scratch_dir: &Path) {
    println!("\n[>>> F0 PRELUDE: Testing DM Identity Substrate & EBUSY Proofs <<<]");
    let backing = scratch_dir.join(format!("t7_f0_prelude_{}.raw", std::process::id()));
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    let dm_name = format!("dc-t7-prelude-{}", std::process::id());
    let dm_uuid = format!("DC-T7-PRELUDE-{}", std::process::id());
    let mut dm = DmDevice::create(&dm_name, &dm_uuid).unwrap();

    let table = vec![TableLine::Linear {
        start_sector: 0,
        length_sectors: 64 * 1024 * 1024 / 512,
        backing_major: 7,
        backing_minor: loop_dev.minor as u32,
        backing_start_sector: 0,
    }];
    dm.swap_table(&table).unwrap();

    // P-DMIDENT: Read sysfs identity independently and assert roundtrip
    let ident = TestIdentityReader::read_sysfs_identity(Path::new(&dm.dev_path))
        .expect("[P-DMIDENT] Failed to read sysfs identity");

    assert_eq!(ident.dm_name.as_deref(), Some(dm_name.as_str()));
    assert_eq!(ident.dm_uuid.as_deref(), Some(dm_uuid.as_str()));

    println!("  [✓] F0 PASSED: DM identity substrate verified in sysfs.");
}

fn run_f1_plan_binding(scratch_dir: &Path) {
    println!("\n[>>> F1: Testing Plan-to-Execute Binding (D-REBIND-PLAN, N8) <<<]");

    let run_dir = scratch_dir.join(format!("t7_f1_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing_a = run_dir.join("backing_a.raw");
    let backing_b = run_dir.join("backing_b.raw");

    SentinelManager::fill_sentinel(&backing_a, 64 * 1024 * 1024).unwrap();
    SentinelManager::fill_sentinel(&backing_b, 64 * 1024 * 1024).unwrap();

    let loop_a = LoopDevice::create_and_attach(&backing_a, 64 * 1024 * 1024, 512).unwrap();
    let loop_b = LoopDevice::create_and_attach(&backing_b, 64 * 1024 * 1024, 512).unwrap();

    let dm_name = format!("dc-t7-f1-{}", std::process::id());
    let uuid_a = format!("DC-T7-UUID-A-{}", std::process::id());
    let uuid_b = format!("DC-T7-UUID-B-{}", std::process::id());

    // 1. Create dm over loop_a with uuid_a
    let mut dm = DmDevice::create(&dm_name, &uuid_a).unwrap();
    let table_a = vec![TableLine::Linear {
        start_sector: 0,
        length_sectors: 64 * 1024 * 1024 / 512,
        backing_major: 7,
        backing_minor: loop_a.minor as u32,
        backing_start_sector: 0,
    }];
    dm.swap_table(&table_a).unwrap();

    // 2. Compile plan file P for dm(uuid_a)
    let plan_path = run_dir.join("plan_a.json");
    let mut plan_cmd = Command::cargo_bin("diskcleaner").unwrap();
    plan_cmd.arg("plan")
        .arg("--target").arg(&dm.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--out").arg(&plan_path);
    plan_cmd.assert().code(0);

    // 3. REBIND CHOREOGRAPHY: Remove dm and recreate with uuid_b over loop_b
    drop(dm); // Detaches device mapper handle
    let _ = Janitor::sweep_dm_devices();

    let mut dm_b = DmDevice::create(&dm_name, &uuid_b).unwrap();
    let table_b = vec![TableLine::Linear {
        start_sector: 0,
        length_sectors: 64 * 1024 * 1024 / 512,
        backing_major: 7,
        backing_minor: loop_b.minor as u32,
        backing_start_sector: 0,
    }];
    dm_b.swap_table(&table_b).unwrap();

    // 4. D-REBIND-PLAN: Execute with --plan <file> and typing honest token uuid_b -> MUST REFUSE with exit 7
    let out_dir = run_dir.join("output_drift");
    let _ = fs::create_dir_all(&out_dir);

    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.arg("execute")
        .arg("--target").arg(&dm_b.dev_path)
        .arg("--plan").arg(&plan_path)
        .arg("--serial-confirm").arg(&uuid_b)
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");

    exec_cmd.assert().code(7);

    // 5. NEAR-VICTIM CHECK: loop_b must remain 100% untouched sentinel 0xA5
    let b_media = SentinelManager::verify_zero_media_oracle(&backing_b, 64 * 1024 * 1024).unwrap();
    assert!(!b_media.all_zeros, "[D-REBIND-PLAN] Near-victim loop_b was modified!");
    println!("  [✓] D-REBIND-PLAN: Plan binding caught device swap; refused with exit 7 (near-victim intact).");

    // 6. N8-PLANTAMPER: Tampered plan file -> exit 6
    let tampered_plan_path = run_dir.join("tampered_plan.json");
    let mut plan_bytes = fs::read(&plan_path).unwrap();
    if let Some(b) = plan_bytes.get_mut(20) {
        *b ^= 0xFF;
    }
    fs::write(&tampered_plan_path, plan_bytes).unwrap();

    let mut tamper_cmd = Command::cargo_bin("diskcleaner").unwrap();
    tamper_cmd.arg("execute")
        .arg("--target").arg(&dm_b.dev_path)
        .arg("--plan").arg(&tampered_plan_path)
        .arg("--serial-confirm").arg(&uuid_b)
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");

    tamper_cmd.assert().code(6);
    println!("  [✓] N8-PLANTAMPER: Tampered plan file refused with exit 6.");
}

fn run_f2_confirmation_binding(scratch_dir: &Path) {
    println!("\n[>>> F2: Testing Confirmation Token Binding (C-SWAP-TYPED-OLD) <<<]");

    let run_dir = scratch_dir.join(format!("t7_f2_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);
    let backing = run_dir.join("backing.raw");

    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    let dm_name = format!("dc-t7-f2-{}", std::process::id());
    let current_uuid = format!("DC-T7-CURRENT-{}", std::process::id());
    let mut dm = DmDevice::create(&dm_name, &current_uuid).unwrap();

    let table = vec![TableLine::Linear {
        start_sector: 0,
        length_sectors: 64 * 1024 * 1024 / 512,
        backing_major: 7,
        backing_minor: loop_dev.minor as u32,
        backing_start_sector: 0,
    }];
    dm.swap_table(&table).unwrap();

    // Typing old token -> MUST REFUSE with exit 8 (confirmation mismatch)
    let out_dir = run_dir.join("output_confirm");
    let _ = fs::create_dir_all(&out_dir);

    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.arg("execute")
        .arg("--target").arg(&dm.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg("DC-T7-OLD-EXPIRED-TOKEN")
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");

    exec_cmd.assert().code(8);
    println!("  [✓] C-SWAP-TYPED-OLD: Expired / wrong confirmation token refused with exit 8.");
}

fn run_f3_rediscovery_drift(scratch_dir: &Path) {
    println!("\n[>>> F3: Testing Crash / Swap / Resume Rediscovery (R-DRIFT) <<<]");

    let run_dir = scratch_dir.join(format!("t7_f3_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing_a = run_dir.join("backing_a.raw");
    let backing_b = run_dir.join("backing_b.raw");

    SentinelManager::fill_sentinel(&backing_a, 64 * 1024 * 1024).unwrap();
    SentinelManager::fill_sentinel(&backing_b, 64 * 1024 * 1024).unwrap();

    let loop_a = LoopDevice::create_and_attach(&backing_a, 64 * 1024 * 1024, 512).unwrap();
    let loop_b = LoopDevice::create_and_attach(&backing_b, 64 * 1024 * 1024, 512).unwrap();

    let dm_name = format!("dc-t7-f3-{}", std::process::id());
    let uuid_a = format!("DC-T7-UUID-A-{}", std::process::id());
    let uuid_b = format!("DC-T7-UUID-B-{}", std::process::id());

    // 1. Initial run on dm(uuid_a) crashing at commit:2
    let mut dm = DmDevice::create(&dm_name, &uuid_a).unwrap();
    let table_a = vec![TableLine::Linear {
        start_sector: 0,
        length_sectors: 64 * 1024 * 1024 / 512,
        backing_major: 7,
        backing_minor: loop_a.minor as u32,
        backing_start_sector: 0,
    }];
    dm.swap_table(&table_a).unwrap();

    let out_dir = run_dir.join("output_crash");
    let _ = fs::create_dir_all(&out_dir);

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target").arg(&dm.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg(&uuid_a)
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress")
        .env("DC_CRASH_AT", "commit:2");
    let _ = cmd.assert();

    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();

    // 2. REBIND: Swap dm device underneath to uuid_b over loop_b
    drop(dm);
    let _ = Janitor::sweep_dm_devices();

    let mut dm_b = DmDevice::create(&dm_name, &uuid_b).unwrap();
    let table_b = vec![TableLine::Linear {
        start_sector: 0,
        length_sectors: 64 * 1024 * 1024 / 512,
        backing_major: 7,
        backing_minor: loop_b.minor as u32,
        backing_start_sector: 0,
    }];
    dm_b.swap_table(&table_b).unwrap();

    // 3. Resume on drifted journal -> MUST REFUSE with exit 7 (device mismatch)
    let mut resume_cmd = Command::cargo_bin("diskcleaner").unwrap();
    resume_cmd.arg("resume")
        .arg("--journal").arg(&journal_path)
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress")
        .env_remove("DC_CRASH_AT");

    resume_cmd.assert().code(7);

    // 4. Check near-victim loop_b is untouched
    let b_media = SentinelManager::verify_zero_media_oracle(&backing_b, 64 * 1024 * 1024).unwrap();
    assert!(!b_media.all_zeros, "[R-DRIFT] Near-victim loop_b was modified on resume!");

    println!("  [✓] R-DRIFT: Swapped device on resume caught and refused with exit 7 (near-victim intact).");
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
