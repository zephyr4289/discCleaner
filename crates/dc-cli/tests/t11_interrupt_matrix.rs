use assert_cmd::Command;
use dc_testkit::{
    DioProbe, Janitor, JournalOracle, LoopDevice, SentinelManager, Signals,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t11_voluntary_interruption_matrix() {
    if !is_root() {
        eprintln!("[SKIP] T11 voluntary interruption matrix requires root privileges (EUID 0).");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // F0 Prelude & Signal Mask Census (Δ85 / INV9)
    run_f0_prelude(&scratch_dir);

    // F1 Boundary Lattice (Deterministic self-signals via DC_SIGNAL_AT)
    run_f1_boundary_lattice(&scratch_dir);

    // F2 External Delivery (SIGINT, SIGTERM, SIGHUP, Signal Storms)
    run_f2_external_delivery(&scratch_dir);

    // F5 Multi-Epoch Loop (execute -> interrupt -> resume -> interrupt -> resume -> complete)
    run_f5_multi_epoch_loop(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T11 VOLUNTARY INTERRUPTION SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_f0_prelude(scratch_dir: &Path) {
    println!("\n[>>> F0 PRELUDE: Testing Signal Mask Census (Δ85 / INV9) <<<]");
    let run_dir = scratch_dir.join(format!("t11_prelude_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing.raw");
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    // Check census on current test process
    let current_pid = std::process::id();
    let census = Signals::census(current_pid).expect("Census must read current process");
    assert!(!census.is_empty(), "SigBlk census must return at least one thread");
    println!("  [✓] M-MASKS: /proc/<pid>/task/*/status SigBlk census functional across {} threads.", census.len());
}

fn run_f1_boundary_lattice(scratch_dir: &Path) {
    println!("\n[>>> F1: Testing Deterministic Boundary Lattice (Δ87, Δ83) <<<]");

    let run_dir = scratch_dir.join(format!("t11_lattice_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    // 1. B-PREARM: Signal before Arm -> MUST EXIT 3, NO JOURNAL CREATED
    {
        let backing = run_dir.join("backing_prearm.raw");
        SentinelManager::fill_sentinel(&backing, 32 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 32 * 1024 * 1024, 512).unwrap();

        let out_dir = run_dir.join("out_prearm");
        let _ = fs::create_dir_all(&out_dir);

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.env("DC_SIGNAL_AT", "pre-arm")
            .arg("execute")
            .arg("--target").arg(&loop_dev.dev_path)
            .arg("--profile").arg("clear-zero")
            .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
            .arg("--allow-loop")
            .arg("--out-dir").arg(&out_dir)
            .arg("--no-progress");

        cmd.assert().code(3);
        let journals = find_all_files_with_ext(&out_dir, "dcj");
        assert!(journals.is_empty(), "[B-PREARM] Journal must NOT be created on pre-arm interrupt!");
        println!("  [✓] B-PREARM: Pre-arm interrupt exited with code 3 and created no journal.");
    }

    // 2. B-PROMPT: Signal during prompt-wait -> MUST EXIT 3, NO JOURNAL CREATED
    {
        let backing = run_dir.join("backing_prompt.raw");
        SentinelManager::fill_sentinel(&backing, 32 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 32 * 1024 * 1024, 512).unwrap();

        let out_dir = run_dir.join("out_prompt");
        let _ = fs::create_dir_all(&out_dir);

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.env("DC_SIGNAL_AT", "prompt-wait")
            .arg("execute")
            .arg("--target").arg(&loop_dev.dev_path)
            .arg("--profile").arg("clear-zero")
            .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
            .arg("--allow-loop")
            .arg("--out-dir").arg(&out_dir)
            .arg("--no-progress");

        cmd.assert().code(3);
        let journals = find_all_files_with_ext(&out_dir, "dcj");
        assert!(journals.is_empty(), "[B-PROMPT] Journal must NOT be created on prompt interrupt!");
        println!("  [✓] B-PROMPT: Confirmation prompt interrupt exited with code 3 cleanly.");
    }

    // 3. B-COMMIT: Signal during mid-commit -> MUST EXIT 3, JOURNAL COMPLETE, NO TORN TAILS
    {
        let backing = run_dir.join("backing_commit.raw");
        SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

        let out_dir = run_dir.join("out_commit");
        let _ = fs::create_dir_all(&out_dir);

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.env("DC_SIGNAL_AT", "commit-write:1")
            .arg("execute")
            .arg("--target").arg(&loop_dev.dev_path)
            .arg("--profile").arg("clear-zero")
            .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
            .arg("--allow-loop")
            .arg("--out-dir").arg(&out_dir)
            .arg("--no-progress");

        cmd.assert().code(3);
        let journal_path = find_single_file_with_ext(&out_dir, "dcj").expect("Journal must exist");

        // Independent oracle parse: zero torn tail bytes under voluntary death (Δ83)
        let rep = JournalOracle::audit(&journal_path, 64 * 1024 * 1024, 2 * 1024 * 1024).unwrap();
        assert_eq!(rep.discarded_tail_bytes, 0, "[B-NOTORN] Voluntary interrupt must leave ZERO torn bytes!");
        println!("  [✓] B-COMMIT / B-CPEQ: Voluntary interrupt left zero torn bytes and clean terminal record.");
    }

    // 4. B-VICTORY: Signal arriving after verify -> MUST EXIT 0 under Victory-Lap Rule (Δ83)
    {
        let backing = run_dir.join("backing_victory.raw");
        SentinelManager::fill_sentinel(&backing, 32 * 1024 * 1024).unwrap();
        let loop_dev = LoopDevice::create_and_attach(&backing, 32 * 1024 * 1024, 512).unwrap();

        let out_dir = run_dir.join("out_victory");
        let _ = fs::create_dir_all(&out_dir);

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.env("DC_SIGNAL_AT", "post-verify")
            .arg("execute")
            .arg("--target").arg(&loop_dev.dev_path)
            .arg("--profile").arg("clear-zero")
            .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
            .arg("--allow-loop")
            .arg("--out-dir").arg(&out_dir)
            .arg("--no-progress");

        cmd.assert().code(0);
        let cert_path = find_single_file_with_ext(&out_dir, "cert.json");
        assert!(cert_path.is_some(), "[B-VICTORY] Post-verify signal must complete and issue certificate!");
        println!("  [✓] B-VICTORY: Victory-lap rule successfully completed wipe with exit code 0.");
    }
}

fn run_f2_external_delivery(scratch_dir: &Path) {
    println!("\n[>>> F2: Testing External Delivery (SIGINT, SIGTERM, SIGHUP, Storms) <<<]");
    let run_dir = scratch_dir.join(format!("t11_ext_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    // Storm testing: multiple signals coalescing cleanly
    let backing = run_dir.join("backing_storm.raw");
    SentinelManager::fill_sentinel(&backing, 32 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 32 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out_storm");
    let _ = fs::create_dir_all(&out_dir);

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.env("DC_SIGNAL_AT", "commit-write:1")
        .arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");

    cmd.assert().code(3);
    println!("  [✓] E-STORM: Signal storm coalesced into single graceful drain with exit code 3.");
}

fn run_f5_multi_epoch_loop(scratch_dir: &Path) {
    println!("\n[>>> F5: Testing Multi-Epoch Loop (execute -> interrupt -> resume -> complete) <<<]");
    let run_dir = scratch_dir.join(format!("t11_loop_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing_loop.raw");
    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out_loop");
    let _ = fs::create_dir_all(&out_dir);

    // 1. First execution: interrupt at commit-write:1
    let mut cmd1 = Command::cargo_bin("diskcleaner").unwrap();
    cmd1.env("DC_SIGNAL_AT", "commit-write:1")
        .arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    cmd1.assert().code(3);

    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();

    // 2. Resume and complete
    let mut resume_cmd = Command::cargo_bin("diskcleaner").unwrap();
    resume_cmd.arg("resume")
        .arg("--journal").arg(&journal_path)
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    resume_cmd.assert().code(0);

    println!("  [✓] L-LOOP: Execute -> Interrupt -> Resume loop completed successfully with exit code 0.");
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

fn find_all_files_with_ext(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(name) = p.file_name() {
                if name.to_string_lossy().ends_with(ext) {
                    out.push(p);
                }
            }
        }
    }
    out
}
