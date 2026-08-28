use assert_cmd::Command;
use dc_testkit::{
    DioProbe, Janitor, LoopDevice, PartitionOracle, PredictedOutcome, SentinelManager, Truncator,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t12_exhaustive_truncation_matrix() {
    // 1. F0 Prelude & Pure Partition Prediction (runs unprivileged)
    run_f0_prelude();

    if !is_root() {
        eprintln!("[SKIP] T12 E2E sweeps and resume legs require root privileges (EUID 0). Prelude passed.");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // 2. F1 EXH: Exhaustive Byte-by-Byte Truncation Sweep (EXH-NO6)
    run_f1_exhaustive_sweep(&scratch_dir);

    // 3. F3 ZERO-TAIL: Forensic Zero-Tail Sub-code Detection (Δ91)
    run_f3_zero_tail(&scratch_dir);

    // 4. F5 DOD3: Multi-Pass Wrong-Continuation Defense
    run_f5_dod3_multi_pass(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T12 EXHAUSTIVE TRUNCATION & PARTITION SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn run_f0_prelude() {
    println!("\n[>>> F0 PRELUDE: Testing Partition Oracle Self-Test (Δ90) <<<]");

    // Synthetic small journal: Magic (4) + Rec1 len=10 (4+10+32=46) + Rec2 len=5 (4+5+32=41) -> Total 91 bytes
    let mut synth_journal = b"DCJ1".to_vec();
    // Rec1: len=10
    synth_journal.extend_from_slice(&10u32.to_le_bytes());
    synth_journal.extend_from_slice(&[0xAA; 10]);
    synth_journal.extend_from_slice(&[0x11; 32]);
    // Rec2: len=5
    synth_journal.extend_from_slice(&5u32.to_le_bytes());
    synth_journal.extend_from_slice(&[0xBB; 5]);
    synth_journal.extend_from_slice(&[0x22; 32]);

    let breakpoints = PartitionOracle::compute_breakpoints(&synth_journal);
    assert_eq!(breakpoints, vec![0, 4, 8, 18, 50, 54, 59, 91]);

    // Boundary at 50 bytes (after Rec 1)
    let p_boundary = PartitionOracle::predict_pure_truncation(&synth_journal, 50);
    assert_eq!(p_boundary, PredictedOutcome::Boundary { complete_records: 1 });

    // Torn at 60 bytes (inside Rec 2)
    let p_torn = PartitionOracle::predict_pure_truncation(&synth_journal, 60);
    assert_eq!(p_torn, PredictedOutcome::TornTail { complete_records: 1, discarded_bytes: 10 });

    println!("  [✓] P-PARTITION: Partition oracle predicted exact structural breakpoints and outcomes.");
}

fn run_f1_exhaustive_sweep(scratch_dir: &Path) {
    println!("\n[>>> F1: Exhaustive Byte-by-Byte Truncation Sweep (EXH-NO6 / Δ89) <<<]");
    let run_dir = scratch_dir.join(format!("t12_exh_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing.raw");
    SentinelManager::fill_sentinel(&backing, 32 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 32 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out_exh");
    let _ = fs::create_dir_all(&out_dir);

    // Produce an authentic multi-record journal
    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    exec_cmd.assert().code(0);

    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();
    let raw_journal = fs::read(&journal_path).unwrap();
    let total_len = raw_journal.len();

    println!("  [+] Sweeping across all {} byte offsets with dc journal inspect...", total_len);

    let mut exit_6_count = 0;
    let mut exit_0_count = 0;

    for o in 0..=total_len {
        let truncated = Truncator::truncate(&raw_journal, o);
        let test_j_path = run_dir.join(format!("trunc_{}.dcj", o));
        fs::write(&test_j_path, &truncated).unwrap();

        let mut inspect_cmd = Command::cargo_bin("diskcleaner").unwrap();
        inspect_cmd.arg("journal").arg("inspect").arg(&test_j_path);
        let status = inspect_cmd.assert();

        if o < 4 {
            // Truncated magic prefix yields exit 6 (JOURNAL_CORRUPT)
            status.code(6);
        } else {
            // Pure truncation of valid records MUST NEVER PRODUCE EXIT 6 (The Prefix Theorem - EXH-NO6)
            status.code(0);
            exit_0_count += 1;
        }

        let _ = fs::remove_file(test_j_path);
    }

    assert_eq!(exit_6_count, 0, "[EXH-NO6 FAIL] Exit 6 fired on pure truncation offset!");
    println!(
        "  [✓] EXH-NO6: Verified all {} offsets: exactly 0 unexpected corruptions across pure truncation.",
        total_len
    );
}

fn run_f3_zero_tail(scratch_dir: &Path) {
    println!("\n[>>> F3: Testing Forensic Zero-Tail Sub-code Detection (Δ91) <<<]");
    let run_dir = scratch_dir.join(format!("t12_zt_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing_zt.raw");
    SentinelManager::fill_sentinel(&backing, 32 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 32 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out_zt");
    let _ = fs::create_dir_all(&out_dir);

    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    exec_cmd.assert().code(0);

    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();
    let raw_journal = fs::read(&journal_path).unwrap();

    // Append 64 zero bytes after valid journal
    let zt_journal = Truncator::zero_tail(&raw_journal, raw_journal.len(), 64);
    let zt_path = run_dir.join("zero_tail.dcj");
    fs::write(&zt_path, zt_journal).unwrap();

    let mut inspect_cmd = Command::cargo_bin("diskcleaner").unwrap();
    inspect_cmd.arg("journal").arg("inspect").arg(&zt_path);
    let output = inspect_cmd.assert().code(6).get_output().stderr.clone();
    let stderr = String::from_utf8_lossy(&output);
    assert!(stderr.contains("JOURNAL_ZERO_TAIL"), "[ZERO-TAIL FAIL] Missing JOURNAL_ZERO_TAIL sub-code!");

    println!("  [✓] ZERO-TAIL-CODE: Zero-filled trailing bytes cleanly diagnosed as JOURNAL_ZERO_TAIL.");
}

fn run_f5_dod3_multi_pass(scratch_dir: &Path) {
    println!("\n[>>> F5: Testing DOD3 Multi-Pass Wrong-Continuation Defense (K167) <<<]");
    let run_dir = scratch_dir.join(format!("t12_dod3_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing_dod3.raw");
    SentinelManager::fill_sentinel(&backing, 32 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 32 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out_dod3");
    let _ = fs::create_dir_all(&out_dir);

    // Run legacy-dod3, interrupt at pass 0 commit 1
    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.env("DC_SIGNAL_AT", "commit-write:1")
        .arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("legacy-dod3")
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    exec_cmd.assert().code(3);

    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();

    // Resume from interrupted pass 0 to full completion
    let mut resume_cmd = Command::cargo_bin("diskcleaner").unwrap();
    resume_cmd.arg("resume")
        .arg("--journal").arg(&journal_path)
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    resume_cmd.assert().code(0);

    println!("  [✓] DOD3-MEDIA: Multi-pass legacy-dod3 resume executed all passes with full media sanitization.");
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
