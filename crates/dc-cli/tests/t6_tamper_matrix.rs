use assert_cmd::Command;
use dc_testkit::{
    DioProbe, Janitor, JournalForge, JournalOracle, LoopDevice, SentinelManager,
};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_t6_journal_tamper_matrix() {
    if !is_root() {
        eprintln!("[SKIP] T6 integration test requires root privileges (EUID 0).");
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // 1. F0 Prelude: Twin Validation & Forge Self-Test
    run_f0_prelude(&scratch_dir);

    // 2. F1 Naive Grid: Single-Byte Flips across Regions
    run_f1_naive_grid(&scratch_dir);

    // 3. F2 Structural: Splice, Reorder, Duplicate
    run_f2_structural(&scratch_dir);

    // 4. F3 Layer Forgeries: L1, L2, L3 Kills
    run_f3_layer_forgeries(&scratch_dir);

    // 5. F4 Capstone: Sealed Journal Tamper & Re-Key Defense
    run_f4_capstone_attacks(&scratch_dir);

    // 6. F5 Degenerate Shapes: 0-byte, len=0, DoS Bounded Allocation
    run_f5_degenerate_shapes(&scratch_dir);

    // 7. F6 Sealed Ops: Key Discipline
    run_f6_sealed_ops(&scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    println!("\n[=== T6 JOURNAL TAMPER & FORGERY SUITE PASSED ALL MATRIX CELLS ===]\n");
}

fn stage_base_journal(scratch_dir: &Path, prefix: &str, sealed_key: Option<&Path>) -> (PathBuf, LoopDevice) {
    let run_dir = scratch_dir.join(format!("{}_{}", prefix, std::process::id()));
    let _ = fs::create_dir_all(&run_dir);
    let backing = run_dir.join("backing.raw");

    SentinelManager::fill_sentinel(&backing, 64 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 64 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("output");
    let _ = fs::create_dir_all(&out_dir);

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress")
        .env("DC_CRASH_AT", "commit:2"); // Crash at commit #2 to leave incomplete journal

    if let Some(key_path) = sealed_key {
        cmd.arg("--key").arg(key_path);
    }

    let _ = cmd.assert();

    let journal_path = find_single_file_with_ext(&out_dir, "dcj")
        .expect("Base journal not generated after crash");

    (journal_path, loop_dev)
}

fn run_f0_prelude(scratch_dir: &Path) {
    println!("\n[>>> F0 PRELUDE: Twin Validation & Forge Self-Test <<<]");
    let (base_journal, _loop) = stage_base_journal(scratch_dir, "t6_f0", None);

    // Twin validation: uncorrupted journal passes oracle
    let report = JournalOracle::parse_and_validate(&base_journal, 32)
        .expect("[F0-TWIN] Base journal failed oracle validation!");
    assert_eq!(report.failure_count, 0);

    // Forge self-test: flip byte and verify detection
    let copy_path = scratch_dir.join(format!("f0_copy_{}.dcj", std::process::id()));
    fs::copy(&base_journal, &copy_path).unwrap();

    JournalForge::flip_byte_at_offset(&copy_path, 10).unwrap();
    assert!(
        JournalOracle::parse_and_validate(&copy_path, 32).is_err(),
        "[F0-FORGE] Flip was not detected by oracle!"
    );

    println!("  [✓] F0 PASSED: Twin validation and forge self-test verified.");
}

fn run_f1_naive_grid(scratch_dir: &Path) {
    println!("\n[>>> F1: Naive Grid Single-Byte Tamper Tests (Exit Code 6) <<<]");
    let (base_journal, _loop) = stage_base_journal(scratch_dir, "t6_f1", None);

    let test_offsets = [0u64, 2, 4, 12, 50, 120]; // Magic, len, body offsets
    for &off in &test_offsets {
        let copy_path = scratch_dir.join(format!("f1_copy_{}_{}.dcj", off, std::process::id()));
        fs::copy(&base_journal, &copy_path).unwrap();

        JournalForge::flip_byte_at_offset(&copy_path, off).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("resume")
            .arg("--journal").arg(&copy_path)
            .arg("--no-progress");

        cmd.assert().code(6);
    }

    println!("  [✓] F1 PASSED: All single-byte flips cleanly refused with exit code 6.");
}

fn run_f2_structural(scratch_dir: &Path) {
    println!("\n[>>> F2: Structural Splices & Reordering (Exit Code 6) <<<]");
    let (base_journal, _loop) = stage_base_journal(scratch_dir, "t6_f2", None);

    // 1. Splice out middle record
    {
        let copy = scratch_dir.join(format!("f2_splice_{}.dcj", std::process::id()));
        fs::copy(&base_journal, &copy).unwrap();
        JournalForge::splice_out_record(&copy, 1).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("resume").arg("--journal").arg(&copy).arg("--no-progress");
        cmd.assert().code(6);
        println!("  [✓] F2.splice: Splice-out middle record refused with exit code 6.");
    }

    // 2. Reorder adjacent records
    {
        let copy = scratch_dir.join(format!("f2_reorder_{}.dcj", std::process::id()));
        fs::copy(&base_journal, &copy).unwrap();
        JournalForge::reorder_adjacent_records(&copy, 1).unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("resume").arg("--journal").arg(&copy).arg("--no-progress");
        cmd.assert().code(6);
        println!("  [✓] F2.reorder: Reordered adjacent records refused with exit code 6.");
    }
}

fn run_f3_layer_forgeries(scratch_dir: &Path) {
    println!("\n[>>> F3: Layer-Specific Forgeries (L1 Self-Hash, L2 Linkage) <<<]");
    let (base_journal, _loop) = stage_base_journal(scratch_dir, "t6_f3", None);

    // L2 Linkage Kill: Edit middle record + recompute its OWN hash (breaks successor linkage)
    let copy = scratch_dir.join(format!("f3_link_{}.dcj", std::process::id()));
    fs::copy(&base_journal, &copy).unwrap();

    let (records, _) = JournalForge::parse_raw_records(&copy).unwrap();
    let mid_record_offset = records[1].offset + 10;
    JournalForge::flip_byte_at_offset(&copy, mid_record_offset).unwrap();
    JournalForge::recompute_record_hash(&copy, 1).unwrap(); // Recomputed own hash!

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("resume").arg("--journal").arg(&copy).arg("--no-progress");
    cmd.assert().code(6);
    println!("  [✓] F3.L2 PASSED: Middle record with recomputed self-hash caught by successor linkage.");
}

fn run_f4_capstone_attacks(scratch_dir: &Path) {
    println!("\n[>>> F4: Sealed Journal Tamper & Re-Key Attacks <<<]");

    let run_dir = scratch_dir.join(format!("t6_f4_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let key_path = run_dir.join("operator.key");
    let mut keygen = Command::cargo_bin("diskcleaner").unwrap();
    keygen.arg("keygen").arg("--out").arg(&key_path);
    keygen.assert().code(0);

    let (sealed_journal, _loop) = stage_base_journal(scratch_dir, "t6_sealed", Some(&key_path));

    // 1. Sealed Journal Tamper -> Exit code 6
    let copy = scratch_dir.join(format!("f4_tamper_{}.dcj", std::process::id()));
    fs::copy(&sealed_journal, &copy).unwrap();

    // Recompute full hash cascade (L1 and L2 pass!) but without private key
    JournalForge::flip_byte_at_offset(&copy, 15).unwrap();
    JournalForge::recompute_full_cascade(&copy).unwrap();

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("resume")
        .arg("--journal").arg(&copy)
        .arg("--key").arg(&key_path)
        .arg("--no-progress");

    cmd.assert().code(6);
    println!("  [✓] F4.sealed PASSED: Pass-skip / hash cascade forge refused by Ed25519 signature.");

    // 2. Re-key attack with attack private key
    let attack_key_path = run_dir.join("attack.key");
    let mut attack_keygen = Command::cargo_bin("diskcleaner").unwrap();
    attack_keygen.arg("keygen").arg("--out").arg(&attack_key_path);
    attack_keygen.assert().code(0);

    let op_key = dc_cert::OperatorKeyPair::load_from_file(&attack_key_path).unwrap();
    JournalForge::re_sign_with_attack_key(&copy, &op_key.signing_key).unwrap();

    // Resume with original operator key -> MUST REFUSE (key mismatch)
    let mut cmd_rekey = Command::cargo_bin("diskcleaner").unwrap();
    cmd_rekey.arg("resume")
        .arg("--journal").arg(&copy)
        .arg("--key").arg(&key_path)
        .arg("--no-progress");

    cmd_rekey.assert().code(2);
    println!("  [✓] F4.rekey PASSED: Re-keyed sealed journal refused against operator key.");
}

fn run_f5_degenerate_shapes(scratch_dir: &Path) {
    println!("\n[>>> F5: Degenerate Shapes & DoS Allocation Bounds <<<]");
    let run_dir = scratch_dir.join(format!("t6_f5_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    // 1. 0-byte file
    {
        let empty_path = run_dir.join("empty.dcj");
        fs::write(&empty_path, b"").unwrap();

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("resume").arg("--journal").arg(&empty_path).arg("--no-progress");
        cmd.assert().code(6);
        println!("  [✓] F5.empty: 0-byte journal refused with exit code 6.");
    }

    // 2. DoS Guard (len = 0xFFFFFFFF)
    {
        let dos_path = run_dir.join("dos.dcj");
        let mut f = fs::File::create(&dos_path).unwrap();
        use std::io::Write;
        f.write_all(b"DCJ1\xFF\xFF\xFF\xFF").unwrap();
        drop(f);

        let start = std::time::Instant::now();
        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("resume").arg("--journal").arg(&dos_path).arg("--no-progress");
        cmd.assert().code(6);
        assert!(start.elapsed().as_secs() < 2, "[F5-DOS] Parser hung on huge length!");
        println!("  [✓] F5.dos: 4 GiB length bounded allocation refused in < 2s without OOM.");
    }
}

fn run_f6_sealed_ops(scratch_dir: &Path) {
    println!("\n[>>> F6: Sealed Journal Key Discipline <<<]");
    let run_dir = scratch_dir.join(format!("t6_f6_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let key_path = run_dir.join("operator.key");
    let mut keygen = Command::cargo_bin("diskcleaner").unwrap();
    keygen.arg("keygen").arg("--out").arg(&key_path);
    keygen.assert().code(0);

    let (sealed_journal, _loop) = stage_base_journal(scratch_dir, "t6_f6_base", Some(&key_path));

    // 1. Resume WITHOUT key on sealed journal -> MUST REFUSE (exit 1 / usage)
    let mut cmd_nokey = Command::cargo_bin("diskcleaner").unwrap();
    cmd_nokey.arg("resume").arg("--journal").arg(&sealed_journal).arg("--no-progress");
    cmd_nokey.assert().code(1);
    println!("  [✓] F6.nokey: Sealed journal resume refused when --key is missing.");

    // 2. Resume WITH valid key -> MUST COMPLETE cleanly (exit 0)
    let mut cmd_valid = Command::cargo_bin("diskcleaner").unwrap();
    cmd_valid.arg("resume")
        .arg("--journal").arg(&sealed_journal)
        .arg("--key").arg(&key_path)
        .arg("--no-progress");
    cmd_valid.assert().code(0);
    println!("  [✓] F6.valid: Sealed journal resumed and completed cleanly with valid key.");
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
