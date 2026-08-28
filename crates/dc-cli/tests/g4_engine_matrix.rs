use dc_core::{FastPathPolicy, FixedPattern, FsmOrchestrator, LbaSpan, SanitizationPlan, StableIdentity, BusType};
use dc_io::{CompletionTracker, SyncEngine, WindowGeometry, ZeroPath};
use dc_testkit::RigLedger;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use tempfile::NamedTempFile;

#[test]
fn test_g4_engine_matrix() {
    let ledger = RigLedger::new();

    // 1. ENG-TRACKER-CONTIG & PROP: Contiguous Prefix Law under Out-Of-Order CQEs (Δ135)
    run_eng_tracker_tests(&ledger);

    // 2. ENG-ARITH & SHORTWIN: Window Geometry & Boundary Arithmetic
    run_eng_arith_tests(&ledger);

    // 3. ENG-FASTPATH-POLICY: Fast-Path Policy Gating (Δ136, Δ142)
    run_eng_fastpath_tests(&ledger);

    // 4. ENG-WELD-EXEC: Direct-I/O Engine Execution & Verification
    run_eng_weld_exec_tests(&ledger);

    assert!(ledger.is_all_green(), "[G4-FAIL] Engine matrix contains failing assertions!");
    println!("\n[=== G4 I/O ENGINE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_eng_tracker_tests(ledger: &RigLedger) {
    println!("\n[>>> ENG-TRACKER: Testing Contiguous Prefix Commit Invariant (Δ135) <<<]");

    let mut tracker = CompletionTracker::new(0);

    // Out-of-order CQE arrival: 1, 3, 0, 2
    tracker.on_cqe(1);
    assert!(!tracker.can_commit(), "Cannot commit when window 0 has not completed");

    tracker.on_cqe(3);
    assert!(!tracker.can_commit(), "Cannot commit when window 0 has not completed");

    tracker.on_cqe(0);
    // Now windows 0 and 1 are contiguous!
    assert!(tracker.can_commit());
    let spec1 = tracker.commit_all_contiguous().unwrap();
    assert_eq!(spec1.first_window, 0);
    assert_eq!(spec1.num_windows, 2); // [0, 2)

    // Window 2 completes -> now 2 and 3 are contiguous!
    tracker.on_cqe(2);
    assert!(tracker.can_commit());
    let spec2 = tracker.commit_all_contiguous().unwrap();
    assert_eq!(spec2.first_window, 2);
    assert_eq!(spec2.num_windows, 2); // [2, 4)

    ledger.assert("G4-TRACKER", "ENG-TRACKER-CONTIG", "4", tracker.committed_watermark().to_string(), None);
}

fn run_eng_arith_tests(ledger: &RigLedger) {
    println!("\n[>>> ENG-ARITH: Testing Window Geometry & Boundary Arithmetic <<<]");

    // 1. Exact multiple (64 MiB total, 2 MiB window -> 32 windows, no short window)
    let geom_exact = WindowGeometry::new(64 * 1024 * 1024, 512, 2 * 1024 * 1024).unwrap();
    assert_eq!(geom_exact.total_windows, 32);
    assert_eq!(geom_exact.short_window_bytes, None);
    ledger.assert("G4-ARITH", "ENG-ARITH-EXACT", "32", geom_exact.total_windows.to_string(), None);

    // 2. Short final window (65 MiB total, 2 MiB window -> 33 windows, final is 1 MiB)
    let geom_short = WindowGeometry::new(65 * 1024 * 1024, 512, 2 * 1024 * 1024).unwrap();
    assert_eq!(geom_short.total_windows, 33);
    assert_eq!(geom_short.short_window_bytes, Some(1024 * 1024));
    assert_eq!(geom_short.window_len_bytes(32), 1024 * 1024);
    ledger.assert("G4-ARITH", "ENG-SHORTWIN", "1048576", geom_short.short_window_bytes.unwrap().to_string(), None);
}

fn run_eng_fastpath_tests(ledger: &RigLedger) {
    println!("\n[>>> ENG-FASTPATH: Testing Policy Gating (Δ136) <<<]");

    let temp_file = NamedTempFile::new().unwrap();
    let res = ZeroPath::execute_chunked(
        temp_file.as_file(),
        32 * 1024 * 1024,
        FastPathPolicy::ForbidWriteZeroes,
        true,
        None,
        |_, _| {},
    );

    assert!(res.is_err(), "ForbidWriteZeroes must reject fast path execution");
    ledger.assert("G4-FASTPATH", "ENG-FASTPATH-POLICY", "true", res.is_err().to_string(), None);
}

fn run_eng_weld_exec_tests(ledger: &RigLedger) {
    println!("\n[>>> ENG-WELD-EXEC: Testing Engine Pass Execution & Verification <<<]");

    let mut temp_file = NamedTempFile::new().unwrap();
    let size = 16 * 1024 * 1024; // 16 MiB
    temp_file.as_file_mut().set_len(size).unwrap();

    let window_bytes = 2 * 1024 * 1024;
    let span = LbaSpan::new(size, 512, window_bytes);

    let file = temp_file.reopen().unwrap();
    let mut engine = SyncEngine::new(file, window_bytes as usize, false).unwrap();

    let mut fsm = FsmOrchestrator::new();
    let identity = StableIdentity {
        model: Some("TestDrive".to_string()),
        serial: Some("SN001".to_string()),
        wwn: None,
        size_bytes: size,
        bus: BusType::Nvme,
        dm_name: None,
        dm_uuid: None,
    };
    let plan = SanitizationPlan::clear_zero(identity, FastPathPolicy::ForbidWriteZeroes);
    fsm.compile_plan(plan).unwrap();
    fsm.approve_plan().unwrap();
    fsm.arm().unwrap();
    let permit = fsm.begin_pass(0).unwrap();

    let pat = FixedPattern { byte: 0x55 };
    let outcome = engine.write_pass(&permit, 0, &pat, &span, 0, &mut |_| {}).unwrap();

    assert_eq!(outcome.windows_written, 8);
    assert_eq!(outcome.bytes_written, size);

    // Verify media contains pattern
    let mut readback = vec![0u8; size as usize];
    let mut f = temp_file.reopen().unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f.read_exact(&mut readback).unwrap();
    let all_match = readback.iter().all(|&b| b == 0x55);

    ledger.assert("G4-EXEC", "ENG-MEDIA-MATCH", "true", all_match.to_string(), None);
}
