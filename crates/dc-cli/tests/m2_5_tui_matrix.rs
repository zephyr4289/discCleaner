use dc_testkit::RigLedger;
use dc_tui::{DisplayState, Heatmap, HeatmapCellState, PhaseView, TuiRenderer};

#[test]
fn test_m2_5_tui_matrix() {
    let ledger = RigLedger::new();

    // 1. FRAME-NOHASH-IN-WRITE: Phase-True Rendering in Write Phase (Δ461)
    run_phase_true_write_tests(&ledger);

    // 2. FRAME-VERIFY-ENTROPY-NEUTRAL: Neutral Diagnostic Entropy in Verify Phase (Δ461, Δ465)
    run_phase_true_verify_tests(&ledger);

    // 3. HEATMAP-ALL-OR-MIXED & HEATMAP-FAIL-POSITION: Heatmap Cell State Logic (Δ464)
    run_heatmap_aggregation_tests(&ledger);

    // 4. RECONCILE-FRAME-CERT: Completion Frame Fact Reconciliation (Δ460)
    run_frame_reconciliation_tests(&ledger);

    assert!(ledger.is_all_green(), "[M2.5-FAIL] TUI Dashboard matrix contains failing assertions!");
    println!("\n[=== MILESTONE M2.5 TUI DASHBOARD MATRIX PASSED ALL CELLS ===]\n");
}

fn run_phase_true_write_tests(ledger: &RigLedger) {
    println!("\n[>>> FRAME-NOHASH-IN-WRITE: Testing Phase-True Write Rendering (Δ461) <<<]");

    let state = DisplayState {
        target_path: "/dev/nvme0n1".to_string(),
        target_model: "Samsung 990 PRO".to_string(),
        target_serial: "S6PBNJ0W123456".to_string(),
        phase: PhaseView::Writing {
            pass: 1,
            frontier_lba: 500000,
        },
        written_windows: 5000,
        total_windows: 10000,
        throughput_kib_s: Some(3500000),
        failed_windows: vec![],
    };

    let frame = TuiRenderer::render(&state, 10);

    // Assert NO stream hash and NO entropy line in write phase!
    assert!(frame.stream_hash_line.is_none(), "Stream hash MUST NOT render in write phase!");
    assert!(frame.verify_entropy_line.is_none(), "Entropy line MUST NOT render in write phase!");
    assert!(frame.rate_line.as_ref().unwrap().contains("~3500000 KiB/s (indicative)"));

    ledger.assert("M2.5-FRAME", "FRAME-NOHASH-IN-WRITE", "true", frame.stream_hash_line.is_none().to_string(), None);
}

fn run_phase_true_verify_tests(ledger: &RigLedger) {
    println!("\n[>>> FRAME-VERIFY-ENTROPY-NEUTRAL: Testing Diagnostic Entropy (Δ461, Δ465) <<<]");

    let state = DisplayState {
        target_path: "/dev/nvme0n1".to_string(),
        target_model: "Samsung 990 PRO".to_string(),
        target_serial: "S6PBNJ0W123456".to_string(),
        phase: PhaseView::Verifying {
            pass: 1,
            checked_windows: 5000,
            entropy: 0.0012,
        },
        written_windows: 10000,
        total_windows: 10000,
        throughput_kib_s: Some(4200000),
        failed_windows: vec![],
    };

    let frame = TuiRenderer::render(&state, 10);

    assert!(frame.verify_entropy_line.is_some());
    let entropy_line = frame.verify_entropy_line.unwrap();
    assert!(entropy_line.contains("Entropy H(X): 0.0012 (diagnostic)"));
    assert!(!entropy_line.contains("✓"), "Entropy must never be rendered as pass/fail verdict!");

    ledger.assert("M2.5-FRAME", "FRAME-VERIFY-ENTROPY-NEUTRAL", "true", entropy_line.contains("(diagnostic)").to_string(), None);
}

fn run_heatmap_aggregation_tests(ledger: &RigLedger) {
    println!("\n[>>> HEATMAP: Testing All-or-Mixed Aggregation & Failure Positioning (Δ464) <<<]");

    // 100 windows, 10 cells -> 10 windows per cell
    // Window 25 failed (in cell index 2: windows 20..30)
    let heatmap = Heatmap::build(100, 50, 20, &[25], 10);

    assert_eq!(heatmap.cells[0], HeatmapCellState::Verified); // 0..10 verified
    assert_eq!(heatmap.cells[1], HeatmapCellState::Verified); // 10..20 verified
    assert_eq!(heatmap.cells[2], HeatmapCellState::Failed);   // 20..30 failed at window 25!
    assert_eq!(heatmap.cells[3], HeatmapCellState::Written);  // 30..40 written
    assert_eq!(heatmap.cells[4], HeatmapCellState::Written);  // 40..50 written
    assert_eq!(heatmap.cells[5], HeatmapCellState::Pending);  // 50..60 pending

    ledger.assert("M2.5-HEATMAP", "HEATMAP-FAIL-POSITION", "Failed", format!("{:?}", heatmap.cells[2]), None);
    ledger.assert("M2.5-HEATMAP", "HEATMAP-ALL-OR-MIXED", "Verified", format!("{:?}", heatmap.cells[0]), None);
}

fn run_frame_reconciliation_tests(ledger: &RigLedger) {
    println!("\n[>>> RECONCILE: Testing Completion Frame Reconciliation (Δ460) <<<]");

    let stream_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let state = DisplayState {
        target_path: "/dev/nvme0n1".to_string(),
        target_model: "Samsung 990 PRO".to_string(),
        target_serial: "S6PBNJ0W123456".to_string(),
        phase: PhaseView::Complete {
            stream_hash: stream_digest.to_string(),
            duration_ms: 120000,
        },
        written_windows: 10000,
        total_windows: 10000,
        throughput_kib_s: None,
        failed_windows: vec![],
    };

    let frame = TuiRenderer::render(&state, 10);

    assert!(frame.stream_hash_line.is_some());
    assert!(frame.stream_hash_line.unwrap().contains(stream_digest));
    assert_eq!(state.progress_pct(), 100.0);

    ledger.assert("M2.5-RECONCILE", "RECONCILE-FRAME-CERT", "100", state.progress_pct().to_string(), None);
}
