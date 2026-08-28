use dc_core::fleet::{
    AssignmentRow, BatchManifest, BatchReconstructor, ChildJournalState, FleetJobOutcome,
    FleetJobRecord, FleetReport,
};
use dc_testkit::{FleetRigMock, RigLedger};

#[test]
fn test_t20_fleet_matrix() {
    let ledger = RigLedger::new();

    // 1. ASSIGN-AMBIG: Assignment Manifest Ambiguity & Duplicate Validation (Δ379)
    run_manifest_validation_tests(&ledger);

    // 2. FLEET-VICTORY: Session-Isolated Signal Tree Routing (Δ378)
    run_fleet_signal_victory_tests(&ledger);

    // 3. REPORT-SEVERITY: Aggregate Exit Code Severity Hierarchy (Δ384)
    run_report_severity_tests(&ledger);

    // 4. RECON-SUPERVISOR-DEATH: Evidence-Based Batch Reconstruction (Δ381)
    run_reconstruction_tests(&ledger);

    assert!(ledger.is_all_green(), "[T20-FAIL] Fleet Rig matrix contains failing assertions!");
    println!("\n[=== PHASE T20 FLEET RIG MATRIX PASSED ALL CELLS ===]\n");
}

fn run_manifest_validation_tests(ledger: &RigLedger) {
    println!("\n[>>> ASSIGN-AMBIG: Testing Manifest Ambiguity & Duplicates (Δ379) <<<]");

    // 1. Duplicate slot -> Refused!
    let dup_slot_manifest = BatchManifest::new(
        "BATCH_DUP_SLOT",
        vec![
            AssignmentRow { slot_id: 0, expected_serial: "SN_001".to_string(), plan_profile: "default".to_string(), scan_attestation: "SCAN_1".to_string() },
            AssignmentRow { slot_id: 0, expected_serial: "SN_002".to_string(), plan_profile: "default".to_string(), scan_attestation: "SCAN_2".to_string() },
        ],
    );
    let dup_slot_res = dup_slot_manifest.validate();
    assert!(dup_slot_res.is_err());
    assert_eq!(dup_slot_res.unwrap_err(), "DUPLICATE_SLOT_IN_MANIFEST");

    // 2. Cloned serial across slots -> Refused (Ambiguity gate)!
    let clone_manifest = BatchManifest::new(
        "BATCH_CLONE_SERIAL",
        vec![
            AssignmentRow { slot_id: 0, expected_serial: "SN_CLONE_X".to_string(), plan_profile: "default".to_string(), scan_attestation: "SCAN_1".to_string() },
            AssignmentRow { slot_id: 1, expected_serial: "SN_CLONE_X".to_string(), plan_profile: "default".to_string(), scan_attestation: "SCAN_2".to_string() },
        ],
    );
    let clone_res = clone_manifest.validate();
    assert!(clone_res.is_err());
    assert_eq!(clone_res.unwrap_err(), "AMBIGUOUS_ASSIGNMENT_CLONED_SERIAL");

    // 3. Valid 16-slot manifest -> Accepted!
    let mut valid_rows = Vec::new();
    for i in 0..16 {
        valid_rows.push(AssignmentRow {
            slot_id: i,
            expected_serial: format!("UNIQUE_SN_{:03}", i),
            plan_profile: "default".to_string(),
            scan_attestation: format!("SCAN_{:03}", i),
        });
    }
    let valid_manifest = BatchManifest::new("BATCH_VALID_16", valid_rows);
    assert!(valid_manifest.validate().is_ok());

    ledger.assert("T20-ASSIGN", "ASSIGN-DUP", "true", dup_slot_res.is_err().to_string(), None);
    ledger.assert("T20-ASSIGN", "ASSIGN-CLONE", "true", clone_res.is_err().to_string(), None);
}

fn run_fleet_signal_victory_tests(ledger: &RigLedger) {
    println!("\n[>>> FLEET-VICTORY: Testing Session-Isolated Signal Tree Routing (Δ378) <<<]");

    let mut rig = FleetRigMock::new(16);

    // 9 children complete before operator presses Ctrl-C
    for i in 0..9 {
        rig.mark_completed(i);
    }

    // Operator sends SIGINT to supervisor -> forwards to active children (slots 9..15)
    rig.forward_operator_signal("SIGINT");

    // Assert completed children stayed CLEAN_COMPLETED (victory lap)
    for i in 0..9 {
        assert_eq!(rig.children[i].terminal_outcome.as_deref(), Some("CLEAN_COMPLETED"));
    }

    // Assert mid-pass children received signal and became INTERRUPTED
    for i in 9..16 {
        assert_eq!(rig.children[i].terminal_outcome.as_deref(), Some("INTERRUPTED"));
        assert_eq!(rig.children[i].received_signal.as_deref(), Some("SIGINT"));
    }

    let report = rig.reconstruct_report();
    assert_eq!(report.derive_aggregate_exit_code(), 1); // Mixed report exit code = 1 (Interrupted)

    ledger.assert("T20-FLEET", "FLEET-VICTORY", "1", report.derive_aggregate_exit_code().to_string(), None);
}

fn run_report_severity_tests(ledger: &RigLedger) {
    println!("\n[>>> REPORT-SEVERITY: Testing Exit Code Severity Hierarchy (Δ384) <<<]");

    let records = vec![
        FleetJobRecord { slot_id: 0, serial: "SN0".to_string(), outcome: FleetJobOutcome::Clean, exit_code: 0, cert_hash: None },
        FleetJobRecord { slot_id: 1, serial: "SN1".to_string(), outcome: FleetJobOutcome::Interrupted, exit_code: 1, cert_hash: None },
        FleetJobRecord { slot_id: 2, serial: "SN2".to_string(), outcome: FleetJobOutcome::GuardianRefused, exit_code: 2, cert_hash: None },
        FleetJobRecord { slot_id: 3, serial: "SN3".to_string(), outcome: FleetJobOutcome::VerificationFailed, exit_code: 4, cert_hash: None },
    ];

    let report = FleetReport {
        batch_id: "BATCH_SEVERITY".to_string(),
        manifest_hash: "HASH123".to_string(),
        merkle_fingerprint: "MERKLE456".to_string(),
        records,
    };

    // VerificationFailed (4) outranks all other outcomes
    assert_eq!(report.derive_aggregate_exit_code(), 4);

    ledger.assert("T20-REPORT", "REPORT-SEVERITY-PRECEDENCE", "4", report.derive_aggregate_exit_code().to_string(), None);
}

fn run_reconstruction_tests(ledger: &RigLedger) {
    println!("\n[>>> RECON-SUPERVISOR-DEATH: Testing Batch Reconstruction from Evidence (Δ381) <<<]");

    let manifest = BatchManifest::new(
        "BATCH_RECON",
        vec![
            AssignmentRow { slot_id: 0, expected_serial: "SN_001".to_string(), plan_profile: "default".to_string(), scan_attestation: "SCAN_1".to_string() },
            AssignmentRow { slot_id: 1, expected_serial: "SN_002".to_string(), plan_profile: "default".to_string(), scan_attestation: "SCAN_2".to_string() },
        ],
    );

    let child_journals = vec![
        ChildJournalState { slot_id: 0, serial: "SN_001".to_string(), terminal_state: Some("CLEAN_COMPLETED".to_string()), cert_hash: Some("CERT_HASH_001".to_string()) },
        ChildJournalState { slot_id: 1, serial: "SN_002".to_string(), terminal_state: Some("CLEAN_COMPLETED".to_string()), cert_hash: Some("CERT_HASH_002".to_string()) },
    ];

    // Reconstruct without any supervisor state
    let report = BatchReconstructor::reconstruct_from_evidence(&manifest, &child_journals);

    assert_eq!(report.records.len(), 2);
    assert_eq!(report.derive_aggregate_exit_code(), 0);
    assert!(!report.merkle_fingerprint.is_empty());

    ledger.assert("T20-RECON", "RECON-SUPERVISOR-DEATH", "0", report.derive_aggregate_exit_code().to_string(), None);
}
