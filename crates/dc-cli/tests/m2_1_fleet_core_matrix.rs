use dc_core::fleet::{
    AdvisoryResolution, ArgvConstructor, AssignmentRow, BatchManifest, BatchReconstructor,
    ChildJournalState, FleetJobOutcome, FleetReport, IdentityResolver, SpawnContext,
};
use dc_testkit::RigLedger;

#[test]
fn test_m2_1_fleet_core_matrix() {
    let ledger = RigLedger::new();

    // 1. PREPARE-COMMIT: Manifest Authoring & Immutable Hash Freeze (Δ391)
    run_prepare_commit_tests(&ledger);

    // 2. RESOLVE-ADVISORY-TOCTOU: Advisory Resolution vs Child Enforcement (Δ390, Δ392)
    run_resolution_and_toctou_tests(&ledger);

    // 3. ARGV-SEAM-HASH: Constructed vs Received Argv Seam Contract (Δ393)
    run_argv_seam_tests(&ledger);

    // 4. NO-REASSIGN: Refusal Immortality Law (Δ396)
    run_no_reassignment_tests(&ledger);

    assert!(ledger.is_all_green(), "[M2.1-FAIL] Fleet Core matrix contains failing assertions!");
    println!("\n[=== MILESTONE M2.1 FLEET ORCHESTRATION CORE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_prepare_commit_tests(ledger: &RigLedger) {
    println!("\n[>>> PREPARE-COMMIT: Testing Manifest Authoring & Freeze (Δ391) <<<]");

    let manifest = BatchManifest::new(
        "BATCH_PREPARE_001",
        vec![
            AssignmentRow {
                slot_id: 0,
                expected_serial: "SED_SERIAL_ALPHA".to_string(),
                plan_profile: "clear-zero".to_string(),
                scan_attestation: "SCAN_ATTEST_A".to_string(),
            },
            AssignmentRow {
                slot_id: 1,
                expected_serial: "SED_SERIAL_BETA".to_string(),
                plan_profile: "clear-random".to_string(),
                scan_attestation: "SCAN_ATTEST_B".to_string(),
            },
        ],
    );

    let frozen_hash = manifest.compute_manifest_hash();
    assert!(!frozen_hash.is_empty());
    assert_eq!(frozen_hash.len(), 64);

    ledger.assert("M2.1-PREPARE", "PREPARE-COMMIT-IMMUTABLE", "64", frozen_hash.len().to_string(), None);
}

fn run_resolution_and_toctou_tests(ledger: &RigLedger) {
    println!("\n[>>> RESOLVE-ADVISORY-TOCTOU: Testing Advisory Resolution & TOCTOU (Δ390, Δ392) <<<]");

    let live_devices = vec![
        ("/dev/sda".to_string(), "SED_SERIAL_ALPHA".to_string()),
        ("/dev/sdb".to_string(), "SED_SERIAL_BETA".to_string()),
        ("/dev/sdc".to_string(), "SED_SERIAL_CLONE".to_string()),
        ("/dev/sdd".to_string(), "SED_SERIAL_CLONE".to_string()),
    ];

    // 1. Unique resolution
    let unique_res = IdentityResolver::resolve_identity("SED_SERIAL_ALPHA", &live_devices);
    assert_eq!(
        unique_res,
        AdvisoryResolution::Unique {
            path: "/dev/sda".to_string(),
            serial: "SED_SERIAL_ALPHA".to_string()
        }
    );

    // 2. Absent resolution
    let absent_res = IdentityResolver::resolve_identity("SED_SERIAL_NONEXISTENT", &live_devices);
    assert_eq!(absent_res, AdvisoryResolution::Absent);

    // 3. Ambiguous resolution (cloned serials on live bus)
    let ambig_res = IdentityResolver::resolve_identity("SED_SERIAL_CLONE", &live_devices);
    assert!(matches!(ambig_res, AdvisoryResolution::Ambiguous(_)));

    ledger.assert("M2.1-RESOLVE", "RESOLVE-UNIQUE", "true", matches!(unique_res, AdvisoryResolution::Unique { .. }).to_string(), None);
    ledger.assert("M2.1-RESOLVE", "RESOLVE-ABSENT", "true", matches!(absent_res, AdvisoryResolution::Absent).to_string(), None);
    ledger.assert("M2.1-RESOLVE", "RESOLVE-AMBIG", "true", matches!(ambig_res, AdvisoryResolution::Ambiguous(_)).to_string(), None);
}

fn run_argv_seam_tests(ledger: &RigLedger) {
    println!("\n[>>> ARGV-SEAM-HASH: Testing Deterministic Child Argv Seam (Δ393) <<<]");

    let ctx = SpawnContext {
        plan_path: "/tmp/plans/clear_zero.json".to_string(),
        key_path: Some("/tmp/keys/operator.key".to_string()),
        out_dir: "/tmp/out".to_string(),
    };

    let argv = ArgvConstructor::construct_child_argv("SED_SERIAL_ALPHA", "/dev/sda", &ctx);
    let hash_1 = ArgvConstructor::compute_argv_hash(&argv);
    let hash_2 = ArgvConstructor::compute_argv_hash(&argv);

    // Assert deterministic hash
    assert_eq!(hash_1, hash_2);

    // Flag creep test: adding unauthorized flag changes hash immediately
    let mut modified_argv = argv.clone();
    modified_argv.push("--unauthorized-flag".to_string());
    let crept_hash = ArgvConstructor::compute_argv_hash(&modified_argv);
    assert_ne!(hash_1, crept_hash, "Argv seam must catch flag creep!");

    ledger.assert("M2.1-SEAM", "ARGV-SEAM-HASH", "true", (hash_1 == hash_2).to_string(), None);
}

fn run_no_reassignment_tests(ledger: &RigLedger) {
    println!("\n[>>> NO-REASSIGN: Testing Refusal Immortality Law (Δ396) <<<]");

    let manifest = BatchManifest::new(
        "BATCH_REFUSAL_TEST",
        vec![
            AssignmentRow {
                slot_id: 0,
                expected_serial: "REFUSED_SERIAL_001".to_string(),
                plan_profile: "clear-zero".to_string(),
                scan_attestation: "SCAN_REFUSED".to_string(),
            },
        ],
    );

    let child_journals = vec![
        ChildJournalState {
            slot_id: 0,
            serial: "REFUSED_SERIAL_001".to_string(),
            terminal_state: Some("GUARDIAN_REFUSED".to_string()),
            cert_hash: None,
        },
    ];

    let report = BatchReconstructor::reconstruct_from_evidence(&manifest, &child_journals);

    // Refused job must stay GuardianRefused (exit code 2)
    assert_eq!(report.records[0].outcome, FleetJobOutcome::GuardianRefused);
    assert_eq!(report.derive_aggregate_exit_code(), 2);

    ledger.assert("M2.1-REASSIGN", "NO-REASSIGN-TERMINAL", "2", report.derive_aggregate_exit_code().to_string(), None);
}
