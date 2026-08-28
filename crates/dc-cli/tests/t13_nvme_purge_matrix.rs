use dc_hw::NvmeSanitizeStatus;
use dc_testkit::{
    AdoptionArbiter, AdoptionDecision, MockLogFeed, RigLedger, SanitizeStatusSource,
};

#[test]
fn test_t13_nvme_purge_matrix() {
    let ledger = RigLedger::new();

    // 1. T13-SM-MONO: Monotonic Mock Log Stream Walk (Δ233)
    run_sm_mono_tests(&ledger);

    // 2. T13-SM-STUCK: Frozen Progress Stream (Δ235)
    run_sm_stuck_tests(&ledger);

    // 3. T13-ADOPT: The 4-Case Adoption Matrix (Δ236, INV15)
    run_adopt_four_cases_tests(&ledger);

    assert!(ledger.is_all_green(), "[T13-FAIL] NVMe Purge matrix contains failing assertions!");
    println!("\n[=== PHASE T13 NVME PURGE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_sm_mono_tests(ledger: &RigLedger) {
    println!("\n[>>> T13-SM-MONO: Testing Monotonic Log Stream Walk (Δ233) <<<]");

    let mut feed = MockLogFeed::monotonic();

    let s1 = feed.poll_status().unwrap();
    assert_eq!(s1.progress_permille, 0);
    assert!(s1.is_in_progress);

    let s2 = feed.poll_status().unwrap();
    assert_eq!(s2.progress_permille, 500);
    assert!(s2.is_in_progress);

    let s3 = feed.poll_status().unwrap();
    assert_eq!(s3.progress_permille, 1000);
    assert!(s3.is_completed);

    ledger.assert("T13-SM", "T13-SM-MONO", "1000", s3.progress_permille.to_string(), None);
}

fn run_sm_stuck_tests(ledger: &RigLedger) {
    println!("\n[>>> T13-SM-STUCK: Testing Stuck Progress Stream (Δ235) <<<]");

    let mut feed = MockLogFeed::stuck();

    let s1 = feed.poll_status().unwrap();
    let s2 = feed.poll_status().unwrap();
    let s3 = feed.poll_status().unwrap();

    let is_stuck = s1.progress_permille == 400 && s2.progress_permille == 400 && s3.progress_permille == 400;
    ledger.assert("T13-SM", "T13-SM-STUCK", "true", is_stuck.to_string(), None);
}

fn run_adopt_four_cases_tests(ledger: &RigLedger) {
    println!("\n[>>> T13-ADOPT: Testing The 4-Case Adoption Protocol (Δ236, INV15) <<<]");

    let in_progress_status = NvmeSanitizeStatus {
        progress_permille: 430,
        is_in_progress: true,
        is_completed: false,
        is_failed: false,
        raw_sstat: 2,
        raw_sprog: 28180,
    };

    let completed_status = NvmeSanitizeStatus {
        progress_permille: 1000,
        is_in_progress: false,
        is_completed: true,
        is_failed: false,
        raw_sstat: 1,
        raw_sprog: 65535,
    };

    // Case 1: Ours in flight -> Adopt progress
    let dec1 = AdoptionArbiter::arbitrate(true, false, &in_progress_status);
    let is_adopt_in_flight = matches!(dec1, AdoptionDecision::AdoptInFlight { progress_permille: 430, .. });
    ledger.assert("T13-ADOPT", "T13-ADOPT-OURS", "true", is_adopt_in_flight.to_string(), None);

    // Case 2: Ours completed while process was dead -> Adopt completed
    let dec2 = AdoptionArbiter::arbitrate(true, false, &completed_status);
    let is_adopt_completed = matches!(dec2, AdoptionDecision::AdoptCompleted);
    ledger.assert("T13-ADOPT", "T13-ADOPT-COMPLETE", "true", is_adopt_completed.to_string(), None);

    // Case 3: Foreign in flight (no issuance record) -> Refuse foreign
    let dec3 = AdoptionArbiter::arbitrate(false, false, &in_progress_status);
    let is_refuse_foreign = matches!(dec3, AdoptionDecision::RefuseForeign);
    ledger.assert("T13-ADOPT", "T13-ADOPT-FOREIGN", "true", is_refuse_foreign.to_string(), None);

    // Case 4: Contradiction (journal says failed, drive says in progress) -> Refuse contradiction
    let dec4 = AdoptionArbiter::arbitrate(true, true, &in_progress_status);
    let is_refuse_contra = matches!(dec4, AdoptionDecision::RefuseContradiction { .. });
    ledger.assert("T13-ADOPT", "T13-ADOPT-CONTRA", "true", is_refuse_contra.to_string(), None);
}
