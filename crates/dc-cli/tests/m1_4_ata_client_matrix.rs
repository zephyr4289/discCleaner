use dc_ata::{
    AtaFsmOutcome, AtaLifeline, AtaSecurityFsm, FdGen, FreezeEvaluator, GeometryTransaction,
};
use dc_hw::AtaSecurityStatus;
use dc_testkit::RigLedger;

#[test]
fn test_m1_4_ata_client_matrix() {
    let ledger = RigLedger::new();

    // 1. ATA-FSM-VECTORS: Pure No-Harm Security State Machine (Δ278)
    run_fsm_vectors_tests(&ledger);

    // 2. ATA-LIFELINE-VOID: Lifeline Creation, Voiding & Revocation (Δ276)
    run_lifeline_lifecycle_tests(&ledger);

    // 3. ATA-GEOM-TXN: Geometry Transaction & FdGen Tracking (Δ277, Δ281)
    run_geometry_transaction_tests(&ledger);

    // 4. ATA-FREEZE-DISCLOSE: Freeze Product Contract & Override (Δ280)
    run_freeze_contract_tests(&ledger);

    assert!(ledger.is_all_green(), "[M1.4-FAIL] ATA Client matrix contains failing assertions!");
    println!("\n[=== MILESTONE M1.4 ATA PURGE CLIENT MATRIX PASSED ALL CELLS ===]\n");
}

fn run_fsm_vectors_tests(ledger: &RigLedger) {
    println!("\n[>>> ATA-FSM-VECTORS: Testing No-Harm Security FSM (Δ278) <<<]");

    // 1. Happy path: Arm -> Success -> Clean outcome
    let mut fsm1 = AtaSecurityFsm::new();
    let sec_ok = AtaSecurityStatus {
        supported: true,
        enabled: false,
        locked: false,
        frozen: false,
        enhanced_erase_supported: true,
        erase_time_minutes: Some(30),
        enhanced_erase_time_minutes: Some(30),
    };
    assert!(fsm1.process_intake(&sec_ok).is_ok());
    fsm1.arm("rescue123", true);
    let out1 = fsm1.on_erase_success(true);
    assert_eq!(out1, AtaFsmOutcome::Clean { enhanced: true });
    ledger.assert("M1.4-FSM", "ATA-FSM-CLEAN", "true", "true", None);

    // 2. Erase failure -> Repaired outcome
    let mut fsm2 = AtaSecurityFsm::new();
    assert!(fsm2.process_intake(&sec_ok).is_ok());
    fsm2.arm("rescue456", true);
    let out2 = fsm2.on_erase_failure(true);
    assert_eq!(out2, AtaFsmOutcome::Repaired { rescue_password: "rescue456".to_string() });
    ledger.assert("M1.4-FSM", "ATA-FSM-REPAIR", "rescue456", "rescue456", None);

    // 3. Intake refusal on pre-locked drive
    let mut fsm3 = AtaSecurityFsm::new();
    let mut sec_locked = sec_ok.clone();
    sec_locked.locked = true;
    let intake_res = fsm3.process_intake(&sec_locked);
    assert_eq!(intake_res, Err(AtaFsmOutcome::RefusedPreLocked));
    ledger.assert("M1.4-FSM", "ATA-FSM-INTAKE-REFUSAL", "true", intake_res.is_err().to_string(), None);
}

fn run_lifeline_lifecycle_tests(ledger: &RigLedger) {
    println!("\n[>>> ATA-LIFELINE-VOID: Testing Lifeline Lifecycle (Δ276) <<<]");

    let mut lifeline = AtaLifeline::new("secret_rescue_password");
    assert!(!lifeline.voided);
    assert_eq!(lifeline.plaintext_password, Some("secret_rescue_password".to_string()));

    // Voiding upon verified unlock
    lifeline.void();
    assert!(lifeline.voided);
    assert_eq!(lifeline.plaintext_password, None);
    ledger.assert("M1.4-LIFELINE", "ATA-LIFELINE-VOID", "true", lifeline.voided.to_string(), None);
}

fn run_geometry_transaction_tests(ledger: &RigLedger) {
    println!("\n[>>> ATA-GEOM-TXN: Testing Geometry Transaction & FdGen (Δ277, Δ281) <<<]");

    let mut txn = GeometryTransaction::begin(1_000_000, 1_500_000, 2_000_000);
    let gen0 = FdGen(0);

    // Stage 1: DCO Restore (POR advances FdGen to 1)
    let gen1 = txn.stage_dco_restore(gen0);
    assert_eq!(gen1, FdGen(1));
    assert_eq!(txn.native_capacity, 2_000_000);

    // Stage 2: HPA Unlock
    txn.stage_hpa_unlock(gen1);
    assert_eq!(txn.current_capacity, 2_000_000);

    // Commit
    txn.commit();
    assert!(txn.committed);
    assert_eq!(txn.stages.len(), 2);
    ledger.assert("M1.4-GEOM", "ATA-GEOM-TXN", "2000000", txn.current_capacity.to_string(), None);
}

fn run_freeze_contract_tests(ledger: &RigLedger) {
    println!("\n[>>> ATA-FREEZE-DISCLOSE: Testing Freeze Contract (Δ280) <<<]");

    // Frozen without override -> Refused with disclosure
    let res1 = FreezeEvaluator::evaluate(true, false);
    assert!(res1.is_err());
    let finding = res1.unwrap_err();
    assert!(finding.is_frozen);
    assert!(!finding.override_active);

    // Frozen with override -> Allowed
    let res2 = FreezeEvaluator::evaluate(true, true);
    assert!(res2.is_ok());

    ledger.assert("M1.4-FREEZE", "ATA-FREEZE-DISCLOSE", "true", "true", None);
}
