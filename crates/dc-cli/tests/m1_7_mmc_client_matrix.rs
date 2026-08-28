use dc_mmc::{
    ConfigTransactionPermit, ConfigTxnGuard, MmcPurgeClient, TwoAxisConfirmation,
};
use dc_nvme::PurgePermit;
use dc_scsi::UfsSessionDiscriminator;
use dc_testkit::{MmcAccessClass, RigLedger};

#[test]
fn test_m1_7_mmc_client_matrix() {
    let ledger = RigLedger::new();

    // 1. CONF2-TWO-AXIS: Two-Axis Confirmation & Scope Reconciliation (Δ348)
    run_two_axis_confirmation_tests(&ledger);

    // 2. CFGTXN-DROP-RESTORE: RAII ConfigTxnGuard Destructor Restore (Δ349)
    run_config_txn_guard_tests(&ledger);

    // 3. SESSN-DISCRIMINATOR: UFS Link-Recovery vs Replacement (Δ350)
    run_session_discriminator_tests(&ledger);

    // 4. PROV-PROVENANCE: Proof-Substrate Vocabulary Transparency (Δ347)
    run_provenance_vocabulary_tests(&ledger);

    assert!(ledger.is_all_green(), "[M1.7-FAIL] eMMC/UFS Client matrix contains failing assertions!");
    println!("\n[=== MILESTONE M1.7 EMMC PURGE CLIENT MATRIX PASSED ALL CELLS ===]\n");
}

fn run_two_axis_confirmation_tests(ledger: &RigLedger) {
    println!("\n[>>> CONF2-TWO-AXIS: Testing Two-Axis Confirmation & Scope Reconciliation (Δ348) <<<]");

    let confirmation = TwoAxisConfirmation::new(
        "CID_0x1501004441344742",
        vec!["user".to_string(), "boot0".to_string(), "boot1".to_string()],
    );

    // 1. Matching executed scope -> Ok
    let matching_executed = vec!["user".to_string(), "boot0".to_string(), "boot1".to_string()];
    assert!(confirmation.reconcile_executed_scope(&matching_executed).is_ok());

    // 2. Mismatched executed scope (e.g. boot1 skipped) -> Error
    let drifted_executed = vec!["user".to_string(), "boot0".to_string()];
    let drift_res = confirmation.reconcile_executed_scope(&drifted_executed);
    assert!(drift_res.is_err());

    ledger.assert("M1.7-CONF", "CONF2-TWO-AXIS", "true", drift_res.is_err().to_string(), None);
}

fn run_config_txn_guard_tests(ledger: &RigLedger) {
    println!("\n[>>> CFGTXN-DROP-RESTORE: Testing RAII ConfigTxnGuard Destructor Restore (Δ349) <<<]");

    let permit = PurgePermit::mint("/dev/mmcblk0", "CID_0x1501004441344742", 1724890000);
    let config_permit = ConfigTransactionPermit::derive(&permit);

    let mut partition_config_byte: u8 = 0b0100_1000; // Original config (User area)

    {
        let mut guard = ConfigTxnGuard::new(&config_permit, &mut partition_config_byte);
        *guard.current_partition_config = 0b0100_1001; // Switch to boot0
        assert_eq!(*guard.current_partition_config, 0b0100_1001);
        // Do NOT call guard.commit() -> simulates early exit / error / panic!
    }

    // Upon drop, the guard must have automatically restored the original byte!
    assert_eq!(
        partition_config_byte, 0b0100_1000,
        "ConfigTxnGuard must restore original PARTITION_CONFIG on Drop!"
    );
    ledger.assert("M1.7-GUARD", "CFGTXN-DROP-RESTORE", "72", partition_config_byte.to_string(), None);
}

fn run_session_discriminator_tests(ledger: &RigLedger) {
    println!("\n[>>> SESSN-DISCRIMINATOR: Testing UFS Link-Recovery vs Replacement (Δ350) <<<]");

    let initial_lus = vec!["LU0".to_string(), "LU1".to_string()];

    // 1. Same LUs post link event -> Link Recovery (Proceed)
    let rec_res = UfsSessionDiscriminator::evaluate_link_event(&initial_lus, &initial_lus);
    assert_eq!(rec_res, Ok("LINK_RECOVERY_PROCEED"));

    // 2. Changed LUs post link event -> Session Invalidated (Refuse)
    let changed_lus = vec!["LU0".to_string(), "LU2".to_string()];
    let inv_res = UfsSessionDiscriminator::evaluate_link_event(&initial_lus, &changed_lus);
    assert_eq!(inv_res, Err("SESSION_INVALIDATED_LU_CHANGED"));

    ledger.assert("M1.7-SESSN", "SESSN-RECOVERY", "Ok(\"LINK_RECOVERY_PROCEED\")", format!("{:?}", rec_res), None);
    ledger.assert("M1.7-SESSN", "SESSN-REPLACEMENT", "Err(\"SESSION_INVALIDATED_LU_CHANGED\")", format!("{:?}", inv_res), None);
}

fn run_provenance_vocabulary_tests(ledger: &RigLedger) {
    println!("\n[>>> PROV-PROVENANCE: Testing Proof-Substrate Vocabulary (Δ347) <<<]");

    let mut client = MmcPurgeClient::new(MmcAccessClass::NativeController);
    let permit = PurgePermit::mint("/dev/mmcblk0", "CID_0x1501004441344742", 1724890000);
    let confirmation = TwoAxisConfirmation::new(
        "CID_0x1501004441344742",
        vec!["user".to_string(), "boot0".to_string(), "boot1".to_string()],
    );
    let mut config_byte: u8 = 0b0100_1000;

    let summary = client
        .execute_confirmed_purge(&permit, &confirmation, &mut config_byte)
        .unwrap();

    assert_eq!(summary.proof_substrate, "MockTranscribed");
    ledger.assert("M1.7-PROV", "PROV-VOCAB-MOCK", "MockTranscribed", summary.proof_substrate, None);
}
