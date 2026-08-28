use dc_testkit::{
    AssetLifecycleRecord, BridgeClassification, BridgeMatrixLedger, EstateLedger,
    ObservationChannel, ProbeBattery, RigLedger,
};

#[test]
fn test_t16_bridge_matrix() {
    let ledger = RigLedger::new();

    // 1. MATRIX-CHAIN: Cryptographic Hash-Chained Bridge Ledger (Δ296)
    run_matrix_chain_tests(&ledger);

    // 2. BATTERY-CAPMASK: Dual-Path Observation & 6th Lie Detection (Δ299, Δ304)
    run_capmask_tests(&ledger);

    // 3. ESTATE-BUDGET-GATE: Asset Lifecycle & Budget Gates (Δ302)
    run_estate_budget_tests(&ledger);

    assert!(ledger.is_all_green(), "[T16-FAIL] Bridge Matrix contains failing assertions!");
    println!("\n[=== PHASE T16 BRIDGE MATRIX & MENAGERIE PASSED ALL CELLS ===]\n");
}

fn run_matrix_chain_tests(ledger: &RigLedger) {
    println!("\n[>>> MATRIX-CHAIN: Testing Bridge Matrix Ledger Chaining (Δ296) <<<]");

    let mut matrix = BridgeMatrixLedger::new();

    // Entry 1: JMicron JMS583 honest crypto sanitize
    matrix.append(
        0x152D,
        0x0583,
        "v00.02.01.04",
        "UAS",
        "NVME_SANITIZE",
        BridgeClassification::Honest,
        "bundle_hash_1111",
    );

    // Entry 2: ASMedia ASM2362 lying DCO restore
    matrix.append(
        0x174C,
        0x2362,
        "v19.01.00.01",
        "BOT",
        "ATA_DCO_RESTORE",
        BridgeClassification::Lie {
            class: dc_testkit::BridgeLieClass::AcceptNoop,
            detail: "Silently dropped DCO restore command while returning 0".to_string(),
        },
        "bundle_hash_2222",
    );

    assert_eq!(matrix.entries.len(), 2);
    assert!(matrix.verify_chain(), "Bridge matrix hash chain must be cryptographically valid!");
    ledger.assert("T16-MATRIX", "MATRIX-CHAIN", "true", matrix.verify_chain().to_string(), None);
}

fn run_capmask_tests(ledger: &RigLedger) {
    println!("\n[>>> BATTERY-CAPMASK: Testing Dual-Path 6th Lie Detection (Δ299, Δ304) <<<]");

    let direct_sata_lba: u64 = 3_907_029_168; // 2.0 TB native
    let bridged_clipped_lba: u64 = 1_953_525_168; // 1.0 TB clipped by buggy bridge

    let cap_res = ProbeBattery::check_capacity_mask(
        direct_sata_lba,
        bridged_clipped_lba,
        ObservationChannel::DualPath,
    );

    assert!(cap_res.is_err(), "Must detect CAPACITY_MASK lie via dual-path!");
    ledger.assert("T16-BATTERY", "BATTERY-CAPMASK", "true", cap_res.is_err().to_string(), None);
}

fn run_estate_budget_tests(ledger: &RigLedger) {
    println!("\n[>>> ESTATE-BUDGET-GATE: Testing Estate Lifecycle & Budget Gates (Δ302) <<<]");

    let mut estate = EstateLedger::new();
    estate.register_asset(AssetLifecycleRecord {
        serial: "S6B0NJ0W123456X".to_string(),
        model: "Samsung 990 PRO 2TB".to_string(),
        sacrificial: true,
        tbw_budget_gb: 1200, // 1200 TBW
        tbw_consumed_gb: 1100, // 1100 TBW already consumed
        retired: false,
    });

    // Attempting a 200 TBW campaign exceeds budget (1100 + 200 = 1300 > 1200) -> Refused!
    let auth_fail = estate.authorize_campaign("S6B0NJ0W123456X", 200);
    assert!(auth_fail.is_err());
    assert_eq!(auth_fail.unwrap_err(), "ESTATE_BUDGET_EXCEEDED_UNAFFORDABLE");

    // Attempting a 50 TBW campaign is within budget -> Authorized!
    let auth_ok = estate.authorize_campaign("S6B0NJ0W123456X", 50);
    assert!(auth_ok.is_ok());

    ledger.assert("T16-ESTATE", "ESTATE-BUDGET-GATE", "true", auth_fail.is_err().to_string(), None);
}
