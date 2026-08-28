use dc_cert::Cert2Projector;
use dc_core::{
    AttestedCapabilities, DeviceTransportClass, StrategyCompiler,
};
use dc_testkit::RigLedger;

#[test]
fn test_m1_5_assembly_matrix() {
    let ledger = RigLedger::new();

    // 1. STRAT-COMPILE: Strategy Ladder Compilation (Δ317)
    run_strategy_compiler_tests(&ledger);

    // 2. STRAT-CONFLICT: Option Conflict & Teaching Errors (Δ318)
    run_strategy_conflict_tests(&ledger);

    // 3. PLAN-EQUIV-HW: Hardware Plan Deterministic Equivalence (Δ317)
    run_plan_equiv_hw_tests(&ledger);

    // 4. PROJ2-MINCLASS: cert/2 Min-Class Anti-Grade-Laundering (Δ321)
    run_proj2_minclass_tests(&ledger);

    assert!(ledger.is_all_green(), "[M1.5-FAIL] Assembly matrix contains failing assertions!");
    println!("\n[=== MILESTONE M1.5 ASSEMBLY MATRIX PASSED ALL CELLS ===]\n");
}

fn run_strategy_compiler_tests(ledger: &RigLedger) {
    println!("\n[>>> STRAT-COMPILE: Testing Strategy Ladder Compilation (Δ317) <<<]");

    let caps = AttestedCapabilities {
        supports_sanitize_crypto: true,
        supports_sanitize_block: true,
        supports_format_nvm: true,
        supports_ata_security_enhanced: true,
        supports_dco_hpa: true,
        supports_scsi_sanitize: true,
    };

    let nvme_ladder = StrategyCompiler::compile_strategy(DeviceTransportClass::Nvme, &caps, true).unwrap();
    assert_eq!(nvme_ladder.steps[0].name, "NvmeSanitizeCryptoErase");
    assert_eq!(nvme_ladder.steps[0].nist_class, "Purge");

    let sata_ladder = StrategyCompiler::compile_strategy(DeviceTransportClass::SataSsd, &caps, true).unwrap();
    assert_eq!(sata_ladder.steps[0].name, "AtaSecurityEraseEnhanced");

    ledger.assert("M1.5-STRAT", "STRAT-COMPILE-NVME", "NvmeSanitizeCryptoErase", nvme_ladder.steps[0].name.clone(), None);
}

fn run_strategy_conflict_tests(ledger: &RigLedger) {
    println!("\n[>>> STRAT-CONFLICT: Testing Plan Conflict Mutual Exclusivity (Δ318) <<<]");

    let conflict_res = StrategyCompiler::validate_plan_options(true, true);
    assert!(conflict_res.is_err());
    assert_eq!(conflict_res.unwrap_err(), "CONFLICT_EXIT_8_CANNOT_MIX_STRATEGY_AND_PROFILE");

    let ok_res = StrategyCompiler::validate_plan_options(true, false);
    assert!(ok_res.is_ok());

    ledger.assert("M1.5-STRAT", "STRAT-CONFLICT", "true", conflict_res.is_err().to_string(), None);
}

fn run_plan_equiv_hw_tests(ledger: &RigLedger) {
    println!("\n[>>> PLAN-EQUIV-HW: Testing Plan Deterministic Equivalence (Δ317) <<<]");

    let caps = AttestedCapabilities {
        supports_sanitize_crypto: false,
        supports_sanitize_block: true,
        supports_format_nvm: false,
        supports_ata_security_enhanced: false,
        supports_dco_hpa: false,
        supports_scsi_sanitize: false,
    };

    let ladder_a = StrategyCompiler::compile_strategy(DeviceTransportClass::Nvme, &caps, true).unwrap();
    let ladder_b = StrategyCompiler::compile_strategy(DeviceTransportClass::Nvme, &caps, true).unwrap();

    assert_eq!(ladder_a, ladder_b, "Identical inputs must yield byte-identical ladders!");
    ledger.assert("M1.5-EQUIV", "PLAN-EQUIV-HW", "true", (ladder_a == ladder_b).to_string(), None);
}

fn run_proj2_minclass_tests(ledger: &RigLedger) {
    println!("\n[>>> PROJ2-MINCLASS: Testing cert/2 Min-Class Projection (Δ321) <<<]");

    // Scenario 1: Fallback executed Clear mechanism -> cert class must be Clear!
    let cert1 = Cert2Projector::project(
        &["NvmeSanitizeBlockErase (Failed)".to_string(), "LogicalOverwriteZero".to_string()],
        &["Purge".to_string(), "Clear".to_string()],
        "/dev/nvme0n1",
        "S6B0NJ0W123456X",
        1724890000,
        None,
    );
    assert_eq!(cert1.nist_sanitization_class, "Clear");

    // Scenario 2: Successful Purge mechanism -> cert class is Purge
    let cert2 = Cert2Projector::project(
        &["NvmeSanitizeCryptoErase".to_string()],
        &["Purge".to_string()],
        "/dev/nvme0n1",
        "S6B0NJ0W123456X",
        1724890000,
        Some("nvme get-log /dev/nvme0 -i 0x81"),
    );
    assert_eq!(cert2.nist_sanitization_class, "Purge");

    ledger.assert("M1.5-PROJ2", "PROJ2-MINCLASS-FALLBACK", "Clear", cert1.nist_sanitization_class, None);
    ledger.assert("M1.5-PROJ2", "PROJ2-MINCLASS-PURGE", "Purge", cert2.nist_sanitization_class, None);
}
