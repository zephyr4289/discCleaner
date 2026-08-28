use dc_testkit::{
    AtaDev, AtaSecurityResult, BridgeLieClass, BridgeLieDetector, RigLedger,
};

#[test]
fn test_t14_ata_purge_matrix() {
    let ledger = RigLedger::new();

    // 1. T14-NOHARM: Password Lifeline, Repair & Intake Rejection (Δ258)
    run_noharm_tests(&ledger);

    // 2. T14-GEOM: DCO -> HPA Geometry Unlocking Ordering & 3-Capacity Evidence (Δ260)
    run_geometry_ordering_tests(&ledger);

    // 3. T14-LIE: Bridge-Lie Taxonomy v1 & Effect Verification (Δ265)
    run_bridge_lie_tests(&ledger);

    assert!(ledger.is_all_green(), "[T14-FAIL] ATA Purge matrix contains failing assertions!");
    println!("\n[=== PHASE T14 ATA PURGE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_noharm_tests(ledger: &RigLedger) {
    println!("\n[>>> T14-NOHARM: Testing No-Harm Rule & Password Lifeline (Δ258) <<<]");

    // 1. Happy path erase (clears lock on success)
    let mut dev1 = AtaDev::new(1_000_000, 2_000_000, 2_000_000);
    let res1 = dev1.execute_security_erase("rescue_pwd_123", true);
    assert_eq!(res1, AtaSecurityResult::Success { erased_enhanced: true });
    assert!(!dev1.state.is_locked);
    ledger.assert("T14-NOHARM", "T14-NOHARM-SUCCESS", "true", (!dev1.state.is_locked).to_string(), None);

    // 2. Erase fails -> Automatic SECURITY DISABLE PASSWORD repair clears lock!
    let mut dev2 = AtaDev::new(1_000_000, 2_000_000, 2_000_000);
    dev2.fail_erase_unit = true;
    let res2 = dev2.execute_security_erase("rescue_pwd_456", true);
    assert_eq!(res2, AtaSecurityResult::EraseFailedRepaired { rescue_password: "rescue_pwd_456".to_string() });
    assert!(!dev2.state.is_locked, "Drive must be repaired to unlocked state!");
    ledger.assert("T14-NOHARM", "T14-NOHARM-REPAIR", "true", (!dev2.state.is_locked).to_string(), None);

    // 3. Intake check refuses pre-locked drives
    let mut dev3 = AtaDev::new(1_000_000, 2_000_000, 2_000_000);
    dev3.state.is_locked = true;
    let intake_res = dev3.check_intake();
    assert!(intake_res.is_err());
    ledger.assert("T14-NOHARM", "T14-INTAKE-LOCKED", "true", intake_res.is_err().to_string(), None);
}

fn run_geometry_ordering_tests(ledger: &RigLedger) {
    println!("\n[>>> T14-GEOM: Testing Geometry Restoration (DCO -> HPA) (Δ260) <<<]");

    // Device with HPA (current=1.0 TB) and DCO (native=1.5 TB, factory DCO=2.0 TB)
    let current_lba: u64 = 1_953_525_168; // ~1.0 TB
    let native_lba: u64 = 2_930_277_168;  // ~1.5 TB
    let dco_lba: u64 = 3_907_029_168;     // ~2.0 TB

    let mut dev = AtaDev::new(current_lba, native_lba, dco_lba);

    // Step 1: Restore DCO
    let after_dco = dev.restore_dco();
    assert_eq!(after_dco, dco_lba);

    // Step 2: Unlock HPA
    let after_hpa = dev.unlock_hpa();
    assert_eq!(after_hpa, dco_lba);

    // Three-capacity evidence reporting:
    assert_eq!(dev.state.current_lba, dco_lba);
    ledger.assert("T14-GEOM", "T14-GEOM-ORDER", dco_lba.to_string(), dev.state.current_lba.to_string(), None);
}

fn run_bridge_lie_tests(ledger: &RigLedger) {
    println!("\n[>>> T14-LIE: Testing Bridge-Lie Catchers (Δ265) <<<]");

    let word128_before: u16 = 0x0001; // Security supported, not enabled
    let word128_after: u16 = 0x0001;  // Unchanged despite "success"

    // Bridge reports SCSI GOOD, but state did not change -> ACCEPT_NOOP lie detected!
    let verify_res = BridgeLieDetector::verify_state_change(
        true,
        &word128_before,
        &word128_after,
        Some(BridgeLieClass::AcceptNoop),
    );

    assert!(verify_res.is_err());
    assert_eq!(verify_res.unwrap_err(), "BRIDGE_LIE_DETECTED_ACCEPT_NOOP");
    ledger.assert("T14-LIE", "T14-LIE-ACCEPT_NOOP", "true", verify_res.is_err().to_string(), None);
}
