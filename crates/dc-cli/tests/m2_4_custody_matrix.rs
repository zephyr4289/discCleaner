use dc_cert::{AuthorizationSet, CustodyType, KeyringEntry, KeyringRegistry};
use dc_cli::approve::PlanApprover;
use dc_cli::key::KeyLifecycleVerbs;
use dc_testkit::RigLedger;

#[test]
fn test_m2_4_custody_matrix() {
    let ledger = RigLedger::new();

    // 1. GATE-INCOMPLETE-REFUSES & GATE-APPROVE-EXEC: Pre-Arm 2PI Gating (Δ448)
    run_pre_arm_gating_tests(&ledger);

    // 2. VOCAB-CUSTODY-DERIVED: Derived Custody Field (Δ455)
    run_custody_vocabulary_tests(&ledger);

    // 3. ROT-BILATERAL: Bilateral Key Rotation (Δ450)
    run_bilateral_rotation_tests(&ledger);

    // 4. REV-PRE-T-STANDS & REV-POST-T-SUSPECT: At-or-After Revocation (Δ452)
    run_revocation_semantics_tests(&ledger);

    assert!(ledger.is_all_green(), "[M2.4-FAIL] Custody matrix contains failing assertions!");
    println!("\n[=== MILESTONE M2.4 TWO-PERSON INTEGRITY & CUSTODY MATRIX PASSED ALL CELLS ===]\n");
}

fn run_pre_arm_gating_tests(ledger: &RigLedger) {
    println!("\n[>>> GATE-PRE-ARM: Testing Pre-Arm 2PI Gating (Δ448) <<<]");

    let plan_hash = "3a7b9c1d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b";

    let mut auth_set = AuthorizationSet::new(plan_hash);
    let sig_officer_a = PlanApprover::countersign_plan(plan_hash, "OFFICER_A_KEY_HASH", false);
    auth_set.add_signature(sig_officer_a);

    // 1. Single signature under 2PI policy -> Refused!
    let res_single = auth_set.verify_pre_arm_authorization(plan_hash, true);
    assert_eq!(res_single, Err("AUTHORIZATION_INCOMPLETE"));

    // 2. Add second signature from Officer B -> Accepted!
    let sig_officer_b = PlanApprover::countersign_plan(plan_hash, "OFFICER_B_KEY_HASH", false);
    auth_set.add_signature(sig_officer_b);
    let res_dual = auth_set.verify_pre_arm_authorization(plan_hash, true);
    assert!(res_dual.is_ok());

    ledger.assert("M2.4-GATE", "GATE-INCOMPLETE-REFUSES", "true", (res_single == Err("AUTHORIZATION_INCOMPLETE")).to_string(), None);
    ledger.assert("M2.4-GATE", "GATE-APPROVE-EXEC", "true", res_dual.is_ok().to_string(), None);
}

fn run_custody_vocabulary_tests(ledger: &RigLedger) {
    println!("\n[>>> VOCAB-CUSTODY-DERIVED: Testing Derived Custody (Δ455) <<<]");

    let plan_hash = "3a7b9c1d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b";

    // 1. Keyfile pair -> shared-filesystem
    let mut auth_file = AuthorizationSet::new(plan_hash);
    auth_file.add_signature(PlanApprover::countersign_plan(plan_hash, "KEY_A", false));
    auth_file.add_signature(PlanApprover::countersign_plan(plan_hash, "KEY_B", false));
    assert_eq!(auth_file.derive_custody_type(), CustodyType::SharedFilesystem);

    // 2. Hardware HSM pair -> separate-hardware
    let mut auth_hsm = AuthorizationSet::new(plan_hash);
    auth_hsm.add_signature(PlanApprover::countersign_plan(plan_hash, "HSM_A", true));
    auth_hsm.add_signature(PlanApprover::countersign_plan(plan_hash, "HSM_B", true));
    assert_eq!(auth_hsm.derive_custody_type(), CustodyType::SeparateHardware);

    ledger.assert("M2.4-VOCAB", "VOCAB-SHARED-FILESYSTEM", "SharedFilesystem", format!("{:?}", auth_file.derive_custody_type()), None);
    ledger.assert("M2.4-VOCAB", "VOCAB-SEPARATE-HARDWARE", "SeparateHardware", format!("{:?}", auth_hsm.derive_custody_type()), None);
}

fn run_bilateral_rotation_tests(ledger: &RigLedger) {
    println!("\n[>>> ROT-BILATERAL: Testing Bilateral Key Rotation (Δ450) <<<]");

    let mut registry = KeyringRegistry::new();
    KeyLifecycleVerbs::register_generated_key(&mut registry, "KEY_V1_HASH", "Officer Alpha", "Lead Auditor", 1700000000);

    let new_key_entry = KeyringEntry {
        key_hash: "KEY_V2_HASH".to_string(),
        identity: "Officer Alpha".to_string(),
        role: "Lead Auditor".to_string(),
        active_from_utc: 1720000000,
        superseded_at_utc: None,
        revoked_at_utc: None,
    };

    let rot_res = KeyLifecycleVerbs::rotate_key(&mut registry, "KEY_V1_HASH", new_key_entry, 1720000000);
    assert!(rot_res.is_ok());

    assert_eq!(registry.entries[0].superseded_at_utc, Some(1720000000));
    assert_eq!(registry.entries[1].active_from_utc, 1720000000);

    ledger.assert("M2.4-ROT", "ROT-BILATERAL", "true", rot_res.is_ok().to_string(), None);
}

fn run_revocation_semantics_tests(ledger: &RigLedger) {
    println!("\n[>>> REV-SEMANTICS: Testing At-or-After Revocation (Δ452) <<<]");

    let mut registry = KeyringRegistry::new();
    KeyLifecycleVerbs::register_generated_key(&mut registry, "KEY_TARGET_HASH", "Officer Beta", "Wipe Operator", 1700000000);

    // Key revoked at T = 1720000000
    KeyLifecycleVerbs::revoke_key(&mut registry, "KEY_TARGET_HASH", 1720000000).unwrap();

    // 1. Signature signed before revocation (T = 1710000000) -> VALID_AT_TIME
    let res_pre = registry.evaluate_signature_at_time("KEY_TARGET_HASH", 1710000000);
    assert_eq!(res_pre, Ok("VALID_AT_TIME"));

    // 2. Signature signed post-revocation (T = 1730000000) -> SUSPECT_REVOKED_KEY
    let res_post = registry.evaluate_signature_at_time("KEY_TARGET_HASH", 1730000000);
    assert_eq!(res_post, Ok("SUSPECT_REVOKED_KEY"));

    ledger.assert("M2.4-REV", "REV-PRE-T-STANDS", "Ok(\"VALID_AT_TIME\")", format!("{:?}", res_pre), None);
    ledger.assert("M2.4-REV", "REV-POST-T-SUSPECT", "Ok(\"SUSPECT_REVOKED_KEY\")", format!("{:?}", res_post), None);
}
