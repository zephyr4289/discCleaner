use dc_cert::{AuthorizationSet, CustodyType, KeyringEntry, KeyringRegistry, OperatorKeyPair};
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

    assert!(
        ledger.is_all_green(),
        "[M2.4-FAIL] Custody matrix contains failing assertions!"
    );
    println!("\n[=== MILESTONE M2.4 TWO-PERSON INTEGRITY & CUSTODY MATRIX PASSED ALL CELLS ===]\n");
}

fn run_pre_arm_gating_tests(ledger: &RigLedger) {
    println!("\n[>>> GATE-PRE-ARM: Testing Pre-Arm 2PI Gating (Δ448) <<<]");

    let plan_hash = "3a7b9c1d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b";

    // Real officer keypairs: the countersignatures are genuine Ed25519
    // signatures over the plan hash, not forgeable string hashes.
    let officer_a = OperatorKeyPair::generate();
    let officer_b = OperatorKeyPair::generate();

    let mut auth_set = AuthorizationSet::new(plan_hash);
    let sig_officer_a = PlanApprover::countersign_plan(plan_hash, &officer_a, false);
    auth_set.add_signature(sig_officer_a);

    // 1. Single signature under 2PI policy -> Refused!
    let res_single = auth_set.verify_pre_arm_authorization(plan_hash, true);
    assert_eq!(res_single, Err("AUTHORIZATION_INCOMPLETE"));

    // 2. Add second signature from a DISTINCT officer key -> Accepted!
    let sig_officer_b = PlanApprover::countersign_plan(plan_hash, &officer_b, false);
    auth_set.add_signature(sig_officer_b);
    let res_dual = auth_set.verify_pre_arm_authorization(plan_hash, true);
    assert!(res_dual.is_ok());

    // 3. REG-DUALAUTH-FORGERY: a hash-of-strings forgery must be REJECTED.
    //    (The pre-hardening implementation accepted exactly this.)
    let mut forged = AuthorizationSet::new(plan_hash);
    forged.add_signature(dc_cert::AuthSignatureEntry {
        key_fingerprint: blake3::hash(b"OFFICER_A_KEY_HASH").to_hex().to_string(),
        public_key_hex: hex::encode([0u8; 32]),
        signature_hex: blake3::hash(
            format!("APPROVE_PLAN_{}_BY_{}", plan_hash, "OFFICER_A_KEY_HASH").as_bytes(),
        )
        .to_hex()
        .to_string(),
        is_hardware_token: false,
        hardware_attestation: None,
    });
    forged.add_signature(dc_cert::AuthSignatureEntry {
        key_fingerprint: blake3::hash(b"OFFICER_B_KEY_HASH").to_hex().to_string(),
        public_key_hex: hex::encode([1u8; 32]),
        signature_hex: blake3::hash(
            format!("APPROVE_PLAN_{}_BY_{}", plan_hash, "OFFICER_B_KEY_HASH").as_bytes(),
        )
        .to_hex()
        .to_string(),
        is_hardware_token: false,
        hardware_attestation: None,
    });
    let res_forged = forged.verify_pre_arm_authorization(plan_hash, true);
    assert!(
        res_forged.is_err(),
        "Blake3-of-strings forgery must not authorize!"
    );

    // 4. One officer signing twice with two entries is NOT two-person control.
    //    (v0.7.0: the second entry's hardware CLAIM without a PIV
    //    attestation is now itself a hard refusal — the 2PI completeness
    //    check fires for unclaimed software signatures.)
    let mut same_officer_twice = AuthorizationSet::new(plan_hash);
    same_officer_twice.add_signature(PlanApprover::countersign_plan(plan_hash, &officer_a, false));
    same_officer_twice.add_signature(PlanApprover::countersign_plan(plan_hash, &officer_a, true));
    let res_same = same_officer_twice.verify_pre_arm_authorization(plan_hash, true);
    assert_eq!(
        res_same,
        Err("HW_CUSTODY_CLAIM_WITHOUT_ATTESTATION"),
        "a bare is_hardware_token claim must be refused before the 2PI check"
    );

    // 4b. Same key twice, both software entries: AUTHORIZATION_INCOMPLETE.
    let mut same_officer_soft = AuthorizationSet::new(plan_hash);
    same_officer_soft.add_signature(PlanApprover::countersign_plan(plan_hash, &officer_a, false));
    same_officer_soft.add_signature(PlanApprover::countersign_plan(plan_hash, &officer_a, false));
    assert_eq!(
        same_officer_soft.verify_pre_arm_authorization(plan_hash, true),
        Err("AUTHORIZATION_INCOMPLETE")
    );

    // 5. A signature bound to a different plan hash must be rejected.
    let other_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let mut wrong_plan = AuthorizationSet::new(other_hash);
    wrong_plan.add_signature(PlanApprover::countersign_plan(
        other_hash, &officer_a, false,
    ));
    wrong_plan.add_signature(PlanApprover::countersign_plan(
        other_hash, &officer_b, false,
    ));
    let res_binding = wrong_plan.verify_pre_arm_authorization(plan_hash, true);
    assert_eq!(res_binding, Err("PLAN_HASH_BINDING_MISMATCH"));

    ledger.assert(
        "M2.4-GATE",
        "GATE-INCOMPLETE-REFUSES",
        "true",
        (res_single == Err("AUTHORIZATION_INCOMPLETE")).to_string(),
        None,
    );
    ledger.assert(
        "M2.4-GATE",
        "GATE-APPROVE-EXEC",
        "true",
        res_dual.is_ok().to_string(),
        None,
    );
    ledger.assert(
        "M2.4-GATE",
        "GATE-FORGERY-REFUSED",
        "true",
        res_forged.is_err().to_string(),
        None,
    );
    ledger.assert(
        "M2.4-GATE",
        "GATE-SAME-KEY-REFUSED",
        "true",
        res_same.is_err().to_string(),
        None,
    );
    ledger.assert(
        "M2.4-GATE",
        "GATE-BINDING-MISMATCH",
        "true",
        (res_binding == Err("PLAN_HASH_BINDING_MISMATCH")).to_string(),
        None,
    );
}

fn run_custody_vocabulary_tests(ledger: &RigLedger) {
    println!("\n[>>> VOCAB-CUSTODY-DERIVED: Testing Derived Custody (Δ455) <<<]");

    let plan_hash = "3a7b9c1d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b";

    // 1. Keyfile pair -> shared-filesystem
    let key_a = OperatorKeyPair::generate();
    let key_b = OperatorKeyPair::generate();
    let mut auth_file = AuthorizationSet::new(plan_hash);
    auth_file.add_signature(PlanApprover::countersign_plan(plan_hash, &key_a, false));
    auth_file.add_signature(PlanApprover::countersign_plan(plan_hash, &key_b, false));
    assert_eq!(
        auth_file.derive_custody_type(),
        CustodyType::SharedFilesystem
    );

    // 2. Hardware token pair -> separate-hardware (v0.7.0: verified PIV
    //    attestations, not bare boolean claims — a claimed-without-proof
    //    pair now derives SharedFilesystem by REFUSAL at the gate).
    use dc_cert::PIV_AID;
    use dc_cert::ccid::CcidEndpoint;
    use dc_cert::iso7816::{CommandApdu, Iso7816Transport, ResponseApdu};
    use dc_cert::token::countersign_ed25519_on_token;
    use std::path::PathBuf;

    struct ScriptedTokenCard {
        slot_key: OperatorKeyPair,
    }

    impl Iso7816Transport for ScriptedTokenCard {
        fn exchange(&mut self, command: &CommandApdu) -> Result<ResponseApdu, String> {
            let raw: Vec<u8> = match command.ins {
                0xA4 => {
                    assert_eq!(command.data, PIV_AID.to_vec());
                    let mut r = vec![0x6F, 0x0A, 0x4F, 0x08];
                    r.extend_from_slice(&PIV_AID[..8]);
                    r.extend_from_slice(&[0x90, 0x00]);
                    r
                }
                0x20 => vec![0x90, 0x00], // VERIFY OK
                0xF7 => {
                    // GET METADATA: tag 0x86 = slot public key.
                    let key = self.slot_key.verifying_key.to_bytes();
                    let mut body = vec![0x86, key.len() as u8];
                    body.extend_from_slice(&key);
                    let mut r = vec![0x01, 0x00, 0x02, 0x00];
                    r.extend_from_slice(&body);
                    r.extend_from_slice(&[0x90, 0x00]);
                    r
                }
                0x87 => {
                    use ed25519_dalek::Signer;
                    let sig = self.slot_key.signing_key.sign(&command.data[4..]);
                    let mut body = vec![0xDA, 64];
                    body.extend_from_slice(&sig.to_bytes());
                    let mut r = vec![0x7C, body.len() as u8];
                    r.extend_from_slice(&body);
                    r.extend_from_slice(&[0x90, 0x00]);
                    r
                }
                other => return Err(format!("unexpected INS 0x{:02X}", other)),
            };
            ResponseApdu::decode(&raw)
        }
    }

    let endpoint = CcidEndpoint {
        device_node: PathBuf::from("/dev/bus/usb/001/009"),
        interface: 0,
        bulk_out_ep: 0x01,
        bulk_in_ep: 0x81,
        id_vendor: 0x1050,
        id_product: 0x0407,
        serial: None,
    };
    let mut card_a = ScriptedTokenCard {
        slot_key: OperatorKeyPair::generate(),
    };
    let mut card_b = ScriptedTokenCard {
        slot_key: OperatorKeyPair::generate(),
    };
    let (sig_a, att_a) = countersign_ed25519_on_token(
        &mut card_a,
        &endpoint,
        dc_cert::PLAN_APPROVAL_DOMAIN,
        plan_hash,
        "111111",
    )
    .expect("token officer A");
    let (sig_b, att_b) = countersign_ed25519_on_token(
        &mut card_b,
        &endpoint,
        dc_cert::PLAN_APPROVAL_DOMAIN,
        plan_hash,
        "222222",
    )
    .expect("token officer B");
    assert!(att_a.pin_verified && att_b.pin_verified);
    let mut auth_hsm = AuthorizationSet::new(plan_hash);
    auth_hsm.add_signature(sig_a);
    auth_hsm.add_signature(sig_b);
    assert_eq!(
        auth_hsm.derive_custody_type(),
        CustodyType::SeparateHardware
    );
    // The attested pair also passes the full pre-arm gate.
    assert!(
        auth_hsm
            .verify_pre_arm_authorization(plan_hash, true)
            .is_ok()
    );

    // 2b. Claimed-but-unattested pair: NOT hardware custody anymore.
    let hsm_a = OperatorKeyPair::generate();
    let hsm_b = OperatorKeyPair::generate();
    let mut auth_claimed = AuthorizationSet::new(plan_hash);
    auth_claimed.add_signature(PlanApprover::countersign_plan(plan_hash, &hsm_a, true));
    auth_claimed.add_signature(PlanApprover::countersign_plan(plan_hash, &hsm_b, true));
    assert_eq!(
        auth_claimed.derive_custody_type(),
        CustodyType::SharedFilesystem
    );

    ledger.assert(
        "M2.4-VOCAB",
        "VOCAB-SHARED-FILESYSTEM",
        "SharedFilesystem",
        format!("{:?}", auth_file.derive_custody_type()),
        None,
    );
    ledger.assert(
        "M2.4-VOCAB",
        "VOCAB-SEPARATE-HARDWARE",
        "SeparateHardware",
        format!("{:?}", auth_hsm.derive_custody_type()),
        None,
    );
}

fn run_bilateral_rotation_tests(ledger: &RigLedger) {
    println!("\n[>>> ROT-BILATERAL: Testing Bilateral Key Rotation (Δ450) <<<]");

    let mut registry = KeyringRegistry::new();
    KeyLifecycleVerbs::register_generated_key(
        &mut registry,
        "KEY_V1_HASH",
        "Officer Alpha",
        "Lead Auditor",
        1700000000,
    );

    let new_key_entry = KeyringEntry {
        key_hash: "KEY_V2_HASH".to_string(),
        identity: "Officer Alpha".to_string(),
        role: "Lead Auditor".to_string(),
        active_from_utc: 1720000000,
        superseded_at_utc: None,
        revoked_at_utc: None,
    };

    let rot_res =
        KeyLifecycleVerbs::rotate_key(&mut registry, "KEY_V1_HASH", new_key_entry, 1720000000);
    assert!(rot_res.is_ok());

    assert_eq!(registry.entries[0].superseded_at_utc, Some(1720000000));
    assert_eq!(registry.entries[1].active_from_utc, 1720000000);

    ledger.assert(
        "M2.4-ROT",
        "ROT-BILATERAL",
        "true",
        rot_res.is_ok().to_string(),
        None,
    );
}

fn run_revocation_semantics_tests(ledger: &RigLedger) {
    println!("\n[>>> REV-SEMANTICS: Testing At-or-After Revocation (Δ452) <<<]");

    let mut registry = KeyringRegistry::new();
    KeyLifecycleVerbs::register_generated_key(
        &mut registry,
        "KEY_TARGET_HASH",
        "Officer Beta",
        "Wipe Operator",
        1700000000,
    );

    // Key revoked at T = 1720000000
    KeyLifecycleVerbs::revoke_key(&mut registry, "KEY_TARGET_HASH", 1720000000).unwrap();

    // 1. Signature signed before revocation (T = 1710000000) -> VALID_AT_TIME
    let res_pre = registry.evaluate_signature_at_time("KEY_TARGET_HASH", 1710000000);
    assert_eq!(res_pre, Ok("VALID_AT_TIME"));

    // 2. Signature signed post-revocation (T = 1730000000) -> SUSPECT_REVOKED_KEY
    let res_post = registry.evaluate_signature_at_time("KEY_TARGET_HASH", 1730000000);
    assert_eq!(res_post, Ok("SUSPECT_REVOKED_KEY"));

    ledger.assert(
        "M2.4-REV",
        "REV-PRE-T-STANDS",
        "Ok(\"VALID_AT_TIME\")",
        format!("{:?}", res_pre),
        None,
    );
    ledger.assert(
        "M2.4-REV",
        "REV-POST-T-SUSPECT",
        "Ok(\"SUSPECT_REVOKED_KEY\")",
        format!("{:?}", res_post),
        None,
    );
}
