use dc_testkit::{
    OpalDevMock, OpalFrameParser, OpalLifecycle, PsidAuthResult, RigLedger,
};

#[test]
fn test_t19_opal_matrix() {
    let ledger = RigLedger::new();

    // 1. T19-SM-LIFECYCLE: Hostage Staging & Revert Lifecycle (Δ357)
    run_hostage_lifecycle_tests(&ledger);

    // 2. T19-PSID-DISAMBIG: Identity-Check-First Disambiguation (Δ358)
    run_psid_disambiguation_tests(&ledger);

    // 3. T19-FRAME-NEST: Nested Frame Length Bounds Validation (Δ361)
    run_frame_bounds_tests(&ledger);

    // 4. T19-STATE: Spec-Inferred / State-Attested Scope Honesty (Δ360)
    run_state_attestation_tests(&ledger);

    assert!(ledger.is_all_green(), "[T19-FAIL] Opal/SED matrix contains failing assertions!");
    println!("\n[=== PHASE T19 OPAL / SED RIG MATRIX PASSED ALL CELLS ===]\n");
}

fn run_hostage_lifecycle_tests(ledger: &RigLedger) {
    println!("\n[>>> T19-SM-LIFECYCLE: Testing Hostage Staging & Revert (Δ357) <<<]");

    let mut dev = OpalDevMock::new("S6B0NJ0W123456X", "ABCD-1234-EFGH-5678");
    assert_eq!(dev.lifecycle, OpalLifecycle::Manufactured);

    // Stage hostage (takes ownership, locks drive)
    dev.stage_hostage();
    assert_eq!(dev.lifecycle, OpalLifecycle::Locked);
    assert!(dev.locking_ranges_configured);

    // Rescue drive via PSID revert
    let res = dev.revert_with_psid("S6B0NJ0W123456X", "ABCD-1234-EFGH-5678");
    assert_eq!(res, PsidAuthResult::Success);
    assert_eq!(dev.lifecycle, OpalLifecycle::Manufactured);
    assert!(!dev.locking_ranges_configured);

    ledger.assert("T19-SM", "T19-SM-LIFECYCLE", "Manufactured", format!("{:?}", dev.lifecycle), None);
}

fn run_psid_disambiguation_tests(ledger: &RigLedger) {
    println!("\n[>>> T19-PSID-DISAMBIG: Testing Identity-Check-First Disambiguation (Δ358) <<<]");

    let mut dev = OpalDevMock::new("TARGET_SED_SN001", "CORRECT_PSID_SECRET");
    dev.stage_hostage();

    // 1. Wrong Device Target -> WRONG_DEVICE (Zero auth attempts burned!)
    let wrong_dev_res = dev.revert_with_psid("DIFFERENT_SED_SN002", "SOME_PSID");
    assert!(matches!(wrong_dev_res, PsidAuthResult::WrongDevice { .. }));

    // 2. Matching Device Target + Bad PSID -> PSID_REJECTED (Attempt burned)
    let bad_psid_res = dev.revert_with_psid("TARGET_SED_SN001", "INCORRECT_PSID");
    assert_eq!(bad_psid_res, PsidAuthResult::PsidRejected);

    ledger.assert("T19-PSID", "T19-PSID-WRONGDEV", "true", matches!(wrong_dev_res, PsidAuthResult::WrongDevice { .. }).to_string(), None);
    ledger.assert("T19-PSID", "T19-PSID-REJECTED", "PsidRejected", format!("{:?}", bad_psid_res), None);
}

fn run_frame_bounds_tests(ledger: &RigLedger) {
    println!("\n[>>> T19-FRAME-NEST: Testing Frame Nested Bounds Checking (Δ361) <<<]");

    // Valid nested lengths (ComPacket: 1024, Packet: 512, SubPacket: 256) -> Ok
    let ok_res = OpalFrameParser::validate_frame_bounds(1024, 512, 256);
    assert!(ok_res.is_ok());

    // Inner Packet length exceeds ComPacket -> Error!
    let err_packet = OpalFrameParser::validate_frame_bounds(512, 1024, 256);
    assert!(err_packet.is_err());
    assert_eq!(err_packet.unwrap_err(), "PACKET_LENGTH_EXCEEDS_COMPACKET");

    // SubPacket length exceeds Packet -> Error!
    let err_sub = OpalFrameParser::validate_frame_bounds(1024, 512, 600);
    assert!(err_sub.is_err());
    assert_eq!(err_sub.unwrap_err(), "SUBPACKET_LENGTH_EXCEEDS_PACKET");

    ledger.assert("T19-FRAME", "T19-FRAME-NEST-BOUNDS", "true", err_packet.is_err().to_string(), None);
}

fn run_state_attestation_tests(ledger: &RigLedger) {
    println!("\n[>>> T19-STATE: Testing Spec-Inferred State Attestation (Δ360) <<<]");

    let mut dev = OpalDevMock::new("S6B0NJ0W123456X", "ABCD-1234-EFGH-5678");
    dev.stage_hostage();
    dev.revert_with_psid("S6B0NJ0W123456X", "ABCD-1234-EFGH-5678");

    let attest = dev.get_post_revert_attestation().unwrap();
    assert_eq!(attest, "SPEC_INFERRED_STATE_ATTESTED_MEK_REGENERATED");

    ledger.assert("T19-STATE", "T19-STATE-SPEC-INFERRED", "SPEC_INFERRED_STATE_ATTESTED_MEK_REGENERATED", attest, None);
}
