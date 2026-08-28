use dc_nvme::PurgePermit;
use dc_opal::{DiscoveryTree, OpalPurgeClient, OpalSscType, PsidSecret};
use dc_testkit::RigLedger;

#[test]
fn test_m1_8_opal_client_matrix() {
    let ledger = RigLedger::new();

    // 1. HYG-PSID-ZEROIZE: PSID Key-Grade Memory Hygiene (Δ367)
    run_psid_hygiene_tests(&ledger);

    // 2. GATE-STATE-LOCKED: State-Gated Strategy Ladder (Δ368)
    run_state_gated_ladder_tests(&ledger);

    // 3. OPAL-E2E-RESCUE: Production PSID Revert Rescue (Δ370)
    run_opal_rescue_e2e_tests(&ledger);

    // 4. DISCOVERY-CLASSIFY: Level 0 Discovery Tree Classification (Δ359)
    run_discovery_tree_tests(&ledger);

    assert!(ledger.is_all_green(), "[M1.8-FAIL] Opal Client matrix contains failing assertions!");
    println!("\n[=== MILESTONE M1.8 OPAL PURGE CLIENT MATRIX PASSED ALL CELLS ===]\n");
}

fn run_psid_hygiene_tests(ledger: &RigLedger) {
    println!("\n[>>> HYG-PSID-ZEROIZE: Testing PSID Memory Hygiene & Hash Output (Δ367) <<<]");

    let secret_raw = b"ABCD-1234-EFGH-5678";
    let psid = PsidSecret::load_from_slice(secret_raw);

    let hash = psid.compute_hash();
    assert!(!hash.is_empty());
    assert_ne!(hash, "ABCD-1234-EFGH-5678");

    let debug_str = format!("{:?}", psid);
    assert!(!debug_str.contains("ABCD-1234-EFGH-5678"), "Debug output must NEVER leak plaintext PSID!");
    assert!(debug_str.contains(&hash));

    ledger.assert("M1.8-HYG", "HYG-PSID-ZEROIZE", "true", (!debug_str.contains("ABCD-1234-EFGH-5678")).to_string(), None);
}

fn run_state_gated_ladder_tests(ledger: &RigLedger) {
    println!("\n[>>> GATE-STATE-LOCKED: Testing State-Gated Strategy Execution (Δ368) <<<]");

    let permit = PurgePermit::mint("/dev/nvme0n1", "S6B0NJ0W123456X", 1724890000);
    let psid = PsidSecret::load_from_slice(b"ABCD-1234-EFGH-5678");

    // 1. Unlocked SED -> Refused!
    let unlocked_res = OpalPurgeClient::execute_psid_revert(&permit, &psid, false);
    assert!(unlocked_res.is_err());
    assert_eq!(unlocked_res.unwrap_err(), "REVERT_REFUSED_DRIVE_NOT_LOCKED_AT_INTAKE");

    // 2. Locked SED -> Accepted!
    let locked_res = OpalPurgeClient::execute_psid_revert(&permit, &psid, true);
    assert!(locked_res.is_ok());

    ledger.assert("M1.8-GATE", "GATE-STATE-LOCKED", "true", locked_res.is_ok().to_string(), None);
}

fn run_opal_rescue_e2e_tests(ledger: &RigLedger) {
    println!("\n[>>> OPAL-E2E-RESCUE: Testing PSID Revert Rescue E2E (Δ370) <<<]");

    let permit = PurgePermit::mint("/dev/nvme0n1", "S6B0NJ0W123456X", 1724890000);
    let psid = PsidSecret::load_from_slice(b"ABCD-1234-EFGH-5678");

    let summary = OpalPurgeClient::execute_psid_revert(&permit, &psid, true).unwrap();
    assert_eq!(summary.target_device, "/dev/nvme0n1");
    assert_eq!(summary.target_serial, "S6B0NJ0W123456X");
    assert_eq!(summary.post_state, "SPEC_INFERRED_STATE_ATTESTED_MEK_REGENERATED");

    ledger.assert("M1.8-E2E", "OPAL-E2E-RESCUE", "SPEC_INFERRED_STATE_ATTESTED_MEK_REGENERATED", summary.post_state, None);
}

fn run_discovery_tree_tests(ledger: &RigLedger) {
    println!("\n[>>> DISCOVERY-CLASSIFY: Testing Level 0 Discovery Classification (Δ359) <<<]");

    assert_eq!(DiscoveryTree::classify_level0(0x0200), OpalSscType::Opal2_0);
    assert_eq!(DiscoveryTree::classify_level0(0x0302), OpalSscType::Pyrite);
    assert_eq!(DiscoveryTree::classify_level0(0x0100), OpalSscType::Enterprise);
    assert_eq!(DiscoveryTree::classify_level0(0x9999), OpalSscType::Unknown);

    ledger.assert("M1.8-DISC", "DISCOVERY-CLASSIFY", "true", "true", None);
}
