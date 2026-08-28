use dc_probe::{BootAttestor, ReadOnlyCandidate};
use dc_testkit::RigLedger;

#[test]
fn test_m2_2_boot_iso_matrix() {
    let ledger = RigLedger::new();

    // 1. ATTEST-FULLHASH-HYBRID: Content-Based Attestation & Hybrid Nodes Protection (Δ414)
    run_boot_attestation_hybrid_tests(&ledger);

    // 2. ATTEST-NEARMISS-REFUSE: Adversarial Near-Miss Marker Rejection (Δ414)
    run_near_miss_attestation_tests(&ledger);

    assert!(ledger.is_all_green(), "[M2.2-FAIL] Boot ISO matrix contains failing assertions!");
    println!("\n[=== MILESTONE M2.2 BOOT ISO MATRIX PASSED ALL CELLS ===]\n");
}

fn run_boot_attestation_hybrid_tests(ledger: &RigLedger) {
    println!("\n[>>> ATTEST-FULLHASH-HYBRID: Testing Content-Based Hybrid Attestation (Δ414) <<<]");

    let expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // Hybrid candidate: the same physical stick presented as both /dev/sr0 (CD) and /dev/sdb (disk)
    let candidates = vec![
        ReadOnlyCandidate {
            device_nodes: vec!["/dev/sr0".to_string(), "/dev/sdb".to_string()],
            marker_content_hash: expected_hash.to_string(),
        },
        ReadOnlyCandidate {
            device_nodes: vec!["/dev/sda".to_string()],
            marker_content_hash: "other_drive_hash_12345".to_string(),
        },
    ];

    let attestation = BootAttestor::attest_boot_medium(&candidates, expected_hash);

    assert!(attestation.matched);
    assert!(attestation.protected_nodes.contains(&"/dev/sr0".to_string()));
    assert!(attestation.protected_nodes.contains(&"/dev/sdb".to_string()));
    assert_eq!(attestation.protected_nodes.len(), 2, "Both hybrid nodes must be protected!");

    ledger.assert("M2.2-ATTEST", "ATTEST-HYBRID-BOTHNODES", "2", attestation.protected_nodes.len().to_string(), None);
}

fn run_near_miss_attestation_tests(ledger: &RigLedger) {
    println!("\n[>>> ATTEST-NEARMISS-REFUSE: Testing Strict Full-Hash Rejection (Δ414) <<<]");

    let expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let near_miss_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"; // 1-bit / 1-char delta!

    let candidates = vec![
        ReadOnlyCandidate {
            device_nodes: vec!["/dev/sdz".to_string()],
            marker_content_hash: near_miss_hash.to_string(),
        },
    ];

    let attestation = BootAttestor::attest_boot_medium(&candidates, expected_hash);

    assert!(!attestation.matched, "Near-miss candidate must NEVER match (no prefix mercy)!");
    assert!(attestation.protected_nodes.is_empty());

    ledger.assert("M2.2-ATTEST", "ATTEST-NEARMISS-REFUSE", "false", attestation.matched.to_string(), None);
}
