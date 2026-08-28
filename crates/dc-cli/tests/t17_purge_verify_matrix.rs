use dc_testkit::{
    Cert2Oracle, ExecutedMechanism, InterrogationContract, NistSanitizationClass,
    ReadbackExpectation, ReadbackLab, ReadbackVerdict, RigLedger,
};

#[test]
fn test_t17_purge_verify_matrix() {
    let ledger = RigLedger::new();

    // 1. RB-VERDICT: Three-Way Readback Verdicts (Δ307)
    run_threeway_readback_tests(&ledger);

    // 2. RB-SIGNATURE-FAIL: Residual Signature Bloodhound (Δ309)
    run_residual_signature_tests(&ledger);

    // 3. CLASS-MIN-FALLBACK: Anti-Grade-Laundering Min-Class Derivation (Δ308, INV13)
    run_min_class_derivation_tests(&ledger);

    // 4. AUDIT-SIM-INTERROGATE: Controller Interrogation Contract Simulation (Δ310)
    run_interrogation_contract_tests(&ledger);

    assert!(ledger.is_all_green(), "[T17-FAIL] Purge-Verification matrix contains failing assertions!");
    println!("\n[=== PHASE T17 PURGE-VERIFICATION & EVIDENCE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_threeway_readback_tests(ledger: &RigLedger) {
    println!("\n[>>> RB-VERDICT: Testing Three-Way Readback Verdicts (Δ307) <<<]");

    // 1. Zero media on zero expectation -> Verified
    let zero_buf = vec![0u8; 4096];
    let v1 = ReadbackLab::evaluate(&zero_buf, ReadbackExpectation::Zeros);
    assert_eq!(v1, ReadbackVerdict::Verified);
    ledger.assert("T17-RB", "RB-VERDICT-ZEROS", "Verified", format!("{:?}", v1), None);

    // 2. Random media on vendor-random expectation -> ConsistentWithErased
    let mut random_buf = vec![0u8; 4096];
    for (i, b) in random_buf.iter_mut().enumerate() {
        *b = ((i * 37 + 13) % 256) as u8;
    }
    let v2 = ReadbackLab::evaluate(&random_buf, ReadbackExpectation::VendorRandom);
    assert!(matches!(v2, ReadbackVerdict::ConsistentWithErased { .. }));
    ledger.assert("T17-RB", "RB-VERDICT-RANDOM", "true", "true", None);
}

fn run_residual_signature_tests(ledger: &RigLedger) {
    println!("\n[>>> RB-SIGNATURE-FAIL: Testing Residual Signature Detection (Δ309) <<<]");

    // Plant an ext4 superblock magic (0x53, 0xEF) at offset 1080
    let mut dirty_buf = vec![0u8; 4096];
    dirty_buf[1080] = 0x53;
    dirty_buf[1081] = 0xEF;

    let verdict = ReadbackLab::evaluate(&dirty_buf, ReadbackExpectation::VendorRandom);
    assert!(matches!(verdict, ReadbackVerdict::Failed { signature_hit: Some(ref s), .. } if s.contains("EXT4")));
    ledger.assert("T17-RB", "RB-SIGNATURE-FAIL", "true", "true", None);
}

fn run_min_class_derivation_tests(ledger: &RigLedger) {
    println!("\n[>>> CLASS-MIN-FALLBACK: Testing Min-Class Derivation (Δ308, INV13) <<<]");

    // Scenario: Purge crypto erase failed; fell back to 1-pass zero overwrite (Clear)
    let executed = vec![
        ExecutedMechanism {
            name: "LogicalZeroOverwrite".to_string(),
            nist_class: NistSanitizationClass::Clear,
            tool_verified: true,
            controller_attested: false,
        },
    ];

    let derived_class = Cert2Oracle::derive_min_nist_class(&executed);
    assert_eq!(derived_class, NistSanitizationClass::Clear, "Class must be Clear, never Purge!");
    ledger.assert("T17-CLASS", "CLASS-MIN-FALLBACK", "Clear", format!("{:?}", derived_class), None);
}

fn run_interrogation_contract_tests(ledger: &RigLedger) {
    println!("\n[>>> AUDIT-SIM-INTERROGATE: Testing Interrogation Contract (Δ310) <<<]");

    let raw_log = vec![0x01, 0x00, 0x01, 0x00]; // SPROG=1, SSTAT=1 (Completed)
    let log_hash = blake3::hash(&raw_log).to_hex().to_string();

    let contract = InterrogationContract {
        log_page_id: 0x81,
        raw_bytes_hex: hex::encode(&raw_log),
        blake3_hash: log_hash,
        verification_command: "nvme get-log /dev/nvme0 -i 0x81".to_string(),
        expected_sstat: 1,
    };

    let is_verified = Cert2Oracle::verify_interrogation_contract(&contract, 1, &raw_log);
    assert!(is_verified, "Interrogation contract must verify against live observation!");
    ledger.assert("T17-AUDIT", "AUDIT-SIM-INTERROGATE", "true", is_verified.to_string(), None);
}
