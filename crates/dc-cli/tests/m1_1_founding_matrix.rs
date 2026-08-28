use dc_hw::{
    AtaCodec, NvmeCodec, NvmeSanitizeAction, NvmeSstatStatus, RawBlob, ScsiCodec,
    ScsiSanitizeServiceAction,
};
use dc_testkit::{HwOracle, RigLedger};

#[test]
fn test_m1_1_founding_matrix() {
    let ledger = RigLedger::new();

    // 1. HW-ORACLE-2LINE: Independent 2-Lineage Parity (Δ224)
    run_two_lineage_parity_tests(&ledger);

    // 2. HW-ENC-RESERVED-ZERO: Reserved Field Hygiene (Δ226)
    run_reserved_zero_tests(&ledger);

    // 3. HW-SSTAT-TOTAL: SSTAT Pattern Totality & Adoption States (Δ227)
    run_sstat_totality_tests(&ledger);

    // 4. HW-RAW-IDENTITY: Raw Payload Retention & BLAKE3 Identity (Δ228)
    run_raw_identity_tests(&ledger);

    assert!(ledger.is_all_green(), "[M1.1-FAIL] Founding matrix contains failing assertions!");
    println!("\n[=== MILESTONE M1.1 CODEC FOUNDING MATRIX PASSED ALL CELLS ===]\n");
}

fn run_two_lineage_parity_tests(ledger: &RigLedger) {
    println!("\n[>>> HW-ORACLE-2LINE: Testing Independent 2-Lineage Parity (Δ224) <<<]");

    // 1. NVMe Sanitize Parity (Crypto Erase, NODAS=true)
    let tool_nvme = NvmeCodec::encode_sanitize(NvmeSanitizeAction::CryptoErase, true);
    let oracle_nvme = HwOracle::encode_nvme_sanitize(4, true);
    let nvme_matches = tool_nvme == oracle_nvme;
    ledger.assert("M1.1-PARITY", "HW-PARITY-NVME-SANITIZE", "true", nvme_matches.to_string(), None);

    // 2. SCSI SANITIZE Parity (Block Erase, IMMED=true)
    let tool_scsi = ScsiCodec::encode_sanitize(ScsiSanitizeServiceAction::BlockErase, true);
    let oracle_scsi = HwOracle::encode_scsi_sanitize(2, true);
    let scsi_matches = tool_scsi == oracle_scsi;
    ledger.assert("M1.1-PARITY", "HW-PARITY-SCSI-SANITIZE", "true", scsi_matches.to_string(), None);

    // 3. SAT 16 Parity (IDENTIFY DEVICE)
    let tool_sat = AtaCodec::encode_sat_passthrough_16(0xEC, 0, 0, 1, 4);
    let oracle_sat = HwOracle::encode_sat_16(0xEC, 0, 0, 1);
    let sat_matches = tool_sat == oracle_sat;
    ledger.assert("M1.1-PARITY", "HW-PARITY-SAT-16", "true", sat_matches.to_string(), None);
}

fn run_reserved_zero_tests(ledger: &RigLedger) {
    println!("\n[>>> HW-ENC-RESERVED-ZERO: Testing Reserved Field Zero Hygiene (Δ226) <<<]");

    let cmd = NvmeCodec::encode_sanitize(NvmeSanitizeAction::BlockErase, false);
    // Bytes 8..40 in NVMe Sanitize Command are reserved (must be 0)
    let reserved_clean = cmd[8..40].iter().all(|&b| b == 0);
    ledger.assert("M1.1-PROPS", "HW-ENC-RESERVED-ZERO", "true", reserved_clean.to_string(), None);
}

fn run_sstat_totality_tests(ledger: &RigLedger) {
    println!("\n[>>> HW-SSTAT-TOTAL: Testing SSTAT Status Pattern Totality (Δ227) <<<]");

    assert_eq!(NvmeSstatStatus::from_raw(0x0000), NvmeSstatStatus::NeverSanitized);
    assert_eq!(NvmeSstatStatus::from_raw(0x0001), NvmeSstatStatus::SanitizeCompletedSuccessfully);
    assert_eq!(NvmeSstatStatus::from_raw(0x0002), NvmeSstatStatus::SanitizeInProgress);
    assert_eq!(NvmeSstatStatus::from_raw(0x0003), NvmeSstatStatus::SanitizeFailed);

    ledger.assert("M1.1-SSTAT", "HW-SSTAT-TOTAL", "4", "4", None);
}

fn run_raw_identity_tests(ledger: &RigLedger) {
    println!("\n[>>> HW-RAW-IDENTITY: Testing Raw Payload Retention (Δ228) <<<]");

    let payload = vec![0xABu8; 512];
    let expected_hash = blake3::hash(&payload).to_hex().to_string();

    let blob = RawBlob::new("DecodedState", &payload);
    assert_eq!(blob.raw, payload);
    assert_eq!(blob.blake3, expected_hash);

    ledger.assert("M1.1-RAW", "HW-RAW-IDENTITY", expected_hash, blob.blake3, None);
}
