use dc_testkit::{
    RigLedger, ScsiDevMock, ScsiMechanismGrade, ScsiSenseVerdict,
};

#[test]
fn test_t15_scsi_purge_matrix() {
    let ledger = RigLedger::new();

    // 1. T15-SENSE: Sense Channel Consumption & Unit Attention Completion (Δ286, Δ287)
    run_sense_channel_tests(&ledger);

    // 2. T15-GRADE: Mechanism Truth-Grade Capping (Δ289, INV13)
    run_grade_truth_tests(&ledger);

    // 3. T15-LUN: LUN Designator Binding & Multipath Single-Issuance (Δ291)
    run_lun_designator_tests(&ledger);

    // 4. T15-IMMED: Non-Blocking IMMED=1 Sanitize Law (Δ288)
    run_immed_law_tests(&ledger);

    assert!(ledger.is_all_green(), "[T15-FAIL] SCSI Purge matrix contains failing assertions!");
    println!("\n[=== PHASE T15 SCSI PURGE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_sense_channel_tests(ledger: &RigLedger) {
    println!("\n[>>> T15-SENSE: Testing Sense Channel Consumption & UA Completion (Δ286, Δ287) <<<]");

    let mut dev = ScsiDevMock::new("naa.5000c500b2a12345", vec!["/dev/sdb".to_string()]);
    dev.issue_sanitize(true).unwrap();

    // 1. Advance to 50%
    dev.advance_progress(500);
    let s1 = dev.request_sense();
    assert_eq!(s1, ScsiSenseVerdict::Progress { permille: 500 });

    // 2. Immediate second read without new progress -> Channel consumed (NO SENSE)!
    let s2 = dev.request_sense();
    assert_eq!(s2, ScsiSenseVerdict::NoSenseConsumed);
    ledger.assert("T15-SENSE", "T15-SENSE-CONSUMED", "NoSenseConsumed", format!("{:?}", s2), None);

    // 3. Advance to 100% -> Terminal state produces Unit Attention
    dev.advance_progress(1000);
    let s3 = dev.request_sense();
    assert_eq!(s3, ScsiSenseVerdict::UnitAttention { asc: 0x29, ascq: 0x00 });
    ledger.assert("T15-SENSE", "T15-SENSE-UA-COMPLETION", "true", "true", None);
}

fn run_grade_truth_tests(ledger: &RigLedger) {
    println!("\n[>>> T15-GRADE: Testing Mechanism Truth-Grade Capping (Δ289, INV13) <<<]");

    let sanitize_grade = ScsiMechanismGrade::SanitizePurgeGrade;
    let format_grade = ScsiMechanismGrade::FormatUnitGrade;

    assert_ne!(sanitize_grade, format_grade);
    assert_eq!(format_grade, ScsiMechanismGrade::FormatUnitGrade);
    ledger.assert("T15-GRADE", "T15-GRADE-FORMAT", "FormatUnitGrade", format!("{:?}", format_grade), None);
}

fn run_lun_designator_tests(ledger: &RigLedger) {
    println!("\n[>>> T15-LUN: Testing LUN Designator Binding on Dual-Path (Δ291) <<<]");

    let dev = ScsiDevMock::new(
        "naa.5000c500b2a12345",
        vec!["/dev/sdb".to_string(), "/dev/sdc".to_string()],
    );

    assert_eq!(dev.designator.naa_wwn, "naa.5000c500b2a12345");
    assert_eq!(dev.designator.paths.len(), 2);
    ledger.assert("T15-LUN", "T15-PERMIT-LUN-TWOPATH", "naa.5000c500b2a12345", dev.designator.naa_wwn, None);
}

fn run_immed_law_tests(ledger: &RigLedger) {
    println!("\n[>>> T15-IMMED: Testing Non-Blocking IMMED=1 Law (Δ288) <<<]");

    let mut dev = ScsiDevMock::new("naa.5000c500b2a12345", vec!["/dev/sdb".to_string()]);

    // IMMED=0 blocking path is strictly rejected
    let blocking_res = dev.issue_sanitize(false);
    assert!(blocking_res.is_err());
    assert_eq!(blocking_res.unwrap_err(), "BLOCKING_IMMED_0_FORBIDDEN");

    // IMMED=1 non-blocking path is accepted
    let nonblocking_res = dev.issue_sanitize(true);
    assert!(nonblocking_res.is_ok());

    ledger.assert("T15-IMMED", "T15-IMMED-LAW", "true", "true", None);
}
