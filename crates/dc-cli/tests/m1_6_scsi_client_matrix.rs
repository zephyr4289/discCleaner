use dc_scsi::{
    PreflightBattery, ProtocolRoute, ScsiSession, TimingIntegrity,
};
use dc_testkit::RigLedger;

#[test]
fn test_m1_6_scsi_client_matrix() {
    let ledger = RigLedger::new();

    // 1. CONSIST-CROSS-CAPMASK: Single-Path Internal Consistency Engine (Δ328)
    run_single_path_consistency_tests(&ledger);

    // 2. ROUTE-VPD-SAT: VPD-Driven Protocol Routing (Δ330)
    run_protocol_routing_tests(&ledger);

    // 3. NODE-BLOCK-RUNTIME: Block-Node Runtime Enforcement (Δ330)
    run_block_node_enforcement_tests(&ledger);

    // 4. TIMING-PROD-ANOMALY: Stopwatch Integrity & Anomaly Detection (Δ335)
    run_timing_integrity_tests(&ledger);

    assert!(ledger.is_all_green(), "[M1.6-FAIL] SCSI Client matrix contains failing assertions!");
    println!("\n[=== MILESTONE M1.6 SCSI PURGE CLIENT MATRIX PASSED ALL CELLS ===]\n");
}

fn run_single_path_consistency_tests(ledger: &RigLedger) {
    println!("\n[>>> CONSIST-CROSS-CAPMASK: Testing Single-Path Consistency (Δ328) <<<]");

    // Scenario 1: Divergence between IDENTIFY and READCAP16 -> CAPACITY_MASK detected!
    let report1 = PreflightBattery::check_single_path_consistency(3_907_029_168, 1_953_525_168);
    assert!(!report1.is_consistent);
    assert!(report1.ceiling_disclosed);
    ledger.assert("M1.6-CONSIST", "CONSIST-CROSS-CAPMASK", "true", (!report1.is_consistent).to_string(), None);

    // Scenario 2: Identical answers -> Consistent
    let report2 = PreflightBattery::check_single_path_consistency(3_907_029_168, 3_907_029_168);
    assert!(report2.is_consistent);
    assert!(!report2.ceiling_disclosed);
    ledger.assert("M1.6-CONSIST", "CONSIST-CROSS-OK", "true", report2.is_consistent.to_string(), None);
}

fn run_protocol_routing_tests(ledger: &RigLedger) {
    println!("\n[>>> ROUTE-VPD-SAT: Testing VPD Protocol Routing (Δ330) <<<]");

    // VPD Page 89 present -> Routes to SatAta
    let session_sat = ScsiSession::open_block_node("/dev/sdb", true, true).unwrap();
    assert_eq!(session_sat.protocol_route, ProtocolRoute::SatAta);

    // VPD Page 89 absent -> Routes to NativeScsi
    let session_scsi = ScsiSession::open_block_node("/dev/sdc", false, false).unwrap();
    assert_eq!(session_scsi.protocol_route, ProtocolRoute::NativeScsi);

    ledger.assert("M1.6-ROUTE", "ROUTE-VPD-SAT", "SatAta", format!("{:?}", session_sat.protocol_route), None);
    ledger.assert("M1.6-ROUTE", "ROUTE-VPD-NATIVE", "NativeScsi", format!("{:?}", session_scsi.protocol_route), None);
}

fn run_block_node_enforcement_tests(ledger: &RigLedger) {
    println!("\n[>>> NODE-BLOCK-RUNTIME: Testing Block-Node Enforcement (Δ330) <<<]");

    // Opening /dev/sg0 character node -> Refused!
    let sg_res = ScsiSession::open_block_node("/dev/sg0", false, false);
    assert!(sg_res.is_err());
    assert_eq!(sg_res.unwrap_err(), "UNCOVERED_DOOR_CHARACTER_NODE_REFUSED");

    // Opening /dev/sdb block node -> Accepted!
    let sd_res = ScsiSession::open_block_node("/dev/sdb", false, false);
    assert!(sd_res.is_ok());

    ledger.assert("M1.6-NODE", "NODE-BLOCK-RUNTIME", "true", sg_res.is_err().to_string(), None);
}

fn run_timing_integrity_tests(ledger: &RigLedger) {
    println!("\n[>>> TIMING-PROD-ANOMALY: Testing Timing Baselines (Δ335) <<<]");

    // Instant completion (< 1000ms) on a 90s (90,000ms) mechanism -> Flagged as anomaly!
    let fast_res = TimingIntegrity::check_mechanism_duration("ScsiSanitizeBlockErase", 250, 90_000);
    assert!(fast_res.is_err());
    assert_eq!(fast_res.unwrap_err(), "TIMING_ANOMALY_TOO_FAST_MANGLE_SUSPECTED");

    // Normal completion (95,000ms) -> Accepted
    let normal_res = TimingIntegrity::check_mechanism_duration("ScsiSanitizeBlockErase", 95_000, 90_000);
    assert!(normal_res.is_ok());

    ledger.assert("M1.6-TIMING", "TIMING-PROD-ANOMALY", "true", fast_res.is_err().to_string(), None);
}
