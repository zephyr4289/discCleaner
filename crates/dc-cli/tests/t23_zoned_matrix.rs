use dc_testkit::{
    RigLedger, ZoneCondition, ZoneDesc, ZoneDisciplinePlanner, ZoneOp, ZoneReport,
    ZoneReportOracle, ZoneType,
};

#[test]
fn test_t23_zoned_matrix() {
    let ledger = RigLedger::new();

    // 1. ZP-BIJECTION-POINTER: Deterministic Sequential Pointer Sequence (Δ496, Δ497)
    run_zone_pointer_bijection_tests(&ledger);

    // 2. ZONE-APPEND-BANNED: Permanent Ban on ZONE APPEND (Δ497)
    run_zone_append_ban_tests(&ledger);

    // 3. ZT-AMBIGUITY: Pass Attribution via Journal Authority (Δ498)
    run_full_zone_ambiguity_tests(&ledger);

    // 4. ZV-GRADE-SEPARATED: Two-Witness Coverage vs Content Certification (Δ500)
    run_zone_attestation_coverage_tests(&ledger);

    // 5. ZDM-TIMING-SUSPICION: DM-SMR Rewrite Collapse Timing Disclosure (Δ501)
    run_dm_smr_timing_suspicion_tests(&ledger);

    assert!(ledger.is_all_green(), "[T23-FAIL] SMR / Zoned Rig matrix contains failing assertions!");
    println!("\n[=== PHASE T23 SMR / ZONED RIG MATRIX PASSED ALL CELLS ===]\n");
}

fn run_zone_pointer_bijection_tests(ledger: &RigLedger) {
    println!("\n[>>> ZP-BIJECTION-POINTER: Testing Pointer Discipline & Bijection (Δ496, Δ497) <<<]");

    let report = ZoneReport {
        nr_zones: 2,
        max_open_zones: 4,
        zones: vec![
            ZoneDesc {
                zone_id: 0,
                start_lba: 0,
                capacity_lbas: 2048,
                write_pointer_lba: 0,
                zone_type: ZoneType::SequentialWriteRequired,
                condition: ZoneCondition::Empty,
            },
            ZoneDesc {
                zone_id: 1,
                start_lba: 2048,
                capacity_lbas: 2048,
                write_pointer_lba: 2048,
                zone_type: ZoneType::SequentialWriteRequired,
                condition: ZoneCondition::Empty,
            },
        ],
    };

    let window_size = 512;
    let ops = ZoneDisciplinePlanner::plan_zone_pass(&report, 1, window_size);

    // Verify Zone 0 sequence: Reset -> Open -> 4 Writes at 0, 512, 1024, 1536 -> Finish
    assert_eq!(ops[0], ZoneOp::Reset { zone_id: 0 });
    assert_eq!(ops[1], ZoneOp::Open { zone_id: 0 });
    assert_eq!(ops[2], ZoneOp::Write { zone_id: 0, target_lba: 0, window_idx: 0 });
    assert_eq!(ops[3], ZoneOp::Write { zone_id: 0, target_lba: 512, window_idx: 1 });
    assert_eq!(ops[4], ZoneOp::Write { zone_id: 0, target_lba: 1024, window_idx: 2 });
    assert_eq!(ops[5], ZoneOp::Write { zone_id: 0, target_lba: 1536, window_idx: 3 });
    assert_eq!(ops[6], ZoneOp::Finish { zone_id: 0 });

    ledger.assert("T23-PLANNER", "ZP-BIJECTION-POINTER", "true", "true", None);
}

fn run_zone_append_ban_tests(ledger: &RigLedger) {
    println!("\n[>>> ZONE-APPEND-BANNED: Testing Permanent Ban on ZONE APPEND (Δ497) <<<]");

    let plain_write_res = ZoneDisciplinePlanner::evaluate_write_command_safety(false);
    let append_write_res = ZoneDisciplinePlanner::evaluate_write_command_safety(true);

    assert!(plain_write_res.is_ok());
    assert!(append_write_res.is_err());
    assert_eq!(append_write_res.unwrap_err(), "ZONE_APPEND_BANNED_TO_PRESERVE_RECIPE_BIJECTION");

    ledger.assert("T23-BAN", "ZONE-APPEND-BANNED", "true", append_write_res.is_err().to_string(), None);
}

fn run_full_zone_ambiguity_tests(ledger: &RigLedger) {
    println!("\n[>>> ZT-AMBIGUITY: Testing Journal Attribution for FULL Zones (Δ498) <<<]");

    // Device state: Zone is FULL at capacity (looks identical whether Pass 1 or Pass 2)
    let full_zone = ZoneDesc {
        zone_id: 0,
        start_lba: 0,
        capacity_lbas: 2048,
        write_pointer_lba: 2048,
        zone_type: ZoneType::SequentialWriteRequired,
        condition: ZoneCondition::Full,
    };

    // Journal says Pass 2 completed
    let pass_res = ZoneDisciplinePlanner::resolve_full_zone_ambiguity(&full_zone, 2).unwrap();
    assert_eq!(pass_res, 2, "Pass attribution must derive strictly from journal transaction!");

    ledger.assert("T23-RESUME", "ZT-AMBIGUITY-JOURNAL-AUTHORITY", "2", pass_res.to_string(), None);
}

fn run_zone_attestation_coverage_tests(ledger: &RigLedger) {
    println!("\n[>>> ZV-GRADE-SEPARATED: Testing Two-Witness Coverage vs Content (Δ500) <<<]");

    let full_report = ZoneReport {
        nr_zones: 1,
        max_open_zones: 4,
        zones: vec![ZoneDesc {
            zone_id: 0,
            start_lba: 0,
            capacity_lbas: 2048,
            write_pointer_lba: 2048,
            zone_type: ZoneType::SequentialWriteRequired,
            condition: ZoneCondition::Full,
        }],
    };

    let coverage_res = ZoneReportOracle::evaluate_full_coverage(&full_report).unwrap();
    assert_eq!(coverage_res, "ZONE_ATTESTED_FULL_COVERAGE");

    ledger.assert("T23-VERIFY", "ZV-GRADE-SEPARATED", "ZONE_ATTESTED_FULL_COVERAGE", coverage_res, None);
}

fn run_dm_smr_timing_suspicion_tests(ledger: &RigLedger) {
    println!("\n[>>> ZDM-TIMING-SUSPICION: Testing DM-SMR Rewrite Collapse Disclosure (Δ501) <<<]");

    // Sweep 1: 150,000 KiB/s baseline; Sweep 2: 15,000 KiB/s (10x collapse!)
    let suspicion = ZoneDisciplinePlanner::evaluate_smr_timing_anomaly(150_000, 15_000);
    assert!(suspicion.is_some());
    assert!(suspicion.unwrap().contains("suspected-managed-smr"));

    // Normal CMR: Sweep 1: 150,000 KiB/s; Sweep 2: 145,000 KiB/s
    let normal = ZoneDisciplinePlanner::evaluate_smr_timing_anomaly(150_000, 145_000);
    assert!(normal.is_none());

    ledger.assert("T23-DMSMR", "ZDM-TIMING-SUSPICION", "true", suspicion.is_some().to_string(), None);
}
