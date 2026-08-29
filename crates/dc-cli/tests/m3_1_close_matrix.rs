use dc_cert::{CapacityThreeNumbers, CrossVersionCertVerifier, ZoneAttestationBlock};
use dc_testkit::{ProjectCloseLedger, RigLedger, WriteModel, ZoneProductionDriver};

#[test]
fn test_m3_1_close_matrix() {
    let ledger = RigLedger::new();

    // 1. AXIS-ROUTING-ZONED & RE-DERIVATION: Compiler Second Axis (Δ507, Δ508)
    run_compiler_axis_tests(&ledger);

    // 2. XVER-CERT-OLD-REFUSES: Strict Schema Addition & Compatibility (Δ510)
    run_cross_version_schema_tests(&ledger);

    // 3. SURF-ALL-SLOTS: Three Capacity Numbers & Suspicion Rendering (Δ511)
    run_surface_census_tests(&ledger);

    // 4. CLOSE-DRAWER-EMPTY: Final Project Ledger & Empty Drawer (Δ517, Δ518)
    run_project_close_tests(&ledger);

    assert!(ledger.is_all_green(), "[M3.1-FAIL] Milestone M3.1 Project Close matrix contains failing assertions!");
    println!("\n[=== MILESTONE M3.1 ZONE-AWARE ENGINE & PROJECT CLOSE (v0.3.1) PASSED ALL CELLS ===]\n");
}

fn run_compiler_axis_tests(ledger: &RigLedger) {
    println!("\n[>>> AXIS-ROUTING-ZONED: Testing Compiler Write-Model Axis (Δ507, Δ508) <<<]");

    // 1. Conventional drive + crypto erase
    let strat_conv = ZoneProductionDriver::compile_zoned_strategy(false, true);
    assert_eq!(strat_conv.write_model, WriteModel::RandomCapable);
    assert!(!strat_conv.requires_post_sanitize_zone_reread);

    // 2. Zoned drive + crypto erase -> requires post-sanitize re-derivation!
    let strat_zoned = ZoneProductionDriver::compile_zoned_strategy(true, true);
    assert_eq!(strat_zoned.write_model, WriteModel::ZonedSequential);
    assert!(strat_zoned.requires_post_sanitize_zone_reread, "Composed zoned strategy must re-read zone report post-sanitize!");

    ledger.assert("M3.1-AXIS", "AXIS-ROUTING-ZONED", "ZonedSequential", format!("{:?}", strat_zoned.write_model), None);
    ledger.assert("M3.1-AXIS", "AXIS-RE-DERIVATION", "true", strat_zoned.requires_post_sanitize_zone_reread.to_string(), None);
}

fn run_cross_version_schema_tests(ledger: &RigLedger) {
    println!("\n[>>> XVER-CERT-OLD-REFUSES: Testing Strict Schema Refusal on Old Binaries (Δ510) <<<]");

    let zoned_cert_json = "{\"cert_schema\":\"dc-cert/2\",\"status\":\"CLEAN\",\"zone_attestation\":{\"grade\":\"CONTROLLER_ATTESTED\"}}";
    let legacy_cert_json = "{\"cert_schema\":\"dc-cert/2\",\"status\":\"CLEAN\"}";

    // 1. v0.2.x binary handed zoned cert -> Refuses with SCHEMA_UNKNOWN_FIELD
    let old_tool_res = CrossVersionCertVerifier::verify_cert_json(zoned_cert_json, "v0.2.2");
    assert!(old_tool_res.is_err());
    assert_eq!(old_tool_res.unwrap_err(), "SCHEMA_UNKNOWN_FIELD: zone_attestation");

    // 2. v0.2.x binary handed legacy cert -> Verifies clean
    let old_tool_legacy_res = CrossVersionCertVerifier::verify_cert_json(legacy_cert_json, "v0.2.2");
    assert!(old_tool_legacy_res.is_ok());

    // 3. v0.3.1 binary handed zoned cert -> Verifies clean
    let new_tool_res = CrossVersionCertVerifier::verify_cert_json(zoned_cert_json, "v0.3.1");
    assert!(new_tool_res.is_ok());

    ledger.assert("M3.1-XVER", "XVER-CERT-OLD-REFUSES", "true", old_tool_res.is_err().to_string(), None);
    ledger.assert("M3.1-XVER", "XVER-CERT-NEW-ACCEPTS", "true", new_tool_res.is_ok().to_string(), None);
}

fn run_surface_census_tests(ledger: &RigLedger) {
    println!("\n[>>> SURF-ALL-SLOTS: Testing Surface Census & Capacity Numbers (Δ511) <<<]");

    let cap = CapacityThreeNumbers {
        total_drive_lbas: 20_000_000,
        writable_zone_capacity_lbas: 19_500_000,
        wiped_extent_lbas: 19_500_000,
    };

    let block = ZoneAttestationBlock::new(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ZONE_ATTESTED_FULL_COVERAGE",
        cap.clone(),
        Some("suspected-managed-smr: 10x rewrite throughput drop"),
    );

    assert_eq!(block.grade, "CONTROLLER_ATTESTED");
    assert_eq!(block.capacity.total_drive_lbas, 20_000_000);
    assert_eq!(block.capacity.writable_zone_capacity_lbas, 19_500_000);
    assert_eq!(block.capacity.wiped_extent_lbas, 19_500_000);
    assert!(block.suspicion_line.is_some());

    ledger.assert("M3.1-SURF", "SURF-ALL-SLOTS", "true", (block.capacity == cap).to_string(), None);
}

fn run_project_close_tests(ledger: &RigLedger) {
    println!("\n[>>> CLOSE-DRAWER-EMPTY: Testing Project Close & Ledger Check (Δ517, Δ518) <<<]");

    let close_ledger = ProjectCloseLedger::canonical_close();
    let close_res = close_ledger.verify_project_close();

    assert!(close_res.is_ok());
    assert_eq!(close_res.unwrap(), "PROJECT_CLOSED_ALL_DEVICES_WIPED_OR_REFUSED_BY_LAW");
    assert_eq!(close_ledger.release_version, "v0.3.1");
    assert_eq!(close_ledger.total_specs, 28);
    assert_eq!(close_ledger.total_ceremonies, 16);

    ledger.assert("M3.1-CLOSE", "CLOSE-DRAWER-EMPTY", "true", close_ledger.drawer_empty.to_string(), None);
    ledger.assert("M3.1-CLOSE", "CLOSE-ALL-SPECS-ACCOUNTED", "28", close_ledger.total_specs.to_string(), None);
}
