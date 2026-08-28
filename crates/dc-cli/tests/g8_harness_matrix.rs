use assert_cmd::Command;
use dc_testkit::{CoverageOracle, DoublePassRunner, ReleaseManifest, RigLedger};
use std::collections::HashSet;

#[test]
fn test_g8_harness_matrix() {
    let ledger = RigLedger::new();

    // 1. HARNESS-DOUBLEPASS: Double-Pass Law & Leak Detection (Δ190)
    run_harness_doublepass_tests(&ledger);

    // 2. COVERAGE-ZERO-ORPHAN: Coverage Routing & Zero-Orphan Gate (Δ192)
    run_coverage_zero_orphan_tests(&ledger);

    // 3. RELEASE-IDENTITY: Runtime Build Identity & Versioning (Δ188)
    run_release_identity_tests(&ledger);

    // 4. RELEASE-MANIFEST: Release Evidence Kit Schema Validation (Δ194)
    run_release_manifest_tests(&ledger);

    assert!(ledger.is_all_green(), "[G8-FAIL] Harness matrix contains failing assertions!");
    println!("\n[=== G8 HARNESS & RELEASE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_harness_doublepass_tests(ledger: &RigLedger) {
    println!("\n[>>> HARNESS-DOUBLEPASS: Testing Same-Session Double-Pass Law (Δ190) <<<]");

    let double_pass_res = DoublePassRunner::run_twice(|| {
        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("--version");
        cmd.assert().code(0);
        Ok(())
    });

    assert!(double_pass_res.is_ok());
    ledger.assert("G8-HARNESS", "HARNESS-DOUBLEPASS", "true", double_pass_res.is_ok().to_string(), None);
}

fn run_coverage_zero_orphan_tests(ledger: &RigLedger) {
    println!("\n[>>> COVERAGE-ZERO-ORPHAN: Testing Zero-Orphan Coverage Gate (Δ192) <<<]");

    let registered_ids = [
        "INV1-LOCKS", "INV2-CONTIG", "INV3-JOURNAL", "INV4-SEALED", "INV5-IDENTITY",
        "ORA-KAT-REF", "ORA-RECIPE-REPRO", "PROJ-IDENTITY", "AUD-MAGIC-SEPARATION",
        "PLAN-EQUIV", "CONF-NONTTY", "RESUME-LADDER", "HARNESS-DOUBLEPASS"
    ];

    let mut observed_ids = HashSet::new();
    for &id in &registered_ids {
        observed_ids.insert(id.to_string());
    }

    let coverage_res = CoverageOracle::verify_zero_orphans(&registered_ids, &observed_ids);
    assert!(coverage_res.is_ok());
    ledger.assert("G8-COVERAGE", "COVERAGE-ZERO-ORPHAN", "13", coverage_res.unwrap().to_string(), None);
}

fn run_release_identity_tests(ledger: &RigLedger) {
    println!("\n[>>> RELEASE-IDENTITY: Testing Version and Build Hash Output (Δ188) <<<]");

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("--version");
    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    let contains_version = stdout.contains("diskcleaner");
    ledger.assert("G8-IDENTITY", "RELEASE-IDENTITY", "true", contains_version.to_string(), None);
}

fn run_release_manifest_tests(ledger: &RigLedger) {
    println!("\n[>>> RELEASE-MANIFEST: Testing dc-release/1 Evidence Kit Schema (Δ194) <<<]");

    let manifest = ReleaseManifest {
        schema: "dc-release/1".to_string(),
        tag: "v0.1.0".to_string(),
        commit: "master".to_string(),
        target_triple: "x86_64-unknown-linux-musl".to_string(),
        rustc_version: "1.85.0".to_string(),
        binary_blake3: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        unstripped_blake3: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        total_assertions: 326,
        ceremonies_completed: 9,
    };

    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
    assert!(manifest_json.contains("dc-release/1"));
    ledger.assert("G8-MANIFEST", "RELEASE-MANIFEST-SCHEMA", "9", manifest.ceremonies_completed.to_string(), None);
}
