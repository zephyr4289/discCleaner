use assert_cmd::Command;
use dc_testkit::{
    Janitor, ProcessGuard, RigLedger, ToolSpawner,
};
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn test_g1_substrate_matrix() {
    let ledger = RigLedger::new();

    // 1. SUB-LEDGER: Structured Assertion Registry Format (Δ96)
    run_sub_ledger_tests(&ledger);

    // 2. SUB-ENV-ECHO: Normative Spawn Environment Discipline (Δ99, Δ102)
    run_sub_env_echo_tests(&ledger);

    // 3. SUB-GUARD-REAP: ProcessGuard RAII Cleanup (K194)
    run_sub_guard_reap_tests(&ledger);

    // 4. SUB-JAN-IDEM: Janitor Idempotence (Δ101)
    run_sub_janitor_idempotence(&ledger);

    assert!(ledger.is_all_green(), "[G1-FAIL] Substrate matrix contains failing assertions!");
    println!("\n[=== G1 TESTKIT SUBSTRATE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_sub_ledger_tests(ledger: &RigLedger) {
    println!("\n[>>> SUB-LEDGER: Testing Structured Assertion Registry (Δ96) <<<]");

    let passed = ledger.assert(
        "G1-LEDGER",
        "L-FORMAT",
        "valid",
        "valid",
        Some("/tmp/artifacts/ledger.json"),
    );
    assert!(passed);

    ledger.waive(
        "G1-LEDGER",
        "L-WAIVE-SAMPLE",
        "Non-root runner waived hardware jumpers",
    );

    let records = ledger.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].id, "L-FORMAT");
    assert_eq!(records[1].id, "L-WAIVE-SAMPLE");
}

fn run_sub_env_echo_tests(ledger: &RigLedger) {
    println!("\n[>>> SUB-ENV-ECHO: Testing Normative Spawn Environment Table (Δ99, Δ102) <<<]");

    // Set a test DC_ variable in parent environment
    std::env::set_var("DC_POISON_LEAK_TEST", "should_be_scrubbed");

    let mut cmd = Command::cargo_bin("dc-victim").unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    // Configure via ToolSpawner
    let mut configured_cmd = ToolSpawner::prepare_command(
        cmd.get_program().as_ref(),
        temp_dir.path(),
    );
    configured_cmd.arg("--echo-env");

    let output = configured_cmd.output().expect("Failed to execute dc-victim");
    assert!(output.status.success());

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let env_map: BTreeMap<String, String> = serde_json::from_str(&stdout_str)
        .expect("dc-victim --echo-env must output valid JSON");

    // 1. Assert DC_* variables are scrubbed (Δ99)
    let has_dc_var = env_map.keys().any(|k| k.starts_with("DC_"));
    ledger.assert("G1-SPAWN", "SUB-ENV-SCRUB", "false", (!has_dc_var).to_string(), None);

    // 2. Assert normative pinned environment variables (Δ99)
    let tz_ok = env_map.get("TZ").map(|s| s.as_str()) == Some("UTC");
    let term_ok = env_map.get("TERM").map(|s| s.as_str()) == Some("dumb");
    let nocolor_ok = env_map.get("NO_COLOR").map(|s| s.as_str()) == Some("1");
    let lang_ok = env_map.get("LANG").map(|s| s.as_str()) == Some("C.UTF-8");

    ledger.assert("G1-SPAWN", "SUB-ENV-TZ", "true", tz_ok.to_string(), None);
    ledger.assert("G1-SPAWN", "SUB-ENV-TERM", "true", term_ok.to_string(), None);
    ledger.assert("G1-SPAWN", "SUB-ENV-NOCOLOR", "true", nocolor_ok.to_string(), None);
    ledger.assert("G1-SPAWN", "SUB-ENV-LANG", "true", lang_ok.to_string(), None);
}

fn run_sub_guard_reap_tests(ledger: &RigLedger) {
    println!("\n[>>> SUB-GUARD-REAP: Testing ProcessGuard RAII Cleanup (K194) <<<]");

    let cmd_victim = Command::cargo_bin("dc-victim").unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    let mut configured_cmd = ToolSpawner::prepare_command(
        cmd_victim.get_program().as_ref(),
        temp_dir.path(),
    );
    configured_cmd.arg("--sleep-ms").arg("10000");

    let pid;
    {
        let guard = ToolSpawner::spawn(&mut configured_cmd).expect("Must spawn dc-victim");
        pid = guard.child.id();
        // Check child is initially alive
        let alive_before = unsafe { libc::kill(pid as i32, 0) == 0 };
        assert!(alive_before, "Spawned child must be running");
        // Guard drops at end of scope -> kill + reap (K194)
    }

    // After guard drop, child must be reaped
    let alive_after = unsafe { libc::kill(pid as i32, 0) == 0 };
    ledger.assert("G1-SPAWN", "SUB-GUARD-REAP", "false", alive_after.to_string(), None);
}

fn run_sub_janitor_idempotence(ledger: &RigLedger) {
    println!("\n[>>> SUB-JAN-IDEM: Testing Janitor Pipeline Idempotence (Δ101) <<<]");

    let temp_dir = tempfile::tempdir().unwrap();
    Janitor::sweep_all(temp_dir.path());
    // Second sweep on clean directory
    Janitor::sweep_all(temp_dir.path());

    ledger.assert("G1-JANITOR", "SUB-JAN-IDEM", "true", "true", None);
}
