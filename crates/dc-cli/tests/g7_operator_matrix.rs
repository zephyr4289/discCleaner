use assert_cmd::Command;
use dc_core::{
    FastPathPolicy, Orchestrator, OrchestratorEffect, OrchestratorState, SanitizationPlan,
    StableIdentity, BusType,
};
use dc_testkit::{
    DioProbe, Janitor, LoopDevice, RigLedger, SentinelManager,
};
use std::fs;
use std::path::{Path, PathBuf};

static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn test_g7_operator_surface_matrix() {
    let ledger = RigLedger::new();

    // 1. ORCH-PURE-TRANSCRIPT: Pure Orchestrator FSM Walk (Δ175)
    run_orch_fsm_pure_tests(&ledger);

    // 2. PLAN-EQUIV: Plan Compilation Equivalence (Δ177)
    run_plan_equiv_tests(&ledger);

    // 3. CONF-NONTTY: Non-TTY Execution Rejection (Δ178)
    run_conf_nontty_tests(&ledger);

    if !is_root() {
        eprintln!("[SKIP] G7 E2E live device tests require root privileges (EUID 0). Pure tests passed.");
        assert!(ledger.is_all_green());
        return;
    }

    let _guard = CELL_LOCK.lock().unwrap();

    let scratch_dir = match DioProbe::discover_scratch_dir() {
        Ok(d) => d,
        Err(e) => panic!("[ENV-FAIL] Scratch discovery failed:\n{}", e),
    };

    Janitor::sweep_all(&scratch_dir);

    // 4. RESUME-LADDER: Prompt-less Resume Ladder (Δ180)
    run_resume_ladder_tests(&ledger, &scratch_dir);

    Janitor::sweep_all(&scratch_dir);

    assert!(ledger.is_all_green(), "[G7-FAIL] Operator matrix contains failing assertions!");
    println!("\n[=== G7 OPERATOR SURFACE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_orch_fsm_pure_tests(ledger: &RigLedger) {
    println!("\n[>>> ORCH-PURE: Testing Pure Orchestrator FSM Walk (Δ175) <<<]");

    let mut orch = Orchestrator::new(1);
    assert_eq!(orch.current_state(), OrchestratorState::Initialized);

    let eff1 = orch.step(true);
    assert_eq!(eff1, OrchestratorEffect::PromptConfirmation);
    assert_eq!(orch.current_state(), OrchestratorState::Classified);

    let eff2 = orch.step(true);
    assert_eq!(eff2, OrchestratorEffect::AcquireLocksAndArm);
    assert_eq!(orch.current_state(), OrchestratorState::Confirmed);

    let eff3 = orch.step(true);
    assert_eq!(eff3, OrchestratorEffect::ExecutePass { pass: 0 });
    assert_eq!(orch.current_state(), OrchestratorState::Armed);

    let eff4 = orch.step(true);
    assert_eq!(eff4, OrchestratorEffect::FlushDevice);
    assert_eq!(orch.current_state(), OrchestratorState::Flushed);

    let eff5 = orch.step(true);
    assert_eq!(eff5, OrchestratorEffect::VerifyMedia);
    assert_eq!(orch.current_state(), OrchestratorState::Verifying);

    let eff6 = orch.step(true);
    assert_eq!(eff6, OrchestratorEffect::WriteCertificate);
    assert_eq!(orch.current_state(), OrchestratorState::Completed);

    let eff7 = orch.step(true);
    assert_eq!(eff7, OrchestratorEffect::Exit { code: 0 });

    ledger.assert("G7-ORCH", "ORCH-FSM-WALK", "true", "true", None);
}

fn run_plan_equiv_tests(ledger: &RigLedger) {
    println!("\n[>>> PLAN-EQUIV: Testing Plan Compilation Identity (Δ177) <<<]");

    let identity = StableIdentity {
        model: Some("NVMe 980".to_string()),
        serial: Some("SN001".to_string()),
        wwn: None,
        size_bytes: 32 * 1024 * 1024,
        bus: BusType::Nvme,
        dm_name: None,
        dm_uuid: None,
    };

    let plan1 = SanitizationPlan::clear_zero(identity.clone(), FastPathPolicy::PreferWriteZeroes);
    let plan2 = SanitizationPlan::clear_zero(identity, FastPathPolicy::PreferWriteZeroes);

    let hash1 = plan1.compute_plan_hash().unwrap();
    let hash2 = plan2.compute_plan_hash().unwrap();

    ledger.assert("G7-PLAN", "PLAN-EQUIV", hash1, hash2, None);
}

fn run_conf_nontty_tests(ledger: &RigLedger) {
    println!("\n[>>> CONF-NONTTY: Testing Non-TTY Rejection without Serial Confirm (Δ178) <<<]");

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target").arg("/dev/null")
        .arg("--profile").arg("clear-zero");
    // Should fail with Exit 2 or Exit 8 (refusal / confirm required without TTY)
    let status = cmd.assert();
    let code = status.get_output().status.code().unwrap_or(-1);

    let rejected = code == 2 || code == 8;
    ledger.assert("G7-CONF", "CONF-NONTTY-REJECT", "true", rejected.to_string(), None);
}

fn run_resume_ladder_tests(ledger: &RigLedger, scratch_dir: &Path) {
    println!("\n[>>> RESUME-LADDER: Testing Prompt-less Resume Ladder (Δ180) <<<]");

    let run_dir = scratch_dir.join(format!("g7_resume_{}", std::process::id()));
    let _ = fs::create_dir_all(&run_dir);

    let backing = run_dir.join("backing.raw");
    SentinelManager::fill_sentinel(&backing, 32 * 1024 * 1024).unwrap();
    let loop_dev = LoopDevice::create_and_attach(&backing, 32 * 1024 * 1024, 512).unwrap();

    let out_dir = run_dir.join("out_g7");
    let _ = fs::create_dir_all(&out_dir);

    // Interrupt at pass 0 commit 1
    let mut exec_cmd = Command::cargo_bin("diskcleaner").unwrap();
    exec_cmd.env("DC_SIGNAL_AT", "commit-write:1")
        .arg("execute")
        .arg("--target").arg(&loop_dev.dev_path)
        .arg("--profile").arg("clear-zero")
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    exec_cmd.assert().code(3);

    let journal_path = find_single_file_with_ext(&out_dir, "dcj").unwrap();

    // Prompt-less resume
    let mut resume_cmd = Command::cargo_bin("diskcleaner").unwrap();
    resume_cmd.arg("resume")
        .arg("--journal").arg(&journal_path)
        .arg("--serial-confirm").arg(format!("loop{}", loop_dev.minor))
        .arg("--allow-loop")
        .arg("--out-dir").arg(&out_dir)
        .arg("--no-progress");
    resume_cmd.assert().code(0);

    // Verify certificate was written
    let cert_path = find_single_file_with_ext(&out_dir, "cert.json");
    ledger.assert("G7-RESUME", "RESUME-CERT-ISSUED", "true", cert_path.is_some().to_string(), None);
}

fn find_single_file_with_ext(dir: &Path, ext: &str) -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = p.file_name()?.to_string_lossy().to_string();
            if name.ends_with(ext) {
                return Some(p);
            }
        }
    }
    None
}
