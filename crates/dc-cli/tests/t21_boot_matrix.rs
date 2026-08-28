use dc_testkit::{BootLabMock, EvidenceSinkMode, RigLedger};

#[test]
fn test_t21_boot_matrix() {
    let ledger = RigLedger::new();

    // 1. BOOT-SINK-PROBE: Evidence Sink Pre-Wipe Verification & Volatile RAM Mode (Δ400)
    run_evidence_sink_tests(&ledger);

    // 2. BOOT-PROTECT-MEDIUM-SINK: Never-Overridable Boot & Sink Sentinels (Δ401)
    run_boot_and_sink_protection_tests(&ledger);

    // 3. BOOT-FREEZE-GATE-OWNS-BOX: Owns-the-Box Gated S3 Freeze Cure (Δ402)
    run_freeze_gate_tests(&ledger);

    // 4. BOOT-PROVENANCE-BLOCK: Environment Provenance Embedding (Δ406)
    run_provenance_block_tests(&ledger);

    assert!(ledger.is_all_green(), "[T21-FAIL] Boot Environment matrix contains failing assertions!");
    println!("\n[=== PHASE T21 BOOT ENVIRONMENT RIG MATRIX PASSED ALL CELLS ===]\n");
}

fn run_evidence_sink_tests(ledger: &RigLedger) {
    println!("\n[>>> BOOT-SINK-PROBE: Testing Evidence Sink Probe & RAM Mode (Δ400) <<<]");

    // 1. Persistent sink probe verification
    let mut boot_lab = BootLabMock::new("BOOT_STICK_SN01", "/dev/sdb", "/dev/sdc1", true);
    let probe_res = boot_lab.probe_evidence_sink();
    assert_eq!(probe_res, Ok("EVIDENCE_SINK_PROBED_AND_VERIFIED"));

    // 2. Volatile RAM sink disclosure
    boot_lab.sink_mode = EvidenceSinkMode::VolatileRam { copy_out_rendered: false };
    let ram_res = boot_lab.probe_evidence_sink();
    assert_eq!(ram_res, Ok("VOLATILE_RAM_SINK_DISCLOSED"));

    ledger.assert("T21-SINK", "BOOT-SINK-PROBE", "Ok(\"EVIDENCE_SINK_PROBED_AND_VERIFIED\")", format!("{:?}", probe_res), None);
    ledger.assert("T21-SINK", "BOOT-SINK-RAM-DISCLOSE", "Ok(\"VOLATILE_RAM_SINK_DISCLOSED\")", format!("{:?}", ram_res), None);
}

fn run_boot_and_sink_protection_tests(ledger: &RigLedger) {
    println!("\n[>>> BOOT-PROTECT: Testing Boot-Medium and Sink Protection (Δ401) <<<]");

    let boot_lab = BootLabMock::new("BOOT_STICK_SN01", "/dev/sdb", "/dev/sdc1", true);

    // 1. Target is boot medium -> Refused!
    let boot_target_res = boot_lab.validate_target_safety("BOOT_STICK_SN01", "/dev/sdb");
    assert_eq!(boot_target_res, Err("REFUSAL_BOOT_MEDIUM_TARGET_NEVER_OVERRIDABLE"));

    // 2. Target is evidence sink -> Refused!
    let sink_target_res = boot_lab.validate_target_safety("TARGET_DRIVE_SN02", "/dev/sdc1");
    assert_eq!(sink_target_res, Err("REFUSAL_EVIDENCE_SINK_TARGET_NEVER_OVERRIDABLE"));

    // 3. Target is an ordinary drive -> Accepted!
    let safe_target_res = boot_lab.validate_target_safety("TARGET_DRIVE_SN03", "/dev/sda");
    assert!(safe_target_res.is_ok());

    ledger.assert("T21-PROTECT", "BOOT-PROTECT-MEDIUM", "Err(\"REFUSAL_BOOT_MEDIUM_TARGET_NEVER_OVERRIDABLE\")", format!("{:?}", boot_target_res), None);
    ledger.assert("T21-PROTECT", "BOOT-PROTECT-SINK", "Err(\"REFUSAL_EVIDENCE_SINK_TARGET_NEVER_OVERRIDABLE\")", format!("{:?}", sink_target_res), None);
}

fn run_freeze_gate_tests(ledger: &RigLedger) {
    println!("\n[>>> BOOT-FREEZE-GATE: Testing Owns-The-Box Freeze Gating (Δ402) <<<]");

    // 1. Boot environment (owns_the_box == true) -> S3 unfreeze permitted
    let boot_lab_baremetal = BootLabMock::new("BOOT_STICK_SN01", "/dev/sdb", "/dev/sdc1", true);
    let allowed_dance = boot_lab_baremetal.execute_s3_unfreeze_dance();
    assert_eq!(allowed_dance, Ok("S3_UNFREEZE_DANCE_COMPLETED_UNFROZEN_ASSERTED"));

    // 2. Installed Host OS (owns_the_box == false) -> Refused!
    let boot_lab_host = BootLabMock::new("BOOT_STICK_SN01", "/dev/sdb", "/dev/sdc1", false);
    let refused_dance = boot_lab_host.execute_s3_unfreeze_dance();
    assert_eq!(refused_dance, Err("S3_UNFREEZE_DANCE_REFUSED_INSTALLED_HOST_OS_PROTECTED"));

    ledger.assert("T21-FREEZE", "BOOT-FREEZE-ALLOWED", "Ok(\"S3_UNFREEZE_DANCE_COMPLETED_UNFROZEN_ASSERTED\")", format!("{:?}", allowed_dance), None);
    ledger.assert("T21-FREEZE", "BOOT-FREEZE-REFUSED", "Err(\"S3_UNFREEZE_DANCE_REFUSED_INSTALLED_HOST_OS_PROTECTED\")", format!("{:?}", refused_dance), None);
}

fn run_provenance_block_tests(ledger: &RigLedger) {
    println!("\n[>>> BOOT-PROVENANCE: Testing Environment Provenance Block (Δ406) <<<]");

    let boot_lab = BootLabMock::new("BOOT_STICK_SN01", "/dev/sdb", "/dev/sdc1", true);
    let prov = boot_lab.generate_environment_provenance();

    assert_eq!(prov.kernel_version, "Linux 6.6.21-dc-rt");
    assert_eq!(prov.boot_medium_serial, "BOOT_STICK_SN01");
    assert!(prov.owns_the_box);

    ledger.assert("T21-PROV", "BOOT-PROVENANCE-BLOCK", "true", prov.owns_the_box.to_string(), None);
}
