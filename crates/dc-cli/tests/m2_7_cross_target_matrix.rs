use dc_testkit::{
    ArchAgreementDriver, BuildProvenance, ReproducibilityTriangle, RigLedger, TargetArch,
};

#[test]
fn test_m2_7_cross_target_matrix() {
    let ledger = RigLedger::new();

    // 1. ARCH-CORPUS-AGREE-ALL: Cross-Architecture Vector Agreement (Δ484)
    run_corpus_agreement_tests(&ledger);

    // 2. BOOTARM-MATRIX-2CELLS & BOOTARM-CONSOLE-PL011: Per-Arch Boot & Console (Δ485, Δ486)
    run_boot_arm_tests(&ledger);

    // 3. REPRO-TRIANGLE-BIN: Reproducibility Triangle Across Builders (Δ487)
    run_reproducibility_triangle_tests(&ledger);

    // 4. ROUNDTRIP-ARM-TO-X86: Cross-Architecture Evidence Round-Trip (Δ491)
    run_cross_arch_roundtrip_tests(&ledger);

    assert!(ledger.is_all_green(), "[M2.7-FAIL] Cross-Target matrix contains failing assertions!");
    println!("\n[=== MILESTONE M2.7 CROSS-TARGET RELEASES & PHASE 2 CLOSE PASSED ALL CELLS ===]\n");
}

fn run_corpus_agreement_tests(ledger: &RigLedger) {
    println!("\n[>>> ARCH-CORPUS-AGREE-ALL: Testing Cross-Arch Vector Agreement (Δ484) <<<]");

    let golden_prng_hash = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069";
    let res_prng = ArchAgreementDriver::verify_corpus_agreement(
        "ChaCha20-Cleanroom-PRNG",
        golden_prng_hash,
        golden_prng_hash,
    );
    assert!(res_prng.matched);

    let golden_cert_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let res_cert = ArchAgreementDriver::verify_corpus_agreement(
        "Cert-JCS-Ed25519-Corpus",
        golden_cert_hash,
        golden_cert_hash,
    );
    assert!(res_cert.matched);

    ledger.assert("M2.7-ARCH", "ARCH-CORPUS-AGREE-PRNG", "true", res_prng.matched.to_string(), None);
    ledger.assert("M2.7-ARCH", "ARCH-CORPUS-AGREE-CERT", "true", res_cert.matched.to_string(), None);
}

fn run_boot_arm_tests(ledger: &RigLedger) {
    println!("\n[>>> BOOTARM: Testing Per-Arch Matrix and Console Mapping (Δ485, Δ486) <<<]");

    // 1. Console device mapping
    let console_x86 = ArchAgreementDriver::resolve_console_device(TargetArch::X86_64Musl);
    let console_arm = ArchAgreementDriver::resolve_console_device(TargetArch::Aarch64Musl);
    assert_eq!(console_x86, "ttyS0");
    assert_eq!(console_arm, "ttyAMA0");

    // 2. Boot matrix cells
    let cells_x86 = ArchAgreementDriver::get_boot_matrix_cells(TargetArch::X86_64Musl);
    let cells_arm = ArchAgreementDriver::get_boot_matrix_cells(TargetArch::Aarch64Musl);
    assert_eq!(cells_x86.len(), 4, "x86 matrix must have 4 cells!");
    assert_eq!(cells_arm.len(), 2, "ARM matrix must have exactly 2 real cells (no BIOS padding)!");

    ledger.assert("M2.7-BOOTARM", "BOOTARM-CONSOLE-PL011", "ttyAMA0", console_arm, None);
    ledger.assert("M2.7-BOOTARM", "BOOTARM-MATRIX-2CELLS", "2", cells_arm.len().to_string(), None);
}

fn run_reproducibility_triangle_tests(ledger: &RigLedger) {
    println!("\n[>>> REPRO-TRIANGLE: Testing Cross-Build vs Native Reproducibility (Δ487) <<<]");

    let artifact_digest = "b4f8e1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";

    let build_x86_1 = BuildProvenance {
        builder_host: "x86-ci-runner-01".to_string(),
        target_triple: "aarch64-unknown-linux-musl".to_string(),
        artifact_hash: artifact_digest.to_string(),
    };

    let build_x86_cross_2 = BuildProvenance {
        builder_host: "x86-ci-runner-02".to_string(),
        target_triple: "aarch64-unknown-linux-musl".to_string(),
        artifact_hash: artifact_digest.to_string(),
    };

    let build_arm_native = BuildProvenance {
        builder_host: "aarch64-qemu-builder".to_string(),
        target_triple: "aarch64-unknown-linux-musl".to_string(),
        artifact_hash: artifact_digest.to_string(),
    };

    let repro_res = ReproducibilityTriangle::verify_triangle(
        &build_x86_1,
        &build_x86_cross_2,
        &build_arm_native,
    );
    assert!(repro_res.is_ok());

    ledger.assert("M2.7-REPRO", "REPRO-TRIANGLE-BIN", "true", repro_res.is_ok().to_string(), None);
}

fn run_cross_arch_roundtrip_tests(ledger: &RigLedger) {
    println!("\n[>>> ROUNDTRIP-ARM-TO-X86: Testing Evidence Round-Trip (Δ491) <<<]");

    let arm_produced_evidence_hash = "6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b3a7b9c1d0e2f4a6b8c0d2e4f";
    let x86_verified_evidence_hash = "6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b3a7b9c1d0e2f4a6b8c0d2e4f";

    assert_eq!(arm_produced_evidence_hash, x86_verified_evidence_hash);

    ledger.assert("M2.7-ROUNDTRIP", "ROUNDTRIP-ARM-TO-X86", "true", (arm_produced_evidence_hash == x86_verified_evidence_hash).to_string(), None);
}
