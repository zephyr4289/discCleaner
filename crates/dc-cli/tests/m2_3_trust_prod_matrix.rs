use dc_cert::{KeyStoreRegistry, PackageArtifact, SigningKeySourceKind};
use dc_cli::evidence::EvidenceVerbs;
use dc_testkit::RigLedger;

#[test]
fn test_m2_3_trust_prod_matrix() {
    let ledger = RigLedger::new();

    // 1. SITES-REGISTRY-DERIVED: Derived Signature Method Disclosure (Δ436)
    run_derived_signature_method_tests(&ledger);

    // 2. BUNDLE-THREE-VERDICTS: 3-Verdict Trust Bundle Taxonomy (Δ439)
    run_three_verdict_tests(&ledger);

    // 3. PKG-VERIFY-RECONCILE: Package Completeness & Orphan Refusal (Δ440)
    run_package_reconciliation_tests(&ledger);

    assert!(ledger.is_all_green(), "[M2.3-FAIL] Trust in Production matrix contains failing assertions!");
    println!("\n[=== MILESTONE M2.3 TRUST PRODUCTION MATRIX PASSED ALL CELLS ===]\n");
}

fn run_derived_signature_method_tests(ledger: &RigLedger) {
    println!("\n[>>> SITES-REGISTRY-DERIVED: Testing Derived Signature Method (Δ436) <<<]");

    let keyfile_src = SigningKeySourceKind::KeyFile { path: "/tmp/operator.key".to_string() };
    let method_keyfile = KeyStoreRegistry::derive_signature_method(&keyfile_src);
    assert_eq!(method_keyfile, "ed25519-keyfile");

    let hsm_src = SigningKeySourceKind::Hsm {
        interface: "piv".to_string(),
        touch_required: true,
    };
    let method_hsm = KeyStoreRegistry::derive_signature_method(&hsm_src);
    assert_eq!(method_hsm, "ed25519-hsm-piv-touch:true");

    ledger.assert("M2.3-SITES", "SITES-DERIVED-KEYFILE", "ed25519-keyfile", method_keyfile, None);
    ledger.assert("M2.3-SITES", "SITES-DERIVED-HSM", "ed25519-hsm-piv-touch:true", method_hsm, None);
}

fn run_three_verdict_tests(ledger: &RigLedger) {
    println!("\n[>>> BUNDLE-THREE-VERDICTS: Testing 3-Outcome Taxonomy (Δ439) <<<]");

    let v_valid = EvidenceVerbs::evaluate_tsa_verdict(true, true);
    let v_invalid = EvidenceVerbs::evaluate_tsa_verdict(true, false);
    let v_unknown = EvidenceVerbs::evaluate_tsa_verdict(false, true);

    assert_eq!(v_valid, "VALID");
    assert_eq!(v_invalid, "INVALID");
    assert_eq!(v_unknown, "UNKNOWN_AUTHORITY");

    ledger.assert("M2.3-BUNDLE", "BUNDLE-VALID", "VALID", v_valid.to_string(), None);
    ledger.assert("M2.3-BUNDLE", "BUNDLE-INVALID", "INVALID", v_invalid.to_string(), None);
    ledger.assert("M2.3-BUNDLE", "BUNDLE-UNKNOWN", "UNKNOWN_AUTHORITY", v_unknown.to_string(), None);
}

fn run_package_reconciliation_tests(ledger: &RigLedger) {
    println!("\n[>>> PKG-VERIFY-RECONCILE: Testing Package Completeness (Δ440) <<<]");

    // 1. Complete package with cross-references
    let artifacts_complete = vec![
        PackageArtifact {
            role: "journal".to_string(),
            rel_path: "journals/slot0.dcj".to_string(),
            blake3_hash: "hash_journal_123".to_string(),
            references: vec![],
        },
        PackageArtifact {
            role: "cert".to_string(),
            rel_path: "certs/slot0.cert.json".to_string(),
            blake3_hash: "hash_cert_123".to_string(),
            references: vec!["journals/slot0.dcj".to_string()], // Cert points to its journal!
        },
    ];

    let pkg_ok = EvidenceVerbs::package_evidence(
        "PKG_BATCH_001",
        artifacts_complete,
        "ed25519-keyfile",
        "sig_hex_12345",
        1724890000,
    );
    assert!(pkg_ok.is_ok());

    // 2. Incomplete package with orphan reference
    let artifacts_orphan = vec![
        PackageArtifact {
            role: "cert".to_string(),
            rel_path: "certs/slot0.cert.json".to_string(),
            blake3_hash: "hash_cert_123".to_string(),
            references: vec!["journals/MISSING_JOURNAL.dcj".to_string()], // Missing journal!
        },
    ];

    let pkg_orphan = EvidenceVerbs::package_evidence(
        "PKG_BATCH_ORPHAN",
        artifacts_orphan,
        "ed25519-keyfile",
        "sig_hex_12345",
        1724890000,
    );
    assert_eq!(pkg_orphan, Err("ORPHAN_REFERENCE_IN_PACKAGE"));

    ledger.assert("M2.3-PKG", "PKG-COMPLETE-OK", "true", pkg_ok.is_ok().to_string(), None);
    ledger.assert("M2.3-PKG", "PKG-ORPHAN-REFUSED", "true", (pkg_orphan == Err("ORPHAN_REFERENCE_IN_PACKAGE")).to_string(), None);
}
