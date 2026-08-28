use dc_report::{BatchVerifier, ReportModel};
use dc_testkit::RigLedger;

#[test]
fn test_m2_6_report_matrix() {
    let ledger = RigLedger::new();

    // 1. PDF-DETERMINISM: Deterministic Archival PDF/A Output (Δ472)
    run_pdf_determinism_tests(&ledger);

    // 2. TITLE-DERIVED: Outcome-Driven Document Title (Δ474)
    run_title_derivation_tests(&ledger);

    // 3. EXTRACT-IDENTITY: Embedded Attachment Byte Extraction (Δ473)
    run_embedded_extraction_tests(&ledger);

    // 4. BATCH-FULLSWEEP: Exhaustive Sweep Without Short-Circuit (Δ477)
    run_batch_sweep_tests(&ledger);

    assert!(ledger.is_all_green(), "[M2.6-FAIL] Archival Report matrix contains failing assertions!");
    println!("\n[=== MILESTONE M2.6 ARCHIVAL REPORT & BATCH VERIFICATION MATRIX PASSED ALL CELLS ===]\n");
}

fn run_pdf_determinism_tests(ledger: &RigLedger) {
    println!("\n[>>> PDF-DETERMINISM: Testing Byte-Identical PDF/A Output (Δ472) <<<]");

    let model = ReportModel {
        target_serial: "S6PBNJ0W123456".to_string(),
        mechanism_name: "NvmeFormatCryptoErase".to_string(),
        outcome_clean: true,
        evidence_timestamp_utc: 1724890000,
        embedded_cert_json: "{\"cert_schema\":\"dc-cert/2\",\"status\":\"CLEAN\"}".to_string(),
    };

    let doc_1 = model.generate_pdfa();
    let bytes_1 = doc_1.render_pdf_bytes();

    let doc_2 = model.generate_pdfa();
    let bytes_2 = doc_2.render_pdf_bytes();

    assert_eq!(bytes_1, bytes_2, "PDF/A generation must be 100% deterministic (no clock leaks)!");

    ledger.assert("M2.6-PDF", "PDF-DETERMINISM", "true", (bytes_1 == bytes_2).to_string(), None);
}

fn run_title_derivation_tests(ledger: &RigLedger) {
    println!("\n[>>> TITLE-DERIVED: Testing Outcome-Driven Title (Δ474) <<<]");

    // 1. Clean outcome -> "Certificate of Sanitization"
    let model_clean = ReportModel {
        target_serial: "S6PBNJ0W123456".to_string(),
        mechanism_name: "NvmeFormatCryptoErase".to_string(),
        outcome_clean: true,
        evidence_timestamp_utc: 1724890000,
        embedded_cert_json: "{}".to_string(),
    };
    let title_clean = model_clean.derive_title();
    assert_eq!(title_clean, "Certificate of Sanitization");

    // 2. Failed outcome -> "Sanitization Report — VERIFICATION FAILED"
    let model_failed = ReportModel {
        target_serial: "S6PBNJ0W123456".to_string(),
        mechanism_name: "NvmeFormatCryptoErase".to_string(),
        outcome_clean: false,
        evidence_timestamp_utc: 1724890000,
        embedded_cert_json: "{}".to_string(),
    };
    let title_failed = model_failed.derive_title();
    assert_eq!(title_failed, "Sanitization Report — VERIFICATION FAILED");

    ledger.assert("M2.6-TITLE", "TITLE-DERIVED-CLEAN", "Certificate of Sanitization", title_clean, None);
    ledger.assert("M2.6-TITLE", "TITLE-DERIVED-FAILED", "Sanitization Report — VERIFICATION FAILED", title_failed, None);
}

fn run_embedded_extraction_tests(ledger: &RigLedger) {
    println!("\n[>>> EXTRACT-IDENTITY: Testing Embedded Evidence Extraction (Δ473) <<<]");

    let cert_content = "{\"schema\":\"dc-cert/2\",\"serial\":\"S6PBNJ0W123456\",\"status\":\"CLEAN\"}";
    let model = ReportModel {
        target_serial: "S6PBNJ0W123456".to_string(),
        mechanism_name: "BlockErase".to_string(),
        outcome_clean: true,
        evidence_timestamp_utc: 1724890000,
        embedded_cert_json: cert_content.to_string(),
    };

    let doc = model.generate_pdfa();
    let extracted_bytes = doc.extract_attachment("certificate.json").unwrap();
    let extracted_str = std::str::from_utf8(extracted_bytes).unwrap();

    assert_eq!(extracted_str, cert_content, "Extracted attachment must match original JSON byte-for-byte!");

    ledger.assert("M2.6-EXTRACT", "EXTRACT-IDENTITY", "true", (extracted_str == cert_content).to_string(), None);
}

fn run_batch_sweep_tests(ledger: &RigLedger) {
    println!("\n[>>> BATCH-FULLSWEEP: Testing Exhaustive Sweep (Δ477) <<<]");

    let artifacts = vec![
        ("/certs/slot0_failed.cert.json", false), // First artifact FAILS
        ("/certs/slot1_clean.cert.json", true),
        ("/certs/slot2_clean.cert.json", true),
    ];

    let result = BatchVerifier::verify_directory(&artifacts);

    // Assert ALL 3 artifacts were examined (no short-circuiting!)
    assert_eq!(result.total_examined, 3);
    assert_eq!(result.failed_count, 1);
    assert_eq!(result.passed_count, 2);
    assert_eq!(result.aggregate_exit_code(), 1); // Mixed batch exits loud with code 1

    ledger.assert("M2.6-BATCH", "BATCH-FULLSWEEP-NO-SHORTCIRCUIT", "3", result.total_examined.to_string(), None);
}
