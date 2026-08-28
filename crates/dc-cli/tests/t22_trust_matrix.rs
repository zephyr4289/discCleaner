use dc_testkit::{HsmKeyType, HsmMock, RigLedger, TsaMock};

#[test]
fn test_t22_trust_matrix() {
    let ledger = RigLedger::new();

    // 1. TSA-NONCE-ECHO-REPLAY: Nonce Echo & Replay Defense (Δ428)
    run_tsa_nonce_replay_tests(&ledger);

    // 2. TSA-HISTORICAL-VALIDITY: Chain-At-Token-Time Historical Validity (Δ427)
    run_tsa_historical_validity_tests(&ledger);

    // 3. HSM-ED25519-DETERMINISTIC: Deterministic Ed25519 Hardware Signing (Δ429, Δ431)
    run_hsm_signing_tests(&ledger);

    // 4. HSM-ECDSA-REFUSED: Nondeterministic ECDSA Refusal (Δ429)
    run_hsm_ecdsa_refusal_tests(&ledger);

    assert!(ledger.is_all_green(), "[T22-FAIL] Trust Anchor matrix contains failing assertions!");
    println!("\n[=== PHASE T22 TRUST ANCHOR RIG MATRIX PASSED ALL CELLS ===]\n");
}

fn run_tsa_nonce_replay_tests(ledger: &RigLedger) {
    println!("\n[>>> TSA-NONCE-ECHO-REPLAY: Testing Nonce Echo & Replay Defense (Δ428) <<<]");

    let tsa = TsaMock::new("Sectigo_RFC3161_TSA_2026");
    let doc_hash = "3a7b9c1d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b";
    let nonce_req = "RANDOM_NONCE_9988776655";

    let token = tsa.issue_token(doc_hash, nonce_req, 1724890000, 1);

    // 1. Matching nonce -> Accepted
    let verify_ok = TsaMock::verify_token_offline(&token, doc_hash, nonce_req, 1800000000);
    assert!(verify_ok.is_ok());
    assert!(verify_ok.unwrap().contains("anchored: existed at-or-before"));

    // 2. Mismatched nonce (Replay attack!) -> Refused!
    let verify_replay = TsaMock::verify_token_offline(&token, doc_hash, "DIFFERENT_NONCE_112233", 1800000000);
    assert_eq!(verify_replay, Err("REPLAY_DETECTED_NONCE_MISMATCH"));

    ledger.assert("T22-TSA", "TSA-NONCE-ECHO", "true", verify_ok.is_ok().to_string(), None);
    ledger.assert("T22-TSA", "TSA-REPLAY-REFUSED", "true", (verify_replay == Err("REPLAY_DETECTED_NONCE_MISMATCH")).to_string(), None);
}

fn run_tsa_historical_validity_tests(ledger: &RigLedger) {
    println!("\n[>>> TSA-HISTORICAL-VALIDITY: Testing Chain-At-Token-Time (Δ427) <<<]");

    let tsa = TsaMock::new("GlobalTrust_TSA_Root_2026");
    let doc_hash = "3a7b9c1d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b";
    let nonce = "NONCE_VALIDITY_TEST";

    // Token issued in 2026 (timestamp: 1724890000)
    let token_2026 = tsa.issue_token(doc_hash, nonce, 1724890000, 1);

    // Root expires in 2028 (timestamp: 1800000000). Evaluated in 2035:
    // Because token_2026 was issued before root expiry, it remains VALID forever!
    let verify_historical = TsaMock::verify_token_offline(&token_2026, doc_hash, nonce, 1800000000);
    assert!(verify_historical.is_ok());

    // Token issued in 2029 (timestamp: 1850000000), after root expired in 2028 -> Expired!
    let token_late = tsa.issue_token(doc_hash, nonce, 1850000000, 1);
    let verify_expired = TsaMock::verify_token_offline(&token_late, doc_hash, nonce, 1800000000);
    assert_eq!(verify_expired, Err("ROOT_EXPIRED_PRIOR_TO_TOKEN_ISSUANCE"));

    ledger.assert("T22-HIST", "TSA-HISTORICAL-VALID", "true", verify_historical.is_ok().to_string(), None);
    ledger.assert("T22-HIST", "TSA-HISTORICAL-EXPIRED", "true", (verify_expired == Err("ROOT_EXPIRED_PRIOR_TO_TOKEN_ISSUANCE")).to_string(), None);
}

fn run_hsm_signing_tests(ledger: &RigLedger) {
    println!("\n[>>> HSM-ED25519-DETERMINISTIC: Testing Ed25519 Determinism (Δ429, Δ431) <<<]");

    let hsm = HsmMock::new(HsmKeyType::Ed25519, "123456");
    let doc_bytes = b"CANONICAL_CERTIFICATE_DOCUMENT_JSON_BYTES";

    let sig_1 = hsm.sign_canonical(doc_bytes, "123456").unwrap();
    let sig_2 = hsm.sign_canonical(doc_bytes, "123456").unwrap();

    // Deterministic Ed25519 (RFC 8032) -> identical signatures across sessions!
    assert_eq!(sig_1, sig_2, "Ed25519 hardware signatures must be byte-identical (PROJ-IDENTITY)!");

    // Wrong PIN -> Rejected
    let wrong_pin_res = hsm.sign_canonical(doc_bytes, "999999");
    assert_eq!(wrong_pin_res, Err("PIN_REJECTED"));

    ledger.assert("T22-HSM", "HSM-ED25519-DETERMINISTIC", "true", (sig_1 == sig_2).to_string(), None);
}

fn run_hsm_ecdsa_refusal_tests(ledger: &RigLedger) {
    println!("\n[>>> HSM-ECDSA-REFUSED: Testing Nondeterministic ECDSA Refusal (Δ429) <<<]");

    let hsm_ecdsa = HsmMock::new(HsmKeyType::EcdsaSecp256r1, "123456");
    let doc_bytes = b"CANONICAL_CERTIFICATE_DOCUMENT_JSON_BYTES";

    let res = hsm_ecdsa.sign_canonical(doc_bytes, "123456");
    assert_eq!(res, Err("ECDSA_NONDETERMINISTIC_SIGNATURES_REFUSED"));

    ledger.assert("T22-HSM", "HSM-ECDSA-REFUSED", "true", (res == Err("ECDSA_NONDETERMINISTIC_SIGNATURES_REFUSED")).to_string(), None);
}
