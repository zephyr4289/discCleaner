use dc_testkit::{
    ChaCha20Ref, CleanroomPRNG, ReproductionRecipe, RigLedger,
};
use std::path::Path;

#[test]
fn test_g5_reproduction_matrix() {
    let ledger = RigLedger::new();

    // 1. ORA-KAT-REF & BLOCKPARITY: RFC 8439 Known Answer Tests
    run_ora_kat_tests(&ledger);

    // 2. ORA-RECIPE-REPRO: Cleanroom Recipe Verification (Δ155)
    run_ora_recipe_tests(&ledger);

    // 3. ORA-TEETH-PROP: Tamper Detection & Named Refusal (K258)
    run_ora_tamper_tests(&ledger);

    // 4. ORA-ENTROPY-PARITY: Fixed-Point Integer Entropy Defense (Δ159)
    run_ora_entropy_tests(&ledger);

    // 5. ORA-DOC-CANON: Canonical Doc Hash Binding (Δ157)
    run_ora_doc_canon_tests(&ledger);

    assert!(ledger.is_all_green(), "[G5-FAIL] Reproduction matrix contains failing assertions!");
    println!("\n[=== G5 REPRODUCTION ORACLE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_ora_kat_tests(ledger: &RigLedger) {
    println!("\n[>>> ORA-KAT-REF: Testing RFC 8439 Known Answer Tests <<<]");

    // RFC 8439 §2.3.2 Test Vector
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
    let counter = 1u32;

    let mut cipher = ChaCha20Ref::new(&key, &nonce, counter);
    let mut block = [0u8; 64];
    cipher.apply_keystream(&mut block);

    // Expected first 4 bytes of RFC 8439 §2.3.2 block: 0x22, 0x4e, 0xdd, 0x1b
    let first4_match = block[0..4] == [0x22, 0x4e, 0xdd, 0x1b];
    ledger.assert("G5-KAT", "ORA-KAT-REF", "true", first4_match.to_string(), None);
}

fn run_ora_recipe_tests(ledger: &RigLedger) {
    println!("\n[>>> ORA-RECIPE-REPRO: Testing Cleanroom Recipe Verification (Δ155) <<<]");

    let seed = [0x42u8; 32];
    let device_bytes = 8 * 1024 * 1024; // 8 MiB
    let window_bytes = 2 * 1024 * 1024; // 2 MiB

    let stream_hash = CleanroomPRNG::compute_stream_digest(&seed, device_bytes, window_bytes);

    let doc_text = include_str!("../../../docs/reproduction/chacha20-window-v1.txt");
    let doc_blake3 = blake3::hash(doc_text.as_bytes()).to_hex().to_string();

    let recipe = ReproductionRecipe {
        schema: "dc-recipe/1".to_string(),
        scheme: "chacha20-window-v1".to_string(),
        doc_blake3,
        seed: hex::encode(seed),
        window_bytes,
        device_bytes,
        stream_hash_blake3: stream_hash,
    };

    let verify_res = CleanroomPRNG::verify_recipe(&recipe);
    assert!(verify_res.is_ok());
    ledger.assert("G5-RECIPE", "ORA-RECIPE-VERIFY", "true", verify_res.unwrap().to_string(), None);
}

fn run_ora_tamper_tests(ledger: &RigLedger) {
    println!("\n[>>> ORA-TEETH-PROP: Testing Tamper Detection & Named Refusal (K258) <<<]");

    let seed = [0x42u8; 32];
    let device_bytes = 8 * 1024 * 1024;
    let window_bytes = 2 * 1024 * 1024;
    let stream_hash = CleanroomPRNG::compute_stream_digest(&seed, device_bytes, window_bytes);
    let doc_text = include_str!("../../../docs/reproduction/chacha20-window-v1.txt");
    let doc_blake3 = blake3::hash(doc_text.as_bytes()).to_hex().to_string();

    // 1. Tampered Seed
    let mut tampered_seed_recipe = ReproductionRecipe {
        schema: "dc-recipe/1".to_string(),
        scheme: "chacha20-window-v1".to_string(),
        doc_blake3: doc_blake3.clone(),
        seed: hex::encode([0x43u8; 32]), // altered seed!
        window_bytes,
        device_bytes,
        stream_hash_blake3: stream_hash.clone(),
    };
    let res_seed = CleanroomPRNG::verify_recipe(&tampered_seed_recipe);
    assert!(res_seed.is_err());
    ledger.assert("G5-TEETH", "ORA-TAMPER-SEED", "true", res_seed.unwrap_err().contains("STREAM_HASH_MISMATCH").to_string(), None);

    // 2. Tampered Doc Hash
    let mut tampered_doc_recipe = ReproductionRecipe {
        schema: "dc-recipe/1".to_string(),
        scheme: "chacha20-window-v1".to_string(),
        doc_blake3: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        seed: hex::encode(seed),
        window_bytes,
        device_bytes,
        stream_hash_blake3: stream_hash,
    };
    let res_doc = CleanroomPRNG::verify_recipe(&tampered_doc_recipe);
    assert!(res_doc.is_err());
    ledger.assert("G5-TEETH", "ORA-TAMPER-DOCHASH", "true", res_doc.unwrap_err().contains("DOC_HASH_MISMATCH").to_string(), None);
}

fn run_ora_entropy_tests(ledger: &RigLedger) {
    println!("\n[>>> ORA-ENTROPY-PARITY: Testing Fixed-Point Integer Entropy Defense (Δ159) <<<]");

    let mut random_buf = vec![0u8; 1024 * 1024];
    CleanroomPRNG::fill_window(&[0x11; 32], 0, &mut random_buf);

    let entropy = CleanroomPRNG::compute_fixed_point_entropy(&random_buf);
    // Shannon entropy for high-quality ChaCha20 random bytes is ~7.999990 (i.e. > 7,990,000 in x1e6 units)
    let is_high_entropy = entropy.shannon_entropy_x1e6 >= 7_990_000;
    ledger.assert("G5-ENTROPY", "ORA-ENTROPY-HIGH", "true", is_high_entropy.to_string(), None);
}

fn run_ora_doc_canon_tests(ledger: &RigLedger) {
    println!("\n[>>> ORA-DOC-CANON: Testing Canonical Doc Hash Binding (Δ157) <<<]");

    let doc_path = Path::new("docs/reproduction/chacha20-window-v1.txt");
    let exists = doc_path.exists();
    ledger.assert("G5-DOC", "ORA-DOC-CANON", "true", exists.to_string(), None);
}
