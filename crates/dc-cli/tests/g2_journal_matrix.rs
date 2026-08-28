use assert_cmd::Command;
use dc_cert::OperatorKeyPair;
use dc_testkit::{
    Janitor, JournalOracle, RigLedger,
};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn test_g2_journal_core_matrix() {
    let ledger = RigLedger::new();
    let temp_dir = tempfile::tempdir().unwrap();

    // 1. J-DRIVER-FLAVORS: Generate & Validate Format-Authentic Flavors (Δ119)
    run_j_driver_flavors(&ledger, temp_dir.path());

    // 2. J-INSPECT-RO: Read-Only Immutability Proof (Δ92)
    run_j_inspect_ro(&ledger, temp_dir.path());

    // 3. J-RAWBYTE & J-PERMUTE: Raw-Byte Hashing & Permutation Tolerance (Δ109)
    run_j_rawbyte_permute(&ledger, temp_dir.path());

    // 4. J-BOUNDS: Zero-Len Record Rejection (Δ114)
    run_j_bounds_rejection(&ledger, temp_dir.path());

    assert!(ledger.is_all_green(), "[G2-FAIL] Journal matrix contains failing assertions!");
    println!("\n[=== G2 JOURNAL CORE MATRIX PASSED ALL CELLS ===]\n");
}

fn run_j_driver_flavors(ledger: &RigLedger, out_dir: &Path) {
    println!("\n[>>> J-DRIVER-FLAVORS: Testing Format-Authentic Flavors (Δ119) <<<]");

    let flavors = ["clean", "failed", "interrupted", "dod3", "sealed"];

    for flavor in &flavors {
        let j_path = out_dir.join(format!("{}.dcj", flavor));

        let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
        cmd.arg("journal").arg("selftest-sequence")
            .arg("--flavor").arg(flavor)
            .arg("--out").arg(&j_path);
        cmd.assert().code(0);

        // Verify with independent testkit oracle
        let oracle_rep = JournalOracle::audit(&j_path, 64 * 1024 * 1024, 2 * 1024 * 1024)
            .expect("JournalOracle must audit driver journal cleanly");
        assert!(oracle_rep.is_valid, "[DRIVER-FAIL] Oracle failed on flavor {}", flavor);

        // Verify with dc journal inspect
        let mut inspect_cmd = Command::cargo_bin("diskcleaner").unwrap();
        inspect_cmd.arg("journal").arg("inspect").arg(&j_path);
        inspect_cmd.assert().code(0);

        ledger.assert("G2-DRIVER", &format!("J-FLAVOR-{}", flavor.to_uppercase()), "true", "true", None);
    }
}

fn run_j_inspect_ro(ledger: &RigLedger, out_dir: &Path) {
    println!("\n[>>> J-INSPECT-RO: Testing Read-Only Immutability of Inspect (Δ92) <<<]");

    let j_path = out_dir.join("clean.dcj");
    let pre_bytes = fs::read(&j_path).unwrap();
    let pre_hash = blake3::hash(&pre_bytes).to_hex().to_string();

    let mut inspect_cmd = Command::cargo_bin("diskcleaner").unwrap();
    inspect_cmd.arg("journal").arg("inspect").arg(&j_path);
    inspect_cmd.assert().code(0);

    let post_bytes = fs::read(&j_path).unwrap();
    let post_hash = blake3::hash(&post_bytes).to_hex().to_string();

    ledger.assert("G2-INSPECT", "J-INSPECT-RO", pre_hash, post_hash, None);
}

fn run_j_rawbyte_permute(ledger: &RigLedger, out_dir: &Path) {
    println!("\n[>>> J-RAWBYTE & J-PERMUTE: Testing Raw-Byte Hashing & Permuted Fields (Δ109) <<<]");

    let permuted_path = out_dir.join("permuted.dcj");

    // Manually create a single-record journal where Header JSON fields are permuted
    let permuted_header_json = r#"{"argv_hash":"selftest","engine":"synthetic","identity":{"dev_path":"/dev/nvme0n1","kernel":{"major":259,"minor":0},"kernel_name":"nvme0n1","logical_block_size":512,"physical_block_size":4096,"stable":{"bus":"Nvme","dm_name":null,"dm_uuid":null,"model":"Test","serial":"SN1","size_bytes":67108864,"wwn":null}},"operator_pubkey":null,"plan":{"fast_path":"PreferWriteZeroes","legacy_note":null,"mechanism":{"type":"logical_overwrite","passes":[{"fast_path":"PreferWriteZeroes","index":0,"pattern":{"name":"Zero","type":"zero"}}]},"target_identity":{"bus":"Nvme","dm_name":null,"dm_uuid":null,"model":"Test","serial":"SN1","size_bytes":67108864,"wwn":null},"window_bytes":2097152},"plan_hash":"0000","sealed":false,"started_utc":"2026-08-28T20:00:00Z","tool":{"build_hash":"00","name":"dc","target":"linux","version":"0.1.0"},"tuning":{"checkpoint_mib":512,"checkpoint_ms":5000,"pool_mib":128,"qd":64,"window_bytes":2097152},"type":"header","uuid":"test-uuid-permuted"}"#;

    let mut j_bytes = b"DCJ1".to_vec();
    let rec_bytes = permuted_header_json.as_bytes();
    let len = rec_bytes.len() as u32;

    let mut hasher = blake3::Hasher::new();
    hasher.update(rec_bytes);
    hasher.update(blake3::hash(b"DCJ1").as_bytes());
    let hash = hasher.finalize();

    j_bytes.extend_from_slice(&len.to_le_bytes());
    j_bytes.extend_from_slice(rec_bytes);
    j_bytes.extend_from_slice(hash.as_bytes());

    fs::write(&permuted_path, &j_bytes).unwrap();

    // Verify dc journal inspect succeeds on permuted field record (Δ109)
    let mut inspect_cmd = Command::cargo_bin("diskcleaner").unwrap();
    inspect_cmd.arg("journal").arg("inspect").arg(&permuted_path);
    inspect_cmd.assert().code(0);

    ledger.assert("G2-RAWBYTE", "J-PERMUTE-FIELDS", "true", "true", None);
}

fn run_j_bounds_rejection(ledger: &RigLedger, out_dir: &Path) {
    println!("\n[>>> J-BOUNDS: Testing Zero-Length Record Rejection (Δ114) <<<]");

    let zero_len_path = out_dir.join("zero_len.dcj");
    let mut j_bytes = b"DCJ1".to_vec();
    j_bytes.extend_from_slice(&0u32.to_le_bytes()); // len = 0
    j_bytes.extend_from_slice(&[0u8; 32]); // dummy hash

    fs::write(&zero_len_path, &j_bytes).unwrap();

    let mut inspect_cmd = Command::cargo_bin("diskcleaner").unwrap();
    inspect_cmd.arg("journal").arg("inspect").arg(&zero_len_path);
    inspect_cmd.assert().code(6);

    ledger.assert("G2-BOUNDS", "J-ZERO-LEN-REJECT", "true", "true", None);
}
