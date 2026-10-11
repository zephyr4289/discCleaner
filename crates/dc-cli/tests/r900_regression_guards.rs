//! REGRESSION GUARD SUITE (r900)
//! =============================
//! Every defect fixed in the security-hardening pull request is pinned here
//! with a `REG-*` identifier. If a future change reintroduces one of these
//! bugs, the corresponding test fails by name — the identifier matches the
//! `REG-*` marker embedded in the fix's source comment.
//!
//! Layer: cross-crate integration over public APIs and the real CLI binary
//! (in-crate fine-grained regressions live beside the code they guard).

use assert_cmd::Command;
use dc_cert::{
    AuthSignatureEntry, AuthorizationSet, KeyringEntry, KeyringRegistry, OperatorKeyPair,
};
use dc_core::{AuditLogger, AuditOutcome, AuditRecord};
use dc_hw::{AtaCodec, NvmeCodec, NvmeSanitizeStatus, ScsiCodec};
use dc_io::{AlignedBuffer, BufferPool, LbaSpan, create_engine};
use dc_testkit::JournalOracle;

// ---------------------------------------------------------------------------
// REG-ENGINE-FAILCLOSED: engines may never substitute /dev/null
// ---------------------------------------------------------------------------

#[test]
fn reg_engine_failclosed_never_dev_null() {
    let tmp = tempfile::tempdir().unwrap();
    let backing = tmp.path().join("backing.raw");
    std::fs::write(&backing, vec![0x55u8; 1024 * 1024]).unwrap();
    let file = std::fs::File::open(&backing).unwrap();

    let engine = create_engine(file, 64 * 1024, false, 4)
        .expect("create_engine on a real file must succeed");
    // The engine must be bound to the caller's file, with sane caps.
    assert!(engine.caps().window_bytes > 0);
    assert!(!engine.caps().engine_name.is_empty());
    // Structural guarantee: the dc-io engine-selection source contains no
    // /dev/null fallback path at all (binary-level string scans are
    // unreliable — the literal can legitimately appear in std machinery).
    let engine_sources: [(&str, &str); 3] = [
        ("lib.rs", include_str!("../../dc-io/src/lib.rs")),
        (
            "sync_engine.rs",
            include_str!("../../dc-io/src/sync_engine.rs"),
        ),
        (
            "uring_engine.rs",
            include_str!("../../dc-io/src/uring_engine.rs"),
        ),
    ];
    for (name, src) in engine_sources {
        // Match the CALL form only — doc comments describing the historical
        // bug legitimately mention the path.
        assert!(
            !src.contains("open(\"/dev/null\""),
            "dc-io/{} must not contain a /dev/null fallback call",
            name
        );
    }
    let _ = engine; // (caps assertions above used it)
}

// ---------------------------------------------------------------------------
// REG-DUALAUTH-FORGERY: BLAKE3-of-public-strings can never authorize again
// ---------------------------------------------------------------------------

#[test]
fn reg_dualauth_forgery_is_rejected() {
    let plan_hash = "a".repeat(64);
    let mut set = AuthorizationSet::new(&plan_hash);
    set.add_signature(AuthSignatureEntry {
        key_fingerprint: blake3::hash(b"OFFICER_A_KEY_HASH").to_hex().to_string(),
        public_key_hex: hex::encode([0u8; 32]),
        signature_hex: blake3::hash(
            format!("APPROVE_PLAN_{}_BY_{}", plan_hash, "OFFICER_A_KEY_HASH").as_bytes(),
        )
        .to_hex()
        .to_string(),
        is_hardware_token: false,
    });
    set.add_signature(AuthSignatureEntry {
        key_fingerprint: blake3::hash(b"OFFICER_B_KEY_HASH").to_hex().to_string(),
        public_key_hex: hex::encode([1u8; 32]),
        signature_hex: blake3::hash(
            format!("APPROVE_PLAN_{}_BY_{}", plan_hash, "OFFICER_B_KEY_HASH").as_bytes(),
        )
        .to_hex()
        .to_string(),
        is_hardware_token: false,
    });
    // Two "signatures" that anyone could compute by hashing strings must be
    // refused under the 2PI gate.
    assert!(set.verify_pre_arm_authorization(&plan_hash, true).is_err());

    // Real Ed25519 countersignatures by two distinct officers pass.
    let a = OperatorKeyPair::generate();
    let b = OperatorKeyPair::generate();
    let mut real = AuthorizationSet::new(&plan_hash);
    real.add_signature(dc_cli::approve::PlanApprover::countersign_plan(
        &plan_hash, &a, false,
    ));
    real.add_signature(dc_cli::approve::PlanApprover::countersign_plan(
        &plan_hash, &b, false,
    ));
    assert!(real.verify_pre_arm_authorization(&plan_hash, true).is_ok());
}

// ---------------------------------------------------------------------------
// REG-SCSI-FMTDATA: FORMAT UNIT must not obligate a parameter list
// ---------------------------------------------------------------------------

#[test]
fn reg_scsi_format_unit_fmtdata_clear() {
    let cdb = ScsiCodec::encode_format_unit(false);
    assert_eq!(
        cdb[1] & 0x10,
        0,
        "FMTDATA must be clear (no parameter list follows)"
    );
    let imm = ScsiCodec::encode_format_unit(true);
    assert_eq!(imm[1] & 0x10, 0, "IMMED variant must also clear FMTDATA");
    assert_eq!(imm[1] & 0x80, 0x80, "IMMED bit set when requested");
}

// ---------------------------------------------------------------------------
// REG-SAT-NONDATA: SECURITY ERASE family must never claim data transfers
// ---------------------------------------------------------------------------

#[test]
fn reg_sat_security_erase_is_non_data_framed() {
    let prep = AtaCodec::encode_sat_security_erase_prepare();
    let unit = AtaCodec::encode_sat_security_erase_unit(false);
    let enhanced = AtaCodec::encode_sat_security_erase_unit(true);
    let freeze = AtaCodec::encode_sat_security_freeze_lock();

    for cdb in [&prep, &unit, &enhanced, &freeze] {
        assert_eq!(
            cdb[2] & 0x0F,
            0,
            "SECURITY ERASE family must be T_LENGTH=0, BYTE_BLOCK=0, T_DIR=0"
        );
    }
    assert_eq!(prep[14], 0xF3);
    assert_eq!(unit[14], 0xF4);
    assert_eq!(
        enhanced[4], 0x01,
        "enhanced erase selected via FEATURES register"
    );
    assert_eq!(freeze[14], 0xF5);
}

// ---------------------------------------------------------------------------
// REG-SANITIZE-ROUNDING: SPROG=0xFFFF is 1000 permille
// ---------------------------------------------------------------------------

#[test]
fn reg_sanitize_rounding_full_scale() {
    let mut log = [0u8; 512];
    log[0..2].copy_from_slice(&65535u16.to_le_bytes());
    log[2..4].copy_from_slice(&1u16.to_le_bytes());
    let status: NvmeSanitizeStatus = NvmeCodec::decode_sanitize_status_log(&log).unwrap();
    assert_eq!(
        status.progress_permille, 1000,
        "0xFFFF/0x10000 must round to 1000, not 999"
    );
}

// ---------------------------------------------------------------------------
// REG-ATA-NUL-PAD: identify strings strip NUL padding too
// ---------------------------------------------------------------------------

#[test]
fn reg_ata_identify_nul_padding_trimmed() {
    let mut raw = vec![0u8; 512];
    // Serial slot bytes are byte-swapped 16-bit words; to decode as
    // "SN\0\0" the raw bytes must be ['N','S', 0, 0] (the codec swaps
    // each pair back).
    raw[20] = b'N';
    raw[21] = b'S';
    raw[22] = 0;
    raw[23] = 0;
    let data = AtaCodec::decode_identify_device(&raw).unwrap();
    assert_eq!(
        data.serial, "SN",
        "NUL-padded serials must decode without NULs"
    );
}

// ---------------------------------------------------------------------------
// REG-LBASPAN-OVERFLOW + REG-BUFFERPOOL-OVERFLOW
// ---------------------------------------------------------------------------

#[test]
fn reg_lbaspan_overflow_safe() {
    let span = LbaSpan::new(u64::MAX, 512, 2 * 1024 * 1024);
    assert_eq!(span.total_windows(), u64::MAX.div_ceil(2 * 1024 * 1024));
    let (off, len) = span.window_byte_range(u64::MAX);
    assert_eq!(off, u64::MAX);
    assert_eq!(len, 0);
}

#[test]
fn reg_bufferpool_overflow_refused() {
    assert!(AlignedBuffer::allocate(usize::MAX - 16, 4096).is_err());
    assert!(
        BufferPool::new(1024, 64 * 1024 * 1024).is_err(),
        "64 GiB pool must exceed the cap"
    );
}

// ---------------------------------------------------------------------------
// REG-ORACLE-CHAIN-SEED + REG-ORACLE-SEALED-HEADER-SIG: the independent
// journal oracle agrees with the production writer.
// ---------------------------------------------------------------------------

#[test]
fn reg_oracle_chain_seed_matches_writer() {
    let tmp = tempfile::tempdir().unwrap();
    let j_path = tmp.path().join("clean.dcj");

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("journal")
        .arg("selftest-sequence")
        .arg("--flavor")
        .arg("clean")
        .arg("--out")
        .arg(&j_path);
    cmd.assert().code(0);

    // With the historical zero-seeded oracle this failed at record 0 for
    // EVERY journal ever written by the tool.
    let report = JournalOracle::audit(&j_path, 64 * 1024 * 1024, 2 * 1024 * 1024)
        .expect("oracle must verify a driver-generated journal");
    assert!(report.record_count > 0);
    assert_eq!(report.discarded_tail_bytes, 0);
}

#[test]
fn reg_oracle_sealed_header_signature_consumed() {
    let tmp = tempfile::tempdir().unwrap();
    let j_path = tmp.path().join("sealed.dcj");

    let key_path = tmp.path().join("officer.key");
    let kp = OperatorKeyPair::generate();
    kp.save_to_file(&key_path).unwrap();

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("journal")
        .arg("selftest-sequence")
        .arg("--flavor")
        .arg("sealed")
        .arg("--out")
        .arg(&j_path)
        .arg("--key")
        .arg(&key_path);
    cmd.assert().code(0);

    // The historical oracle desynchronized on sealed journals (record-0's
    // signature was never consumed before the next length prefix).
    let report = JournalOracle::audit(&j_path, 64 * 1024 * 1024, 2 * 1024 * 1024)
        .expect("sealed journals must parse and verify end-to-end");
    assert!(report.sealed);
}

// ---------------------------------------------------------------------------
// REG-KEYRING-SUPERSEDED: rotation makes at-or-after signatures suspect
// ---------------------------------------------------------------------------

#[test]
fn reg_keyring_superseded_at_t() {
    let mut reg = KeyringRegistry::new();
    reg.register_key(KeyringEntry {
        key_hash: "K1".to_string(),
        identity: "O".to_string(),
        role: "R".to_string(),
        active_from_utc: 100,
        superseded_at_utc: None,
        revoked_at_utc: None,
    });
    reg.rotate_key_bilateral(
        "K1",
        KeyringEntry {
            key_hash: "K2".to_string(),
            identity: "O".to_string(),
            role: "R".to_string(),
            active_from_utc: 200,
            superseded_at_utc: None,
            revoked_at_utc: None,
        },
        200,
    )
    .unwrap();
    assert_eq!(
        reg.evaluate_signature_at_time("K1", 199).unwrap(),
        "VALID_AT_TIME"
    );
    assert_eq!(
        reg.evaluate_signature_at_time("K1", 200).unwrap(),
        "SUSPECT_SUPERSEDED_KEY",
        "signatures at-or-after rotation T are suspect"
    );
}

// ---------------------------------------------------------------------------
// REG-KEYFILE-PERMS: operator keyfiles are 0600-enforced both ways
// ---------------------------------------------------------------------------

#[test]
fn reg_keyfile_permissions_enforced() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("k.key");
    let kp = OperatorKeyPair::generate();
    kp.save_to_file(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
        0
    );

    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&path, perms).unwrap();
    assert!(
        OperatorKeyPair::load_from_file(&path).is_err(),
        "world-readable key material must be refused on load"
    );
}

// ---------------------------------------------------------------------------
// REG-AUDIT-SEED: the first record of a fresh audit log verifies
// ---------------------------------------------------------------------------

#[test]
fn reg_audit_first_record_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("audit.log");
    let mut logger = AuditLogger::open_or_create(&path).unwrap();
    logger
        .log(&AuditRecord {
            timestamp_utc: "2026-01-01T00:00:00Z".to_string(),
            argv_hash: "r".to_string(),
            target_path: None,
            outcome: AuditOutcome::Refusal {
                code: "TEST".to_string(),
                detail: "d".to_string(),
            },
        })
        .unwrap();
    drop(logger);
    let (count, _) = AuditLogger::verify_audit_file(&path).unwrap();
    assert_eq!(count, 1, "writer seed must equal verifier seed");
}

// ---------------------------------------------------------------------------
// REG-RFC8439-NONCE: the cleanroom reference matches the true RFC vector
// ---------------------------------------------------------------------------

#[test]
fn reg_rfc8439_reference_kat() {
    dc_testkit::KnownAnswerTests::verify_rfc8439_block_vector()
        .expect("ChaCha20Ref must reproduce the RFC 8439 §2.3.2 block");
}

// ---------------------------------------------------------------------------
// REG-MMC-LAYERING: production code owns MmcAccessClass
// ---------------------------------------------------------------------------

#[test]
fn reg_mmc_layering_production_owns_vocabulary() {
    // The enum must come from dc-mmc (production), not the test kit.
    let class: dc_mmc::MmcAccessClass = dc_mmc::MmcAccessClass::NativeController;
    assert_ne!(class, dc_mmc::MmcAccessClass::ReaderMediated);
    // dc-mmc must NOT link dc-testkit: check its manifest textually so the
    // inverted dependency can never silently return.
    let manifest = include_str!("../../dc-mmc/Cargo.toml");
    assert!(
        !manifest
            .lines()
            .any(|l| l.trim_start().starts_with("dc-testkit")),
        "dc-mmc must never depend on dc-testkit"
    );
}

// ---------------------------------------------------------------------------
// REG-JOURNAL-HEADER-FIRST: record 0 must be the Header
// ---------------------------------------------------------------------------

#[test]
fn reg_journal_first_record_must_be_header() {
    use dc_core::{JournalReader, JournalRecord};
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("no_header.dcj");
    // Forge a valid chain whose record 0 is an Armed record (not a Header).
    let armed_json = r#"{"type":"armed","overrides":[],"locks_held":[],"at":"t"}"#;
    let rec = armed_json.as_bytes();
    let mut bytes = b"DCJ1".to_vec();
    bytes.extend_from_slice(&(rec.len() as u32).to_le_bytes());
    bytes.extend_from_slice(rec);
    let mut h = blake3::Hasher::new();
    h.update(rec);
    h.update(blake3::hash(b"DCJ1").as_bytes());
    bytes.extend_from_slice(h.finalize().as_bytes());
    std::fs::write(&p, &bytes).unwrap();

    let err = JournalReader::read_and_verify_chain(&p).unwrap_err();
    let msg = format!("{:?}", err);
    assert!(msg.contains("FIRST_RECORD_NOT_HEADER"), "got: {}", msg);
    let _ = JournalRecord::Armed {
        overrides: vec![],
        locks_held: vec![],
        at: String::new(),
    };
}

// ---------------------------------------------------------------------------
// CLI-level regression guards (exit codes are security contracts)
// ---------------------------------------------------------------------------

#[test]
fn reg_check_nonexistent_target_is_guardian_refusal_exit_2() {
    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("check")
        .arg("--target")
        .arg("/nonexistent/device/xyz");
    cmd.assert().code(2);
}

#[test]
fn reg_execute_non_tty_without_confirm_refused_exit_2() {
    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target")
        .arg("/dev/null")
        .arg("--profile")
        .arg("clear-zero");
    // No --serial-confirm, non-TTY stdin: must refuse BEFORE probing.
    cmd.assert().code(2);
}

#[test]
fn reg_dryrun_boundary_exits_before_confirmation_prompt() {
    // The bug: `dc execute --dry-run` used to hang on the interactive token
    // prompt. Now the dry run exits 0 before any prompt, even though stdin
    // is not a TTY and no --serial-confirm is provided.
    let tmp = tempfile::tempdir().unwrap();
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let backing = tmp.path().join("dryrun_backing.raw");
    std::fs::write(&backing, vec![0u8; 8 * 1024 * 1024]).unwrap();

    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("execute")
        .arg("--target")
        .arg(&backing)
        .arg("--profile")
        .arg("clear-zero")
        .arg("--dry-run")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--no-progress")
        .timeout(std::time::Duration::from_secs(30));
    cmd.assert().code(0);

    // No journal may be created by a dry run.
    let journals: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "dcj").unwrap_or(false))
        .collect();
    assert!(journals.is_empty(), "dry runs must never create journals");
}

#[test]
fn reg_seed_for_clear_zero_is_rejected_before_probing_exit_8() {
    let mut cmd = Command::cargo_bin("diskcleaner").unwrap();
    cmd.arg("plan")
        .arg("--target")
        .arg("/definitely/not/a/device")
        .arg("--profile")
        .arg("clear-zero")
        .arg("--seed")
        .arg("0".repeat(64));
    // Usage error (exit 8) must fire BEFORE the (nonexistent) device probe.
    cmd.assert().code(8);
}
