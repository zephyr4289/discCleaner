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
        hardware_attestation: None,
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
        hardware_attestation: None,
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
    // Enhanced erase is selected via the FEATURES register bit 1
    // (ATA8-ACS §7.43: bit 0 = Master Password Capability, bit 1 =
    // Enhanced Security Erase). v0.6.0 CORRECTION (REG-ATA-PURGE-SGIO-
    // FRAMING): the pre-0.6.0 codec selected enhanced with bit 0, which
    // names the master-password authority and silently leaves the erase
    // NORMAL — on classified media that downgrade is a certification of
    // an erase that did not happen as ordered.
    assert_eq!(unit[4], 0x00);
    assert_eq!(enhanced[4], 0x02, "enhanced = FEATURES bit 1 (0x02)");
    assert_eq!(freeze[14], 0xF5);
}

// ---------------------------------------------------------------------------
// REG-DEFENSE-SAMPLING-REFUSED: defense profiles never accept sampled or
// disabled verification (v0.6.0 enforcement gate).
// ---------------------------------------------------------------------------

#[test]
fn reg_defense_sampling_refused_exit_8_before_arming() {
    use dc_cli::profiles::{enforce_verification_policy, parse_verify_flag};
    use dc_core::SanitizationProfile;

    // Library gate: every defense profile refuses sampling and none.
    for defense in [
        SanitizationProfile::Dod5220_22M,
        SanitizationProfile::Dod5220_22MEce,
        SanitizationProfile::CertinGoi,
        SanitizationProfile::CsecItsg06,
        SanitizationProfile::BsiVsitr,
    ] {
        for spec in ["sample:4", "sample:64", "none"] {
            let level = parse_verify_flag(spec).unwrap();
            assert!(
                enforce_verification_policy(&defense, &level).is_err(),
                "{:?} must refuse --verify {}",
                defense,
                spec
            );
        }
        assert!(enforce_verification_policy(&defense, &dc_core::VerifyLevel::Full).is_ok());
    }

    // CLI gate: usage error (exit code 8) fires BEFORE the target is
    // probed — the target path is nonexistent on purpose; if the gate
    // leaked past argument validation the exit code would be 2
    // (Guardian probe refusal), not 8.
    for profile in ["dod5220-22m", "certin-goi", "bsi-vsitr"] {
        Command::cargo_bin("diskcleaner")
            .unwrap()
            .arg("execute")
            .arg("--target")
            .arg("/dev/nonexistent-zz")
            .arg("--profile")
            .arg(profile)
            .arg("--verify")
            .arg("sample:4")
            .arg("--dry-run")
            .assert()
            .code(8);
        Command::cargo_bin("diskcleaner")
            .unwrap()
            .arg("execute")
            .arg("--target")
            .arg("/dev/nonexistent-zz")
            .arg("--profile")
            .arg(profile)
            .arg("--verify")
            .arg("none")
            .arg("--dry-run")
            .assert()
            .code(8);
        // The plan verb compiles the same gate: a defense plan may never
        // carry sampled verification.
        Command::cargo_bin("diskcleaner")
            .unwrap()
            .arg("plan")
            .arg("--target")
            .arg("/dev/nonexistent-zz")
            .arg("--profile")
            .arg(profile)
            .arg("--verify")
            .arg("sample:8")
            .assert()
            .code(8);
    }

    // Commercial profiles pass the gate and proceed to the (failing)
    // probe — exit 2, NOT 8: proof the gate did not over-trigger.
    Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("execute")
        .arg("--target")
        .arg("/dev/nonexistent-zz")
        .arg("--profile")
        .arg("nist-clear")
        .arg("--verify")
        .arg("sample:4")
        .arg("--dry-run")
        .assert()
        .code(2);
}

// ---------------------------------------------------------------------------
// REG-PDFA3-COMPLIANT-STRUCTURE: the archival certificate is a real ISO
// 19005-3 document, not the pre-0.6.0 plaintext mock.
// ---------------------------------------------------------------------------

#[test]
fn reg_pdfa3_compliant_structure() {
    let cert_json = br#"{"schema":"diskcleaner-cert/1","signature":{"alg":"Ed25519"}}"#;
    let journal = b"DCJ1-hash-chained-journal-bytes";
    let pdf = dc_report::render_sanitization_archive(
        "Certificate of Sanitization",
        "Hardware Purge — ATA Sanitize Crypto Scramble — SN-TEST",
        "Purge",
        true,
        &[(
            "Executed mechanism".to_string(),
            "AtaSanitizeCryptoScramble".to_string(),
        )],
        &[],
        "2026-10-12T07:33:00Z",
        &[
            dc_report::ArchiveAttachment {
                filename: "certificate.json",
                bytes: cert_json,
                mime: "application/json",
                relationship: "Source",
            },
            dc_report::ArchiveAttachment {
                filename: "journal.dcj",
                bytes: journal,
                mime: "application/octet-stream",
                relationship: "Supplement",
            },
        ],
    );

    // Structural conformance markers a validator checks first.
    let s = String::from_utf8_lossy(&pdf);
    for marker in [
        "%PDF-1.7",
        "xref",
        "/Type /Catalog",
        "/OutputIntents",
        "/GTS_PDFA1",
        "/EmbeddedFiles",
        "/Type /Filespec",
        "/AFRelationship",
        "/Subtype /Type0",
        "/CIDToGIDMap /Identity",
        "pdfaid:part>3<",
        "pdfaid:conformance>B<",
        "startxref",
        "%%EOF",
    ] {
        assert!(s.contains(marker), "PDF/A-3 structure missing {}", marker);
    }

    // The signed certificate and the journal are embedded VERBATIM:
    // an auditor carves them out with a hex viewer and verifies the
    // Ed25519 signature / hash chain as-is.
    assert!(pdf.windows(cert_json.len()).any(|w| w == cert_json));
    assert!(pdf.windows(journal.len()).any(|w| w == journal));

    // XMP <-> Info consistency: the creation date matches in both forms.
    assert!(s.contains("D:20261012073300Z"));
    assert!(s.contains("2026-10-12T07:33:00Z"));

    // Deterministic rendering: no clock leaks into the artifact.
    let pdf2 = dc_report::render_sanitization_archive(
        "Certificate of Sanitization",
        "Hardware Purge — ATA Sanitize Crypto Scramble — SN-TEST",
        "Purge",
        true,
        &[(
            "Executed mechanism".to_string(),
            "AtaSanitizeCryptoScramble".to_string(),
        )],
        &[],
        "2026-10-12T07:33:00Z",
        &[
            dc_report::ArchiveAttachment {
                filename: "certificate.json",
                bytes: cert_json,
                mime: "application/json",
                relationship: "Source",
            },
            dc_report::ArchiveAttachment {
                filename: "journal.dcj",
                bytes: journal,
                mime: "application/octet-stream",
                relationship: "Supplement",
            },
        ],
    );
    assert_eq!(
        pdf, pdf2,
        "identical inputs must produce byte-identical archives"
    );
}

// ---------------------------------------------------------------------------
// REG-ATA-PURGE-SGIO-FRAMING: the SAT CDBs of the ATA purge ladder are
// opcode/feature/framing-correct (and the password payload rides along).
// ---------------------------------------------------------------------------

#[test]
fn reg_ata_purge_sgio_framing() {
    use dc_hw::AtaSanitizeFeature;

    // SANITIZE DEVICE (0xB4): FEATURES selects the operation, non-data.
    let crypto = AtaCodec::encode_sat_sanitize_device(AtaSanitizeFeature::CryptoScramble);
    let block = AtaCodec::encode_sat_sanitize_device(AtaSanitizeFeature::BlockErase);
    assert_eq!(crypto[0], 0x85, "ATA PASS-THROUGH (16)");
    assert_eq!(crypto[14], 0xB4);
    assert_eq!(crypto[4], 0x20, "Crypto Scramble = FEATURES 0x20");
    assert_eq!(block[4], 0x10, "Block Erase = FEATURES 0x10");
    assert_eq!((crypto[1] >> 1) & 0x0F, 3, "non-data protocol 3");

    // SECURITY ERASE UNIT carries its 512-byte password payload as PIO
    // Data-Out with the enhanced bit in FEATURES bit 1 — the v0.6.0 fix.
    let password = [0x5Au8; 32];
    let (cdb, payload) = AtaCodec::encode_sat_security_erase_unit_auth(false, true, &password);
    assert_eq!(cdb[14], 0xF4);
    assert_eq!(cdb[4], 0x02);
    assert_eq!((cdb[1] >> 1) & 0x0F, 5, "PIO Data-Out protocol");
    assert_eq!(cdb[2] & 0x0F, 0b0110, "data-out transfer framing");
    assert_eq!(payload.len(), 512);
    assert_eq!(&payload[2..34], &password, "password at bytes 2..34");

    // Sanitize Status log read: SMART READ LOG with log address 0x30.
    let status_cdb = AtaCodec::encode_sat_smart_read_log(0x30);
    assert_eq!(status_cdb[14], 0xB0);
    assert_eq!(status_cdb[4], 0xD5, "SMART READ LOG feature");
    assert_eq!(status_cdb[8], 0x30, "log address 0x30 in LBA low");
    assert_eq!(status_cdb[10], 0xC2, "SMART signature in LBA mid");

    // Sanitize Status decode: SSTAT/SPROG semantics.
    let mut log = vec![0u8; 512];
    log[4..6].copy_from_slice(&0x8000u16.to_le_bytes()); // 50%
    log[10..12].copy_from_slice(&0x0001u16.to_le_bytes()); // in progress
    let st = dc_hw::AtaSanitizeStatus::decode_log(&log).unwrap();
    assert!(st.is_in_progress && !st.is_completed);
    assert_eq!(st.progress_permille, 500, "0x8000/0x10000 = 50%");

    // READ NATIVE MAX ADDRESS EXT returns via the 0x09 ATA return
    // descriptor in sense data (CK_COND framing bit set).
    let rnmx = AtaCodec::encode_sat_read_native_max_ext();
    assert_eq!(rnmx[14], 0x27);
    assert_ne!(rnmx[2] & 0x20, 0, "CK_COND=1 required");
}

// ---------------------------------------------------------------------------
// REG-SCSI-SANITIZE-CDB: SANITIZE (0x48) encoding + sense-progress polling
// semantics of the SCSI ladder.
// ---------------------------------------------------------------------------

#[test]
fn reg_scsi_sanitize_cdb_and_sense_progress() {
    use dc_hw::{ScsiCodec, ScsiSanitizeServiceAction};

    // CDB framing: opcode 0x48, service action + IMMED in byte 1.
    let crypto = ScsiCodec::encode_sanitize(ScsiSanitizeServiceAction::CryptoErase, true);
    assert_eq!(crypto[0], 0x48);
    assert_eq!(crypto[1] & 0x1F, 0x03, "Crypto Erase service action");
    assert_eq!(crypto[1] & 0x80, 0x80, "IMMED=1 (non-blocking law, Δ288)");
    let block = ScsiCodec::encode_sanitize(ScsiSanitizeServiceAction::BlockErase, true);
    assert_eq!(block[1] & 0x1F, 0x02);
    // FORMAT UNIT: FMTDATA=0 (no parameter-list obligation).
    let fmt = ScsiCodec::encode_format_unit(false);
    assert_eq!(fmt[0], 0x04);
    assert_eq!(fmt[1] & 0x10, 0, "FMTDATA clear");

    // Sense decoding: in-progress (0x02/0x04) with SKS progress, and the
    // UA 0x29/0x00 completion signature.
    let mut sense = vec![0u8; 18];
    sense[0] = 0x70;
    sense[2] = 0x02; // NOT READY
    sense[12] = 0x04; // LOGICAL UNIT NOT READY
    sense[13] = 0x0B; // SANITIZE IN PROGRESS
    sense[15] = 0x80; // SKS valid
    let raw: u16 = 0x8000; // 50% of the 0x10000 progress scale
    sense[16] = (raw >> 8) as u8;
    sense[17] = raw as u8;
    let decoded = ScsiCodec::decode_sense_data(&sense).unwrap();
    assert_eq!(
        (decoded.sense_key, decoded.asc, decoded.ascq),
        (0x02, 0x04, 0x0B)
    );
    assert_eq!(decoded.progress_permille, Some(500));

    let mut ua = vec![0u8; 18];
    ua[0] = 0x70;
    ua[2] = 0x06; // UNIT ATTENTION
    ua[12] = 0x29; // POWER ON OR RESET OCCURRED
    let decoded_ua = ScsiCodec::decode_sense_data(&ua).unwrap();
    assert_eq!((decoded_ua.sense_key, decoded_ua.asc), (0x06, 0x29));
}

// ---------------------------------------------------------------------------
// REG-SMART-GLIST-DISCLOSURE: nonzero reallocated sectors force the
// destruction disclosure on logical overwrites, and the advisory rides
// inside the signed certificate payload.
// ---------------------------------------------------------------------------

#[test]
fn reg_smart_glist_disclosure() {
    use dc_cert::{ExecutionDetails, OperatorKeyPair, SanitizationCertificate};
    use dc_core::{Mechanism, SanitizationPlan, VerifyLevel};

    // Codec half: SMART attribute 0x05 raw value decodes as the count.
    let mut smart = vec![0u8; 512];
    smart[2] = 0x05;
    smart[7..13].copy_from_slice(&2048u64.to_le_bytes()[..6]);
    assert_eq!(
        AtaCodec::decode_smart_reallocated_sectors(&smart).unwrap(),
        2048
    );
    // SCSI grown-defect header: 16-byte list = 2 descriptors.
    assert_eq!(
        ScsiCodec::decode_defect_list_count(&[0x00, 0x00, 0x00, 16]).unwrap(),
        2
    );

    // Certificate half: the advisory must be signed (stripping it breaks
    // the signature) and rendered in the summary.
    let kp = OperatorKeyPair::generate();
    let plan = SanitizationPlan {
        plan_schema: "dc-plan/1".to_string(),
        target: dc_core::StableIdentity {
            model: Some("GList".into()),
            serial: Some("SN-GL".into()),
            wwn: None,
            size_bytes: 1_000_000,
            bus: dc_core::BusType::Sata,
            dm_name: None,
            dm_uuid: None,
        },
        mechanism: Mechanism::LogicalOverwrite { passes: vec![] },
        verification: VerifyLevel::Full,
        window_bytes: SanitizationPlan::DEFAULT_WINDOW_BYTES,
        fast_path: dc_core::FastPathPolicy::ForbidWriteZeroes,
        strategy_ladder: None,
        legacy_note: None,
    };
    let device = dc_core::DeviceIdentity {
        stable: dc_core::StableIdentity {
            model: Some("GList".into()),
            serial: Some("SN-GL".into()),
            wwn: None,
            size_bytes: 1_000_000,
            bus: dc_core::BusType::Sata,
            dm_name: None,
            dm_uuid: None,
        },
        kernel: dc_core::KernelIdentity { major: 8, minor: 0 },
        kernel_name: "sda".into(),
        dev_path: "/dev/sda".into(),
        logical_block_size: 512,
        physical_block_size: 4096,
    };
    let mut cert = SanitizationCertificate::new(
        plan.clone(),
        "a".repeat(64),
        device,
        ExecutionDetails {
            started_utc: "2026-10-12T07:00:00Z".into(),
            finished_utc: "2026-10-12T07:01:00Z".into(),
            duration_mono_ms: 60_000,
            interruptions: vec![],
            failures: vec![],
            passes: vec![],
        },
        dc_verify::StreamVerifier::new(
            VerifyLevel::Full,
            SanitizationPlan::DEFAULT_WINDOW_BYTES,
            512,
            false,
            false,
        )
        .finalize(),
        dc_core::JournalChainSummary {
            path: std::path::PathBuf::from("/tmp/gl.dcj"),
            chain_head: "head".into(),
            record_count: 1,
            discarded_tail_bytes: 0,
            uuid: "dcj-gl".into(),
            sealed: false,
        },
        kp.public_key_hex(),
        kp.key_fingerprint_blake3(),
    )
    .with_defense_warnings(vec![
        "Media contains 2048 reallocated sector(s) inaccessible to logical writes. \
         Physical destruction recommended per NIST SP 800-88 Rev 1"
            .to_string(),
    ]);
    cert.sign(&kp).unwrap();
    assert!(
        cert.verify_signature().unwrap(),
        "advisory-inclusive cert verifies"
    );
    let rendered = cert.render_summary();
    assert!(
        rendered.contains("DEFENSE_WARNING"),
        "summary must disclose"
    );
    assert!(rendered.contains("Physical destruction recommended"));

    // Stripping the advisory breaks the signature: the disclosure is
    // evidence-grade, not cosmetic.
    let mut stripped = cert.clone();
    stripped.defense_warnings = None;
    assert!(
        !stripped.verify_signature().unwrap(),
        "stripping the advisory must invalidate the signature"
    );

    // Old (pre-0.6.0) certificates without the field stay loadable and
    // verifiable (backward compatibility).
    let json = serde_json::to_string(&cert).unwrap();
    assert!(json.contains("defense_warnings"));
    let back: SanitizationCertificate = serde_json::from_str(&json).unwrap();
    assert!(back.verify_signature().unwrap_or(false));
}

// ---------------------------------------------------------------------------
// REG-PURGE-UNIVERSAL-DISPATCH: `dc purge` is bus-dispatched (NVMe admin,
// SATA SAT, SAS SG_IO); unsupported buses are refused fail-closed.
// (Replaces the pre-0.6.0 REG-PURGE-NVME-ONLY invariant.)
// ---------------------------------------------------------------------------

#[test]
fn reg_purge_universal_dispatch() {
    // Missing NVMe target: Guardian probe refusal (exit 2), before any
    // prompt — unchanged since v0.5.0.
    Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("purge")
        .arg("--target")
        .arg("/dev/nvme999n1")
        .arg("--dry-run")
        .assert()
        .code(2);

    // Bus/mechanism compatibility is a usage-class refusal: every
    // mechanism is checked against its bus's menu (library-level because
    // a nonexistent target cannot reach the post-probe validation).
    use dc_cli::purge::RequestedMechanism;
    use dc_core::BusType;
    assert!(
        RequestedMechanism::FormatUnit
            .validate_for_bus(BusType::Nvme)
            .is_err(),
        "format-unit is SCSI-only"
    );
    assert!(
        RequestedMechanism::SecurityEraseEnhanced
            .validate_for_bus(BusType::Nvme)
            .is_err(),
        "security-erase is ATA-only"
    );
    assert!(
        RequestedMechanism::FormatCrypto
            .validate_for_bus(BusType::Sata)
            .is_err(),
        "format-crypto is NVMe-only"
    );
    assert!(
        RequestedMechanism::SanitizeCrypto
            .validate_for_bus(BusType::Nvme)
            .is_ok()
    );
    assert!(
        RequestedMechanism::SanitizeCrypto
            .validate_for_bus(BusType::Sata)
            .is_ok()
    );
    assert!(
        RequestedMechanism::SanitizeCrypto
            .validate_for_bus(BusType::Sas)
            .is_ok()
    );
    assert!(
        RequestedMechanism::SecurityEraseNormal
            .validate_for_bus(BusType::Sata)
            .is_ok()
    );
    // Transport-less buses (loop, virtio) are owned by the dispatch's
    // fail-closed PURGE_TRANSPORT_UNSUPPORTED Guardian refusal (exit 2,
    // pinned end-to-end by t14 F6), not by the mechanism menu.
    assert!(
        RequestedMechanism::Auto
            .validate_for_bus(BusType::Loop)
            .is_ok()
    );
    assert!(
        RequestedMechanism::Auto
            .validate_for_bus(BusType::Virtio)
            .is_ok()
    );

    // Unknown mechanism names are usage errors listing the menu.
    let bad = Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("purge")
        .arg("--target")
        .arg("/dev/nvme999n1")
        .arg("--mechanism")
        .arg("bleach")
        .arg("--dry-run")
        .assert()
        .failure();
    let output = String::from_utf8_lossy(&bad.get_output().stderr).to_string();
    assert!(
        output.contains("security-erase-enhanced") && output.contains("format-unit"),
        "usage error must list the full mechanism menu: {}",
        output
    );
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

// ===========================================================================
// PR2 guards: fleet parallelism, standards matrix, sampled verification, purge
// ===========================================================================

// ---------------------------------------------------------------------------
// REG-PROFILE-MATRIX: the catalog is complete, counts are exact, and the
// CLI renders it (procurement documentation).
// ---------------------------------------------------------------------------

#[test]
fn reg_profile_matrix_catalog_is_complete_and_exact() {
    use dc_core::SanitizationProfile;

    let expect: &[(SanitizationProfile, usize, &str)] = &[
        (SanitizationProfile::NistClear, 1, "nist-clear"),
        (SanitizationProfile::NistClearRandom, 1, "nist-clear-random"),
        (SanitizationProfile::CertinGoi, 3, "certin-goi"),
        (SanitizationProfile::Dod5220_22M, 3, "dod-5220.22m"),
        (SanitizationProfile::Dod5220_22MEce, 7, "dod-5220.22m-ece"),
        (SanitizationProfile::CsecItsg06, 3, "csec-itsg-06"),
        (SanitizationProfile::BsiVsitr, 7, "bsi-vsitr"),
        (SanitizationProfile::Schneier, 7, "schneier"),
        (SanitizationProfile::Gutmann, 35, "gutmann"),
    ];
    assert_eq!(SanitizationProfile::CATALOG.len(), expect.len());
    for (p, n, _slug) in expect {
        assert_eq!(
            p.total_passes(),
            *n,
            "{} pass count drifted",
            p.display_name()
        );
    }

    // CLI renders the full matrix.
    let out = Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("profiles")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for (_, _, slug) in expect {
        assert!(stdout.contains(slug), "dc profiles output missing {}", slug);
    }
    assert!(stdout.contains("CERT-In / GoI"));
    assert!(stdout.contains("NIST SP 800-88"));
}

// ---------------------------------------------------------------------------
// REG-VERIFY-STRIDE: sampled verification skips unsampled windows entirely
// (engine-level contract — the wall-clock saving IS the skipped I/O).
// ---------------------------------------------------------------------------

#[test]
fn reg_verify_stride_skips_unsampled_and_catches_sampled() {
    use dc_core::{FsmOrchestrator, Mechanism, Pattern, SanitizationPlan, VerifyLevel};

    let tmp = tempfile::tempdir().unwrap();
    let backing = tmp.path().join("stride.raw");
    // 8 windows of 64 KiB.
    std::fs::write(&backing, vec![0x00u8; 8 * 64 * 1024]).unwrap();

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&backing)
        .unwrap();
    let mut engine = create_engine(file, 64 * 1024, false, 4).unwrap();

    let plan = SanitizationPlan {
        plan_schema: "dc-plan/1".to_string(),
        target: dc_core::StableIdentity {
            model: Some("StrideTest".into()),
            serial: Some("SN-STRIDE".into()),
            wwn: None,
            size_bytes: 8 * 64 * 1024,
            bus: dc_core::BusType::File,
            dm_name: None,
            dm_uuid: None,
        },
        mechanism: Mechanism::LogicalOverwrite {
            passes: vec![dc_core::Pass {
                pattern: Pattern::Zero,
                label: "zero".into(),
            }],
        },
        verification: VerifyLevel::Sampled { stride: 4 },
        window_bytes: 64 * 1024,
        fast_path: dc_core::FastPathPolicy::ForbidWriteZeroes,
        strategy_ladder: None,
        legacy_note: None,
    };
    let mut fsm = FsmOrchestrator::new();
    fsm.compile_plan(plan).unwrap();
    fsm.approve_plan().unwrap();
    fsm.arm().unwrap();
    let permit = fsm.begin_pass(0).unwrap();

    let span = LbaSpan::new(8 * 64 * 1024, 512, 64 * 1024);
    engine
        .write_pass(&permit, 0, &dc_core::ZeroPattern, &span, 0, &mut |_| {})
        .unwrap();

    let flush_permit = fsm.begin_flush(0).unwrap();
    engine.flush(&flush_permit).unwrap();

    // Case A: corrupt an UNSAMPLED window (index 1: 1 % 4 != 0). A stride-4
    // sampled verification must NOT see it and must pass.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(&backing)
        .unwrap();
    use std::io::{Seek, Write};
    f.seek(std::io::SeekFrom::Start(64 * 1024)).unwrap();
    f.write_all(&vec![0xFFu8; 4096]).unwrap();
    drop(f);

    fsm.begin_verify().unwrap();
    let mut engine2 = {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&backing)
            .unwrap();
        create_engine(file, 64 * 1024, false, 4).unwrap()
    };
    let mut verifier_a = dc_verify::StreamVerifier::new(
        VerifyLevel::Sampled { stride: 4 },
        64 * 1024,
        512,
        false,
        false,
    );
    engine2
        .read_verify(
            &dc_core::ZeroPattern,
            &span,
            4,
            &mut verifier_a,
            &mut |_| {},
        )
        .unwrap();
    let report_a = verifier_a.finalize();
    assert_eq!(
        report_a.mismatch_count, 0,
        "unsampled corruption must not trip sampled verification"
    );
    assert_eq!(
        report_a.windows_checked, 2,
        "stride-4 over 8 windows = 2 checks"
    );

    // Case B: corrupt a SAMPLED window (index 4: 4 % 4 == 0) — must be caught.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(&backing)
        .unwrap();
    f.seek(std::io::SeekFrom::Start(4 * 64 * 1024)).unwrap();
    f.write_all(&vec![0xFFu8; 4096]).unwrap();
    drop(f);

    let mut verifier_b = dc_verify::StreamVerifier::new(
        VerifyLevel::Sampled { stride: 4 },
        64 * 1024,
        512,
        false,
        false,
    );
    engine2
        .read_verify(
            &dc_core::ZeroPattern,
            &span,
            4,
            &mut verifier_b,
            &mut |_| {},
        )
        .unwrap();
    let report_b = verifier_b.finalize();
    assert!(
        report_b.mismatch_count >= 1,
        "sampled corruption MUST be caught by sampled verification"
    );
}

// ---------------------------------------------------------------------------
// REG-VERIFY-FLAG-CONTRACT: --verify parsing and its exclusivity with --plan.
// ---------------------------------------------------------------------------

#[test]
fn reg_verify_flag_contract() {
    // Bad strides rejected by the CLI (fail-fast, exit code 1 = usage).
    for bad in ["sample:1", "sample:70000", "sample:x", "quarter"] {
        Command::cargo_bin("diskcleaner")
            .unwrap()
            .arg("execute")
            .arg("--target")
            .arg("/dev/nonexistent-zz")
            .arg("--verify")
            .arg(bad)
            .arg("--dry-run")
            .assert()
            .failure();
    }
    // Machine-stable tags round-trip.
    for (tag, expect) in [
        ("full", dc_core::VerifyLevel::Full),
        ("none", dc_core::VerifyLevel::None),
        ("sample:64", dc_core::VerifyLevel::Sampled { stride: 64 }),
    ] {
        let parsed = dc_core::VerifyLevel::from_short_tag(tag)
            .unwrap_or_else(|| panic!("tag {} must parse", tag));
        assert_eq!(parsed, expect);
        assert_eq!(expect.short_tag(), tag);
    }
    assert!(dc_core::VerifyLevel::from_short_tag("sample:1").is_none());
    assert!(dc_core::VerifyLevel::from_short_tag("sample:70000").is_none());
    assert!(dc_core::VerifyLevel::from_short_tag("fuller").is_none());
}

// ---------------------------------------------------------------------------
// (Pre-0.6.0 REG-PURGE-NVME-ONLY invariant RETIRED: `dc purge` now
// dispatches to the NVMe / ATA / SCSI transports; superseded by
// REG-PURGE-UNIVERSAL-DISPATCH above.)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// REG-MULTI-ARM-ALLORNOTHING: one bad target aborts the whole batch before
// ANY device is armed, locked, or written (fleet safety invariant).
// (Root-gated full version in t14; this is the non-root CLI guard.)
// ---------------------------------------------------------------------------

#[test]
fn reg_multi_target_rejects_plan_across_batch() {
    // --plan with multiple targets is a usage error (plan binds one device).
    Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("execute")
        .arg("--target")
        .arg("/dev/sda")
        .arg("--target")
        .arg("/dev/sdb")
        .arg("--plan")
        .arg("/tmp/no-such-plan.json")
        .arg("--dry-run")
        .assert()
        .failure();
    // --verify with --plan is a usage error (plan is authoritative).
    Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("execute")
        .arg("--target")
        .arg("/dev/sda")
        .arg("--plan")
        .arg("/tmp/no-such-plan.json")
        .arg("--verify")
        .arg("sample:8")
        .arg("--dry-run")
        .assert()
        .failure();
}

// ---------------------------------------------------------------------------
// REG-CERT-PURGE-EVIDENCE: optional purge/health fields keep old certificates
// loadable AND are covered by the signature payload when present.
// ---------------------------------------------------------------------------

#[test]
fn reg_cert_purge_fields_backward_compatible_and_signed() {
    use dc_cert::PurgeCertificateEvidence;
    use dc_core::{Mechanism, SanitizationPlan, VerifyLevel};

    let kp = OperatorKeyPair::generate();
    let plan = SanitizationPlan {
        plan_schema: "dc-plan/1".to_string(),
        target: dc_core::StableIdentity {
            model: Some("PurgeSSD".into()),
            serial: Some("SN-PURGE".into()),
            wwn: None,
            size_bytes: 1024 * 1024 * 1024,
            bus: dc_core::BusType::Nvme,
            dm_name: None,
            dm_uuid: None,
        },
        mechanism: Mechanism::HardwarePurge {
            ladder: dc_core::StrategyLadder { steps: vec![] },
            selected_mechanism: "SanitizeCryptoErase".into(),
        },
        verification: VerifyLevel::None,
        window_bytes: SanitizationPlan::DEFAULT_WINDOW_BYTES,
        fast_path: dc_core::FastPathPolicy::ForbidWriteZeroes,
        strategy_ladder: None,
        legacy_note: None,
    };

    let mk_cert = || {
        let mut c = dc_cert::SanitizationCertificate::new(
            plan.clone(),
            "hash".into(),
            purge_test_identity(),
            dc_cert::ExecutionDetails {
                started_utc: "t0".into(),
                finished_utc: "t1".into(),
                duration_mono_ms: 42,
                interruptions: vec![],
                failures: vec![],
                passes: vec![],
            },
            dc_verify::StreamVerifier::new(VerifyLevel::None, 2 * 1024 * 1024, 512, false, false)
                .finalize(),
            dc_core::JournalChainSummary {
                path: std::path::PathBuf::from("/tmp/x.dcj"),
                chain_head: "head".into(),
                record_count: 3,
                discarded_tail_bytes: 0,
                uuid: "dcj-x".into(),
                sealed: false,
            },
            kp.public_key_hex(),
            kp.key_fingerprint_blake3(),
        );
        c.sign(&kp).unwrap();
        c
    };

    fn purge_test_identity() -> dc_core::DeviceIdentity {
        dc_core::DeviceIdentity {
            stable: dc_core::StableIdentity {
                model: Some("PurgeSSD".into()),
                serial: Some("SN-PURGE".into()),
                wwn: None,
                size_bytes: 1024 * 1024 * 1024,
                bus: dc_core::BusType::Nvme,
                dm_name: None,
                dm_uuid: None,
            },
            kernel: dc_core::KernelIdentity {
                major: 259,
                minor: 0,
            },
            kernel_name: "nvme0n1".into(),
            dev_path: "/dev/nvme0n1".into(),
            logical_block_size: 512,
            physical_block_size: 4096,
        }
    }

    // Plain cert: no purge fields serialized, still verifiable.
    let plain = mk_cert();
    assert!(plain.verify_signature().unwrap_or(false));
    let json = serde_json::to_string(&plain).unwrap();
    assert!(
        !json.contains("\"purge\":"),
        "plain overwrite certs must not carry the optional purge field"
    );
    let back: dc_cert::SanitizationCertificate = serde_json::from_str(&json).unwrap();
    assert!(back.verify_signature().unwrap_or(false));

    // Purge evidence: attached, serialized, and the signature still verifies
    // (the evidence IS part of the signed payload).
    let evidenced = mk_cert()
        .with_purge(PurgeCertificateEvidence {
            executed_mechanism: "SanitizeCryptoErase".into(),
            fallbacks: vec![],
            completion_evidence: "sanitize-status-log".into(),
            sanitize_progress_permille: 1000,
            readback_expectation: "VendorRandom".into(),
            controller_device: "/dev/nvme0".into(),
        })
        .with_health(None, None);
    let mut evidenced = evidenced;
    evidenced.sign(&kp).unwrap();
    assert!(evidenced.verify_signature().unwrap_or(false));
    let json2 = serde_json::to_string(&evidenced).unwrap();
    assert!(json2.contains("sanitize-status-log"));
    assert!(json2.contains("PurgeSSD".to_string().as_str()) || json2.contains("SN-PURGE"));
}

// ===========================================================================
// v0.7.0 REGRESSION GUARDS (Vector 1-4)
// ===========================================================================

// ---------------------------------------------------------------------------
// REG-TOKEN-CUSTODY-PROOF: is_hardware_token without a PIV attestation can
// no longer claim SeparateHardware custody (the pre-0.7.0 boolean was a
// self-attestation any software key could set).
// ---------------------------------------------------------------------------
#[test]
fn reg_token_custody_proof() {
    use dc_cert::{
        AuthSignatureEntry, AuthorizationSet, HardwareCustodyAttestation, KeyDisclosure,
    };
    use ed25519_dalek::Signer;

    let plan_hash = "b".repeat(64);
    let a = OperatorKeyPair::generate();
    let b = OperatorKeyPair::generate();

    let sig_of = |k: &OperatorKeyPair, hw: bool, att: Option<HardwareCustodyAttestation>| {
        let msg = AuthSignatureEntry::approval_message(dc_cert::PLAN_APPROVAL_DOMAIN, &plan_hash);
        let sig = hex::encode(k.signing_key.sign(&msg).to_bytes());
        AuthSignatureEntry {
            key_fingerprint: k.key_fingerprint_blake3(),
            public_key_hex: k.public_key_hex(),
            signature_hex: sig,
            is_hardware_token: hw,
            hardware_attestation: att,
        }
    };

    // 1. Claimed hardware WITHOUT attestation: hard refusal.
    let mut set = AuthorizationSet::new(&plan_hash);
    set.add_signature(sig_of(&a, true, None));
    set.add_signature(sig_of(&b, false, None));
    assert_eq!(
        set.verify_pre_arm_authorization(&plan_hash, true),
        Err("HW_CUSTODY_CLAIM_WITHOUT_ATTESTATION"),
        "a bare is_hardware_token boolean must never authorize SeparateHardware custody"
    );
    // And the custody derivation does not gift hardware custody either.
    assert_eq!(
        set.derive_custody_type(),
        dc_cert::CustodyType::SharedFilesystem
    );

    // 2. Attestation bound to a DIFFERENT plan: binding mismatch refusal.
    let mut msg = Vec::new();
    msg.extend_from_slice(dc_cert::PLAN_APPROVAL_DOMAIN);
    msg.extend_from_slice(b"feedface"); // a foreign hash
    let att = HardwareCustodyAttestation {
        interface: "PIV/ISO7816-4-over-CCID-USB".to_string(),
        token_path: "/dev/bus/usb/001/004".to_string(),
        token_usb_identity: "1050:0407".to_string(),
        token_serial: Some("YK-1".to_string()),
        slot: "9c (Digital Signature)".to_string(),
        mechanism: "PIV-Ed25519".to_string(),
        pin_verified: true,
        signed_message_blake3: blake3::hash(&msg).to_hex().to_string(),
        key_disclosure: KeyDisclosure::SignatureOnly,
        token_public_key_hex: None,
        custody_cosignature_hex: None,
        transcript_chain_blake3: "0".repeat(64),
    };
    let mut set = AuthorizationSet::new(&plan_hash);
    set.add_signature(sig_of(&a, true, Some(att.clone())));
    set.add_signature(sig_of(&b, false, None));
    assert_eq!(
        set.verify_pre_arm_authorization(&plan_hash, true),
        Err("HW_ATTESTATION_MESSAGE_BINDING_MISMATCH"),
        "a token transcript for a foreign plan hash must not authorize this one"
    );

    // 3. Attestation not PIN-verified: refused.
    let mut bad = att.clone();
    bad.pin_verified = false;
    let mut set = AuthorizationSet::new(&plan_hash);
    set.add_signature(sig_of(&a, true, Some(bad)));
    set.add_signature(sig_of(&b, false, None));
    assert_eq!(
        set.verify_pre_arm_authorization(&plan_hash, true),
        Err("HW_ATTESTATION_PIN_NOT_VERIFIED")
    );

    // 4. Consistent attestation with key disclosure binding: hardware
    // custody verifies and derives SeparateHardware.
    let mut msg = Vec::new();
    msg.extend_from_slice(dc_cert::PLAN_APPROVAL_DOMAIN);
    msg.extend_from_slice(plan_hash.as_bytes());
    let mut good = att.clone();
    good.pin_verified = true;
    good.signed_message_blake3 = blake3::hash(&msg).to_hex().to_string();
    good.token_public_key_hex = Some(a.public_key_hex());
    let mut set = AuthorizationSet::new(&plan_hash);
    set.add_signature(sig_of(&a, true, Some(good)));
    set.add_signature(sig_of(&b, false, None));
    assert!(set.verify_pre_arm_authorization(&plan_hash, true).is_ok());
    // SeparateHardware still requires BOTH signatures to be token-signed;
    // one software officer keeps it SharedFilesystem.
    assert_eq!(
        set.derive_custody_type(),
        dc_cert::CustodyType::SharedFilesystem
    );

    // 5. The CLI surface offers the token verbs.
    let out = Command::cargo_bin("dc")
        .unwrap()
        .arg("approve")
        .arg("--help")
        .unwrap()
        .stdout;
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("--token"), "dc approve must offer --token");
    assert!(text.contains("--token2"), "dc approve must offer --token2");
}

// ---------------------------------------------------------------------------
// REG-COLDBUS-RESET-LADDER: the sysfs freeze-drop ladder walks its steps in
// order, records every write, and ends with the manual advisory when the
// lock survives (never a fabricated success).
// ---------------------------------------------------------------------------
#[test]
fn reg_coldbus_reset_ladder() {
    use dc_ata::coldbus::{ColdBusOutcome, SysfsOps, attempt_cold_unfreeze};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    struct ScriptedSysfs {
        attrs: RefCell<BTreeMap<String, String>>,
        links: BTreeMap<String, PathBuf>,
        writes: RefCell<Vec<(String, String)>>,
    }

    impl SysfsOps for ScriptedSysfs {
        fn read_str(&self, path: &Path) -> Result<String, String> {
            self.attrs
                .borrow()
                .get(&path.display().to_string())
                .cloned()
                .ok_or_else(|| format!("no such attribute {}", path.display()))
        }
        fn write_str(&self, path: &Path, value: &str) -> Result<(), String> {
            self.writes
                .borrow_mut()
                .push((path.display().to_string(), value.to_string()));
            self.attrs
                .borrow_mut()
                .insert(path.display().to_string(), value.to_string());
            Ok(())
        }
        fn exists(&self, _path: &Path) -> bool {
            true
        }
        fn read_link(&self, path: &Path) -> Result<PathBuf, String> {
            self.links
                .get(&path.display().to_string())
                .cloned()
                .ok_or_else(|| format!("no such link {}", path.display()))
        }
        fn list_dir(&self, _path: &Path) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }
    }

    let mk = || ScriptedSysfs {
        attrs: RefCell::new(BTreeMap::new()),
        links: {
            let mut l = BTreeMap::new();
            l.insert(
                "/sys/block/sda".to_string(),
                PathBuf::from(
                    "/sys/devices/pci0000:00/0000:00:17.0/ata3/host3/target3:0:0/3:0:0:0/block/sda",
                ),
            );
            l
        },
        writes: RefCell::new(Vec::new()),
    };

    // Still-frozen path: LUN delete + rescan, then port PM cycle, then the
    // manual power-cycle advisory.
    let sysfs = mk();
    sysfs.attrs.borrow_mut().insert(
        "/sys/class/ata_port/ata3/power/runtime_status".to_string(),
        "suspended".into(),
    );
    let outcome = attempt_cold_unfreeze(&sysfs, "sda", || Ok(true));
    match &outcome {
        ColdBusOutcome::StillFrozen { steps, advisory } => {
            assert_eq!(steps.len(), 2, "both ladder steps must execute");
            assert_eq!(steps[0].step, "lun-delete-host-rescan");
            assert_eq!(steps[1].step, "ata-port-runtime-pm-cycle");
            assert!(advisory.contains("Power-cycle"));
        }
        other => panic!("expected StillFrozen, got {:?}", other),
    }
    let writes = sysfs.writes.borrow();
    assert_eq!(
        writes[0],
        ("/sys/block/sda/device/delete".to_string(), "1".to_string())
    );
    assert_eq!(
        writes[1],
        (
            "/sys/class/scsi_host/host3/scan".to_string(),
            "- - -".to_string()
        )
    );
    assert!(
        writes
            .iter()
            .any(|(p, v)| p == "/sys/class/ata_port/ata3/power/control" && v == "auto")
    );
    assert!(
        writes
            .iter()
            .any(|(p, v)| p == "/sys/class/ata_port/ata3/power/control" && v == "on")
    );

    // Cleared path: certificate-grade step records with the re-probe.
    let sysfs = mk();
    let outcome = attempt_cold_unfreeze(&sysfs, "sda", || Ok(false));
    assert!(matches!(outcome, ColdBusOutcome::Cleared { .. }));
    if let ColdBusOutcome::Cleared { steps } = outcome {
        assert!(steps[0].outcome.contains("freeze cleared"));
    }

    // CLI surface: --cold-unfreeze exists on the purge verb.
    let out = Command::cargo_bin("dc")
        .unwrap()
        .arg("purge")
        .arg("--help")
        .unwrap()
        .stdout;
    assert!(String::from_utf8_lossy(&out).contains("--cold-unfreeze"));
}

// ---------------------------------------------------------------------------
// REG-THERMAL-GOVERNOR: threshold semantics (55 throttle / 70 critical),
// SMART attr 194 decode, SCSI LOG SENSE 0x0D decode, hwmon millidegrees.
// ---------------------------------------------------------------------------
#[test]
fn reg_thermal_governor() {
    use dc_hw::thermal::{ThermalDecision, ThermalGovernor, ThermalReading, ThermalSource};
    use std::time::Duration;

    let g = ThermalGovernor::default();
    assert_eq!(
        g.evaluate(&ThermalReading::from_ata_smart(54)),
        ThermalDecision::Continue
    );
    match g.evaluate(&ThermalReading::from_ata_smart(57)) {
        ThermalDecision::Pace(d) => assert_eq!(d, Duration::from_millis(500)),
        other => panic!("57 C must pace 500 ms, got {:?}", other),
    }
    assert_eq!(
        g.evaluate(&ThermalReading::from_ata_smart(71)),
        ThermalDecision::Abort {
            temperature_c: 71,
            limit_c: 70
        }
    );
    // Kelvin + millidegree conversions are exact.
    assert_eq!(ThermalReading::from_nvme_kelvin(328).temperature_c, 55);
    assert_eq!(
        ThermalReading::from_hwmon_millidegrees(70_499).temperature_c,
        70
    );

    // SMART attribute 194 decode from a realistic 512-byte table.
    use dc_hw::thermal::decode_smart_temperature;
    let mut raw = [0u8; 512];
    raw[2] = 194;
    raw[2 + 5] = 48;
    let reading = decode_smart_temperature(&raw).unwrap();
    assert_eq!(reading.temperature_c, 48);
    assert_eq!(reading.source, ThermalSource::AtaSmartAttr194);

    // SCSI LOG SENSE page 0x0D parameter 0x0000.
    use dc_hw::thermal::decode_log_sense_temperature;
    let mut page = vec![0x0D, 0x00, 0x00, 0x0A];
    page.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x39]); // 57 C
    let reading = decode_log_sense_temperature(&page).unwrap();
    assert_eq!(reading.temperature_c, 57);
    assert_eq!(reading.source, ThermalSource::ScsiLogSense0d);

    // CLI surface: purge exposes the thermal flags.
    let out = Command::cargo_bin("dc")
        .unwrap()
        .arg("purge")
        .arg("--help")
        .unwrap()
        .stdout;
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("--thermal-critical-c"));
    assert!(text.contains("--no-thermal-guard"));
}

// ---------------------------------------------------------------------------
// REG-PID1-INIT-SEQUENCE: the real PID-1 bootstrap (mounts, RNDADDENTROPY,
// zombie reaper) and the appliance build pipeline contract.
// ---------------------------------------------------------------------------
#[test]
fn reg_pid1_init_sequence() {
    use dc_cli::init::{InitBackend, Pid1SequenceRecord, evaluate_boot_state};
    use std::cell::RefCell;

    struct ScriptedInit {
        mounts: RefCell<Vec<(String, String, String)>>,
        entropy_calls: RefCell<Vec<(Vec<u8>, u32)>>,
        reaper: RefCell<bool>,
    }

    impl InitBackend for ScriptedInit {
        fn mount(&self, source: &str, target: &str, fstype: &str) -> Result<(), String> {
            self.mounts
                .borrow_mut()
                .push((source.into(), target.into(), fstype.into()));
            Ok(())
        }
        fn is_mounted(&self, _target: &str) -> bool {
            false
        }
        fn add_entropy(&self, bytes: &[u8], bits: u32) -> Result<(), String> {
            self.entropy_calls.borrow_mut().push((bytes.to_vec(), bits));
            Ok(())
        }
        fn install_zombie_reaper(&self) -> Result<(), String> {
            *self.reaper.borrow_mut() = true;
            Ok(())
        }
    }

    // The RNDADDENTROPY ioctl number is kernel UAPI (pinned in dc-cli
    // internals; the sequence record proves the call happened).
    let _backend = ScriptedInit {
        mounts: RefCell::new(Vec::new()),
        entropy_calls: RefCell::new(Vec::new()),
        reaper: RefCell::new(false),
    };
    // run_pid1_init_real is invoked through cmd_boot in production; the
    // pure seam keeps the v0.6.0 contract pinned.
    assert_eq!(
        evaluate_boot_state(false, true, "x"),
        Err("ENTROPY_STARVATION_UNREADY")
    );

    // Entropy starvation refuses even with a scripted backend (the harvest
    // source is hardware; the gate itself is pure).
    // (Mount order + entropy + reaper are pinned by dc-cli unit tests and
    // t27; this guard pins the CONTRACT and the build pipeline below.)

    // The appliance build script exists and pins its stages.
    let script = include_str!("../../../scripts/build-appliance.sh");
    for stage in [
        "x86_64-unknown-linux-musl",
        "boot pack",
        "verify-against",
        "xorriso",
        "rdinit=/init",
    ] {
        assert!(
            script.contains(stage),
            "build-appliance.sh must contain the '{}' stage",
            stage
        );
    }

    // The `dc boot` verb exists with its subcommands.
    let out = Command::cargo_bin("dc")
        .unwrap()
        .arg("boot")
        .arg("--help")
        .unwrap()
        .stdout;
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("init"), "dc boot init must exist");
    assert!(text.contains("pack"), "dc boot pack must exist");

    let _ = Pid1SequenceRecord {
        mounted: vec![],
        already_mounted: vec![],
        entropy_bytes_credited: 0,
        zombie_reaper_installed: true,
    };
}

// ---------------------------------------------------------------------------
// REG-FIRMWARE-ATTESTATION: NVMe Telemetry LID 0x07 encode/decode, ATA
// Device Statistics wear decode, firmware-drift defense warning in the
// signed certificate.
// ---------------------------------------------------------------------------
#[test]
fn reg_firmware_attestation() {
    use dc_cert::{FirmwareAttestationEvidence, FirmwareIdentity};
    use dc_hw::{AtaCodec, AtaDeviceStatisticsPage, NvmeCodec};

    // 1. NVMe Telemetry Host-Initiated (LID 0x07): the CREATE bit lives in
    // CDW12 (LSP field), and NUMDL sizes the 512-byte header.
    let cmd = NvmeCodec::encode_get_telemetry_log(true);
    assert_eq!(cmd[0], 0x02, "Get Log Page opcode");
    assert_eq!(cmd[40], 0x07, "LID 0x07 (Telemetry Host-Initiated)");
    let cdw12 = u32::from_le_bytes([cmd[48], cmd[49], cmd[50], cmd[51]]);
    assert_eq!(cdw12 & 0x1, 1, "LSP bit 0: create a fresh snapshot");
    let no_create = NvmeCodec::encode_get_telemetry_log(false);
    let cdw12b = u32::from_le_bytes([no_create[48], no_create[49], no_create[50], no_create[51]]);
    assert_eq!(cdw12b & 0x1, 0);

    // 2. Header decode: reason identifier, generation, data-area offsets.
    let mut payload = vec![0u8; 518];
    payload[0] = 0b111; // all three data areas supported
    payload[1] = 0x2A; // generation 42
    payload[8..12].copy_from_slice(b"dc-p"); // reason identifier
    payload[509..512].copy_from_slice(&[0x00, 0x02, 0x00]); // area 1 last block 512
    payload[512..515].copy_from_slice(&[0x00, 0x10, 0x00]); // area 2 last block 4096
    let header = NvmeCodec::decode_telemetry_header(&payload).unwrap();
    assert_eq!(header.data_areas_supported, 0b111);
    assert_eq!(header.generation, 0x2A);
    assert_eq!(header.reason_identifier, "dc-p");
    assert_eq!(header.area1_last_block, 512);
    assert_eq!(header.area2_last_block, 4096);

    // 3. ATA Device Statistics page 0x04: Percentage Used Endurance (1
    // byte) + page 0x00 sector counters (6 bytes).
    let mut page4 = [0u8; 512];
    page4[0..2].copy_from_slice(&0x04u16.to_le_bytes());
    page4[4..8].copy_from_slice(&3u32.to_le_bytes()); // 3 entries
    // entry 1 at 8: code 0x0001 (endurance), 1-byte value 37.
    page4[8..10].copy_from_slice(&0x0001u16.to_le_bytes());
    page4[10] = 0x10; // flags (D bit)
    page4[12] = 37; // value at off+4, 1 byte
    // entry 2 at 8+5=13: code 0x0002 (read sectors), 6-byte value.
    page4[13..15].copy_from_slice(&0x0002u16.to_le_bytes());
    page4[15] = 0x10; // flags at off+2
    page4[17..23].copy_from_slice(&123_456u64.to_le_bytes()[..6]); // value at off+4
    // entry 3 at 13+10=23: code 0x0004 (written sectors), 6-byte value.
    page4[23..25].copy_from_slice(&0x0004u16.to_le_bytes());
    page4[25] = 0x10;
    page4[27..33].copy_from_slice(&987_654u64.to_le_bytes()[..6]);
    let decoded4 = AtaDeviceStatisticsPage::decode(&page4, 0x04).unwrap();
    assert_eq!(decoded4.page_number, 0x04);
    assert_eq!(decoded4.percentage_used_endurance(), Some(37));
    assert_eq!(decoded4.entry(0x0002).map(|e| e.value), Some(123_456));
    assert_eq!(decoded4.entry(0x0004).map(|e| e.value), Some(987_654));

    // 4. Firmware drift: revision change inside the window -> defense
    // warning in the SIGNED certificate payload.
    let kp = OperatorKeyPair::generate();
    let mk_cert = |pre_rev: &str, post_rev: &str| {
        let plan = dc_core::SanitizationPlan {
            plan_schema: "dc-plan/1".into(),
            target: dc_core::StableIdentity {
                model: Some("X".into()),
                serial: Some("S".into()),
                wwn: None,
                size_bytes: 1 << 30,
                bus: dc_core::BusType::Nvme,
                dm_name: None,
                dm_uuid: None,
            },
            mechanism: dc_core::Mechanism::HardwarePurge {
                ladder: dc_core::StrategyLadder { steps: vec![] },
                selected_mechanism: "Sanitize".into(),
            },
            verification: dc_core::VerifyLevel::None,
            window_bytes: dc_core::SanitizationPlan::DEFAULT_WINDOW_BYTES,
            fast_path: dc_core::FastPathPolicy::ForbidWriteZeroes,
            strategy_ladder: None,
            legacy_note: None,
        };
        let mut fsm = dc_core::FsmOrchestrator::new();
        let plan_hash = fsm.compile_plan(plan.clone()).unwrap();
        fsm.approve_plan().unwrap();
        fsm.arm().unwrap();
        let _pass_permit = fsm.begin_pass(0).unwrap();
        let _flush_permit = fsm.begin_flush(0).unwrap();
        fsm.begin_verify().unwrap();
        fsm.certify().unwrap();
        let identity = dc_core::DeviceIdentity {
            stable: plan.target.clone(),
            kernel: dc_core::KernelIdentity {
                major: 259,
                minor: 0,
            },
            kernel_name: "nvme0n1".into(),
            dev_path: "/dev/nvme0n1".into(),
            logical_block_size: 512,
            physical_block_size: 4096,
        };
        let mut cert = dc_cert::SanitizationCertificate::new(
            plan,
            plan_hash,
            identity,
            dc_cert::ExecutionDetails {
                started_utc: "2026-10-12T00:00:00Z".into(),
                finished_utc: "2026-10-12T00:01:00Z".into(),
                duration_mono_ms: 60_000,
                interruptions: vec![],
                failures: vec![],
                passes: vec![],
            },
            dc_verify::StreamVerifier::new(
                dc_core::VerifyLevel::None,
                dc_core::SanitizationPlan::DEFAULT_WINDOW_BYTES,
                512,
                false,
                false,
            )
            .finalize(),
            dc_core::JournalChainSummary {
                path: "j.dcj".into(),
                discarded_tail_bytes: 0,
                uuid: "dcj-x".into(),
                record_count: 2,
                chain_head: "h".into(),
                sealed: false,
            },
            kp.public_key_hex(),
            kp.key_fingerprint_blake3(),
        );
        cert = cert.with_firmware_attestation(FirmwareAttestationEvidence {
            pre: FirmwareIdentity {
                bus: "nvme".into(),
                model: "M".into(),
                serial: "S".into(),
                firmware_revision: pre_rev.into(),
                subsystem_vendor: Some("144d".into()),
                subsystem_device: None,
            },
            post: FirmwareIdentity {
                bus: "nvme".into(),
                model: "M".into(),
                serial: "S".into(),
                firmware_revision: post_rev.into(),
                subsystem_vendor: Some("144d".into()),
                subsystem_device: None,
            },
            nvme_telemetry_pre: None,
            nvme_telemetry_post: None,
            ata_devstat_pre: None,
            ata_devstat_post: None,
            raw_snapshots: vec![],
        });
        cert.sign(&kp).unwrap();
        cert
    };
    let drifted = mk_cert("1B2QEXM7", "1B2QEXM9");
    let json = serde_json::to_string(&drifted).unwrap();
    assert!(
        json.contains("DEFENSE_WARNING"),
        "firmware drift must produce a signed defense warning"
    );
    assert!(json.contains("firmware revision changed"));
    assert!(drifted.verify_signature().unwrap_or(false));

    let stable = mk_cert("1B2QEXM7", "1B2QEXM7");
    let json2 = serde_json::to_string(&stable).unwrap();
    assert!(!json2.contains("firmware revision changed"));

    // 5. READ LOG EXT framing for the Device Statistics pages: log 0x04 in
    // the LBA low byte, page in the high byte.
    let cdb = AtaCodec::encode_sat_read_log_ext(0x04, 0x04, 1);
    assert_eq!(cdb[0], 0x85, "ATA PASS-THROUGH (16)");
    assert_eq!(cdb[1] >> 1 & 0x7, 4, "PIO Data-In protocol");
    // The passthrough-16 LBA mapping (see encode_sat_passthrough_16_framed):
    // cdb[11]=LBA47:40, cdb[9]=LBA39:32, cdb[7]=LBA31:24, cdb[12]=LBA23:16,
    // cdb[10]=LBA15:8, cdb[8]=LBA7:0.
    let lba = ((cdb[11] as u64) << 40)
        | ((cdb[9] as u64) << 32)
        | ((cdb[7] as u64) << 24)
        | ((cdb[12] as u64) << 16)
        | ((cdb[10] as u64) << 8)
        | cdb[8] as u64;
    assert_eq!(lba, 0x04 | (0x04 << 8), "log 0x04, page 4 in the LBA field");
    // Sector count 1 in the 16-bit count field.
    assert_eq!(cdb[6], 1);
}
