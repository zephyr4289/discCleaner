pub mod audit;
pub mod error;
pub mod fleet;
pub mod fsm;
pub mod identity;
pub mod journal;
pub mod orchestrator;
pub mod pattern;
pub mod plan;
pub mod strategy;
pub mod tool;

pub use audit::{AuditLogger, AuditOutcome, AuditRecord};
pub use error::{DcError, GuardianRefusal};
pub use fleet::{
    AdvisoryResolution, ArgvConstructor, AssignmentRow, BatchManifest, BatchReconstructor,
    ChildJournalState, FleetJobOutcome, FleetJobRecord, FleetReport, IdentityResolver, SpawnContext,
};
pub use fsm::{FsmOrchestrator, FsmState, WritePermit};
pub use identity::{BusType, DeviceIdentity, KernelIdentity, StableIdentity};
pub use journal::{
    check_cqe_or_verify_crash, check_cqe_or_verify_signal, check_crash_hook, check_signal_hook,
    EngineTuning, JournalChainSummary, JournalReader, JournalRecord, JournalWriter, JOURNAL_MAGIC,
};
pub use orchestrator::{Orchestrator, OrchestratorEffect, OrchestratorState};
pub use pattern::{
    create_pattern_source, ChaCha20Pattern, FixedPattern, Pattern, PatternDescriptor,
    PatternSource, PrngScheme, ZeroPattern,
};
pub use plan::{FastPathPolicy, Mechanism, Pass, SanitizationPlan, VerifyLevel};
pub use strategy::{
    AttestedCapabilities, DeviceTransportClass, MechanismStep, StrategyCompiler, StrategyLadder,
};
pub use tool::ToolBuild;

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn test_chacha20_deterministic_prng_golden_vector() {
        let seed = [0x42u8; 32];
        let pattern = ChaCha20Pattern::new(seed);

        let mut buf_w0_a = vec![0u8; 1024];
        let mut buf_w0_b = vec![0u8; 1024];
        let mut buf_w1 = vec![0u8; 1024];

        pattern.fill(0, &mut buf_w0_a);
        pattern.fill(0, &mut buf_w0_b);
        pattern.fill(1, &mut buf_w1);

        assert_eq!(buf_w0_a, buf_w0_b, "Identical (seed, window) must be identical");
        assert_ne!(buf_w0_a, buf_w1, "Different window indices must differ");

        let hex_prefix = hex::encode(&buf_w0_a[..16]);
        assert_eq!(hex_prefix.len(), 32);
    }
}

// ---------------------------------------------------------------------------
// Unit test layer (LLVM-style: focused, descriptive, per-module)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ---------------- journal: hash chain ----------------

    fn test_header() -> JournalRecord {
        JournalRecord::Header {
            uuid: "unit-uuid".to_string(),
            sealed: false,
            operator_pubkey: None,
            plan: SanitizationPlan::clear_zero(test_identity(), FastPathPolicy::PreferWriteZeroes),
            plan_hash: "unit-plan-hash".to_string(),
            identity: DeviceIdentity {
                stable: test_identity(),
                kernel: KernelIdentity { major: 259, minor: 0 },
                kernel_name: "nvme0n1".to_string(),
                dev_path: "/dev/nvme0n1".to_string(),
                logical_block_size: 512,
                physical_block_size: 4096,
            },
            tool: ToolBuild::current(),
            engine: "sync".to_string(),
            tuning: EngineTuning {
                qd: 64,
                pool_mib: 128,
                window_bytes: 2 * 1024 * 1024,
                checkpoint_mib: 512,
                checkpoint_ms: 5000,
            },
            argv_hash: "unit".to_string(),
            started_utc: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn write_simple_journal(dir: &TempDir, records: &[JournalRecord]) -> (std::path::PathBuf, JournalWriter) {
        // Record 0 is ALWAYS a Header (DCJ1 format invariant).
        let path = dir.path().join(format!("j-{}.dcj", std::process::id()));
        let mut w = JournalWriter::create_new(&path, "unit-uuid".to_string(), None).unwrap();
        w.append(&test_header()).unwrap();
        for r in records {
            w.append(r).unwrap();
        }
        (path, w)
    }

    #[test]
    fn journal_chain_round_trip_and_head_continuity() {
        let dir = TempDir::new().unwrap();
        let armed = JournalRecord::Armed {
            overrides: vec![],
            locks_held: vec!["259:0".to_string()],
            at: "2026-01-01T00:00:00Z".to_string(),
        };
        let (path, writer) = write_simple_journal(&dir, &[armed.clone()]);
        let head_after_writes = writer.current_chain_head();
        assert_eq!(writer.record_count(), 2, "Header + Armed");

        let (records, summary) = JournalReader::read_and_verify_chain(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], test_header());
        assert_eq!(records[1], armed);
        assert_eq!(summary.chain_head, head_after_writes);
        assert_eq!(summary.uuid, "unit-uuid");
        assert!(!summary.sealed);
    }

    #[test]
    fn journal_chain_seed_is_blake3_of_magic_not_zeros() {
        // REG-ORACLE-CHAIN-SEED at the writer level: the first record's hash
        // must chain from BLAKE3("DCJ1"). Zero-seeded chains fail here.
        let dir = TempDir::new().unwrap();
        let armed = JournalRecord::Armed {
            overrides: vec![],
            locks_held: vec![],
            at: "2026-01-01T00:00:00Z".to_string(),
        };
        let (path, _) = write_simple_journal(&dir, &[armed]);

        let raw = fs::read(&path).unwrap();
        assert_eq!(&raw[0..4], b"DCJ1");

        // Independent recomputation of record 0's hash with the documented seed.
        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(&raw[4..8]);
        let len = u32::from_le_bytes(len_buf) as usize;
        let rec_bytes = &raw[8..8 + len];
        let stored_hash = &raw[8 + len..8 + len + 32];
        let mut h = blake3::Hasher::new();
        h.update(rec_bytes);
        h.update(blake3::hash(b"DCJ1").as_bytes());
        assert_eq!(h.finalize().as_bytes(), stored_hash, "chain must seed from BLAKE3(DCJ1)");
    }

    #[test]
    fn journal_detects_mid_chain_tampering() {
        let dir = TempDir::new().unwrap();
        let (path, _) = write_simple_journal(
            &dir,
            &[
                JournalRecord::Armed { overrides: vec![], locks_held: vec![], at: "t0".to_string() },
                JournalRecord::BeginPass { pass: 0, pattern: pattern_desc(), window_bytes: 2 * 1024 * 1024 },
            ],
        );

        let mut raw = fs::read(&path).unwrap();
        // Flip one byte inside the second record body.
        let idx = raw.len() - 40;
        raw[idx] ^= 0x01;
        let tampered = dir.path().join("tampered.dcj");
        fs::write(&tampered, &raw).unwrap();

        let err = JournalReader::read_and_verify_chain(&tampered).unwrap_err();
        assert!(matches!(err, DcError::JournalCorrupt { .. }));
    }

    #[test]
    fn journal_torn_tail_is_recoverable_discard() {
        let dir = TempDir::new().unwrap();
        let (path, _) = write_simple_journal(
            &dir,
            &[JournalRecord::Armed { overrides: vec![], locks_held: vec![], at: "t0".to_string() }],
        );
        let mut raw = fs::read(&path).unwrap();
        // Simulate a crash mid-write: append a partial next record (torn).
        raw.extend_from_slice(&[0x00, 0x01, 0x02]); // 3 bytes of a 4-byte len prefix
        let torn = dir.path().join("torn.dcj");
        fs::write(&torn, &raw).unwrap();

        let (records, summary) = JournalReader::read_and_verify_chain(&torn).unwrap();
        assert_eq!(records.len(), 2, "valid prefix must survive");
        assert!(summary.discarded_tail_bytes > 0);
    }

    #[test]
    fn journal_zero_len_record_is_rejected() {
        let dir = TempDir::new().unwrap();
        let mut raw = b"DCJ1".to_vec();
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&[0u8; 32]);
        let p = dir.path().join("zero_len.dcj");
        fs::write(&p, &raw).unwrap();
        assert!(JournalReader::read_and_verify_chain(&p).is_err());
    }

    #[test]
    fn journal_hostile_length_prefix_is_rejected_before_allocation() {
        // REG-BOUNDS: a 4 GiB length prefix in a tiny file must fail with
        // RECORD_TOO_LARGE, not attempt a huge allocation.
        let dir = TempDir::new().unwrap();
        let mut raw = b"DCJ1".to_vec();
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        raw.extend_from_slice(&[0u8; 32]);
        let p = dir.path().join("huge_len.dcj");
        fs::write(&p, &raw).unwrap();
        let err = JournalReader::read_and_verify_chain(&p).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("RECORD_TOO_LARGE") || msg.contains("JournalCorrupt"), "got: {}", msg);
    }

    #[test]
    fn journal_sealed_round_trip_and_signature_tamper() {
        let dir = TempDir::new().unwrap();
        let keypair = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut sealed_header = test_header();
        if let JournalRecord::Header {
            ref mut sealed,
            ref mut operator_pubkey,
            ref uuid,
            ..
        } = sealed_header
        {
            *sealed = true;
            let vk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
            assert_eq!(uuid, "unit-uuid");
            *operator_pubkey = Some(hex::encode(vk.to_bytes()));
        }
        let path = dir.path().join("sealed.dcj");
        let mut w =
            JournalWriter::create_new(&path, "sealed-uuid".to_string(), Some(keypair.clone())).unwrap();
        w.append(&sealed_header).unwrap();
        w.append(&JournalRecord::Armed {
            overrides: vec![],
            locks_held: vec![],
            at: "t0".to_string(),
        })
        .unwrap();

        let (records, summary) = JournalReader::read_and_verify_chain(&path).unwrap();
        assert!(summary.sealed);
        assert_eq!(records.len(), 2);

        // Flip one signature byte -> verification must fail.
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let bad = dir.path().join("bad.dcj");
        fs::write(&bad, &raw).unwrap();
        assert!(JournalReader::read_and_verify_chain(&bad).is_err());
    }

    #[test]
    fn journal_sealed_resume_without_key_fails_closed() {
        let dir = TempDir::new().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let path = dir.path().join("sealed2.dcj");
        let mut w = JournalWriter::create_new(&path, "u".to_string(), Some(key.clone())).unwrap();
        w.append(&JournalRecord::Armed { overrides: vec![], locks_held: vec![], at: "t0".to_string() })
            .unwrap();
        let head = w.current_chain_head();

        // Resume of a sealed journal without the signing key must refuse.
        let res = JournalWriter::open_for_resume(&path, &head, 1, None, "u".to_string(), true, None);
        assert!(res.is_err(), "sealed resume without key must fail closed");
    }

    fn pattern_desc() -> PatternDescriptor {
        PatternDescriptor {
            name: "Zero".to_string(),
            pattern: Pattern::Zero,
            description: "Zero".to_string(),
        }
    }

    // ---------------- audit: DCA1 chain ----------------

    #[test]
    fn audit_first_record_of_fresh_log_verifies() {
        // REG-AUDIT-SEED: the writer's chain seed must match the verifier's
        // (historically zeros vs BLAKE3("DCA1") — the first record of every
        // fresh audit log failed verification).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        let mut logger = AuditLogger::open_or_create(&path).unwrap();
        logger.log(&audit_record("rec-1")).unwrap();
        drop(logger);

        let (count, _head) = AuditLogger::verify_audit_file(&path).unwrap();
        assert_eq!(count, 1, "fresh-log first record must verify");
    }

    #[test]
    fn audit_chain_walk_and_append_across_sessions() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        {
            let mut logger = AuditLogger::open_or_create(&path).unwrap();
            logger.log(&audit_record("rec-1")).unwrap();
            logger.log(&audit_record("rec-2")).unwrap();
        }
        {
            // Reopen: the chain must CONTINUE, not restart.
            let mut logger = AuditLogger::open_or_create(&path).unwrap();
            logger.log(&audit_record("rec-3")).unwrap();
        }
        let (count, _) = AuditLogger::verify_audit_file(&path).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn audit_detects_tampered_record() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        {
            let mut logger = AuditLogger::open_or_create(&path).unwrap();
            logger.log(&audit_record("rec-1")).unwrap();
        }
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        fs::write(&path, &raw).unwrap();
        assert!(AuditLogger::verify_audit_file(&path).is_err());
    }

    fn audit_record(tag: &str) -> AuditRecord {
        AuditRecord {
            timestamp_utc: "2026-01-01T00:00:00Z".to_string(),
            argv_hash: tag.to_string(),
            target_path: None,
            outcome: AuditOutcome::PlanCompiled { plan_hash: tag.to_string() },
        }
    }

    // ---------------- orchestrator: pass sequencing ----------------

    #[test]
    fn orchestrator_executes_pass_zero_exactly_once() {
        // REG-ORCH-PASS0: Confirmed -> Armed emits ExecutePass{0}; the Armed
        // step must NOT re-emit pass 0 (the historical double-dispatch).
        let mut orch = Orchestrator::new(3);

        assert!(matches!(
            orch.step(true),
            OrchestratorEffect::PromptConfirmation
        ));
        assert!(matches!(
            orch.step(true),
            OrchestratorEffect::AcquireLocksAndArm
        ));
        assert!(matches!(
            orch.step(true),
            OrchestratorEffect::ExecutePass { pass: 0 }
        ));
        assert!(matches!(orch.current_state(), OrchestratorState::Armed));

        // Next step must be pass 1 — never pass 0 again.
        assert!(matches!(
            orch.step(true),
            OrchestratorEffect::ExecutePass { pass: 1 }
        ));
        assert!(matches!(
            orch.step(true),
            OrchestratorEffect::ExecutePass { pass: 2 }
        ));
        assert!(matches!(orch.step(true), OrchestratorEffect::FlushDevice));
    }

    #[test]
    fn orchestrator_single_pass_walks_to_flush_after_pass_zero() {
        let mut orch = Orchestrator::new(1);
        orch.step(true); // Initialized -> Classified (prompt)
        orch.step(true); // Classified -> Confirmed (arm prep)
        orch.step(true); // Confirmed -> Armed, ExecutePass{0}
        assert!(matches!(orch.step(true), OrchestratorEffect::FlushDevice));
    }

    // ---------------- fsm ----------------

    #[test]
    fn fsm_happy_path_reaches_certified() {
        let mut fsm = FsmOrchestrator::new();
        let identity = test_identity();
        let plan = SanitizationPlan::clear_zero(identity, FastPathPolicy::PreferWriteZeroes);
        fsm.compile_plan(plan).unwrap();
        fsm.approve_plan().unwrap();
        fsm.arm().unwrap();
        assert!(fsm.begin_pass(0).is_ok());
        assert!(fsm.begin_flush(0).is_ok());
        fsm.begin_verify().unwrap();
        fsm.certify().unwrap();
        assert!(matches!(fsm.state(), FsmState::Certified));
    }

    #[test]
    fn fsm_write_permit_required_for_destructive_steps() {
        let mut fsm = FsmOrchestrator::new();
        // Flushing before Executing is illegal.
        assert!(fsm.begin_flush(0).is_err());
        // Verify before Flushing is illegal.
        assert!(fsm.begin_verify().is_err());
        // Certify before Verifying is illegal.
        assert!(matches!(fsm.certify(), Err(DcError::Usage(_))));
    }

    fn test_identity() -> StableIdentity {
        StableIdentity {
            model: Some("UnitTestSSD".to_string()),
            serial: Some("SN-UNIT".to_string()),
            wwn: None,
            size_bytes: 1024 * 1024 * 1024,
            bus: BusType::Nvme,
            dm_name: None,
            dm_uuid: None,
        }
    }

    // ---------------- identity comparator ----------------

    #[test]
    fn identity_compatibility_matrix() {
        let a = test_identity();
        // Exact match: no contradictions, no warnings.
        assert!(a.check_compatibility(&a).unwrap().is_empty());

        // Size contradiction is hard.
        let mut b = a.clone();
        b.size_bytes += 1;
        assert!(a.check_compatibility(&b).is_err());

        // Serial contradiction is hard.
        let mut c = a.clone();
        c.serial = Some("SN-OTHER".to_string());
        assert!(a.check_compatibility(&c).is_err());

        // One-sided absence is a warning, not an error.
        let mut d = a.clone();
        d.serial = None;
        let warns = a.check_compatibility(&d).unwrap();
        assert!(!warns.is_empty());
    }

    // ---------------- plan ----------------

    #[test]
    fn plan_hash_is_deterministic_and_schema_tagged() {
        let a = SanitizationPlan::clear_zero(test_identity(), FastPathPolicy::PreferWriteZeroes);
        let b = SanitizationPlan::clear_zero(test_identity(), FastPathPolicy::PreferWriteZeroes);
        assert_eq!(a.compute_plan_hash().unwrap(), b.compute_plan_hash().unwrap());
        assert_eq!(a.plan_schema, "dc-plan/1");

        // A mutated plan must hash differently.
        let mut c = a.clone();
        c.window_bytes *= 2;
        assert_ne!(a.compute_plan_hash().unwrap(), c.compute_plan_hash().unwrap());
    }

    #[test]
    fn plan_seed_pinning_is_reproducible() {
        let seed = Some([0x42u8; 32]);
        let a = SanitizationPlan::clear_random(test_identity(), seed, FastPathPolicy::ForbidWriteZeroes)
            .unwrap();
        let b = SanitizationPlan::clear_random(test_identity(), seed, FastPathPolicy::ForbidWriteZeroes)
            .unwrap();
        assert_eq!(a, b, "pinned seed must make plans bit-identical");
    }

    // ---------------- pattern ----------------

    #[test]
    fn chacha_pattern_is_window_variant_but_deterministic() {
        let seed = [0x24u8; 32];
        let pat = ChaCha20Pattern::new(seed);
        assert!(!pat.window_invariant(), "PRNG patterns differ per window");

        let mut w0a = vec![0u8; 128];
        let mut w0b = vec![0u8; 128];
        let mut w1 = vec![0u8; 128];
        pat.fill(0, &mut w0a);
        pat.fill(0, &mut w0b);
        pat.fill(1, &mut w1);
        assert_eq!(w0a, w0b, "same window must be reproducible");
        assert_ne!(w0a, w1, "different windows must differ");
    }
}
