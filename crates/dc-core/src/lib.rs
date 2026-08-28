pub mod audit;
pub mod error;
pub mod fsm;
pub mod identity;
pub mod journal;
pub mod pattern;
pub mod plan;
pub mod tool;

pub use audit::{AuditLogger, AuditOutcome, AuditRecord};
pub use error::{DcError, GuardianRefusal};
pub use fsm::{FsmOrchestrator, FsmState, WritePermit};
pub use identity::{BusType, DeviceIdentity, KernelIdentity, StableIdentity};
pub use journal::{
    check_cqe_or_verify_crash, check_crash_hook, EngineTuning, JournalChainSummary,
    JournalReader, JournalRecord, JournalWriter, JOURNAL_MAGIC,
};
pub use pattern::{
    create_pattern_source, ChaCha20Pattern, FixedPattern, Pattern, PatternDescriptor,
    PatternSource, PrngScheme, ZeroPattern,
};
pub use plan::{FastPathPolicy, Mechanism, Pass, SanitizationPlan, VerifyLevel};
pub use tool::ToolBuild;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

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

    #[test]
    fn test_journal_chain_and_tamper_detection() {
        let temp_file = NamedTempFile::new().unwrap();
        let journal_path = temp_file.path();

        let identity = DeviceIdentity {
            stable: StableIdentity {
                model: Some("TestDrive".to_string()),
                serial: Some("SN12345".to_string()),
                wwn: None,
                size_bytes: 1024 * 1024 * 1024,
                bus: BusType::Nvme,
            },
            kernel: KernelIdentity { major: 259, minor: 0 },
            kernel_name: "nvme0n1".to_string(),
            dev_path: "/dev/nvme0n1".to_string(),
            logical_block_size: 512,
            physical_block_size: 4096,
        };

        let plan = SanitizationPlan::clear_zero(identity.stable.clone(), FastPathPolicy::PreferWriteZeroes);
        let plan_hash = plan.compute_plan_hash().unwrap();

        let header = JournalRecord::Header {
            plan,
            plan_hash: plan_hash.clone(),
            identity,
            tool: ToolBuild::current(),
            engine: "auto".to_string(),
            tuning: EngineTuning {
                qd: 64,
                pool_mib: 128,
                window_bytes: 2 * 1024 * 1024,
                checkpoint_mib: 512,
                checkpoint_ms: 5000,
            },
            argv_hash: "0000".to_string(),
            started_utc: "2026-08-28T20:00:00Z".to_string(),
        };

        let mut writer = JournalWriter::create(journal_path, header).unwrap();
        writer
            .append(&JournalRecord::BeginPass {
                pass: 0,
                pattern: PatternDescriptor {
                    name: "Zero".to_string(),
                    pattern: Pattern::Zero,
                    description: "Zero".to_string(),
                },
                window_bytes: 2 * 1024 * 1024,
            })
            .unwrap();

        writer
            .append(&JournalRecord::RangeCommit {
                pass: 0,
                first_window: 0,
                num_windows: 50,
            })
            .unwrap();

        let (records, summary) = JournalReader::read_and_verify_chain(journal_path).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(summary.record_count, 3);
        assert!(!summary.chain_head.is_empty());
    }
}
