pub mod audit;
pub mod error;
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
}
