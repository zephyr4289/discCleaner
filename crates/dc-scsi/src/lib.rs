pub mod preflight;
pub mod purge;
pub mod timing;
pub mod transport;
pub mod ufs;

pub use preflight::{ConsistencyReport, PreflightBattery};
pub use purge::{
    LinuxScsiPurge, ScsiCompletionEvidence, ScsiMechanismFallback, ScsiPurgeClient,
    ScsiPurgeExecutionSummary, ScsiPurgeMechanism, ScsiPurgePermit, ScsiPurgeTransport, ScsiReply,
    ScsiXfer,
};
pub use timing::TimingIntegrity;
pub use transport::{ProtocolRoute, ScsiSession};
pub use ufs::UfsSessionDiscriminator;

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn preflight_flags_capacity_masking_bridges() {
        // A USB bridge that under-reports capacity must be disclosed.
        let report = PreflightBattery::check_single_path_consistency(1_000_000, 500_000);
        assert!(!report.is_consistent);
        assert!(report.ceiling_disclosed);
        assert!(report.detail.contains("CAPACITY_MASK"));

        let clean = PreflightBattery::check_single_path_consistency(1_000_000, 1_000_000);
        assert!(clean.is_consistent);
        assert!(!clean.ceiling_disclosed);
    }

    #[test]
    fn timing_integrity_flags_impossible_durations() {
        // Instant completion of a 90-second mechanism = mangled evidence.
        assert!(
            TimingIntegrity::check_mechanism_duration("ScsiSanitizeBlockErase", 250, 90_000)
                .is_err()
        );
        // Plausible durations pass.
        assert!(TimingIntegrity::check_mechanism_duration(
            "ScsiSanitizeBlockErase",
            95_000,
            90_000
        )
        .is_ok());
    }

    #[test]
    fn block_node_enforcement_rejects_sg_character_nodes() {
        // REG-SCSI-SG-NODE: /dev/sg* is the UNCOVERED DOOR and must be refused.
        assert!(ScsiSession::open_block_node("/dev/sg0", false, false).is_err());
        // /dev/sdb is a block node and is acceptable to open.
        assert!(ScsiSession::open_block_node("/dev/sdb", false, false).is_ok());
    }
}
