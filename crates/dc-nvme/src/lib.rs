pub mod permit;
pub mod purge;
pub mod transport;

pub use permit::PurgePermit;
pub use purge::{
    CompletionEvidence, MechanismFallback, NvmePurgeClient, PurgeExecutionSummary,
    PurgeMechanism,
};
pub use transport::{ErrnoClassifier, IoctlTaxonomy, NvmeAdminTransport};

// ---------------------------------------------------------------------------
// Unit test layer
// ---------------------------------------------------------------------------
#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::time::Duration;

    struct TerminalTransport;
    impl NvmeAdminTransport for TerminalTransport {
        fn admin_passthrough(&mut self, cmd: &[u8; 64]) -> Result<Vec<u8>, IoctlTaxonomy> {
            match cmd[0] {
                0x84 => Ok(vec![]),              // Sanitize accepted
                0x02 => {                        // Get Log Page 0x81
                    let mut log = vec![0u8; 512];
                    log[0..2].copy_from_slice(&65535u16.to_le_bytes()); // SPROG full
                    log[2..4].copy_from_slice(&1u16.to_le_bytes());     // SSTAT completed
                    Ok(log)
                }
                _ => Ok(vec![]),
            }
        }
    }

    struct InProgressTransport;
    impl NvmeAdminTransport for InProgressTransport {
        fn admin_passthrough(&mut self, cmd: &[u8; 64]) -> Result<Vec<u8>, IoctlTaxonomy> {
            match cmd[0] {
                0x84 => Ok(vec![]),
                0x02 => {
                    let mut log = vec![0u8; 512];
                    log[0..2].copy_from_slice(&1000u16.to_le_bytes());
                    log[2..4].copy_from_slice(&2u16.to_le_bytes()); // in progress
                    Ok(log)
                }
                _ => Ok(vec![]),
            }
        }
    }

    struct RejectAllSanitize;
    impl NvmeAdminTransport for RejectAllSanitize {
        fn admin_passthrough(&mut self, cmd: &[u8; 64]) -> Result<Vec<u8>, IoctlTaxonomy> {
            match cmd[0] {
                0x84 | 0x80 => Err(IoctlTaxonomy::ControllerRejected {
                    errno: libc::EIO,
                    description: "unsupported".to_string(),
                }),
                _ => Ok(vec![]),
            }
        }
    }

    fn permit() -> PurgePermit {
        PurgePermit::mint("/dev/nvme0n3", "SN-X", 1724890000)
    }

    #[test]
    fn errno_taxonomy_maps_kernel_errnos() {
        assert!(matches!(ErrnoClassifier::classify(0), IoctlTaxonomy::Success));
        assert!(matches!(ErrnoClassifier::classify(libc::EIO), IoctlTaxonomy::ControllerRejected { .. }));
        assert!(matches!(ErrnoClassifier::classify(libc::EFAULT), IoctlTaxonomy::OurBug { .. }));
        assert!(matches!(ErrnoClassifier::classify(libc::ETIMEDOUT), IoctlTaxonomy::TimeoutAmbiguous { .. }));
        assert!(matches!(ErrnoClassifier::classify(libc::ENOSYS), IoctlTaxonomy::UnmappedLoud { .. }));
    }

    #[test]
    fn sanitize_crypto_erase_requires_terminal_status() {
        // REG-NVME-FABRICATED-COMPLETION: Ok is only possible on terminal
        // SSTAT; an in-progress stream must eventually refuse, never report
        // completion.
        let mut t = InProgressTransport;
        let mut client = NvmePurgeClient::new(&mut t).with_poll_budget(3, Duration::from_millis(0));
        let res = client.execute_purge_ladder(&permit(), PurgeMechanism::SanitizeCryptoErase);
        let err = res.unwrap_err();
        assert!(err.contains("SANITIZE_INCOMPLETE"), "got: {}", err);
    }

    #[test]
    fn sanitize_terminal_status_completes_cleanly() {
        let mut t = TerminalTransport;
        let mut client = NvmePurgeClient::new(&mut t);
        let summary = client
            .execute_purge_ladder(&permit(), PurgeMechanism::SanitizeCryptoErase)
            .unwrap();
        assert!(summary.status.is_completed);
        assert_eq!(summary.fallbacks.len(), 0);
        assert_eq!(summary.completion_evidence(), CompletionEvidence::SanitizeStatusLog);
    }

    #[test]
    fn ladder_falls_back_on_controller_rejection() {
        let mut t = RejectAllSanitize;
        let mut client = NvmePurgeClient::new(&mut t)
            .with_poll_budget(2, Duration::from_millis(0));
        let res = client.execute_purge_ladder(&permit(), PurgeMechanism::SanitizeCryptoErase);
        let err = res.unwrap_err();
        assert!(err.contains("LOGICAL_OVERWRITE_NOT_ADMIN_EXECUTABLE"), "got: {}", err);
    }

    #[test]
    fn nsid_is_derived_from_permit_not_hardcoded() {
        // REG-NVME-NSID: /dev/nvme0n3 must format namespace 3.
        assert_eq!(NvmePurgeClient::nsid_of_target("/dev/nvme0n3"), 3);
        assert_eq!(NvmePurgeClient::nsid_of_target("/dev/nvme0"), 1);
    }

    #[test]
    fn permit_binds_target_and_serial() {
        let p = permit();
        assert_eq!(p.target_device, "/dev/nvme0n3");
        assert_eq!(p.target_serial, "SN-X");
        assert_eq!(p.authorized_at_utc, 1724890000);
    }
}
