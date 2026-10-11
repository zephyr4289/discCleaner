pub mod access;
pub mod client;
pub mod confirm;
pub mod permit;

pub use access::{write_partition_config, MmcAccessClass};
pub use client::{MmcPurgeClient, MmcPurgeExecutionSummary};
pub use confirm::TwoAxisConfirmation;
pub use permit::{ConfigTransactionPermit, ConfigTxnGuard};

// ---------------------------------------------------------------------------
// Unit test layer
// ---------------------------------------------------------------------------
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn two_axis_reconciliation_detects_scope_drift() {
        let conf =
            TwoAxisConfirmation::new("CID_0xABC", vec!["user".to_string(), "boot0".to_string()]);
        // Exact scope: OK.
        assert!(conf
            .reconcile_executed_scope(&["user".to_string(), "boot0".to_string()])
            .is_ok());
        // Unconfirmed partition executed: refusal.
        assert!(conf
            .reconcile_executed_scope(&["user".to_string(), "rpmb".to_string()])
            .is_err());
        // Confirmed partition missing from execution: refusal.
        assert!(conf
            .reconcile_executed_scope(&["user".to_string()])
            .is_err());
    }

    #[test]
    fn partition_config_preserves_adjacent_bits() {
        // Bits [5:3] BOOT_PARTITION_ENABLE and bit 6 BOOT_ACK must survive a
        // PARTITION_ACCESS update (Δ340).
        let initial = 0b0100_1000u8; // BOOT_ACK=1, BOOT_PART=1, ACCESS=0
        let updated = write_partition_config(initial, 0b101);
        assert_eq!(
            updated, 0b0100_1101,
            "access bits replaced, boot bits preserved"
        );
    }

    #[test]
    fn access_class_is_production_vocabulary() {
        // REG-MMC-LAYERING: the enum now lives in dc-mmc (production) and the
        // testkit re-exports it; a production build must never depend on
        // dc-testkit for this type.
        assert_eq!(
            MmcAccessClass::NativeController,
            MmcAccessClass::NativeController
        );
        assert_ne!(
            MmcAccessClass::NativeController,
            MmcAccessClass::ReaderMediated
        );
    }
}
