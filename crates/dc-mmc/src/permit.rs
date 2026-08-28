use dc_nvme::PurgePermit;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigTransactionPermit {
    pub target_device: String,
    pub target_serial: String,
    pub authorized_at_utc: u64,
}

impl ConfigTransactionPermit {
    /// Derive a single-use configuration transaction permit from an armed PurgePermit (Δ349).
    pub fn derive(permit: &PurgePermit) -> Self {
        Self {
            target_device: permit.target_device.clone(),
            target_serial: permit.target_serial.clone(),
            authorized_at_utc: permit.authorized_at_utc,
        }
    }
}

pub struct ConfigTxnGuard<'a> {
    pub permit: &'a ConfigTransactionPermit,
    pub original_partition_config: u8,
    pub current_partition_config: &'a mut u8,
    pub committed: bool,
}

impl<'a> ConfigTxnGuard<'a> {
    pub fn new(
        permit: &'a ConfigTransactionPermit,
        current_config: &'a mut u8,
    ) -> Self {
        let original = *current_config;
        Self {
            permit,
            original_partition_config: original,
            current_partition_config: current_config,
            committed: false,
        }
    }

    /// Commit the transaction and mark it as safely completed.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl<'a> Drop for ConfigTxnGuard<'a> {
    fn drop(&mut self) {
        // Enforce Drop-path no-harm restore on early exit or panic (Δ349, INV11)
        if !self.committed {
            *self.current_partition_config = self.original_partition_config;
        }
    }
}
