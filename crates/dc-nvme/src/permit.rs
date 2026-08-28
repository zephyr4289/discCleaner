use serde::{Deserialize, Serialize};

/// Typestate token authorizing destructive hardware purge execution (INV11, Δ272).
/// Structurally required by all destructive NVMe sanitize/format APIs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PurgePermit {
    pub target_device: String,
    pub target_serial: String,
    pub authorized_at_utc: u64,
}

impl PurgePermit {
    /// Mint an authorized purge permit for an armed target.
    pub fn mint(target_device: &str, target_serial: &str, timestamp_utc: u64) -> Self {
        Self {
            target_device: target_device.to_string(),
            target_serial: target_serial.to_string(),
            authorized_at_utc: timestamp_utc,
        }
    }
}
