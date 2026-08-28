use crate::ata_lying::BridgeLieClass;
use crate::matrix::BridgeClassification;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationChannel {
    CommandPath,
    DualPath,
    SmartDelta,
    Timing,
    StatusLogSense,
}

pub struct ProbeBattery;

impl ProbeBattery {
    /// Dual-path observation law: compare direct-SATA native geometry against bridged USB geometry (Δ299).
    pub fn check_capacity_mask(
        direct_sata_lba: u64,
        bridged_usb_lba: u64,
        channel: ObservationChannel,
    ) -> Result<(), BridgeClassification> {
        if direct_sata_lba != bridged_usb_lba {
            return Err(BridgeClassification::Lie {
                class: BridgeLieClass::Mangle, // Masks or clips capacity
                detail: format!(
                    "CAPACITY_MASK detected: Direct LBA={}, Bridged LBA={}, via {:?}",
                    direct_sata_lba, bridged_usb_lba, channel
                ),
            });
        }
        Ok(())
    }
}
