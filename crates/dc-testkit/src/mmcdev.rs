use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmcAccessClass {
    NativeController,
    ReaderMediated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmcPartitionDisposition {
    Wiped { mechanism: String },
    WriteProtectedPermanent { detail: String },
    KeyProtectedInaccessible { detail: String }, // Mandatory vocabulary for RPMB
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmcPartitionMap {
    pub user_area: MmcPartitionDisposition,
    pub boot0: MmcPartitionDisposition,
    pub boot1: MmcPartitionDisposition,
    pub rpmb: MmcPartitionDisposition,
}

impl MmcPartitionMap {
    /// Calculate the honest scope certification (Δ339, INV16-mmc).
    pub fn derive_scope_verdict(&self) -> &'static str {
        let is_user_wiped = matches!(self.user_area, MmcPartitionDisposition::Wiped { .. });
        let is_boot0_wiped = matches!(self.boot0, MmcPartitionDisposition::Wiped { .. });
        let is_boot1_wiped = matches!(self.boot1, MmcPartitionDisposition::Wiped { .. });
        let is_rpmb_honest = matches!(self.rpmb, MmcPartitionDisposition::KeyProtectedInaccessible { .. });

        if is_user_wiped && is_boot0_wiped && is_boot1_wiped && is_rpmb_honest {
            "DEVICE_PURGE_COMPLETE"
        } else if is_user_wiped {
            "USER_AREA_ONLY_CLEAR_SCOPE"
        } else {
            "UNSANITIZED"
        }
    }
}

pub struct ExtCsdRegister;

impl ExtCsdRegister {
    /// Read-modify-write PARTITION_CONFIG (byte 179) preserving adjacent bits (Δ340).
    /// Bits [2:0] = PARTITION_ACCESS (target partition).
    /// Bits [5:3] = BOOT_PARTITION_ENABLE (preserved!).
    /// Bit [6]   = BOOT_ACK (preserved!).
    pub fn write_partition_config(current_val: u8, target_part_access: u8) -> u8 {
        let preserved_mask = 0b1111_1000; // Preserve bits 7..3
        let preserved_bits = current_val & preserved_mask;
        let new_access_bits = target_part_access & 0b0000_0111;
        preserved_bits | new_access_bits
    }
}

pub struct MmcDevMock {
    pub access_class: MmcAccessClass,
    pub partition_config_byte: u8,
    pub partition_map: MmcPartitionMap,
}

impl MmcDevMock {
    pub fn new(access_class: MmcAccessClass) -> Self {
        Self {
            access_class,
            partition_config_byte: 0b0100_1000, // Boot ACK=1, Boot Partition 1 enabled, Access=User
            partition_map: MmcPartitionMap {
                user_area: MmcPartitionDisposition::Wiped { mechanism: "MmcSanitize".to_string() },
                boot0: MmcPartitionDisposition::Wiped { mechanism: "MmcSecureTrim".to_string() },
                boot1: MmcPartitionDisposition::Wiped { mechanism: "MmcSecureTrim".to_string() },
                rpmb: MmcPartitionDisposition::KeyProtectedInaccessible {
                    detail: "RPMB key-protected authenticated storage (not sanitized)".to_string(),
                },
            },
        }
    }

    /// Select physical partition target via register transaction (Δ340).
    pub fn switch_partition(&mut self, target_access_bits: u8) {
        self.partition_config_byte = ExtCsdRegister::write_partition_config(
            self.partition_config_byte,
            target_access_bits,
        );
    }
}
