use serde::{Deserialize, Serialize};

/// Physical access class for an eMMC/SD target (Δ337).
///
/// Determines which purge vocabulary is honestly certifiable:
/// - `NativeController`: the kernel MMC subsystem is directly reachable
///   (e.g. `/dev/mmcblk0`), so boot-partition switching, secure trim and
///   CMD38 SANITIZE are executable.
/// - `ReaderMediated`: the media sits behind a USB reader that abstracts
///   the controller away; only user-area access is possible and the
///   certificate must reflect the degraded scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmcAccessClass {
    NativeController,
    ReaderMediated,
}

/// Write PARTITION_CONFIG (byte 179) preserving adjacent bits.
/// Bits [2:0] = PARTITION_ACCESS (target partition).
/// Bits [5:3] = BOOT_PARTITION_ENABLE (preserved).
/// Bit [6]    = BOOT_ACK (preserved).
pub fn write_partition_config(current_val: u8, target_part_access: u8) -> u8 {
    let preserved_mask = 0b1111_1000; // preserve bits 7..3
    let preserved_bits = current_val & preserved_mask;
    let new_access_bits = target_part_access & 0b0000_0111;
    preserved_bits | new_access_bits
}
