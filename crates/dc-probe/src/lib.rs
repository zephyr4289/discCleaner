pub mod classify;
pub mod guardian;
pub mod identity;
pub mod inventory;
pub mod layer_stack;
pub mod sniff;

pub use classify::{classify_pure, BlockTree, DeviceNode};
pub use guardian::{Guardian, GuardianFlags, GuardianLockHandle};
pub use identity::{IdentityComparison, IdentityComparator};
pub use inventory::InventoryScanner;
pub use layer_stack::{LayerStackDetector, MountEntry};
pub use sniff::{Sniffer, StorageSignature};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_name_detection() {
        assert!(Guardian::is_partition_name("sda1"));
        assert!(Guardian::is_partition_name("sdb2"));
        assert!(Guardian::is_partition_name("nvme0n1p1"));
        assert!(Guardian::is_partition_name("mmcblk0p1"));
        assert!(Guardian::is_partition_name("loop0p1"));

        assert!(!Guardian::is_partition_name("sda"));
        assert!(!Guardian::is_partition_name("sdb"));
        assert!(!Guardian::is_partition_name("nvme0n1"));
        assert!(!Guardian::is_partition_name("mmcblk0"));
        assert!(!Guardian::is_partition_name("loop0"));
    }
}
