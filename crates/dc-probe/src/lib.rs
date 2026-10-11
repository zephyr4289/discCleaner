pub mod bootfacts;
pub mod classify;
pub mod graph;
pub mod guardian;
pub mod identity;
pub mod inventory;
pub mod layer_stack;
pub mod sniff;

pub use bootfacts::{BootAttestation, BootAttestor, ReadOnlyCandidate};
pub use classify::{classify_pure, BlockTree, DeviceNode};
pub use graph::{BlockGraph, DangerHop, DangerPath, WalkOutcome};
pub use guardian::{Guardian, GuardianFlags, GuardianLockHandle};
pub use identity::{IdentityComparator, IdentityComparison};
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

// ---------------------------------------------------------------------------
// Unit test layer
// ---------------------------------------------------------------------------
#[cfg(test)]
mod unit_tests {
    use super::*;

    // ---------------- Guardian: pure name-classification rules ----------------

    #[test]
    fn partition_name_matrix_separates_disks_from_partitions() {
        // REG-PARTITION-NAME: "loop0" is a WHOLE DISK (the 'p' inside "loop"
        // is part of the driver name, not a partition separator).
        for disk in ["sda", "sdb", "nvme0n1", "nvme10n2", "mmcblk0", "loop0", "loop7", "zram0", "vda", "hdа".replace('а', "a").as_str()] {
            assert!(!Guardian::is_partition_name(disk), "{} is a whole disk", disk);
        }
        for part in ["sda1", "sdb12", "nvme0n1p1", "nvme0n1p12", "mmcblk0p2", "loop0p1", "vda3"] {
            assert!(Guardian::is_partition_name(part), "{} is a partition", part);
        }
    }

    #[test]
    fn guardian_refuses_ram_backed_devices() {
        use dc_core::{BusType, DeviceIdentity, KernelIdentity, StableIdentity};
        let mk = |name: &str| DeviceIdentity {
            stable: StableIdentity {
                model: None,
                serial: Some("SN".to_string()),
                wwn: None,
                size_bytes: 512 * 1024 * 1024,
                bus: BusType::Unknown,
                dm_name: None,
                dm_uuid: None,
            },
            kernel: KernelIdentity { major: 254, minor: 0 },
            kernel_name: name.to_string(),
            dev_path: format!("/dev/{}", name),
            logical_block_size: 512,
            physical_block_size: 512,
        };

        for (name, code) in [("zram0", "RAM_BACKED"), ("ram1", "RAM_BACKED"), ("loop0", "LOOP")] {
            let flags = GuardianFlags {
                allow_system_disk: false,
                serial_confirm: None,
                allow_loop: false,
                allow_inactive_signatures: true,
                allow_member: true,
            };
            let err = Guardian::evaluate(std::path::Path::new(&format!("/dev/{}", name)), &mk(name), &flags)
                .unwrap_err();
            match err {
                dc_core::DcError::Guardian(ref g) => assert_eq!(g.code, code, "for {}", name),
                other => panic!("expected Guardian refusal for {}, got {:?}", name, other),
            }
        }
    }
}
