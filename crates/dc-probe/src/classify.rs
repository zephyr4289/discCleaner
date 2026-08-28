use crate::guardian::GuardianFlags;
use dc_core::GuardianRefusal;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceNode {
    pub name: String,
    pub maj_min: (u32, u32),
    pub size_bytes: u64,
    pub is_partition: bool,
    pub is_ram_backed: bool,
    pub is_zoned: bool,
    pub is_read_only: bool,
    pub mounts: Vec<String>,
    pub holders: Vec<String>,
    pub swap_active: bool,
    pub active_lvm: bool,
    pub active_md: bool,
    pub active_crypt: bool,
    pub is_loop: bool,
    pub inactive_sig: Option<String>,
    pub is_member: bool,
}

#[derive(Clone, Debug, Default)]
pub struct BlockTree {
    pub nodes: BTreeMap<String, DeviceNode>,
}

pub fn classify_pure(target_name: &str, tree: &BlockTree, flags: &GuardianFlags) -> Result<(), GuardianRefusal> {
    let node = match tree.nodes.get(target_name) {
        Some(n) => n,
        None => {
            return Err(GuardianRefusal {
                code: "DEVICE_NOT_FOUND",
                detail: format!("Target device '{}' not found in block device tree.", target_name),
                hint: "Ensure the device exists and is visible in /sys/block/.".to_string(),
            });
        }
    };

    // 1. SIZE_ANOMALY
    if node.size_bytes < 1024 * 1024 {
        return Err(GuardianRefusal {
            code: "SIZE_ANOMALY",
            detail: format!("Device size is suspiciously small: {} bytes", node.size_bytes),
            hint: "Device must be at least 1 MiB in capacity.".to_string(),
        });
    }

    // 2. NOT_WHOLE_DISK
    if node.is_partition {
        return Err(GuardianRefusal {
            code: "NOT_WHOLE_DISK",
            detail: format!("Target '{}' is a partition, not a whole disk block device.", node.name),
            hint: "Target the parent drive instead (e.g. /dev/sda instead of /dev/sda1).".to_string(),
        });
    }

    // 3. RAM_BACKED
    if node.is_ram_backed {
        return Err(GuardianRefusal {
            code: "RAM_BACKED",
            detail: format!("Device '{}' is a RAM-backed volatile block device.", node.name),
            hint: "RAM devices disappear upon reboot and cannot be sanitized as physical media.".to_string(),
        });
    }

    // 4. ZONED
    if node.is_zoned {
        return Err(GuardianRefusal {
            code: "ZONED",
            detail: format!("Device '{}' is a host-managed/aware zoned device (SMR).", node.name),
            hint: "Zoned storage wiping requires a sequential zone-reset engine (Phase 3).".to_string(),
        });
    }

    // 5. READ_ONLY
    if node.is_read_only {
        return Err(GuardianRefusal {
            code: "READ_ONLY",
            detail: format!("Device '{}' is marked read-only by hardware switch or kernel.", node.name),
            hint: "Disable hardware write-protect switch or run 'blockdev --setrw'.".to_string(),
        });
    }

    // 6. MULTIPATH_PATH
    if node.name.contains('c') && node.name.starts_with("nvme") && node.name.contains('n') {
        return Err(GuardianRefusal {
            code: "MULTIPATH_PATH",
            detail: format!("Target '{}' appears to be an NVMe controller multipath sub-handle.", node.name),
            hint: "Target the base namespace instead (e.g. /dev/nvme0n1).".to_string(),
        });
    }

    // 7. SYSTEM_DISK & 8. MOUNTED
    if !node.mounts.is_empty() {
        let is_system = node.mounts.iter().any(|m| m == "/" || m == "/boot" || m == "/boot/efi" || m == "/home" || m == "/usr" || m == "/var" || m == "/etc");
        if is_system {
            if !flags.allow_system_disk {
                return Err(GuardianRefusal {
                    code: "SYSTEM_DISK",
                    detail: format!("Target '{}' contains critical active system mount points: {:?}", node.name, node.mounts),
                    hint: "Refusing to destroy operating system root disk. Requires explicit override.".to_string(),
                });
            }
        } else {
            return Err(GuardianRefusal {
                code: "MOUNTED",
                detail: format!("Target '{}' (or one of its partitions) is currently mounted on {:?}", node.name, node.mounts),
                hint: "Unmount all partitions on this device before proceeding.".to_string(),
            });
        }
    }

    // 9. SWAP_ACTIVE
    if node.swap_active {
        return Err(GuardianRefusal {
            code: "SWAP_ACTIVE",
            detail: format!("Target '{}' (or one of its partitions) is an active Linux swap area.", node.name),
            hint: "Run 'swapoff' on the active partition before proceeding.".to_string(),
        });
    }

    // 10. LVM_ACTIVE
    if node.active_lvm {
        return Err(GuardianRefusal {
            code: "LVM_ACTIVE",
            detail: format!("Target '{}' is an active LVM Physical Volume with active Logical Volumes.", node.name),
            hint: "Deactivate active LVM volume groups ('vgchange -an') before wiping.".to_string(),
        });
    }

    // 11. MD_ACTIVE
    if node.active_md {
        return Err(GuardianRefusal {
            code: "MD_ACTIVE",
            detail: format!("Target '{}' is an active member of a Linux MD software RAID array.", node.name),
            hint: "Stop the MD RAID array ('mdadm --stop') before proceeding.".to_string(),
        });
    }

    // 12. CRYPT_ACTIVE
    if node.active_crypt {
        return Err(GuardianRefusal {
            code: "CRYPT_ACTIVE",
            detail: format!("Target '{}' is backing an active mapped LUKS device.", node.name),
            hint: "Close the active dm-crypt mapping ('cryptsetup close') before wiping.".to_string(),
        });
    }

    // 13. HOLDERS_PRESENT
    if !node.holders.is_empty() {
        return Err(GuardianRefusal {
            code: "HOLDERS_PRESENT",
            detail: format!("Target '{}' has active kernel device holders: {:?}", node.name, node.holders),
            hint: "Deactivate upper-layer kernel devices before wiping.".to_string(),
        });
    }

    // 14. LOOP_BACKED
    if node.is_loop && !flags.allow_loop {
        return Err(GuardianRefusal {
            code: "LOOP_BACKED",
            detail: format!("Target '{}' is a loopback virtual block device.", node.name),
            hint: "Pass '--allow-loop' if testing against virtual disk files.".to_string(),
        });
    }

    // 15. INACTIVE_SIGNATURES
    if let Some(ref sig) = node.inactive_sig {
        if !flags.allow_inactive_signatures {
            return Err(GuardianRefusal {
                code: "INACTIVE_SIGNATURES",
                detail: format!("Target '{}' contains inactive/dormant storage signature: {}", node.name, sig),
                hint: "Pass '--allow-inactive-signatures' to overwrite recognized dormant signatures.".to_string(),
            });
        }
    }

    // 16. RETIRED_MEMBER
    if node.is_member && !flags.allow_member {
        return Err(GuardianRefusal {
            code: "RETIRED_MEMBER",
            detail: format!("Target '{}' was previously part of an LVM Volume Group or MD RAID array.", node.name),
            hint: "Pass '--allow-member' to allow wiping retired array members.".to_string(),
        });
    }

    Ok(())
}
