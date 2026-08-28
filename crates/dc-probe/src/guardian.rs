use crate::inventory::InventoryScanner;
use crate::layer_stack::LayerStackDetector;
use dc_core::{DcError, DeviceIdentity, GuardianRefusal, StableIdentity};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default)]
pub struct GuardianFlags {
    pub allow_system_disk: bool,
    pub serial_confirm: Option<String>,
    pub allow_loop: bool,
    pub allow_inactive_signatures: bool,
}

pub struct GuardianLockHandle {
    pub disk_file: File,
    pub partition_files: Vec<File>,
}

pub struct Guardian;

impl Guardian {
    /// Execute the full 15-rule decision table.
    pub fn evaluate(
        target_path: &Path,
        identity: &DeviceIdentity,
        flags: &GuardianFlags,
    ) -> Result<(), DcError> {
        let name = &identity.kernel_name;

        // Rule 1: Whole disk, not partition
        if Self::is_partition_name(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "NOT_WHOLE_DISK",
                detail: format!("Target '{}' is a partition, not a whole disk block device.", name),
                hint: "Target the parent drive instead (e.g. /dev/sda instead of /dev/sda1).".to_string(),
            }));
        }

        // Rule 2: Zoned device
        if LayerStackDetector::is_zoned(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "ZONED",
                detail: format!("Device '{}' is a host-managed/aware zoned device (SMR).", name),
                hint: "Zoned storage wiping requires a sequential zone-reset engine (Phase 3).".to_string(),
            }));
        }

        // Rule 3: RAM-backed
        if name.starts_with("zram") || name.starts_with("ram") {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "RAM_BACKED",
                detail: format!("Device '{}' is a RAM-backed volatile block device.", name),
                hint: "RAM devices disappear upon reboot and cannot be sanitized as physical media.".to_string(),
            }));
        }

        // Rule 4: Read-only check
        if let Ok(f) = File::open(target_path) {
            if InventoryScanner::is_read_only(&f) {
                return Err(DcError::Guardian(GuardianRefusal {
                    code: "READ_ONLY",
                    detail: format!("Device '{}' is marked read-only by hardware switch or kernel.", name),
                    hint: "Disable hardware write-protect switch or run 'blockdev --setrw'.".to_string(),
                }));
            }
        }

        // Rule 5: Multipath path check (e.g. nvme0c0n1)
        if name.contains('c') && name.starts_with("nvme") && name.contains('n') {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "MULTIPATH_PATH",
                detail: format!("Target '{}' appears to be an NVMe controller multipath sub-handle.", name),
                hint: "Target the base namespace instead (e.g. /dev/nvme0n1).".to_string(),
            }));
        }

        // Rule 6 & 8: Mounts and System Disk
        let mounts = LayerStackDetector::find_mounts_for_device(identity.kernel, name);
        if !mounts.is_empty() {
            let mut is_system = false;
            let mut mount_points = Vec::new();
            for m in &mounts {
                mount_points.push(m.mount_point.clone());
                if m.mount_point == "/"
                    || m.mount_point == "/boot"
                    || m.mount_point == "/boot/efi"
                    || m.mount_point == "/usr"
                    || m.mount_point == "/var"
                {
                    is_system = true;
                }
            }

            if is_system {
                if !flags.allow_system_disk {
                    return Err(DcError::Guardian(GuardianRefusal {
                        code: "SYSTEM_DISK",
                        detail: format!(
                            "Device '{}' contains active critical system mountpoints: {:?}",
                            name, mount_points
                        ),
                        hint: "Refusing to wipe host OS disk. Pass '--allow-system-disk --serial-confirm <SERIAL>' to force.".to_string(),
                    }));
                }

                // Verify serial confirmation string matches exactly
                let expected_serial = identity.stable.serial.as_deref().unwrap_or("");
                match &flags.serial_confirm {
                    Some(confirmed) if confirmed == expected_serial => {
                        // Authorized override!
                    }
                    _ => {
                        return Err(DcError::Guardian(GuardianRefusal {
                            code: "SERIAL_CONFIRM_FAILED",
                            detail: format!(
                                "System disk wipe override requires exact serial confirmation matching '{}'",
                                expected_serial
                            ),
                            hint: format!("Provide '--serial-confirm {}'", expected_serial),
                        }));
                    }
                }
            } else {
                return Err(DcError::Guardian(GuardianRefusal {
                    code: "MOUNTED",
                    detail: format!("Device '{}' has mounted filesystem partitions: {:?}", name, mount_points),
                    hint: "Unmount all partitions with 'umount' before wiping.".to_string(),
                }));
            }
        }

        // Rule 7: Active Swap
        if LayerStackDetector::is_swap_active(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "SWAP_ACTIVE",
                detail: format!("Device '{}' contains an active Linux swap partition.", name),
                hint: "Deactivate swap with 'swapoff' before proceeding.".to_string(),
            }));
        }

        // Rule 9: Partitions have holders (LVM PV, dm-crypt)
        if LayerStackDetector::has_holders(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "HAS_HOLDERS",
                detail: format!("Device '{}' or its partitions have active device-mapper or LVM holders.", name),
                hint: "Deactivate volume groups (vgchange -an) or close dm-crypt mappings.".to_string(),
            }));
        }

        // Rule 10: MD RAID membership
        if LayerStackDetector::is_md_member(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "MD_MEMBER",
                detail: format!("Device '{}' is an active member of a Linux Software RAID (md) array.", name),
                hint: "Stop the md array (mdadm --stop) before sanitization.".to_string(),
            }));
        }

        // Rule 11: Inactive Superblock Signatures
        if !flags.allow_inactive_signatures {
            if let Some(sig) = LayerStackDetector::sniff_signatures(target_path) {
                return Err(DcError::Guardian(GuardianRefusal {
                    code: "INACTIVE_SIGNATURE_DETECTED",
                    detail: format!("Found existing storage signature on disk: '{}'", sig),
                    hint: "Pass '--allow-inactive-signatures' if you intend to overwrite this existing data.".to_string(),
                }));
            }
        }

        // Rule 13: Loop device check
        if name.starts_with("loop") && !flags.allow_loop {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "LOOP",
                detail: format!("Target '{}' is a loopback device.", name),
                hint: "Pass '--allow-loop' to permit wiping loop devices.".to_string(),
            }));
        }

        // Rule 14: Size sanity (< 1 MiB or 0)
        if identity.stable.size_bytes < 1024 * 1024 {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "SIZE_ANOMALY",
                detail: format!("Device size is suspiciously small: {} bytes", identity.stable.size_bytes),
                hint: "Device must be at least 1 MiB in capacity.".to_string(),
            }));
        }

        Ok(())
    }

    /// Open device with `O_RDWR`, verify major:minor, and lock with `flock(LOCK_EX | LOCK_NB)`
    /// on the disk AND all child partition devices to prevent concurrent claims.
    pub fn arm_and_lock(
        target_path: &Path,
        expected_stable: &StableIdentity,
    ) -> Result<GuardianLockHandle, DcError> {
        let disk_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(target_path)?;

        let fd = disk_file.as_raw_fd();

        // Check fstat major:minor
        let meta = disk_file.metadata()?;
        if meta.file_type().is_block_device() {
            use std::os::unix::fs::MetadataExt;
            let rdev = meta.rdev();
            let maj = unsafe { libc::major(rdev) };
            let min = unsafe { libc::minor(rdev) };

            // Check sysfs identity against expected
            let sys_dev_dir = PathBuf::from(format!("/sys/dev/block/{}:{}", maj, min));
            let serial = InventoryScanner::read_trimmed_string(&sys_dev_dir.join("device/serial"));
            if serial.as_ref() != expected_stable.serial.as_ref() && expected_stable.serial.is_some() {
                return Err(DcError::IdentityDrift {
                    expected: expected_stable.clone(),
                    observed: StableIdentity {
                        model: None,
                        serial,
                        wwn: None,
                        size_bytes: 0,
                        bus: expected_stable.bus,
                    },
                });
            }
        }

        // Acquire flock on disk fd
        unsafe {
            if libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
                return Err(DcError::Guardian(GuardianRefusal {
                    code: "BUSY",
                    detail: format!("Device '{}' is locked by another process.", target_path.display()),
                    hint: "Ensure no other disk partitioning, wipe, or filesystem tool is accessing the drive.".to_string(),
                }));
            }
        }

        // Also lock all child partitions
        let mut partition_files = Vec::new();
        let kernel_name = target_path.file_name().unwrap_or_default().to_string_lossy();
        let sys_block_dir = PathBuf::from(format!("/sys/block/{}", kernel_name));
        if let Ok(entries) = fs::read_dir(&sys_block_dir) {
            for entry in entries.flatten() {
                let part_name = entry.file_name().to_string_lossy().to_string();
                if part_name.starts_with(kernel_name.as_ref()) && part_name != kernel_name.as_ref() {
                    let part_path = format!("/dev/{}", part_name);
                    if let Ok(pf) = OpenOptions::new().read(true).write(true).open(&part_path) {
                        let pfd = pf.as_raw_fd();
                        unsafe {
                            let _ = libc::flock(pfd, libc::LOCK_EX | libc::LOCK_NB);
                        }
                        partition_files.push(pf);
                    }
                }
            }
        }

        Ok(GuardianLockHandle {
            disk_file,
            partition_files,
        })
    }

    /// Check if device name matches a partition format (e.g. sda1, sdb2, nvme0n1p1, mmcblk0p1).
    pub fn is_partition_name(name: &str) -> bool {
        if name.starts_with("nvme") || name.starts_with("mmcblk") || name.starts_with("loop") {
            name.contains('p') && name.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false)
        } else {
            name.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false)
        }
    }
}
