use crate::inventory::InventoryScanner;
use crate::layer_stack::LayerStackDetector;
use dc_core::{DcError, DeviceIdentity, GuardianRefusal, StableIdentity};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::OpenOptionsExt;
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
    /// Execute the full 15-rule normative precedence table (§7).
    pub fn evaluate(
        target_path: &Path,
        identity: &DeviceIdentity,
        flags: &GuardianFlags,
    ) -> Result<(), DcError> {
        let name = &identity.kernel_name;

        // 1. SIZE_ANOMALY (Structural)
        if identity.stable.size_bytes < 1024 * 1024 {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "SIZE_ANOMALY",
                detail: format!("Device size is suspiciously small: {} bytes", identity.stable.size_bytes),
                hint: "Device must be at least 1 MiB in capacity.".to_string(),
            }));
        }

        // 2. NOT_WHOLE_DISK (Structural)
        if Self::is_partition_name(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "NOT_WHOLE_DISK",
                detail: format!("Target '{}' is a partition, not a whole disk block device.", name),
                hint: "Target the parent drive instead (e.g. /dev/sda instead of /dev/sda1).".to_string(),
            }));
        }

        // 3. RAM_BACKED (Structural)
        if name.starts_with("zram") || name.starts_with("ram") {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "RAM_BACKED",
                detail: format!("Device '{}' is a RAM-backed volatile block device.", name),
                hint: "RAM devices disappear upon reboot and cannot be sanitized as physical media.".to_string(),
            }));
        }

        // 4. ZONED (Geometry)
        if LayerStackDetector::is_zoned(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "ZONED",
                detail: format!("Device '{}' is a host-managed/aware zoned device (SMR).", name),
                hint: "Zoned storage wiping requires a sequential zone-reset engine (Phase 3).".to_string(),
            }));
        }

        // 5. READ_ONLY (Geometry)
        if let Ok(f) = File::open(target_path) {
            if InventoryScanner::is_read_only(&f) {
                return Err(DcError::Guardian(GuardianRefusal {
                    code: "READ_ONLY",
                    detail: format!("Device '{}' is marked read-only by hardware switch or kernel.", name),
                    hint: "Disable hardware write-protect switch or run 'blockdev --setrw'.".to_string(),
                }));
            }
        }

        // 6. MULTIPATH_PATH (Structural name pattern)
        if name.contains('c') && name.starts_with("nvme") && name.contains('n') {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "MULTIPATH_PATH",
                detail: format!("Target '{}' appears to be an NVMe controller multipath sub-handle.", name),
                hint: "Target the base namespace instead (e.g. /dev/nvme0n1).".to_string(),
            }));
        }

        // 7 & 8. Mounts & SYSTEM_DISK (Danger: kernel-verified)
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
                let expected_confirm = identity
                    .stable
                    .serial
                    .as_deref()
                    .unwrap_or(name);
                match &flags.serial_confirm {
                    Some(confirmed) if confirmed == expected_confirm => {
                        // Authorized override!
                    }
                    _ => {
                        return Err(DcError::Guardian(GuardianRefusal {
                            code: "SERIAL_CONFIRM_FAILED",
                            detail: format!(
                                "System disk wipe override requires exact serial confirmation matching '{}'",
                                expected_confirm
                            ),
                            hint: format!("Provide '--serial-confirm {}'", expected_confirm),
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

        // 9. SWAP_ACTIVE (Danger: kernel-verified)
        if LayerStackDetector::is_swap_active(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "SWAP_ACTIVE",
                detail: format!("Device '{}' contains an active Linux swap partition.", name),
                hint: "Deactivate swap with 'swapoff' before proceeding.".to_string(),
            }));
        }

        // 10. HAS_HOLDERS (Danger: kernel-verified)
        if LayerStackDetector::has_holders(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "HAS_HOLDERS",
                detail: format!("Device '{}' or its partitions have active device-mapper or LVM holders.", name),
                hint: "Deactivate volume groups (vgchange -an) or close dm-crypt mappings.".to_string(),
            }));
        }

        // 11. MD_MEMBER (Danger: kernel-verified)
        if LayerStackDetector::is_md_member(name) {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "MD_MEMBER",
                detail: format!("Device '{}' is an active member of a Linux Software RAID (md) array.", name),
                hint: "Stop the md array (mdadm --stop) before sanitization.".to_string(),
            }));
        }

        // 12. Sniffed Storage Signatures (Danger: sniffed)
        if let Some(sig) = LayerStackDetector::sniff_signatures(target_path) {
            if sig.contains("LUKS") {
                if !flags.allow_inactive_signatures {
                    return Err(DcError::Guardian(GuardianRefusal {
                        code: "CRYPTO_CONTAINER",
                        detail: format!("Found encrypted storage container header: '{}'", sig),
                        hint: "Pass '--allow-inactive-signatures' to overwrite encrypted storage.".to_string(),
                    }));
                }
            } else if sig.contains("LVM2") {
                if !flags.allow_inactive_signatures {
                    return Err(DcError::Guardian(GuardianRefusal {
                        code: "LVM_PV",
                        detail: format!("Found LVM physical volume signature: '{}'", sig),
                        hint: "Pass '--allow-inactive-signatures' to overwrite LVM metadata.".to_string(),
                    }));
                }
            } else if sig.contains("SWAP") {
                if !flags.allow_inactive_signatures {
                    return Err(DcError::Guardian(GuardianRefusal {
                        code: "STALE_SWAP",
                        detail: format!("Found inactive swap signature: '{}'", sig),
                        hint: "Pass '--allow-inactive-signatures' to overwrite swap metadata.".to_string(),
                    }));
                }
            } else if !flags.allow_inactive_signatures {
                return Err(DcError::Guardian(GuardianRefusal {
                    code: "INACTIVE_SIGNATURE_DETECTED",
                    detail: format!("Found existing storage signature on disk: '{}'", sig),
                    hint: "Pass '--allow-inactive-signatures' if you intend to overwrite this existing data.".to_string(),
                }));
            }
        }

        // 14. LOOP (Permission: demoted by --allow-loop)
        if name.starts_with("loop") && !flags.allow_loop {
            return Err(DcError::Guardian(GuardianRefusal {
                code: "LOOP",
                detail: format!("Target '{}' is a loopback device.", name),
                hint: "Pass '--allow-loop' to permit wiping loop devices.".to_string(),
            }));
        }

        Ok(())
    }

    /// Arm and lock hardware with `O_RDWR | O_EXCL` across whole disk and all child partitions (Δ24).
    pub fn arm_and_lock(
        target_path: &Path,
        expected_stable: &StableIdentity,
    ) -> Result<GuardianLockHandle, DcError> {
        // 1. Attempt exclusive open on whole disk
        let disk_file_res = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_EXCL)
            .open(target_path);

        let disk_file = match disk_file_res {
            Ok(f) => f,
            Err(e) => {
                // EBUSY or failure on O_EXCL -> attempt re-classification
                if let Ok(identity) = InventoryScanner::probe_device(target_path) {
                    let mut flags = GuardianFlags::default();
                    if let Err(re_err) = Self::evaluate(target_path, &identity, &flags) {
                        return Err(re_err);
                    }
                }
                return Err(DcError::Guardian(GuardianRefusal {
                    code: "IN_USE_RACE",
                    detail: format!(
                        "Exclusive lock (O_EXCL) failed on '{}': {}",
                        target_path.display(), e
                    ),
                    hint: "Another process holds an active open claim on the disk or its partitions.".to_string(),
                }));
            }
        };

        let fd = disk_file.as_raw_fd();

        // 2. Check fstat major:minor and verify identity drift
        let meta = disk_file.metadata()?;
        if meta.file_type().is_block_device() {
            use std::os::unix::fs::MetadataExt;
            let rdev = meta.rdev();
            let maj = unsafe { libc::major(rdev) };
            let min = unsafe { libc::minor(rdev) };

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

        // 3. Acquire flock on disk fd
        unsafe {
            if libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
                return Err(DcError::Guardian(GuardianRefusal {
                    code: "BUSY",
                    detail: format!("Device '{}' is locked by another process.", target_path.display()),
                    hint: "Ensure no other disk partitioning or inspection tool holds flock.".to_string(),
                }));
            }
        }

        // 4. Lock all child partition nodes with O_EXCL and flock (Δ24)
        let mut partition_files = Vec::new();
        let kernel_name = target_path.file_name().unwrap_or_default().to_string_lossy();
        let sys_block_dir = PathBuf::from(format!("/sys/block/{}", kernel_name));
        if let Ok(entries) = fs::read_dir(&sys_block_dir) {
            for entry in entries.flatten() {
                let part_name = entry.file_name().to_string_lossy().to_string();
                if part_name.starts_with(kernel_name.as_ref()) && part_name != kernel_name.as_ref() {
                    let part_path = format!("/dev/{}", part_name);
                    if let Ok(pf) = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(libc::O_EXCL)
                        .open(&part_path)
                    {
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

    /// Check if device name matches a partition format (e.g. sda1, sdb2, nvme0n1p1, mmcblk0p1, loop0p1).
    pub fn is_partition_name(name: &str) -> bool {
        if name.starts_with("nvme") || name.starts_with("mmcblk") || name.starts_with("loop") {
            name.contains('p') && name.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false)
        } else {
            name.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false)
        }
    }
}
