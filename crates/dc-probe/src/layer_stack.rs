use dc_core::KernelIdentity;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub struct MountEntry {
    pub major: u32,
    pub minor: u32,
    pub mount_point: String,
    pub fs_type: String,
}

pub struct LayerStackDetector;

impl LayerStackDetector {
    /// Parse `/proc/self/mountinfo` to find all active mountpoints and major:minor numbers.
    pub fn get_mounts() -> Vec<MountEntry> {
        let mut list = Vec::new();
        let content = match fs::read_to_string("/proc/self/mountinfo") {
            Ok(c) => c,
            Err(_) => {
                // Fallback to /proc/mounts if mountinfo is missing
                return Self::get_legacy_mounts();
            }
        };

        for line in content.lines() {
            // Format: 36 35 98:0 /mnt /rw,noatime master:1 - ext4 /dev/root rw,data=ordered
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 5 {
                let maj_min = fields[2];
                if let Some((maj_str, min_str)) = maj_min.split_once(':') {
                    if let (Ok(maj), Ok(min)) = (maj_str.parse::<u32>(), min_str.parse::<u32>()) {
                        let mount_point = fields[4].to_string();
                        let fs_type = fields.get(8).unwrap_or(&"unknown").to_string();
                        list.push(MountEntry {
                            major: maj,
                            minor: min,
                            mount_point,
                            fs_type,
                        });
                    }
                }
            }
        }
        list
    }

    fn get_legacy_mounts() -> Vec<MountEntry> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string("/proc/mounts") {
            for line in content.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 3 {
                    let dev = fields[0];
                    let mount_point = fields[1].to_string();
                    let fs_type = fields[2].to_string();
                    if let Ok(meta) = fs::metadata(dev) {
                        use std::os::unix::fs::MetadataExt;
                        let rdev = meta.rdev();
                        let maj = unsafe { libc::major(rdev) };
                        let min = unsafe { libc::minor(rdev) };
                        list.push(MountEntry {
                            major: maj,
                            minor: min,
                            mount_point,
                            fs_type,
                        });
                    }
                }
            }
        }
        list
    }

    /// Check if target or any child partition is currently mounted.
    pub fn find_mounts_for_device(kernel: KernelIdentity, kernel_name: &str) -> Vec<MountEntry> {
        let all_mounts = Self::get_mounts();
        let mut matching = Vec::new();

        // 1. Direct match on major:minor
        for m in &all_mounts {
            if m.major == kernel.major && m.minor == kernel.minor {
                matching.push(MountEntry {
                    major: m.major,
                    minor: m.minor,
                    mount_point: m.mount_point.clone(),
                    fs_type: m.fs_type.clone(),
                });
            }
        }

        // 2. Partition match via sysfs
        let sys_block_dir = PathBuf::from(format!("/sys/block/{}", kernel_name));
        if let Ok(entries) = fs::read_dir(&sys_block_dir) {
            for entry in entries.flatten() {
                let part_name = entry.file_name().to_string_lossy().to_string();
                if part_name.starts_with(kernel_name) && part_name != kernel_name {
                    let dev_file = sys_block_dir.join(&part_name).join("dev");
                    if let Ok(dev_str) = fs::read_to_string(dev_file) {
                        if let Some((maj_s, min_s)) = dev_str.trim().split_once(':') {
                            if let (Ok(p_maj), Ok(p_min)) = (maj_s.parse::<u32>(), min_s.parse::<u32>()) {
                                for m in &all_mounts {
                                    if m.major == p_maj && m.minor == p_min {
                                        matching.push(MountEntry {
                                            major: m.major,
                                            minor: m.minor,
                                            mount_point: m.mount_point.clone(),
                                            fs_type: m.fs_type.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        matching
    }

    /// Parse `/proc/swaps` to detect active swap partitions.
    pub fn is_swap_active(kernel_name: &str) -> bool {
        if let Ok(content) = fs::read_to_string("/proc/swaps") {
            for line in content.lines().skip(1) {
                if let Some(dev) = line.split_whitespace().next() {
                    if dev.contains(kernel_name) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if target block device or any partition has device-mapper or LVM holders.
    pub fn has_holders(kernel_name: &str) -> bool {
        let sys_block_dir = PathBuf::from(format!("/sys/block/{}", kernel_name));
        let holders_dir = sys_block_dir.join("holders");
        if let Ok(entries) = fs::read_dir(&holders_dir) {
            if entries.flatten().count() > 0 {
                return true;
            }
        }

        // Check child partitions
        if let Ok(entries) = fs::read_dir(&sys_block_dir) {
            for entry in entries.flatten() {
                let part_name = entry.file_name().to_string_lossy().to_string();
                if part_name.starts_with(kernel_name) && part_name != kernel_name {
                    let part_holders = sys_block_dir.join(&part_name).join("holders");
                    if let Ok(h_entries) = fs::read_dir(&part_holders) {
                        if h_entries.flatten().count() > 0 {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if device is member of an active md raid array via `/proc/mdstat`.
    pub fn is_md_member(kernel_name: &str) -> bool {
        if let Ok(content) = fs::read_to_string("/proc/mdstat") {
            return content.contains(kernel_name);
        }
        false
    }

    /// Check if device is a zoned block device (SMR host-managed/aware).
    pub fn is_zoned(kernel_name: &str) -> bool {
        let zoned_file = format!("/sys/block/{}/queue/zoned", kernel_name);
        if let Ok(s) = fs::read_to_string(zoned_file) {
            let trimmed = s.trim();
            return trimmed != "none" && !trimmed.is_empty();
        }
        false
    }

    /// Check if BLKZEROOUT / write_zeroes is supported.
    pub fn can_write_zeroes(kernel_name: &str) -> bool {
        let wz_file = format!("/sys/block/{}/queue/write_zeroes_max_bytes", kernel_name);
        if let Ok(s) = fs::read_to_string(wz_file) {
            if let Ok(bytes) = s.trim().parse::<u64>() {
                return bytes > 0;
            }
        }
        false
    }

    /// Sniff first 4 KiB superblock signatures without executing external binaries.
    pub fn sniff_signatures(path: &Path) -> Option<&'static str> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return None,
        };

        let mut buf = [0u8; 4096];
        if file.read_exact(&mut buf).is_err() {
            return None;
        }

        // Check LUKS: "LUKS\xba\xbe"
        if buf.starts_with(b"LUKS\xba\xbe") {
            return Some("LUKS Encrypted Container");
        }

        // Check LVM2 label: "LABELONE" at offset 0 or 512
        if &buf[0..8] == b"LABELONE" || (buf.len() >= 520 && &buf[512..520] == b"LABELONE") {
            return Some("LVM2 Physical Volume");
        }

        // Check Linux Swap signature at end of 4K page (offset 4086..4096)
        if &buf[4086..4096] == b"SWAPSPACE2" || &buf[4086..4096] == b"SWAP-SPACE" {
            return Some("Linux Swap Signature");
        }

        // Check MD RAID superblock: 0xa92b4efc LE
        if buf.starts_with(&[0xfc, 0x4e, 0x2b, 0xa9]) {
            return Some("Linux Software RAID Superblock");
        }

        None
    }
}
