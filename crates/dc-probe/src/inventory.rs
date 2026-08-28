use dc_core::{BusType, DeviceIdentity, KernelIdentity, StableIdentity};
use std::fs::{self, File};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

const BLKROGET: libc::c_ulong = 0x125e;
const BLKSSZGET: libc::c_ulong = 0x1268;
const BLKPBSZGET: libc::c_ulong = 0x127b;
const BLKGETSIZE64: libc::c_ulong = 0x80081272;

pub struct InventoryScanner;

impl InventoryScanner {
    /// Scan all block devices in `/sys/block` and return whole-disk identities.
    pub fn scan_all() -> Vec<DeviceIdentity> {
        let mut list = Vec::new();
        let sys_block = Path::new("/sys/block");
        if !sys_block.exists() {
            return list;
        }

        let entries = match fs::read_dir(sys_block) {
            Ok(entries) => entries,
            Err(_) => return list,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip partitions or virtual non-storage subsystems
            if name.starts_with("ram") || name.starts_with("zram") {
                continue;
            }

            let dev_path = format!("/dev/{}", name);
            if let Ok(identity) = Self::probe_device(Path::new(&dev_path)) {
                list.push(identity);
            }
        }

        list.sort_by(|a, b| a.kernel_name.cmp(&b.kernel_name));
        list
    }

    /// Probe a single device path (e.g. `/dev/sda`, `/dev/nvme0n1`, `/dev/mapper/foo`, `/dev/dm-0`).
    pub fn probe_device(path: &Path) -> Result<DeviceIdentity, std::io::Error> {
        let metadata = fs::metadata(path)?;
        let file_type = metadata.file_type();

        let (major, minor) = if file_type.is_block_device() {
            use std::os::unix::fs::MetadataExt;
            let rdev = metadata.rdev();
            let maj = unsafe { libc::major(rdev) };
            let min = unsafe { libc::minor(rdev) };
            (maj, min)
        } else if file_type.is_file() {
            (0, 0)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Target is neither a block device nor a regular file",
            ));
        };

        let kernel_name = if file_type.is_block_device() {
            // Find canonical kernel name from /sys/dev/block/maj:min
            let sys_dev_link = PathBuf::from(format!("/sys/dev/block/{}:{}", major, minor));
            if let Ok(canon) = fs::canonicalize(&sys_dev_link) {
                canon
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| {
                        path.file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    })
            } else {
                path.file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            }
        } else {
            path.file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        };

        let sys_dev_dir = PathBuf::from(format!("/sys/dev/block/{}:{}", major, minor));
        let sys_block_dir = PathBuf::from(format!("/sys/block/{}", kernel_name));

        let model = Self::read_trimmed_string(&sys_block_dir.join("device/model"))
            .or_else(|| Self::read_trimmed_string(&sys_dev_dir.join("device/model")))
            .or_else(|| Self::read_trimmed_string(&sys_block_dir.join("device/name")))
            .or_else(|| Self::read_trimmed_string(&sys_block_dir.join("dm/name")));

        let serial = Self::read_trimmed_string(&sys_block_dir.join("device/serial"))
            .or_else(|| Self::read_trimmed_string(&sys_dev_dir.join("device/serial")))
            .or_else(|| Self::read_trimmed_string(&sys_block_dir.join("device/wwid")))
            .or_else(|| Self::read_trimmed_string(&sys_block_dir.join("dm/uuid")));

        let wwn = Self::read_trimmed_string(&sys_block_dir.join("device/wwn"))
            .or_else(|| Self::read_trimmed_string(&sys_dev_dir.join("device/wwn")));

        let bus = Self::detect_bus_type(&kernel_name, &sys_block_dir);

        // Open read-only to query block sizes and capacity via ioctls
        let file = File::open(path)?;
        let fd = file.as_raw_fd();

        let size_bytes = if file_type.is_block_device() {
            let mut sz: u64 = 0;
            unsafe {
                if libc::ioctl(fd, BLKGETSIZE64, &mut sz) == 0 {
                    sz
                } else {
                    metadata.len()
                }
            }
        } else {
            metadata.len()
        };

        let logical_block_size = if file_type.is_block_device() {
            let mut lbs: u32 = 0;
            unsafe {
                if libc::ioctl(fd, BLKSSZGET, &mut lbs) == 0 && lbs > 0 {
                    lbs
                } else {
                    512
                }
            }
        } else {
            512
        };

        let physical_block_size = if file_type.is_block_device() {
            let mut pbs: u32 = 0;
            unsafe {
                if libc::ioctl(fd, BLKPBSZGET, &mut pbs) == 0 && pbs > 0 {
                    pbs
                } else {
                    logical_block_size
                }
            }
        } else {
            512
        };

        Ok(DeviceIdentity {
            stable: StableIdentity {
                model,
                serial,
                wwn,
                size_bytes,
                bus,
            },
            kernel: KernelIdentity { major, minor },
            kernel_name,
            dev_path: path.to_string_lossy().to_string(),
            logical_block_size,
            physical_block_size,
        })
    }

    fn detect_bus_type(name: &str, sys_block_dir: &Path) -> BusType {
        if name.starts_with("nvme") {
            BusType::Nvme
        } else if name.starts_with("mmcblk") {
            BusType::Mmc
        } else if name.starts_with("loop") {
            BusType::Loop
        } else if name.starts_with("dm-") || name.starts_with("dm") {
            BusType::DeviceMapper
        } else if name.starts_with("vd") {
            BusType::Virtio
        } else {
            // Check sysfs device link target
            if let Ok(target) = fs::read_link(sys_block_dir.join("device")) {
                let target_str = target.to_string_lossy();
                if target_str.contains("usb") {
                    BusType::Usb
                } else if target_str.contains("ata") || target_str.contains("sata") {
                    BusType::Sata
                } else if target_str.contains("scsi") || target_str.contains("sas") {
                    BusType::Sas
                } else {
                    BusType::Sata
                }
            } else if name.starts_with("sd") {
                BusType::Sata
            } else {
                BusType::Unknown
            }
        }
    }

    pub fn is_read_only(file: &File) -> bool {
        let fd = file.as_raw_fd();
        let mut ro: libc::c_int = 0;
        unsafe {
            if libc::ioctl(fd, BLKROGET, &mut ro) == 0 {
                ro != 0
            } else {
                false
            }
        }
    }

    pub fn read_trimmed_string(path: &Path) -> Option<String> {
        fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
}
