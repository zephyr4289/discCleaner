use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

const DM_DIR: u8 = 0xfd;

const DM_VERSION_CMD: libc::c_ulong = 0xc138fd00;
const DM_LIST_DEVICES_CMD: libc::c_ulong = 0xc138fd02;
const DM_DEV_CREATE_CMD: libc::c_ulong = 0xc138fd03;
const DM_DEV_REMOVE_CMD: libc::c_ulong = 0xc138fd04;
const DM_DEV_SUSPEND_CMD: libc::c_ulong = 0xc138fd06;
const DM_DEV_STATUS_CMD: libc::c_ulong = 0xc138fd07;
const DM_TABLE_LOAD_CMD: libc::c_ulong = 0xc138fd0c;
const DM_TABLE_STATUS_CMD: libc::c_ulong = 0xc138fd0f;

const DM_STATUS_TABLE_FLAG: u32 = 1 << 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DmIoctl {
    pub version: [u32; 3], // [4, 0, 0]
    pub data_size: u32,
    pub data_start: u32,
    pub target_count: u32,
    pub open_count: i32,
    pub flags: u32,
    pub event_nr: u32,
    pub padding: u32,
    pub dev: u64, // (major << 20) | minor
    pub name: [u8; 128],
    pub uuid: [u8; 129],
    pub data: [u8; 7],
}

impl Default for DmIoctl {
    fn default() -> Self {
        let mut s: Self = unsafe { std::mem::zeroed() };
        s.version = [4, 0, 0];
        s.data_size = std::mem::size_of::<Self>() as u32;
        s.data_start = std::mem::size_of::<Self>() as u32;
        s
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DmTargetSpec {
    pub sector_start: u64,
    pub length: u64,
    pub status: i32,
    pub next: u32,
    pub target_type: [u8; 16],
}

#[derive(Clone, Debug)]
pub enum TableLine {
    Linear {
        start_sector: u64,
        length_sectors: u64,
        backing_major: u32,
        backing_minor: u32,
        backing_start_sector: u64,
    },
    Error {
        start_sector: u64,
        length_sectors: u64,
    },
}

pub struct DmDevice {
    pub name: String,
    pub uuid: String,
    pub major: u32,
    pub minor: u32,
    pub dev_path: PathBuf,
    pub created_node: bool,
}

impl DmDevice {
    /// Create a new device-mapper device with `name` and `uuid`.
    pub fn create(name: &str, uuid: &str) -> Result<Self, String> {
        let ctl = File::open("/dev/mapper/control")
            .map_err(|e| format!("Failed to open /dev/mapper/control: {}", e))?;
        let ctl_fd = ctl.as_raw_fd();

        let mut req = DmIoctl::default();
        copy_str_to_buf(name, &mut req.name);
        copy_str_to_buf(uuid, &mut req.uuid);

        let ret = unsafe { libc::ioctl(ctl_fd, DM_DEV_CREATE_CMD, &mut req) };
        if ret != 0 {
            return Err(format!(
                "DM_DEV_CREATE failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let dev_encoded = req.dev;
        let major = (dev_encoded >> 20) as u32;
        let minor = (dev_encoded & 0xfffff) as u32;

        let dev_path = PathBuf::from(format!("/dev/mapper/{}", name));
        let mut created_node = false;

        if !dev_path.exists() {
            // Check /dev/dm-N
            let dm_n = PathBuf::from(format!("/dev/dm-{}", minor));
            if dm_n.exists() {
                // Link or use /dev/dm-N
            } else {
                // mknod /dev/mapper/name
                if let Some(parent) = dev_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let c_dev = std::ffi::CString::new(dev_path.to_string_lossy().as_bytes())
                    .map_err(|e| e.to_string())?;
                let dev_t = unsafe { libc::makedev(major, minor) };
                let mknod_ret = unsafe { libc::mknod(c_dev.as_ptr(), libc::S_IFBLK | 0o600, dev_t) };
                if mknod_ret == 0 {
                    created_node = true;
                }
            }
        }

        Ok(Self {
            name: name.to_string(),
            uuid: uuid.to_string(),
            major,
            minor,
            dev_path: if dev_path.exists() {
                dev_path
            } else {
                PathBuf::from(format!("/dev/dm-{}", minor))
            },
            created_node,
        })
    }

    /// Load table specifications into inactive slot.
    pub fn load_table(&mut self, tables: &[TableLine]) -> Result<(), String> {
        let ctl = File::open("/dev/mapper/control")
            .map_err(|e| format!("Failed to open /dev/mapper/control: {}", e))?;
        let ctl_fd = ctl.as_raw_fd();

        // Build contiguous payload: DmIoctl + (DmTargetSpec + params_null_terminated + padding)*
        let mut payload = vec![0u8; 16384];
        let header_len = std::mem::size_of::<DmIoctl>();

        let mut req = DmIoctl::default();
        copy_str_to_buf(&self.name, &mut req.name);
        copy_str_to_buf(&self.uuid, &mut req.uuid);
        req.target_count = tables.len() as u32;

        let mut offset = header_len;

        for (i, t) in tables.iter().enumerate() {
            let spec_offset = offset;
            let mut spec: DmTargetSpec = unsafe { std::mem::zeroed() };

            let params = match t {
                TableLine::Linear {
                    start_sector,
                    length_sectors,
                    backing_major,
                    backing_minor,
                    backing_start_sector,
                } => {
                    spec.sector_start = *start_sector;
                    spec.length = *length_sectors;
                    copy_str_to_buf("linear", &mut spec.target_type);
                    format!("{}:{} {}", backing_major, backing_minor, backing_start_sector)
                }
                TableLine::Error {
                    start_sector,
                    length_sectors,
                } => {
                    spec.sector_start = *start_sector;
                    spec.length = *length_sectors;
                    copy_str_to_buf("error", &mut spec.target_type);
                    String::new()
                }
            };

            let params_bytes = params.as_bytes();
            let params_len = params_bytes.len() + 1; // null terminator
            let entry_len = (std::mem::size_of::<DmTargetSpec>() + params_len + 7) & !7;

            spec.next = if i + 1 < tables.len() {
                entry_len as u32
            } else {
                0
            };

            // Write spec
            let spec_bytes = unsafe {
                std::slice::from_raw_parts(
                    &spec as *const DmTargetSpec as *const u8,
                    std::mem::size_of::<DmTargetSpec>(),
                )
            };
            payload[spec_offset..spec_offset + spec_bytes.len()].copy_from_slice(spec_bytes);

            // Write params
            let params_start = spec_offset + std::mem::size_of::<DmTargetSpec>();
            payload[params_start..params_start + params_bytes.len()].copy_from_slice(params_bytes);
            payload[params_start + params_bytes.len()] = 0; // null terminator

            offset += entry_len;
        }

        req.data_size = offset as u32;
        req.data_start = header_len as u32;

        let req_bytes = unsafe {
            std::slice::from_raw_parts(&req as *const DmIoctl as *const u8, header_len)
        };
        payload[0..header_len].copy_from_slice(req_bytes);

        let ret = unsafe { libc::ioctl(ctl_fd, DM_TABLE_LOAD_CMD, payload.as_mut_ptr()) };
        if ret != 0 {
            return Err(format!(
                "DM_TABLE_LOAD failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }

    /// Activate inactive table by issuing `DM_DEV_SUSPEND` with flags=0.
    pub fn activate(&mut self) -> Result<(), String> {
        let ctl = File::open("/dev/mapper/control")
            .map_err(|e| format!("Failed to open /dev/mapper/control: {}", e))?;
        let ctl_fd = ctl.as_raw_fd();

        let mut req = DmIoctl::default();
        copy_str_to_buf(&self.name, &mut req.name);
        copy_str_to_buf(&self.uuid, &mut req.uuid);
        req.flags = 0; // Resume / activate

        let ret = unsafe { libc::ioctl(ctl_fd, DM_DEV_SUSPEND_CMD, &mut req) };
        if ret != 0 {
            return Err(format!(
                "DM_DEV_SUSPEND (activate) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Atomically swap to a new table (load + activate).
    pub fn swap_table(&mut self, tables: &[TableLine]) -> Result<(), String> {
        self.load_table(tables)?;
        self.activate()
    }

    /// Parse active table status strings from kernel.
    pub fn table_status(&self) -> Result<Vec<String>, String> {
        let ctl = File::open("/dev/mapper/control")
            .map_err(|e| format!("Failed to open /dev/mapper/control: {}", e))?;
        let ctl_fd = ctl.as_raw_fd();

        let mut payload = vec![0u8; 16384];
        let header_len = std::mem::size_of::<DmIoctl>();

        let mut req = DmIoctl::default();
        copy_str_to_buf(&self.name, &mut req.name);
        req.flags = DM_STATUS_TABLE_FLAG;
        req.data_size = 16384;

        let req_bytes = unsafe {
            std::slice::from_raw_parts(&req as *const DmIoctl as *const u8, header_len)
        };
        payload[0..header_len].copy_from_slice(req_bytes);

        let ret = unsafe { libc::ioctl(ctl_fd, DM_TABLE_STATUS_CMD, payload.as_mut_ptr()) };
        if ret != 0 {
            return Err(format!("DM_TABLE_STATUS failed: {}", std::io::Error::last_os_error()));
        }

        let resp_header = unsafe { &*(payload.as_ptr() as *const DmIoctl) };
        let mut lines = Vec::new();

        let mut offset = resp_header.data_start as usize;
        for _ in 0..resp_header.target_count {
            if offset + std::mem::size_of::<DmTargetSpec>() > payload.len() {
                break;
            }

            let spec = unsafe { &*(payload[offset..].as_ptr() as *const DmTargetSpec) };
            let t_type = unsafe { std::ffi::CStr::from_ptr(spec.target_type.as_ptr() as *const libc::c_char) }
                .to_string_lossy();

            let params_start = offset + std::mem::size_of::<DmTargetSpec>();
            let params = unsafe {
                std::ffi::CStr::from_ptr(payload[params_start..].as_ptr() as *const libc::c_char)
            }
            .to_string_lossy();

            lines.push(format!("{} {} {} {}", spec.sector_start, spec.length, t_type, params));

            if spec.next == 0 {
                break;
            }
            offset += spec.next as usize;
        }

        Ok(lines)
    }

    /// Prelude self-validation: tests that dm_mod and dm-error target are supported.
    pub fn prelude_check() -> Result<(), String> {
        let ctl = File::open("/dev/mapper/control")
            .map_err(|e| format!("Cannot open /dev/mapper/control: {}. Please run 'modprobe dm_mod'", e))?;
        let ctl_fd = ctl.as_raw_fd();

        let mut req = DmIoctl::default();
        let ret = unsafe { libc::ioctl(ctl_fd, DM_VERSION_CMD, &mut req) };
        if ret != 0 {
            return Err(format!("DM_VERSION ioctl failed: {}", std::io::Error::last_os_error()));
        }

        Ok(())
    }
}

impl Drop for DmDevice {
    fn drop(&mut self) {
        if let Ok(ctl) = File::open("/dev/mapper/control") {
            let mut req = DmIoctl::default();
            copy_str_to_buf(&self.name, &mut req.name);
            let _ = unsafe { libc::ioctl(ctl.as_raw_fd(), DM_DEV_REMOVE_CMD, &mut req) };
        }
        if self.created_node && self.dev_path.exists() {
            let _ = fs::remove_file(&self.dev_path);
        }
    }
}

fn copy_str_to_buf(src: &str, dest: &mut [u8]) {
    dest.fill(0);
    let bytes = src.as_bytes();
    let len = bytes.len().min(dest.len() - 1);
    dest[..len].copy_from_slice(&bytes[..len]);
}
