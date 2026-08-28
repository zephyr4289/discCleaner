use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

const LOOP_CTL_ADD: libc::c_ulong = 0x4C80;
const LOOP_CTL_REMOVE: libc::c_ulong = 0x4C81;
const LOOP_SET_FD: libc::c_ulong = 0x4C00;
const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_SET_STATUS64: libc::c_ulong = 0x4C04;
const LOOP_GET_STATUS64: libc::c_ulong = 0x4C05;
const LOOP_SET_BLOCK_SIZE: libc::c_ulong = 0x4C08;
const LOOP_CONFIGURE: libc::c_ulong = 0x4C0A;

const LO_FLAGS_DIRECT_IO: u32 = 16;
const BLKSSZGET: libc::c_ulong = 0x1268;
const BLKPBSZGET: libc::c_ulong = 0x127b;
const BLKGETSIZE64: libc::c_ulong = 0x80081272;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LoopInfo64 {
    pub lo_device: u64,
    pub lo_inode: u64,
    pub lo_rdevice: u64,
    pub lo_offset: u64,
    pub lo_sizelimit: u64,
    pub lo_number: u32,
    pub lo_encrypt_type: u32,
    pub lo_encrypt_key_size: u32,
    pub lo_flags: u32,
    pub lo_file_name: [u8; 64],
    pub lo_crypt_name: [u8; 64],
    pub lo_encrypt_key: [u8; 32],
    pub lo_init: [u64; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LoopConfig {
    pub fd: u32,
    pub block_size: u32,
    pub info: LoopInfo64,
    pub __reserved: [u64; 8],
}

pub struct LoopDevice {
    pub minor: i32,
    pub dev_path: PathBuf,
    pub backing_path: PathBuf,
    pub created_node: bool,
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub size_bytes: u64,
    pub write_zeroes_max_bytes: u64,
}

impl LoopDevice {
    /// Acquire a fresh exclusive loop device using `LOOP_CTL_ADD` and attach with `LO_FLAGS_DIRECT_IO`.
    pub fn create_and_attach(
        backing_path: &Path,
        expected_size: u64,
        requested_lbs: u32,
    ) -> Result<Self, String> {
        // 1. Open loop control
        let ctl_file = File::open("/dev/loop-control")
            .map_err(|e| format!("Failed to open /dev/loop-control: {}", e))?;
        let ctl_fd = ctl_file.as_raw_fd();

        // 2. LOOP_CTL_ADD: mints a brand-new minor
        let minor = unsafe { libc::ioctl(ctl_fd, LOOP_CTL_ADD, -1) };
        if minor < 0 {
            return Err(format!(
                "LOOP_CTL_ADD failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let dev_path = PathBuf::from(format!("/dev/loop{}", minor));
        let mut created_node = false;

        if !dev_path.exists() {
            // mknod /dev/loopN (major 7, minor N)
            let c_dev = std::ffi::CString::new(dev_path.to_string_lossy().as_bytes())
                .map_err(|e| e.to_string())?;
            let dev_t = unsafe { libc::makedev(7, minor as u32) };
            let ret = unsafe { libc::mknod(c_dev.as_ptr(), libc::S_IFBLK | 0o600, dev_t) };
            if ret != 0 {
                unsafe { libc::ioctl(ctl_fd, LOOP_CTL_REMOVE, minor) };
                return Err(format!("mknod failed for {}: {}", dev_path.display(), std::io::Error::last_os_error()));
            }
            created_node = true;
        }

        // 3. Open backing file
        let backing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(backing_path)
            .map_err(|e| format!("Failed to open backing file: {}", e))?;
        let backing_fd = backing_file.as_raw_fd();

        // 4. Open loop device
        let loop_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dev_path)
            .map_err(|e| format!("Failed to open loop device {}: {}", dev_path.display(), e))?;
        let loop_fd = loop_file.as_raw_fd();

        // 5. Attach with direct I/O
        let mut config: LoopConfig = unsafe { std::mem::zeroed() };
        config.fd = backing_fd as u32;
        config.block_size = requested_lbs;
        config.info.lo_flags = LO_FLAGS_DIRECT_IO;

        let ret = unsafe { libc::ioctl(loop_fd, LOOP_CONFIGURE, &config) };
        if ret != 0 {
            // Fallback for pre-5.8 kernels: LOOP_SET_FD -> LOOP_SET_STATUS64 -> LOOP_SET_BLOCK_SIZE
            let set_fd_ret = unsafe { libc::ioctl(loop_fd, LOOP_SET_FD, backing_fd) };
            if set_fd_ret != 0 {
                Self::cleanup_minor(minor, &dev_path, created_node);
                return Err(format!("LOOP_SET_FD failed: {}", std::io::Error::last_os_error()));
            }

            let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
            info.lo_flags = LO_FLAGS_DIRECT_IO;
            let status_ret = unsafe { libc::ioctl(loop_fd, LOOP_SET_STATUS64, &info) };
            if status_ret != 0 {
                let _ = unsafe { libc::ioctl(loop_fd, LOOP_CLR_FD, 0) };
                Self::cleanup_minor(minor, &dev_path, created_node);
                return Err(format!("LOOP_SET_STATUS64 failed: {}", std::io::Error::last_os_error()));
            }

            if requested_lbs > 512 {
                let _ = unsafe { libc::ioctl(loop_fd, LOOP_SET_BLOCK_SIZE, requested_lbs) };
            }
        }

        // 6. Geometry Readback and Self-Verification (§5.4)
        let mut actual_size: u64 = 0;
        let mut actual_lbs: u32 = 0;
        let mut actual_pbs: u32 = 0;

        unsafe {
            let _ = libc::ioctl(loop_fd, BLKGETSIZE64, &mut actual_size);
            let _ = libc::ioctl(loop_fd, BLKSSZGET, &mut actual_lbs);
            let _ = libc::ioctl(loop_fd, BLKPBSZGET, &mut actual_pbs);
        }

        if actual_size != expected_size {
            let _ = unsafe { libc::ioctl(loop_fd, LOOP_CLR_FD, 0) };
            Self::cleanup_minor(minor, &dev_path, created_node);
            return Err(format!(
                "Loop size mismatch: expected {} bytes, kernel reports {}",
                expected_size, actual_size
            ));
        }

        // Read sysfs write_zeroes_max_bytes
        let wz_file = format!("/sys/block/loop{}/queue/write_zeroes_max_bytes", minor);
        let write_zeroes_max_bytes = fs::read_to_string(wz_file)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);

        Ok(Self {
            minor,
            dev_path,
            backing_path: backing_path.to_path_buf(),
            created_node,
            logical_block_size: actual_lbs,
            physical_block_size: actual_pbs,
            size_bytes: actual_size,
            write_zeroes_max_bytes,
        })
    }

    fn cleanup_minor(minor: i32, dev_path: &Path, created_node: bool) {
        if let Ok(ctl) = File::open("/dev/loop-control") {
            let _ = unsafe { libc::ioctl(ctl.as_raw_fd(), LOOP_CTL_REMOVE, minor) };
        }
        if created_node && dev_path.exists() {
            let _ = fs::remove_file(dev_path);
        }
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        if let Ok(loop_file) = OpenOptions::new().read(true).write(true).open(&self.dev_path) {
            let _ = unsafe { libc::ioctl(loop_file.as_raw_fd(), LOOP_CLR_FD, 0) };
        }
        let _ = fs::remove_file(&self.backing_path);
        Self::cleanup_minor(self.minor, &self.dev_path, self.created_node);
    }
}
