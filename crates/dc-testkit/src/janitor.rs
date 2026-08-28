use std::fs::{self, File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;

const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_CTL_REMOVE: libc::c_ulong = 0x4C81;
const DM_DEV_REMOVE_CMD: libc::c_ulong = 0xc138fd04;

pub struct Janitor;

impl Janitor {
    /// Janitor v4:
    /// 1. Reads `/proc/swaps` and deactivates any swap residing on scratch loops (`swapoff`).
    /// 2. Sweeps test LVM VGs (`vgchange -an dct5-*`).
    /// 3. Sweeps leaked DM devices starting with `dc-t2-`, `dc-t4-`, or `dct5-`.
    /// 4. Sweeps leaked loop devices whose backing file is under `scratch_prefix`.
    pub fn sweep_all(scratch_prefix: &Path) -> Vec<String> {
        let mut reclaimed = Vec::new();

        // 1. Swapoff scratch-backed swap
        reclaimed.extend(Self::sweep_active_swaps(scratch_prefix));

        // 2. Deactivate test VGs
        reclaimed.extend(Self::sweep_lvm_vgs());

        // 3. Clean leaked DM devices
        reclaimed.extend(Self::sweep_dm_devices());

        // 4. Clean leaked loop devices
        reclaimed.extend(Self::sweep_leaked_loops(scratch_prefix));

        reclaimed
    }

    pub fn sweep_active_swaps(scratch_prefix: &Path) -> Vec<String> {
        let mut reclaimed = Vec::new();
        if let Ok(content) = fs::read_to_string("/proc/swaps") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(dev_path) = parts.first() {
                    let dev = Path::new(dev_path);
                    if dev.starts_with("/dev/loop") {
                        let c_path = std::ffi::CString::new(*dev_path).unwrap();
                        unsafe {
                            if libc::swapoff(c_path.as_ptr()) == 0 {
                                reclaimed.push(format!("swapoff:{}", dev_path));
                            }
                        }
                    }
                }
            }
        }
        reclaimed
    }

    pub fn sweep_lvm_vgs() -> Vec<String> {
        let mut reclaimed = Vec::new();
        let mapper_dir = Path::new("/dev/mapper");
        if !mapper_dir.exists() {
            return reclaimed;
        }

        if let Ok(entries) = fs::read_dir(mapper_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("dct5-") {
                    let _ = Command::new("vgchange")
                        .args(&["-an", &name])
                        .output();
                    reclaimed.push(format!("vgchange -an:{}", name));
                }
            }
        }
        reclaimed
    }

    pub fn sweep_dm_devices() -> Vec<String> {
        let mut reclaimed = Vec::new();
        let mapper_dir = Path::new("/dev/mapper");
        if !mapper_dir.exists() {
            return reclaimed;
        }

        if let Ok(entries) = fs::read_dir(mapper_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("dc-t2-") || name.starts_with("dc-t4-") || name.starts_with("dct5-") {
                    if let Ok(ctl) = File::open("/dev/mapper/control") {
                        let mut req = crate::dm::DmIoctl::default();
                        let bytes = name.as_bytes();
                        let len = bytes.len().min(127);
                        req.name[..len].copy_from_slice(&bytes[..len]);
                        let _ = unsafe { libc::ioctl(ctl.as_raw_fd(), DM_DEV_REMOVE_CMD, &mut req) };
                        reclaimed.push(format!("dm:{}", name));
                    }
                }
            }
        }
        reclaimed
    }

    pub fn sweep_leaked_loops(scratch_prefix: &Path) -> Vec<String> {
        let mut reclaimed = Vec::new();
        let sys_block = Path::new("/sys/block");
        if !sys_block.exists() {
            return reclaimed;
        }

        let entries = match fs::read_dir(sys_block) {
            Ok(e) => e,
            Err(_) => return reclaimed,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("loop") {
                continue;
            }

            let minor_str = name.trim_start_matches("loop");
            let minor: i32 = match minor_str.parse() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let backing_file_path = entry.path().join("loop/backing_file");
            if let Ok(backing_content) = fs::read_to_string(backing_file_path) {
                let backing = Path::new(backing_content.trim());
                if backing.starts_with(scratch_prefix) {
                    // Detach and remove
                    let dev_path = format!("/dev/{}", name);
                    if let Ok(f) = OpenOptions::new().read(true).write(true).open(&dev_path) {
                        let _ = unsafe { libc::ioctl(f.as_raw_fd(), LOOP_CLR_FD, 0) };
                    }
                    if let Ok(ctl) = File::open("/dev/loop-control") {
                        let _ = unsafe { libc::ioctl(ctl.as_raw_fd(), LOOP_CTL_REMOVE, minor) };
                    }
                    reclaimed.push(format!("loop:{}", name));
                }
            }
        }

        reclaimed
    }
}
