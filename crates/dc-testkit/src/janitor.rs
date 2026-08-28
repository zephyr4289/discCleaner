use std::fs::{self, File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::Path;

const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_CTL_REMOVE: libc::c_ulong = 0x4C81;
const DM_DEV_REMOVE_CMD: libc::c_ulong = 0xc138fd04;

pub struct Janitor;

impl Janitor {
    /// Janitor v2: Clean up leaked dm devices first, then clean up leaked loops.
    pub fn sweep_all(scratch_prefix: &Path) -> Vec<String> {
        let mut reclaimed = Vec::new();

        // 1. Clean leaked DM devices
        reclaimed.extend(Self::sweep_dm_devices());

        // 2. Clean leaked loop devices
        reclaimed.extend(Self::sweep_leaked_loops(scratch_prefix));

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
                if name.starts_with("dc-t2-") {
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
