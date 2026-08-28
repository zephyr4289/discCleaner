use std::fs::{self, File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::Path;

const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_CTL_REMOVE: libc::c_ulong = 0x4C81;

pub struct Janitor;

impl Janitor {
    /// Sweep all loop devices and detach any whose backing file resides under `scratch_prefix`.
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
                    reclaimed.push(name);
                }
            }
        }

        reclaimed
    }
}
