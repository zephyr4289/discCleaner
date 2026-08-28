use std::fs;
use std::path::Path;

pub struct Signals;

#[derive(Clone, Debug)]
pub struct TaskSignalStatus {
    pub tid: u32,
    pub sig_blk: String,
    pub sig_ign: String,
    pub sig_cgt: String,
}

impl Signals {
    /// Read `/proc/<pid>/task/*/status` to perform SigBlk census (INV9 / Δ85).
    pub fn census(pid: u32) -> Result<Vec<TaskSignalStatus>, String> {
        let task_dir = format!("/proc/{}/task", pid);
        let path = Path::new(&task_dir);
        if !path.exists() {
            return Err(format!("Process {} does not exist or exited", pid));
        }

        let mut statuses = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let tid_str = entry.file_name().to_string_lossy().to_string();
            if let Ok(tid) = tid_str.parse::<u32>() {
                let status_path = entry.path().join("status");
                if let Ok(content) = fs::read_to_string(&status_path) {
                    let mut sig_blk = String::new();
                    let mut sig_ign = String::new();
                    let mut sig_cgt = String::new();

                    for line in content.lines() {
                        if line.starts_with("SigBlk:") {
                            sig_blk = line.trim_start_matches("SigBlk:").trim().to_string();
                        } else if line.starts_with("SigIgn:") {
                            sig_ign = line.trim_start_matches("SigIgn:").trim().to_string();
                        } else if line.starts_with("SigCgt:") {
                            sig_cgt = line.trim_start_matches("SigCgt:").trim().to_string();
                        }
                    }

                    statuses.push(TaskSignalStatus {
                        tid,
                        sig_blk,
                        sig_ign,
                        sig_cgt,
                    });
                }
            }
        }

        Ok(statuses)
    }

    /// Send SIGINT to target PID.
    pub fn send_sigint(pid: u32) -> Result<(), String> {
        unsafe {
            if libc::kill(pid as i32, libc::SIGINT) == 0 {
                Ok(())
            } else {
                Err(format!("Failed to send SIGINT to PID {}", pid))
            }
        }
    }

    /// Send SIGTERM to target PID.
    pub fn send_sigterm(pid: u32) -> Result<(), String> {
        unsafe {
            if libc::kill(pid as i32, libc::SIGTERM) == 0 {
                Ok(())
            } else {
                Err(format!("Failed to send SIGTERM to PID {}", pid))
            }
        }
    }

    /// Send SIGHUP to target PID.
    pub fn send_sighup(pid: u32) -> Result<(), String> {
        unsafe {
            if libc::kill(pid as i32, libc::SIGHUP) == 0 {
                Ok(())
            } else {
                Err(format!("Failed to send SIGHUP to PID {}", pid))
            }
        }
    }

    /// Send signal storm (SIGINT + SIGTERM + SIGHUP in rapid succession) (Δ82).
    pub fn send_signal_storm(pid: u32) -> Result<(), String> {
        unsafe {
            let p = pid as i32;
            libc::kill(p, libc::SIGINT);
            libc::kill(p, libc::SIGTERM);
            libc::kill(p, libc::SIGHUP);
        }
        Ok(())
    }
}
