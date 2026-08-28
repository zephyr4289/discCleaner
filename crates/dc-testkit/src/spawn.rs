use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub struct ProcessGuard {
    pub child: Child,
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct ToolSpawner;

impl ToolSpawner {
    /// Configure Command with normative spawn environment discipline (Δ99).
    pub fn prepare_command(bin_path: &Path, cwd: &Path) -> Command {
        let mut cmd = Command::new(bin_path);
        cmd.current_dir(cwd);

        // 1. Scrub all DC_* environment variables
        for (k, _) in std::env::vars() {
            if k.starts_with("DC_") {
                cmd.env_remove(&k);
            }
        }

        // 2. Pin normative environment variables (Δ99)
        cmd.env("TZ", "UTC");
        cmd.env("TERM", "dumb");
        cmd.env("NO_COLOR", "1");
        cmd.env("LANG", "C.UTF-8");
        cmd.env("LC_ALL", "C");

        cmd.stdin(Stdio::null());
        cmd
    }

    /// Spawn a tool command with RAII ProcessGuard.
    pub fn spawn(cmd: &mut Command) -> std::io::Result<ProcessGuard> {
        let child = cmd.spawn()?;
        Ok(ProcessGuard { child })
    }
}
