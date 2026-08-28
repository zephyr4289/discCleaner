use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::Instant;

pub struct PtraceKiller;

impl PtraceKiller {
    /// Run child with ptrace and deliver SIGKILL after target_fdatasync_count `fdatasync` syscall exits.
    pub fn run_and_kill_at_fdatasync(
        mut cmd: Command,
        target_fdatasync_count: u64,
    ) -> Result<i32, String> {
        let child = unsafe {
            cmd.pre_exec(|| {
                libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                Ok(())
            })
            .spawn()
            .map_err(|e| format!("Failed to spawn child: {}", e))?
        };

        let pid = child.id() as libc::pid_t;
        let mut status: libc::c_int = 0;

        // Wait for initial stop after exec
        unsafe { libc::waitpid(pid, &mut status, 0) };

        let mut fdatasync_count = 0u64;
        let start_time = Instant::now();

        loop {
            // Resume to next syscall
            let ret = unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) };
            if ret != 0 {
                break;
            }

            let wait_ret = unsafe { libc::waitpid(pid, &mut status, 0) };
            if wait_ret < 0 || libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                break;
            }

            if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP {
                // In Linux, syscall exit stops can be detected
                fdatasync_count += 1;

                if fdatasync_count >= target_fdatasync_count * 2 {
                    // Reached target fdatasync exit -> Deliver SIGKILL
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                        libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
                        libc::waitpid(pid, &mut status, 0);
                    }
                    return Ok(libc::SIGKILL);
                }
            }

            if start_time.elapsed().as_secs() > 120 {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                return Err("Ptrace execution timed out".to_string());
            }
        }

        Ok(libc::SIGKILL)
    }
}
