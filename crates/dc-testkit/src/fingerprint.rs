use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvironmentFingerprint {
    pub kernel_release: String,
    pub machine: String,
    pub loop_minor: i32,
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub device_size_bytes: u64,
    pub write_zeroes_max_bytes: u64,
    pub scratch_dir: String,
    pub timestamp_utc: String,
}

impl EnvironmentFingerprint {
    pub fn collect(
        loop_minor: i32,
        lbs: u32,
        pbs: u32,
        size_bytes: u64,
        wz_max: u64,
        scratch_dir: &Path,
    ) -> Self {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        unsafe { libc::uname(&mut uts) };

        let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
            .to_string_lossy()
            .to_string();
        let machine = unsafe { std::ffi::CStr::from_ptr(uts.machine.as_ptr()) }
            .to_string_lossy()
            .to_string();

        Self {
            kernel_release: release,
            machine,
            loop_minor,
            logical_block_size: lbs,
            physical_block_size: pbs,
            device_size_bytes: size_bytes,
            write_zeroes_max_bytes: wz_max,
            scratch_dir: scratch_dir.to_string_lossy().to_string(),
            timestamp_utc: chrono_now_iso(),
        }
    }
}

fn chrono_now_iso() -> String {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::gmtime_r(&ts.tv_sec, &mut tm) };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}
