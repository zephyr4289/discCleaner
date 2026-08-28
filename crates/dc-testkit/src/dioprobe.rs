use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub struct DioProbe;

impl DioProbe {
    /// Empirically probe for a scratch directory supporting true O_DIRECT writes and >= 2.25 GiB free space.
    pub fn discover_scratch_dir() -> Result<PathBuf, String> {
        let mut candidates = Vec::new();

        if let Ok(custom) = std::env::var("DC_T1_SCRATCH") {
            candidates.push(PathBuf::from(custom));
        }
        candidates.push(PathBuf::from("/var/tmp"));
        candidates.push(PathBuf::from("/tmp"));
        candidates.push(PathBuf::from("."));

        let mut errors = Vec::new();

        for candidate in candidates {
            if !candidate.exists() {
                let _ = fs::create_dir_all(&candidate);
            }
            if !candidate.is_dir() {
                continue;
            }

            // 1. Check free space (>= 2.25 GiB = 2,415,919,104 bytes)
            if let Err(e) = Self::check_free_space(&candidate, 2_415_919_104) {
                errors.push(format!("{}: {}", candidate.display(), e));
                continue;
            }

            // 2. Empirically probe O_DIRECT write & read-back
            match Self::probe_direct_io(&candidate) {
                Ok(()) => return Ok(candidate),
                Err(e) => {
                    errors.push(format!("{}: O_DIRECT failed ({})", candidate.display(), e));
                }
            }
        }

        Err(format!(
            "No candidate scratch directory supports true O_DIRECT and >= 2.25 GiB free space. Details:\n{}",
            errors.join("\n")
        ))
    }

    fn check_free_space(dir: &Path, min_bytes: u64) -> Result<(), String> {
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let c_path = std::ffi::CString::new(dir.to_string_lossy().as_bytes()).map_err(|e| e.to_string())?;
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if ret != 0 {
            return Err(format!("statvfs failed: {}", std::io::Error::last_os_error()));
        }

        let free_bytes = stat.f_bavail as u64 * stat.f_frsize as u64;
        if free_bytes < min_bytes {
            return Err(format!(
                "Insufficient free space: have {:.2} GiB, require {:.2} GiB",
                free_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                min_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
            ));
        }
        Ok(())
    }

    fn probe_direct_io(dir: &Path) -> Result<(), String> {
        let test_file = dir.join(format!(".dio_probe_{}.tmp", std::process::id()));

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_DIRECT)
            .open(&test_file)
            .map_err(|e| e.to_string())?;

        let fd = file.as_raw_fd();

        // Allocate 4096B aligned buffer
        let mut raw_ptr: *mut libc::c_void = std::ptr::null_mut();
        let ret = unsafe { libc::posix_memalign(&mut raw_ptr, 4096, 4096) };
        if ret != 0 || raw_ptr.is_null() {
            let _ = fs::remove_file(&test_file);
            return Err("posix_memalign failed".to_string());
        }

        let write_buf = unsafe {
            let s = std::slice::from_raw_parts_mut(raw_ptr as *mut u8, 4096);
            s.fill(0xA5);
            s
        };

        let pwrite_ret = unsafe {
            libc::pwrite(
                fd,
                write_buf.as_ptr() as *const libc::c_void,
                4096,
                0,
            )
        };

        if pwrite_ret != 4096 {
            unsafe { libc::free(raw_ptr) };
            let _ = fs::remove_file(&test_file);
            return Err(format!("pwrite returned {}", pwrite_ret));
        }

        let mut read_ptr: *mut libc::c_void = std::ptr::null_mut();
        unsafe { libc::posix_memalign(&mut read_ptr, 4096, 4096) };
        let read_buf = unsafe {
            let s = std::slice::from_raw_parts_mut(read_ptr as *mut u8, 4096);
            s.fill(0x00);
            s
        };

        let pread_ret = unsafe {
            libc::pread(
                fd,
                read_buf.as_mut_ptr() as *mut libc::c_void,
                4096,
                0,
            )
        };

        let is_match = pread_ret == 4096 && read_buf == write_buf;

        unsafe {
            libc::free(raw_ptr);
            libc::free(read_ptr);
        }
        let _ = fs::remove_file(&test_file);

        if !is_match {
            return Err("Readback content mismatch in O_DIRECT test".to_string());
        }

        Ok(())
    }
}
