use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub struct ExclHolder {
    pub file: File,
}

impl ExclHolder {
    /// Acquire an exclusive claim on a block device using O_EXCL.
    pub fn hold(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_EXCL)
            .open(path)
            .map_err(|e| format!("Failed to open O_EXCL on {}: {}", path.display(), e))?;

        Ok(Self { file })
    }

    /// Empirical prelude test proving O_EXCL claim semantics work on the running kernel.
    pub fn prelude_verify_excl_semantics(target_path: &Path) -> Result<(), String> {
        // 1. Open primary exclusive holder
        let holder1 = Self::hold(target_path)?;

        // 2. Secondary open with O_EXCL MUST fail with EBUSY
        let holder2_res = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_EXCL)
            .open(target_path);

        match holder2_res {
            Ok(_) => Err("O_EXCL secondary open SUCCEEDED unexpectedly (kernel lack claim semantics)".to_string()),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                // Expected EBUSY!
                drop(holder1);
                Ok(())
            }
            Err(e) => {
                drop(holder1);
                Err(format!("Expected EBUSY, got: {}", e))
            }
        }
    }
}
