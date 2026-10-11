use crate::BLKZEROOUT_IOCTL;
use dc_core::FastPathPolicy;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub const DEFAULT_CHUNK_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB chunk (Δ136)

pub struct ZeroPath;

impl ZeroPath {
    /// Execute fast-path zeroing in discrete 2 GiB chunks with cancellation checks (Δ136, Δ142).
    pub fn execute_chunked(
        file: &File,
        total_size: u64,
        policy: FastPathPolicy,
        supports_write_zeroes: bool,
        cancel_token: Option<&Arc<AtomicBool>>,
        mut on_chunk_done: impl FnMut(u64, u64),
    ) -> Result<u64, String> {
        if policy == FastPathPolicy::ForbidWriteZeroes || !supports_write_zeroes {
            return Err(
                "Fast-path write-zeroes disabled by policy or unsupported by kernel".to_string(),
            );
        }

        let chunk_size = DEFAULT_CHUNK_BYTES.min(total_size);
        let mut current_offset = 0u64;

        while current_offset < total_size {
            // Check cancellation before each chunk (Δ142)
            if let Some(cancel) = cancel_token
                && cancel.load(Ordering::Relaxed)
            {
                return Ok(current_offset);
            }

            let len = (total_size - current_offset).min(chunk_size);

            // Execute BLKZEROOUT ioctl
            #[cfg(target_os = "linux")]
            {
                let range = [current_offset, len];
                let fd = file.as_raw_fd();
                let ret = unsafe { libc::ioctl(fd, BLKZEROOUT_IOCTL, range.as_ptr()) };
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(format!(
                        "BLKZEROOUT failed at offset {}: {}",
                        current_offset, err
                    ));
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                // Fail-closed: never report fast-path zeroing as performed on
                // platforms where the ioctl does not exist.
                return Err(
                    "BLKZEROOUT fast path is Linux-only; refusing to fake completion".to_string(),
                );
            }

            current_offset += len;
            on_chunk_done(current_offset, len);
        }

        Ok(current_offset)
    }
}
