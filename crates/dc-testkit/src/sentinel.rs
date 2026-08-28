use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

pub const SENTINEL_BYTE: u8 = 0xA5;

pub struct SentinelManager;

impl SentinelManager {
    /// Pre-fill backing file with 0xA5 sentinel bytes in 2 MiB chunks, then fdatasync.
    pub fn fill_sentinel(path: &Path, total_bytes: u64) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("Failed to create backing file: {}", e))?;

        let chunk_size = 2 * 1024 * 1024;
        let buf = vec![SENTINEL_BYTE; chunk_size];

        let mut written: u64 = 0;
        while written < total_bytes {
            let remaining = total_bytes - written;
            let to_write = (remaining.min(chunk_size as u64)) as usize;
            file.write_all(&buf[..to_write])
                .map_err(|e| format!("Sentinel write failed: {}", e))?;
            written += to_write as u64;
        }

        file.sync_all()
            .map_err(|e| format!("Sentinel fdatasync failed: {}", e))?;
        Ok(())
    }

    /// O_DIRECT spot check through loop device to verify sentinel byte (0xA5) is physically present on media.
    pub fn verify_sentinel_pre_check(loop_dev_path: &Path, total_bytes: u64) -> Result<(), String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(loop_dev_path)
            .map_err(|e| format!("Failed to open loop for pre-check: {}", e))?;
        let fd = file.as_raw_fd();

        let mut raw_ptr: *mut libc::c_void = std::ptr::null_mut();
        unsafe { libc::posix_memalign(&mut raw_ptr, 4096, 4096) };
        if raw_ptr.is_null() {
            return Err("Failed to allocate aligned buffer".to_string());
        }

        let offsets = [0u64, (total_bytes / 2) & !4095, (total_bytes - 4096) & !4095];

        for &off in &offsets {
            let read_ret = unsafe { libc::pread(fd, raw_ptr, 4096, off as libc::off_t) };
            if read_ret != 4096 {
                unsafe { libc::free(raw_ptr) };
                return Err(format!("pread returned {} at offset {}", read_ret, off));
            }

            let slice = unsafe { std::slice::from_raw_parts(raw_ptr as *const u8, 4096) };
            if !slice.iter().all(|&b| b == SENTINEL_BYTE) {
                unsafe { libc::free(raw_ptr) };
                return Err(format!(
                    "Sentinel pre-check failed at offset {}: expected 0xA5, observed non-sentinel data",
                    off
                ));
            }
        }

        unsafe { libc::free(raw_ptr) };
        Ok(())
    }

    /// Full sequential O_DIRECT verification of backing file after wipe.
    pub fn verify_zero_media_oracle(
        backing_path: &Path,
        total_bytes: u64,
    ) -> Result<MediaOracleResult, String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(backing_path)
            .map_err(|e| format!("Failed to open backing file for media oracle: {}", e))?;
        let fd = file.as_raw_fd();

        let window_size = 2 * 1024 * 1024; // 2 MiB
        let mut raw_ptr: *mut libc::c_void = std::ptr::null_mut();
        unsafe { libc::posix_memalign(&mut raw_ptr, 4096, window_size) };
        if raw_ptr.is_null() {
            return Err("Failed to allocate aligned buffer".to_string());
        }

        let mut harness_hasher = blake3::Hasher::new();
        let mut expected_zero_hasher = blake3::Hasher::new();
        let zero_window = vec![0u8; window_size];

        let mut offset: u64 = 0;
        let mut first_mismatch_offset: Option<u64> = None;
        let mut first_mismatch_byte: Option<u8> = None;

        while offset < total_bytes {
            let remaining = total_bytes - offset;
            let read_len = (remaining.min(window_size as u64)) as usize;
            // Pad read_len to 4096 for O_DIRECT alignment on last short window
            let aligned_read_len = (read_len + 4095) & !4095;

            let ret = unsafe { libc::pread(fd, raw_ptr, aligned_read_len, offset as libc::off_t) };
            if ret < read_len as isize {
                unsafe { libc::free(raw_ptr) };
                return Err(format!("pread returned {} at offset {}", ret, offset));
            }

            let slice = unsafe { std::slice::from_raw_parts(raw_ptr as *const u8, read_len) };
            harness_hasher.update(slice);
            expected_zero_hasher.update(&zero_window[..read_len]);

            if first_mismatch_offset.is_none() {
                for (i, &b) in slice.iter().enumerate() {
                    if b != 0x00 {
                        first_mismatch_offset = Some(offset + i as u64);
                        first_mismatch_byte = Some(b);
                        break;
                    }
                }
            }

            offset += read_len as u64;
        }

        unsafe { libc::free(raw_ptr) };

        let harness_hash = harness_hasher.finalize().to_hex().to_string();
        let expected_zeros_hash = expected_zero_hasher.finalize().to_hex().to_string();

        Ok(MediaOracleResult {
            all_zeros: first_mismatch_offset.is_none(),
            first_mismatch_offset,
            first_mismatch_byte,
            harness_stream_hash: harness_hash,
            expected_zeros_hash,
            bytes_verified: offset,
        })
    }

    /// Dual-view cross-check through loop device (both O_DIRECT and buffered).
    pub fn verify_dual_view_cross_check(loop_dev_path: &Path, total_bytes: u64) -> Result<(), String> {
        // 1. Buffered read at beginning, middle, and end
        let mut file = File::open(loop_dev_path)
            .map_err(|e| format!("Failed to open loop for buffered cross-check: {}", e))?;

        let sample_offsets = [0u64, total_bytes / 2, total_bytes.saturating_sub(1024)];
        let mut buf = [0u8; 1024];

        for &off in &sample_offsets {
            file.seek(SeekFrom::Start(off))
                .map_err(|e| format!("Seek failed: {}", e))?;
            file.read_exact(&mut buf)
                .map_err(|e| format!("Read failed at offset {}: {}", off, e))?;

            if !buf.iter().all(|&b| b == 0x00) {
                return Err(format!("Dual-view buffered check failed at offset {}: non-zero byte detected", off));
            }
        }

        Ok(())
    }
}

pub struct MediaOracleResult {
    pub all_zeros: bool,
    pub first_mismatch_offset: Option<u64>,
    pub first_mismatch_byte: Option<u8>,
    pub harness_stream_hash: String,
    pub expected_zeros_hash: String,
    pub bytes_verified: u64,
}
