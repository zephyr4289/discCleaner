use crate::buffer_pool::{AlignedBuffer, BufferPool};
use crate::traits::{Engine, EngineCaps, EngineProgress, LbaSpan, PassOutcome, VerifySink};
use dc_core::{DcError, PatternSource, WritePermit, ZeroPattern};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

const BLKZEROOUT: libc::c_ulong = 0x1277;

pub struct SyncEngine {
    file: File,
    caps: EngineCaps,
    buffer: AlignedBuffer,
    cancel_flag: Arc<AtomicBool>,
}

impl SyncEngine {
    pub fn new(
        file: File,
        window_bytes: usize,
        supports_write_zeroes: bool,
    ) -> Result<Self, std::io::Error> {
        let buffer = AlignedBuffer::allocate(window_bytes, 4096)?;
        let caps = EngineCaps {
            engine_name: "SyncEngine (O_DIRECT / pwrite)",
            supports_io_uring: false,
            supports_write_zeroes,
            max_write_zeroes_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB chunks
            max_qd: 1,
            window_bytes: window_bytes as u64,
        };

        Ok(Self {
            file,
            caps,
            buffer,
            cancel_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn cancel_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel_flag)
    }
}

impl Engine for SyncEngine {
    fn caps(&self) -> &EngineCaps {
        &self.caps
    }

    fn write_pass(
        &mut self,
        _permit: &WritePermit,
        pass_index: u8,
        pat: &dyn PatternSource,
        span: &LbaSpan,
        start_window: u64,
        prog: &mut dyn FnMut(EngineProgress),
    ) -> Result<PassOutcome, DcError> {
        let fd = self.file.as_raw_fd();
        let total_windows = span.total_windows();
        let is_invariant = pat.window_invariant();

        if is_invariant {
            pat.fill(0, &mut self.buffer);
        }

        let start_time = Instant::now();
        let mut last_prog_time = Instant::now();
        let mut bytes_written_in_pass: u64 = 0;

        for w in start_window..total_windows {
            if self.cancel_flag.load(Ordering::Relaxed) {
                return Err(DcError::Interrupted {
                    completed_through: Some((pass_index, w.saturating_sub(1))),
                });
            }

            let (offset, len) = span.window_byte_range(w);
            if len == 0 {
                break;
            }

            if !is_invariant {
                pat.fill(w, &mut self.buffer[..len]);
            }

            // Perform direct pwrite
            let slice = &self.buffer[..len];
            let mut written = 0;
            while written < len {
                let ret = unsafe {
                    libc::pwrite(
                        fd,
                        slice[written..].as_ptr() as *const libc::c_void,
                        len - written,
                        (offset + written as u64) as libc::off_t,
                    )
                };

                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(DcError::Io {
                        op: "pwrite",
                        errno: err.raw_os_error().unwrap_or(5),
                        at_lba: Some(offset / span.logical_block_size as u64),
                    });
                }
                written += ret as usize;
            }

            bytes_written_in_pass += len as u64;

            if last_prog_time.elapsed().as_millis() >= 250 || w + 1 == total_windows {
                let elapsed_secs = start_time.elapsed().as_secs_f64().max(0.001);
                let throughput = (bytes_written_in_pass as f64 / (1024.0 * 1024.0)) / elapsed_secs;
                prog(EngineProgress {
                    pass: pass_index,
                    windows_done: w + 1,
                    total_windows,
                    bytes_done: offset + len as u64,
                    total_bytes: span.total_bytes,
                    throughput_mib_s: throughput,
                });
                last_prog_time = Instant::now();
            }
        }

        Ok(PassOutcome {
            windows_written: total_windows.saturating_sub(start_window),
            bytes_written: bytes_written_in_pass,
            fast_path_used: false,
            duration_ms: start_time.elapsed().as_millis() as u64,
        })
    }

    fn zero_pass(
        &mut self,
        permit: &WritePermit,
        pass_index: u8,
        span: &LbaSpan,
        start_window: u64,
        prog: &mut dyn FnMut(EngineProgress),
    ) -> Result<PassOutcome, DcError> {
        let fd = self.file.as_raw_fd();
        let total_windows = span.total_windows();
        let start_time = Instant::now();

        if self.caps.supports_write_zeroes {
            let chunk_size = self.caps.max_write_zeroes_bytes;
            let mut current_offset = start_window * span.window_bytes;
            let total_bytes = span.total_bytes;
            let mut last_prog_time = Instant::now();
            let mut total_zeroed = 0u64;

            while current_offset < total_bytes {
                if self.cancel_flag.load(Ordering::Relaxed) {
                    let completed_window = current_offset / span.window_bytes;
                    return Err(DcError::Interrupted {
                        completed_through: Some((pass_index, completed_window.saturating_sub(1))),
                    });
                }

                let remaining = total_bytes - current_offset;
                let this_chunk = remaining.min(chunk_size);
                let range = [current_offset, this_chunk];

                let ret = unsafe { libc::ioctl(fd, BLKZEROOUT, &range) };
                if ret != 0 {
                    // BLKZEROOUT failed, fallback to software write_pass
                    tracing::warn!("BLKZEROOUT failed with errno {}, falling back to buffer write", std::io::Error::last_os_error());
                    let zero_pat = ZeroPattern;
                    let remaining_start_window = current_offset / span.window_bytes;
                    return self.write_pass(permit, pass_index, &zero_pat, span, remaining_start_window, prog);
                }

                current_offset += this_chunk;
                total_zeroed += this_chunk;

                if last_prog_time.elapsed().as_millis() >= 250 || current_offset >= total_bytes {
                    let elapsed_secs = start_time.elapsed().as_secs_f64().max(0.001);
                    let throughput = (total_zeroed as f64 / (1024.0 * 1024.0)) / elapsed_secs;
                    let windows_done = (current_offset + span.window_bytes - 1) / span.window_bytes;
                    prog(EngineProgress {
                        pass: pass_index,
                        windows_done: windows_done.min(total_windows),
                        total_windows,
                        bytes_done: current_offset,
                        total_bytes,
                        throughput_mib_s: throughput,
                    });
                    last_prog_time = Instant::now();
                }
            }

            Ok(PassOutcome {
                windows_written: total_windows.saturating_sub(start_window),
                bytes_written: total_zeroed,
                fast_path_used: true,
                duration_ms: start_time.elapsed().as_millis() as u64,
            })
        } else {
            let zero_pat = ZeroPattern;
            self.write_pass(permit, pass_index, &zero_pat, span, start_window, prog)
        }
    }

    fn read_verify(
        &mut self,
        pat: &dyn PatternSource,
        span: &LbaSpan,
        sink: &mut dyn VerifySink,
        prog: &mut dyn FnMut(EngineProgress),
    ) -> Result<(), DcError> {
        let fd = self.file.as_raw_fd();
        let total_windows = span.total_windows();
        let mut expected_buf = AlignedBuffer::allocate(span.window_bytes as usize, 4096)?;
        let is_invariant = pat.window_invariant();

        if is_invariant {
            pat.fill(0, &mut expected_buf);
        }

        let start_time = Instant::now();
        let mut last_prog_time = Instant::now();
        let mut bytes_verified = 0u64;

        for w in 0..total_windows {
            if self.cancel_flag.load(Ordering::Relaxed) {
                return Err(DcError::Interrupted {
                    completed_through: None,
                });
            }

            let (offset, len) = span.window_byte_range(w);
            if len == 0 {
                break;
            }

            let slice = &mut self.buffer[..len];
            let mut read_bytes = 0;
            while read_bytes < len {
                let ret = unsafe {
                    libc::pread(
                        fd,
                        slice[read_bytes..].as_mut_ptr() as *mut libc::c_void,
                        len - read_bytes,
                        (offset + read_bytes as u64) as libc::off_t,
                    )
                };

                if ret <= 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(DcError::Io {
                        op: "pread",
                        errno: err.raw_os_error().unwrap_or(5),
                        at_lba: Some(offset / span.logical_block_size as u64),
                    });
                }
                read_bytes += ret as usize;
            }

            if !is_invariant {
                pat.fill(w, &mut expected_buf[..len]);
            }

            let is_valid = slice == &expected_buf[..len];
            sink.on_window(w, is_valid, slice)?;

            bytes_verified += len as u64;

            if last_prog_time.elapsed().as_millis() >= 250 || w + 1 == total_windows {
                let elapsed_secs = start_time.elapsed().as_secs_f64().max(0.001);
                let throughput = (bytes_verified as f64 / (1024.0 * 1024.0)) / elapsed_secs;
                prog(EngineProgress {
                    pass: 0,
                    windows_done: w + 1,
                    total_windows,
                    bytes_done: offset + len as u64,
                    total_bytes: span.total_bytes,
                    throughput_mib_s: throughput,
                });
                last_prog_time = Instant::now();
            }
        }

        Ok(())
    }

    fn flush(&mut self, _permit: &WritePermit) -> Result<(), DcError> {
        let fd = self.file.as_raw_fd();
        let ret = unsafe { libc::fsync(fd) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(DcError::Io {
                op: "fsync",
                errno: err.raw_os_error().unwrap_or(5),
                at_lba: None,
            });
        }
        Ok(())
    }

    fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::SeqCst);
    }
}
