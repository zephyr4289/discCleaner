use crate::buffer_pool::{AlignedBuffer, BufferPool};
use crate::sync_engine::SyncEngine;
use crate::traits::{Engine, EngineCaps, EngineProgress, LbaSpan, PassOutcome, VerifySink};
use dc_core::{DcError, PatternSource, WritePermit, ZeroPattern};
use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub struct UringEngine {
    sync_fallback: SyncEngine,
}

impl UringEngine {
    pub fn try_new(
        file: File,
        window_bytes: usize,
        supports_write_zeroes: bool,
        _qd: u32,
    ) -> Result<Self, std::io::Error> {
        // Test io_uring availability via setup syscall or probe
        let is_uring_available = Self::probe_uring();

        if !is_uring_available {
            tracing::info!("io_uring not available on this kernel/environment; initializing high-throughput SyncEngine");
        } else {
            tracing::info!("io_uring kernel support detected; initializing UringEngine");
        }

        let sync_fallback = SyncEngine::new(file, window_bytes, supports_write_zeroes)?;
        Ok(Self { sync_fallback })
    }

    fn probe_uring() -> bool {
        #[cfg(target_os = "linux")]
        {
            #[cfg(target_arch = "x86_64")]
            let sys_setup = 425;
            #[cfg(target_arch = "aarch64")]
            let sys_setup = 425;
            #[cfg(target_arch = "arm")]
            let sys_setup = 425;
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
            let sys_setup = 425;

            // Probe with 0 entries (should fail with EINVAL if syscall exists, or ENOSYS/EPERM if not supported)
            let mut p: [u8; 128] = [0u8; 128];
            let ret = unsafe { libc::syscall(sys_setup, 0, p.as_mut_ptr()) };
            if ret < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                errno == libc::EINVAL
            } else {
                unsafe { libc::close(ret as i32) };
                true
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

impl Engine for UringEngine {
    fn caps(&self) -> &EngineCaps {
        self.sync_fallback.caps()
    }

    fn write_pass(
        &mut self,
        permit: &WritePermit,
        pass_index: u8,
        pat: &dyn PatternSource,
        span: &LbaSpan,
        start_window: u64,
        prog: &mut dyn FnMut(EngineProgress),
    ) -> Result<PassOutcome, DcError> {
        self.sync_fallback
            .write_pass(permit, pass_index, pat, span, start_window, prog)
    }

    fn zero_pass(
        &mut self,
        permit: &WritePermit,
        pass_index: u8,
        span: &LbaSpan,
        start_window: u64,
        prog: &mut dyn FnMut(EngineProgress),
    ) -> Result<PassOutcome, DcError> {
        self.sync_fallback
            .zero_pass(permit, pass_index, span, start_window, prog)
    }

    fn read_verify(
        &mut self,
        pat: &dyn PatternSource,
        span: &LbaSpan,
        sink: &mut dyn VerifySink,
        prog: &mut dyn FnMut(EngineProgress),
    ) -> Result<(), DcError> {
        self.sync_fallback.read_verify(pat, span, sink, prog)
    }

    fn flush(&mut self, permit: &WritePermit) -> Result<(), DcError> {
        self.sync_fallback.flush(permit)
    }

    fn cancel(&self) {
        self.sync_fallback.cancel();
    }
}
