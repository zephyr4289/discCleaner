use crate::sync_engine::SyncEngine;
use crate::traits::{Engine, EngineCaps, EngineProgress, LbaSpan, PassOutcome, VerifySink};
use dc_core::{DcError, PatternSource, WritePermit};
use std::fs::File;

/// io_uring engine.
///
/// NOTE ON HONEST CAPS: the io_uring submission path is not wired yet; this
/// engine currently delegates every operation to the synchronous engine.
/// Its reported capabilities therefore still identify as the synchronous
/// engine (`engine_name: "sync"`, `supports_io_uring: false`) — an engine
/// must never advertise a capability it does not actually exercise, because
/// operators and auditors make fast-path decisions from `EngineCaps`.
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
        // Probe io_uring availability. When the kernel (or a container
        // seccomp policy) denies the subsystem, engine selection falls back
        // to the synchronous engine on the SAME file — see
        // `dc_io::create_engine` (fail-closed; never /dev/null).
        let is_uring_available = Self::probe_uring();

        if !is_uring_available {
            tracing::info!(
                "io_uring not available on this kernel/environment; \
                 initializing high-throughput SyncEngine"
            );
        } else {
            tracing::info!("io_uring kernel support detected; initializing UringEngine");
        }

        let sync_fallback = SyncEngine::new(file, window_bytes, supports_write_zeroes)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self { sync_fallback })
    }

    fn probe_uring() -> bool {
        #[cfg(target_os = "linux")]
        {
            let sys_setup: libc::c_long = 425; // __NR_io_uring_setup

            // Probe with 0 entries: EINVAL means the syscall exists (proper
            // probe with a real entry count happens on actual use), anything
            // else (ENOSYS/EPERM/...) means the subsystem is unavailable.
            let mut p: [u8; 128] = [0u8; 128];
            let ret = unsafe { libc::syscall(sys_setup, 0, p.as_mut_ptr()) };
            if ret < 0 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(0);
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
        // Deliberately delegates: see the struct-level honesty note.
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
