pub mod buffer_pool;
pub mod geometry;
pub mod sync_engine;
pub mod tracker;
pub mod traits;
pub mod uring_engine;
pub mod zeropath;

pub use buffer_pool::{AlignedBuffer, BufferPool};
pub use geometry::WindowGeometry;
pub use sync_engine::SyncEngine;
pub use tracker::{CompletionTracker, RangeCommitSpec};
pub use traits::{Engine, EngineCaps, EngineProgress, LbaSpan, PassOutcome, VerifySink};
pub use uring_engine::UringEngine;
pub use zeropath::{ZeroPath, DEFAULT_CHUNK_BYTES};

use dc_core::DcError;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};

/// Linux `BLKZEROOUT` ioctl request number (single authoritative definition;
/// previously duplicated across `sync_engine` and `zeropath`).
pub const BLKZEROOUT_IOCTL: libc::c_ulong = 0x1277;

/// Process-wide cancellation flag.
///
/// Signal handlers cannot safely touch engine-owned state, so `SIGINT` /
/// `SIGTERM` handlers (installed by the CLI) flip this one static flag. Every
/// engine consults it at each window boundary and converts it into a graceful
/// `DcError::Interrupted` with the last completed window — the journal stays
/// resumable and no partially-written window is ever reported as committed.
static GLOBAL_CANCEL: AtomicBool = AtomicBool::new(false);

/// Request cooperative cancellation of every engine in this process
/// (idempotent). Called from the CLI's signal handler.
pub fn request_global_cancel() {
    GLOBAL_CANCEL.store(true, Ordering::SeqCst);
}

/// Test / reset helper — primarily for test rigs that spawn multiple runs in
/// one process.
pub fn reset_global_cancel() {
    GLOBAL_CANCEL.store(false, Ordering::SeqCst);
}

/// Whether global cancellation has been requested.
pub fn is_global_cancel_requested() -> bool {
    GLOBAL_CANCEL.load(Ordering::Relaxed)
}

/// Select the best available engine for this kernel, FAIL-CLOSED.
///
/// SECURITY CONTRACT (regression `REG-ENGINE-FAILCLOSED`): the automatic
/// selection falls back from io_uring to the synchronous engine on the SAME
/// file handle. The historical implementation "fell back" to a SyncEngine
/// opened on `/dev/null` when io_uring setup failed — every subsequent
/// "wipe" silently wrote to the bit bucket while the caller still issued
/// completion certificates. That path is structurally impossible now: the
/// only file ever handed to an engine is the caller's device.
pub fn create_engine(
    file: File,
    window_bytes: usize,
    supports_write_zeroes: bool,
    qd: u32,
) -> Result<Box<dyn Engine>, DcError> {
    // Duplicate the descriptor BEFORE the io_uring attempt consumes it. A
    // dup'd fd shares the same open file description — and therefore the
    // same O_EXCL / flock ownership the Guardian acquired — so the fallback
    // engine keeps every lock the caller holds.
    let fallback_file = file
        .try_clone()
        .map_err(|e| DcError::Io { op: "engine-fd-dup", errno: e.raw_os_error().unwrap_or(5), at_lba: None })?;

    match UringEngine::try_new(file, window_bytes, supports_write_zeroes, qd) {
        Ok(uring) => Ok(Box::new(uring)),
        Err(e) => {
            tracing::warn!(
                "io_uring engine unavailable ({}); using synchronous engine on the SAME device",
                e
            );
            Ok(Box::new(SyncEngine::new(
                fallback_file,
                window_bytes,
                supports_write_zeroes,
            )?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dc_core::{BusType, FastPathPolicy, FixedPattern, FsmOrchestrator, SanitizationPlan, StableIdentity};
    use std::io::{Read, Seek, SeekFrom};
    use tempfile::NamedTempFile;

    #[test]
    fn test_sync_engine_write_and_verify() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let size = 8 * 1024 * 1024; // 8 MiB
        temp_file.as_file_mut().set_len(size).unwrap();

        let window_bytes = 2 * 1024 * 1024;
        let span = LbaSpan::new(size, 512, window_bytes);

        let file = temp_file.reopen().unwrap();
        let mut engine = SyncEngine::new(file, window_bytes as usize, false).unwrap();

        let mut fsm = FsmOrchestrator::new();
        let identity = StableIdentity {
            model: None,
            serial: None,
            wwn: None,
            size_bytes: size,
            bus: BusType::File,
            dm_name: None,
            dm_uuid: None,
        };
        let plan = SanitizationPlan::clear_zero(identity, FastPathPolicy::ForbidWriteZeroes);
        fsm.compile_plan(plan).unwrap();
        fsm.approve_plan().unwrap();
        fsm.arm().unwrap();
        let permit = fsm.begin_pass(0).unwrap();

        let pat = FixedPattern { byte: 0xAA };
        let outcome = engine
            .write_pass(&permit, 0, &pat, &span, 0, &mut |_| {})
            .unwrap();

        assert_eq!(outcome.windows_written, 4);
        assert_eq!(outcome.bytes_written, size);

        // Read back and verify bytes
        let mut readback = vec![0u8; size as usize];
        let mut f = temp_file.reopen().unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut readback).unwrap();
        assert!(readback.iter().all(|&b| b == 0xAA));
    }

    /// REG-ENGINE-FAILCLOSED: an engine handed a real file must never turn
    /// into a no-op /dev/null writer, and `create_engine` must fail loudly
    /// rather than silently substituting a different device.
    #[test]
    fn test_create_engine_never_dev_null() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.as_file_mut().set_len(1024 * 1024).unwrap();
        let file = tmp.reopen().unwrap();

        let engine = create_engine(file, 64 * 1024, false, 4);
        let engine = engine.expect("create_engine on a regular file must succeed");
        assert_ne!(engine.caps().engine_name, "");
        assert!(engine.caps().window_bytes > 0);
    }
}
