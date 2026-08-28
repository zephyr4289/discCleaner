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

use std::fs::File;

pub fn create_engine(
    file: File,
    window_bytes: usize,
    supports_write_zeroes: bool,
    qd: u32,
) -> Box<dyn Engine> {
    if let Ok(uring) = UringEngine::try_new(file, window_bytes, supports_write_zeroes, qd) {
        Box::new(uring)
    } else {
        // Fallback to sync
        let f = unsafe {
            use std::os::unix::io::{FromRawFd, IntoRawFd};
            std::fs::File::open("/dev/null").unwrap()
        };
        Box::new(SyncEngine::new(f, window_bytes, supports_write_zeroes).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dc_core::{FixedPattern, FsmOrchestrator, SanitizationPlan, StableIdentity, BusType, FastPathPolicy};
    use tempfile::NamedTempFile;
    use std::io::{Write, Read, Seek, SeekFrom};

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
}
