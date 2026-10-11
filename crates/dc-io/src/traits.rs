use dc_core::{DcError, PatternSource, WritePermit};

#[derive(Clone, Copy, Debug)]
pub struct LbaSpan {
    pub start_byte: u64,
    pub total_bytes: u64,
    pub logical_block_size: u32,
    pub window_bytes: u64,
}

impl LbaSpan {
    pub fn new(total_bytes: u64, logical_block_size: u32, window_bytes: u64) -> Self {
        Self {
            start_byte: 0,
            total_bytes,
            logical_block_size: logical_block_size.max(512),
            window_bytes: window_bytes.max(4096),
        }
    }

    /// Ceiling division of total bytes by window bytes (overflow-safe).
    pub fn total_windows(&self) -> u64 {
        if self.window_bytes == 0 {
            return 0;
        }
        // div_ceil avoids the historical `total + window - 1` overflow on
        // near-u64::MAX sizes (regression REG-LBASPAN-OVERFLOW).
        self.total_bytes.div_ceil(self.window_bytes)
    }

    pub fn window_byte_range(&self, window_index: u64) -> (u64, usize) {
        // `window_index * window_bytes` saturates instead of wrapping.
        let offset = window_index
            .checked_mul(self.window_bytes)
            .and_then(|o| self.start_byte.checked_add(o))
            .unwrap_or(u64::MAX);
        let remaining = self.total_bytes.saturating_sub(offset);
        let len = (remaining.min(self.window_bytes)) as usize;
        (offset, len)
    }
}

#[derive(Clone, Debug)]
pub struct EngineCaps {
    pub engine_name: &'static str,
    pub supports_io_uring: bool,
    pub supports_write_zeroes: bool,
    pub max_write_zeroes_bytes: u64,
    pub max_qd: u32,
    pub window_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct PassOutcome {
    pub windows_written: u64,
    pub bytes_written: u64,
    pub fast_path_used: bool,
    pub duration_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct EngineProgress {
    pub pass: u8,
    pub windows_done: u64,
    pub total_windows: u64,
    pub bytes_done: u64,
    pub total_bytes: u64,
    pub throughput_mib_s: f64,
}

pub trait VerifySink: Send {
    fn on_window(&mut self, window_index: u64, is_valid: bool, data: &[u8]) -> Result<(), DcError>;
}

pub trait Engine: Send {
    fn caps(&self) -> &EngineCaps;

    fn write_pass(
        &mut self,
        permit: &WritePermit,
        pass_index: u8,
        pat: &dyn PatternSource,
        span: &LbaSpan,
        start_window: u64,
        prog: &mut dyn FnMut(EngineProgress),
    ) -> Result<PassOutcome, DcError>;

    fn zero_pass(
        &mut self,
        permit: &WritePermit,
        pass_index: u8,
        span: &LbaSpan,
        start_window: u64,
        prog: &mut dyn FnMut(EngineProgress),
    ) -> Result<PassOutcome, DcError>;

    fn read_verify(
        &mut self,
        pat: &dyn PatternSource,
        span: &LbaSpan,
        sink: &mut dyn VerifySink,
        prog: &mut dyn FnMut(EngineProgress),
    ) -> Result<(), DcError>;

    fn flush(&mut self, permit: &WritePermit) -> Result<(), DcError>;

    fn cancel(&self);
}
