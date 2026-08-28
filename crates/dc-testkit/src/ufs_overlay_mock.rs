use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UfsOverlayMock {
    pub lu_count: usize,
    pub write_booster_enabled: bool,
    pub write_booster_flushed: bool,
}

impl UfsOverlayMock {
    pub fn new(lu_count: usize, write_booster_enabled: bool) -> Self {
        Self {
            lu_count,
            write_booster_enabled,
            write_booster_flushed: false,
        }
    }

    /// Flush the device-internal WriteBooster cache (Δ342).
    pub fn flush_write_booster(&mut self) {
        self.write_booster_flushed = true;
    }

    /// Verify logical readback, strictly requiring a prior WriteBooster flush if enabled.
    pub fn verify_logical_readback(&self) -> Result<(), &'static str> {
        if self.write_booster_enabled && !self.write_booster_flushed {
            Err("UNFLUSHED_WRITE_BOOSTER_CACHE_FOOLED_VERIFICATION")
        } else {
            Ok(())
        }
    }
}
