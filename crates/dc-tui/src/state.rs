use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PhaseView {
    Idle,
    Writing {
        pass: u8,
        frontier_lba: u64,
    },
    Verifying {
        pass: u8,
        checked_windows: u64,
        entropy: f64,
    },
    Complete {
        stream_hash: String,
        duration_ms: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DisplayState {
    pub target_path: String,
    pub target_model: String,
    pub target_serial: String,
    pub phase: PhaseView,
    pub written_windows: u64,
    pub total_windows: u64,
    pub throughput_kib_s: Option<u64>, // Indicative observation
    pub failed_windows: Vec<u64>,
}

impl DisplayState {
    pub fn progress_pct(&self) -> f64 {
        if self.total_windows == 0 {
            0.0
        } else {
            (self.written_windows as f64 / self.total_windows as f64) * 100.0
        }
    }
}
