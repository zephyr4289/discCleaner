use crate::heatmap::Heatmap;
use crate::state::{DisplayState, PhaseView};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedFrame {
    pub header_line: String,
    pub progress_line: String,
    pub rate_line: Option<String>,
    pub verify_entropy_line: Option<String>,
    pub stream_hash_line: Option<String>,
    pub heatmap_summary: String,
}

pub struct TuiRenderer;

impl TuiRenderer {
    /// Render pure frame from DisplayState honoring phase-true and visual grade laws (Δ461, Δ462, Δ465).
    pub fn render(state: &DisplayState, grid_cells: usize) -> RenderedFrame {
        let header_line = format!(
            "TARGET: {} | MODEL: {} | SN: {}",
            state.target_path, state.target_model, state.target_serial
        );

        let progress_line = format!(
            "PROGRESS: {:.1}% ({}/{} windows)",
            state.progress_pct(),
            state.written_windows,
            state.total_windows
        );

        // Indicative rate with ~ suffix (Δ465)
        let rate_line = state
            .throughput_kib_s
            .map(|r| format!("THROUGHPUT: ~{} KiB/s (indicative)", r));

        // Phase-true fields (Δ461)
        let mut verify_entropy_line = None;
        let mut stream_hash_line = None;
        let mut verified_windows = 0;

        match &state.phase {
            PhaseView::Idle => {}
            PhaseView::Writing { .. } => {
                // Write phase MUST NOT render stream hash or entropy! (Δ461)
            }
            PhaseView::Verifying { checked_windows, entropy, .. } => {
                verified_windows = *checked_windows;
                // Neutral diagnostic rendering (Δ461, Δ465)
                verify_entropy_line = Some(format!(
                    "VERIFICATION: Checked {} windows | Entropy H(X): {:.4} (diagnostic)",
                    checked_windows, entropy
                ));
            }
            PhaseView::Complete { stream_hash, duration_ms } => {
                verified_windows = state.total_windows;
                stream_hash_line = Some(format!(
                    "STREAM DIGEST: BLAKE3:{} (completed in {}ms)",
                    stream_hash, duration_ms
                ));
            }
        }

        let heatmap = Heatmap::build(
            state.total_windows,
            state.written_windows,
            verified_windows,
            &state.failed_windows,
            grid_cells,
        );

        let heatmap_summary = format!(
            "HEATMAP: {} cells (Verified: {}, Mixed: {}, Failed: {}, Pending: {})",
            heatmap.total_cells,
            heatmap.cells.iter().filter(|&&c| c == crate::heatmap::HeatmapCellState::Verified).count(),
            heatmap.cells.iter().filter(|&&c| c == crate::heatmap::HeatmapCellState::Mixed).count(),
            heatmap.cells.iter().filter(|&&c| c == crate::heatmap::HeatmapCellState::Failed).count(),
            heatmap.cells.iter().filter(|&&c| c == crate::heatmap::HeatmapCellState::Pending).count(),
        );

        RenderedFrame {
            header_line,
            progress_line,
            rate_line,
            verify_entropy_line,
            stream_hash_line,
            heatmap_summary,
        }
    }
}
