use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeatmapCellState {
    Pending,
    Written,
    Verified,
    Failed,
    Mixed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heatmap {
    pub total_cells: usize,
    pub cells: Vec<HeatmapCellState>,
}

impl Heatmap {
    /// Aggregate per-window states into a cell grid with strict all-or-mixed law (Δ464).
    pub fn build(
        total_windows: u64,
        written_windows: u64,
        verified_windows: u64,
        failed_windows: &[u64],
        grid_cells: usize,
    ) -> Self {
        if total_windows == 0 || grid_cells == 0 {
            return Self {
                total_cells: grid_cells,
                cells: vec![HeatmapCellState::Pending; grid_cells],
            };
        }

        let windows_per_cell = (total_windows as f64 / grid_cells as f64).ceil() as u64;
        let mut cells = Vec::with_capacity(grid_cells);

        for cell_idx in 0..grid_cells {
            let start_win = cell_idx as u64 * windows_per_cell;
            let end_win = std::cmp::min((cell_idx as u64 + 1) * windows_per_cell, total_windows);

            if start_win >= total_windows {
                cells.push(HeatmapCellState::Pending);
                continue;
            }

            // Check for failures in this range
            let has_failure = failed_windows.iter().any(|&w| w >= start_win && w < end_win);
            if has_failure {
                cells.push(HeatmapCellState::Failed);
                continue;
            }

            // Check verification status
            if verified_windows >= end_win {
                cells.push(HeatmapCellState::Verified);
            } else if verified_windows > start_win {
                cells.push(HeatmapCellState::Mixed);
            } else if written_windows >= end_win {
                cells.push(HeatmapCellState::Written);
            } else if written_windows > start_win {
                cells.push(HeatmapCellState::Mixed);
            } else {
                cells.push(HeatmapCellState::Pending);
            }
        }

        Self {
            total_cells: grid_cells,
            cells,
        }
    }
}
