pub mod heatmap;
pub mod render;
pub mod state;

pub use heatmap::{Heatmap, HeatmapCellState};
pub use render::{RenderedFrame, TuiRenderer};
pub use state::{DisplayState, PhaseView};

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn heatmap_aggregation_follows_all_or_mixed_law() {
        // 10 windows into 5 cells (2 windows/cell).
        let hm = Heatmap::build(10, 10, 10, &[], 5);
        assert_eq!(hm.total_cells, 5);
        assert!(hm.cells.iter().all(|c| matches!(c, HeatmapCellState::Verified)));

        // Partial verification: cell 0 covers windows [0,2) which are fully
        // verified (3 >= 2) so it IS Verified; cell 1 is partially covered
        // and must be Mixed — never a false Verified for a half-done cell.
        let hm2 = Heatmap::build(10, 10, 3, &[], 5);
        assert!(matches!(hm2.cells[0], HeatmapCellState::Verified), "fully verified cell");
        assert!(matches!(hm2.cells[1], HeatmapCellState::Mixed), "partially verified cell");
        assert!(hm2.cells[2..].iter().all(|c| matches!(c, HeatmapCellState::Written)));

        // Any failure in a cell's range marks it Failed.
        let hm3 = Heatmap::build(10, 10, 10, &[5], 5);
        assert!(matches!(hm3.cells[2], HeatmapCellState::Failed));
        assert_eq!(hm3.cells.iter().filter(|c| matches!(c, HeatmapCellState::Failed)).count(), 1);
    }

    #[test]
    fn display_state_progress_is_bounded() {
        let st = DisplayState {
            target_path: "/dev/null".to_string(),
            target_model: "M".to_string(),
            target_serial: "S".to_string(),
            phase: PhaseView::Writing { pass: 0, frontier_lba: 512 },
            written_windows: 25,
            total_windows: 100,
            throughput_kib_s: Some(1024),
            failed_windows: vec![],
        };
        assert_eq!(st.progress_pct(), 25.0);

        let empty = DisplayState {
            target_path: String::new(),
            target_model: String::new(),
            target_serial: String::new(),
            phase: PhaseView::Idle,
            written_windows: 0,
            total_windows: 0,
            throughput_kib_s: None,
            failed_windows: vec![],
        };
        assert_eq!(empty.progress_pct(), 0.0, "no divide-by-zero on empty state");
    }
}
