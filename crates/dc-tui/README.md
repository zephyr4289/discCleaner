# dc-tui — Operator Dashboard and Epistemic Heatmap

`dc-tui` renders live execution state for operators watching a wipe: which
windows are written, which are verified, and which failed — with a strict
**all-or-mixed aggregation law** (Δ464): a heatmap cell is `Verified` only
when every window it covers is verified; partial coverage renders `Mixed`.
A dashboard that over-reports completion is a safety hazard.

## Module map

- `heatmap.rs` — window→cell aggregation (Pending/Written/Verified/Failed/Mixed)
- `state.rs` — `DisplayState`/`PhaseView`: render-model state (progress is
  derived, never stored, so it cannot drift)
- `render.rs` — frame rendering

## Testing

`cargo test -p dc-tui --lib` — aggregation law + progress bounds
(including the empty-state zero-division guard). Integration: `m2_5_tui_matrix`.
