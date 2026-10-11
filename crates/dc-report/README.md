# dc-report — Archival Reporting and Batch Verification

`dc-report` turns sanitization evidence into archival artifacts and verifies
them in batches.

## Module map

- `batch.rs` — `BatchVerifier`: **exhaustive** directory verification
  (Δ477) — every artifact gets a verdict, no short-circuit after the first
  failure; `aggregate_exit_code()` derives the process verdict
- `pdfa.rs` — PDF/A archival document embedding (evidence attachments)
- `project.rs` — report model projection from certificates/journals

## Testing

`cargo test -p dc-report --lib` — 2 unit tests (exhaustiveness, clean-batch
aggregation). Integration: `m2_6_report_matrix`, `m2_7_cross_target_matrix`.
