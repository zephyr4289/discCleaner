# dc-report — Archival Reporting and Batch Verification

`dc-report` turns sanitization evidence into archival artifacts and verifies
them in batches.

## Module map

- `batch.rs` — `BatchVerifier`: **exhaustive** directory verification
  (Δ477) — every artifact gets a verdict, no short-circuit after the first
  failure; `aggregate_exit_code()` derives the process verdict
- `pdfa/` — **REAL ISO 19005-3 (PDF/A-3b) archival engine (v0.6.0)**:
  - `pdfw.rs` — zero-dependency PDF 1.7 writer (classic xref, trailer /ID)
  - `icc.rs` — hand-built minimal sRGB ICC v2.1 output-intent profile
  - `xmp.rs` — XMP packet declaring `pdfaid:part 3 / conformance B`
  - `font.rs` — minimal TrueType parser + Type0/CIDFontType2 embedder
    (full Liberation Serif face, `/W` widths, ToUnicode CMap)
  - `mod.rs` — document assembly: catalog + OutputIntent + `/Names
    /EmbeddedFiles` + `/AF` associated files; the legacy `PdfaDocument`
    API now renders through the real engine
- `template.rs` — visual certificate front page: navy masthead, NIST
  SP 800-88 class badge, verdict badge, evidence table, defense-warning
  box, attachment manifest with per-attachment BLAKE3 digests
- `project.rs` — report model projection from certificates/journals
- `render_sanitization_archive()` — the entry point `dc purge` and
  `dc execute` call: emits the two-page archival PDF with
  `certificate.json` and `journal.dcj` embedded **unfiltered** (an
  auditor carves them out with a hex viewer and verifies the Ed25519
  signature / hash chain byte-identical)

Determinism contract: identical inputs produce byte-identical PDFs; the
only time source is the caller-provided creation instant (no clock leaks,
Δ472/Δ476). The pre-0.6.0 plaintext mock generator is gone.

## Testing

`cargo test -p dc-report --lib` — 14 unit tests (xref offset walking,
ICC tag-table validity, XMP conformance markers, font parsing/embedding,
attachment carving, determinism, legacy API). Integration:
`m2_6_report_matrix`, `m2_7_cross_target_matrix`, `r900` (REG-PDFA3-
COMPLIANT-STRUCTURE), `t24_universal_purge` (attachment round-trip).

## Font licensing

`assets/fonts/LiberationSerif-Regular.ttf` (SIL OFL 1.1) is embedded in
every archive because PDF/A requires fully-embedded fonts — see
`assets/fonts/NOTICE.md`.
