# dc-io — Destructive Write Engines, Windows, and Buffers

`dc-io` performs the actual media writes and read-back verification. It is
the only crate permitted to issue writes against a device the Guardian has
armed, and it can only do so while holding a `WritePermit` minted by the
FSM (see `dc-core`).

## The fail-closed engine contract

`create_engine()` selects io_uring when the kernel offers it and otherwise
falls back to the synchronous engine **on the same file descriptor**. The
historical implementation "fell back" to a `SyncEngine` opened on
**/dev/null**, silently turning every wipe into a no-op while the caller
still issued completion certificates. That path is structurally impossible
now (`REG-ENGINE-FAILCLOSED`): the only `File` an engine ever holds is the
caller's.

## Module map

- `traits.rs` — `Engine` trait, `LbaSpan` (overflow-safe window arithmetic:
  `div_ceil` + saturating offsets, `REG-LBASPAN-OVERFLOW`), `EngineCaps`
  (engines must never advertise capabilities they do not exercise)
- `sync_engine.rs` — pread/pwrite engine with EINTR retry, per-window
  cancellation checks, BLKZEROOUT fast path with software fallback
- `uring_engine.rs` — io_uring wrapper (delegates to the sync path until the
  submission loop lands; caps stay honest about that)
- `buffer_pool.rs` — 4096-aligned, mlocked buffers with overflow-checked
  allocation and a 4 GiB total-pool cap (`REG-BUFFERPOOL-OVERFLOW`)
- `zeropath.rs` — chunked BLKZEROOUT fast path (2 GiB chunks), Linux-only
  and fail-closed elsewhere
- `tracker.rs` — `CompletionTracker` enforcing INV2: **the committed range
  never contains a hole**
- `geometry.rs` — `WindowGeometry` validation (block-multiple windows)

## Cancellation model

`request_global_cancel()` (this crate) is the process-wide flag flipped by
the CLI's SIGINT/SIGTERM handler. Engines coalesce it with their local
cancel flag at every window boundary and convert it into
`DcError::Interrupted { completed_through }` so the journal stays resumable
— no partially-written window is ever reported as committed.

## Testing

`cargo test -p dc-io --lib` — 10 tests (overflow math, pool caps, INV2,
geometry, plus an end-to-end write/verify over a temp file). Integration:
`dc-cli/tests/g4_engine_matrix`, `t11_interrupt_matrix`.

## v0.5.0 — sampled verification stride

`Engine::read_verify` now takes a `stride` parameter implementing NIST SP
800-88 sampled verification: windows whose index is not divisible by
`stride` are skipped **entirely** — no read, no compare, no hash — which is
where the wall-clock saving comes from (verified by
`REG-VERIFY-STRIDE`). `stride == 1` is full verification.
`LbaSpan::window_is_sampled(w, stride)` is the single sampling oracle.
