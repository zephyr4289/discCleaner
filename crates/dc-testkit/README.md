# dc-testkit — The Test Rig (Oracles, Mocks, Cleanroom, Forges)

`dc-testkit` is the adversarial half of the project: independent oracles,
hardware mocks, and the cleanroom re-implementation that lets a third party
re-derive everything the tool claims.

## Independence principle

Oracles re-implement the formats **from the spec, not from the production
code** — `ChaCha20Ref` is a hand-rolled RFC 8439 reference, `JournalOracle`
parses DCJ1 from scratch, `CertOracle` verifies signatures independently.
When production and oracle agree, the agreement means something.

## Highlights

- `cleanroom.rs` — `CleanroomPRNG`: seed + geometry → full media stream
  digest; `verify_certificate_reproduction()` re-derives a wipe's attested
  digest from the certificate alone (A2 Moat, Δ161)
- `journal_oracle.rs` — independent DCJ1 chain verification (chain seeded
  from `BLAKE3("DCJ1")`, sealed record-0 signatures consumed in parse
  order, signal-aware FSM grammar)
- `kat.rs` — RFC 8439 / RFC 8032 / RFC 8785 / BLAKE3 known-answer tests
  (dual-verified: reference implementation AND production crate)
- `forge.rs` — adversarial journal surgery (splice, reorder, duplicate,
  chop, re-sign with attacker keys, recompute cascades)
- `spawn.rs` — `ToolSpawner`: child process environment scrubbing (DC_* is
  stripped; TZ/TERM/NO_COLOR/LANG pinned) + `ProcessGuard` RAII reaping
- `loopdev.rs` / `lvmx.rs` / `dm.rs` — privileged rig helpers (loop
  devices, LVM sandboxes, device-mapper ioctls) for root-only suites
- `signals.rs`, `ptrace_kill.rs`, `watchdog.rs` — signal/storm/kill rigs
- Hardware mocks: `atadev`, `scsi_mock`, `opaldev`, `mmcdev`, `sanitize_mock`
- `dc_victim` — child binary for environment/kill experiments

## Layering law

`dc-testkit` may depend on production crates; **production crates may never
depend on `dc-testkit`** (the historical dc-mmc inversion is pinned by
`REG-MMC-LAYERING`).

## Testing

Every rig is exercised by the integration suites it backs; `g1_substrate_matrix`
covers spawn/ledger/reap machinery.
