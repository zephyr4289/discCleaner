# dc-scsi — SCSI/SAS Session and Purge Preflight

`dc-scsi` runs SCSI SANITIZE/FORMAT mechanisms with the paranoia a SAS
backplane deserves: bridges lie, timings betray mangling, and the character
device is an uncovered door.

## Module map

- `transport.rs` — `ScsiSession` with **block-node enforcement** (Δ330):
  opening `/dev/sg*` (the character door) is refused; only block nodes like
  `/dev/sdb` are accepted (`REG-SCSI-SG-NODE`)
- `preflight.rs` — single-path consistency cross-examination (Δ328):
  IDENTIFY-reported LBA counts vs READ CAPACITY (16); divergence discloses
  `CAPACITY_MASK` — the bridge is lying about the ceiling
- `timing.rs` — `TimingIntegrity` (Δ335): a 90-second mechanism completing
  in 250 ms is flagged `TIMING_ANOMALY_TOO_FAST_MANGLE_SUSPECTED`;
  evidence that finished impossibly fast is not evidence
- `ufs.rs` — UFS session discrimination

## Testing

`cargo test -p dc-scsi --lib` — 3 unit tests (capacity-mask disclosure,
timing bounds, sg-node refusal). Integration: `m1_6_scsi_client_matrix`,
`t15_scsi_purge_matrix`, `t16_bridge_matrix`.
