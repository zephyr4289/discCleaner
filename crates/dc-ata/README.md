# dc-ata — Native ATA / SAT Security-Erase Executor

`dc-ata` drives the ATA SECURITY ERASE family for drives reached directly
or through SAT (SCSI-to-ATA Translation) bridges.

## Module map

- `security.rs` — the no-harm security FSM: intake refuses **locked** and
  **frozen** drives; arming mints a random password *lifeline* whose
  plaintext is structurally voided the moment the drive confirms unlock
  (Δ276); erase failure attempts repair and only then reports
- `freeze.rs` — freeze-lock evaluation with explicit override gating (Δ280):
  a frozen drive refuses destructive security commands unless the operator
  consciously overrides in a boot environment
- `geometry.rs` — `GeometryTransaction`: staged, generation-tagged
  (FdGen) DCO-restore / HPA-unlock sequencing so capacity ceilings hidden
  by bridges can be lifted before the wipe and audited afterwards

## Wire-format safety

All CDBs are built with `dc-hw::AtaCodec`'s class-framed encoders: SECURITY
ERASE commands are encoded as **non-data** (SAT protocol 3) — the historical
single-framing encoder claimed PIO data-in transfers for them, which hangs
HBAs (`REG-SAT-NONDATA`).

## Testing

`cargo test -p dc-ata --lib` — 5 unit tests (intake refusals, lifeline
voiding, freeze gating, geometry staging). Integration:
`m1_4_ata_client_matrix`, `t14_ata_purge_matrix`.
