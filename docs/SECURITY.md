# discCleaner — Security Model

## Threat model

The tool's job is to make a claim — "this media is sanitized" — that
militaries, auditors, and courts can rely on. The threats:

1. **A lie about completion** (software claims success without evidence)
2. **A wrong target** (operator error: the live OS disk, the wrong drive)
3. **Fabricated authority** (one person pretending to be two; replayed or
   forged approvals)
4. **Tampered evidence** (journal/certificate edits after the fact)
5. **Hidden capacity** (bridge chips under-reporting device geometry)
6. **Secret leakage** (keys, PSIDs, lifeline passwords in logs)
7. **The tool itself** (a hostile environment variable triggering
   destructive behavior; fault-injection hooks escaping into production)
8. **Supply-chain drift** (unreviewed dependency changes)

## Controls, and where they live

### Completion honesty
- NVMe sanitize paths return success only on a **terminal status log**
  (never a single optimistic read); Format NVM completion is provenance-
  tagged; logical overwrite is refused by the admin client outright
  (`dc-nvme/purge.rs`, `REG-NVME-FABRICATED-COMPLETION`)
- SCSI timing integrity flags impossibly fast completions as mangled
  evidence (`dc-scsi/timing.rs`)
- Verification reads back **100% of LBAs** and streams BLAKE3 over what
  the media actually contains — write accounting is never trusted
  (`dc-verify`)

### Wrong-target protection
- The Guardian's 15-rule table + fail-closed partition locking
  (`dc-probe/guardian.rs`)
- `is_partition_name` separator logic (`REG-PARTITION-NAME`)
- Non-TTY execution without `--serial-confirm` refuses (Δ178)
- Dry runs exit **before** the confirmation prompt (`REG-DRYRUN-BOUNDARY`)
- Resumes re-run the Guardian on live device state

### Authority
- Two-person integrity is **real Ed25519 countersignatures** over
  domain-separated plan hashes; distinct keys required; the forgeable
  BLAKE3-of-strings scheme is dead (`dc-cert/dualauth.rs`,
  `REG-DUALAUTH-FORGERY`)
- Key lifecycle: bilateral rotation makes at-or-after signatures suspect;
  revocation windows; 0600 keyfiles enforced on save AND load

### Evidence integrity
- Hash-chained journals (BLAKE3 per record, chained from `BLAKE3("DCJ1")`)
  with optional per-record Ed25519 sealing; sealed journals fail closed
  without the operator key
- Strict certificate parsing: BOM, duplicate keys, unknown forward fields,
  depth bounds — all rejected (Δ169)
- Append-only audit logs with `flock` exclusion and matching writer/
  verifier chain seeds

### Hidden capacity
- DCO/HPA staging with generation numbers (`dc-ata/geometry.rs`)
- IDENTIFY × READ CAPACITY(16) cross-examination discloses `CAPACITY_MASK`
  bridges (`dc-scsi/preflight.rs`)

### Secret hygiene
- PSID zeroizes on drop; Debug prints hashes only
- ATA lifeline plaintext is structurally voided on unlock
- Child processes get scrubbed environments (DC_* stripped)
- Keyfiles are 0600 and refused when world-readable

### The tool itself
- Fault-injection hooks (`DC_CRASH_AT` / `DC_SIGNAL_AT`) compile only into
  debug builds or explicit `--features fault-injection` rigs; release
  binaries have no such code path
- `/dev/null` engine fallback is eliminated structurally — engine selection
  is `Result`-typed and only ever receives the caller's file

## Security disclosure

Found something? Do not open a public issue. Contact the maintainers
privately with reproduction steps. Regressions found internally are pinned
in `crates/dc-cli/tests/r900_regression_guards.rs` with `REG-*` identifiers
that also appear at the fix site in the source.
