# dc-cli — Operator Surface (the `diskcleaner` and `dc` binaries)

The command line is a **safety instrument**, not a convenience: every exit
code is a contract, every prompt is a controlled boundary, and every
destructive verb is gated by the Guardian and the FSM.

## Commands

| Command | Safety posture |
|---|---|
| `list` | read-only inventory scan |
| `check` | Guardian pre-flight (read-only probe; missing target → exit 2, not 1) |
| `plan` | compiles and hashes a plan; argument validation fires **before** device probing |
| `execute` | full gate chain (below); `--dry-run` exits **before** the confirmation prompt |
| `resume` | re-runs the Guardian on live device state, then re-arms and continues from the journal frontier |
| `verify` | standalone media re-verification against a journal or certificate |
| `cert show/verify/reconstruct` | strict certificate verification, journal reconciliation, lossless projection |
| `journal inspect/selftest-sequence` | read-only diagnostics + format-authentic journal synthesis |
| `keygen` | Ed25519 operator keypair (0600) |
| `approve` | two-officer countersignature of a plan (real Ed25519, domain-separated) |

## The `execute` gate chain

1. argument validation (fail-fast, before any probing)
2. **non-TTY without `--serial-confirm` refuses** (Δ178, exit 2) — an
   unattended irreversible command may never block on a prompt nobody can
   answer
3. probe (Guardian-classified) + plan binding (`--plan` hash + identity
   compatibility)
4. Guardian evaluation (15-rule table)
5. plan compilation + hash
6. `--dry-run` boundary: print, audit, exit 0, **no journal**
7. two-officer gate (`--auth-set`, if supplied)
8. confirmation token (interactive prompt or `--serial-confirm`)
9. arming (O_EXCL + flock on disk and every partition)
10. sealed/unsealed journal creation, engine execution, graceful-signal
    drain, full read-back verification, certificate issuance

## Signal boundaries (Δ87 / Δ83)

`prompt-wait` and `pre-arm` signals exit 3 with **no journal**; mid-flight
signals drain at the next window boundary and write an `Interrupted` record
so `resume` can continue; a signal after verification completes under the
**victory-lap rule** (exit 0 + certificate — abandoning finished evidence
would only destroy it).

## Testing

48 integration suites (`tests/`) incl. `r900_regression_guards.rs` (20
pinned defects with `REG-*` identifiers). Lit-style driver:
`python3 tests/run_tests.py` from the repo root.

## v0.5.0 — fleet-grade command surface

| Command | What it does |
|---|---|
| `dc execute --target A --target B ...` | **Parallel multi-device wipe**: all-or-nothing precheck (probe/Guardian/plan per device — any refusal aborts the batch with nothing armed), one interactive comma-separated token confirmation, atomic O_EXCL arming of every device, then one worker thread per device (own FSM, journal, engine, certificate) with multiplexed progress bars and a batch summary. |
| `dc profiles` | Renders the full standards profile catalog (pass counts, verification defaults, standard references, flash suitability) — procurement-ready reference table. |
| `dc bench --file F --size-mib N` | Bake-off evidence: runs the production engines (zero write + read-back verify) on a regular file and reports MiB/s plus an ETA table for every profile at a reference capacity. Refuses block devices and `/dev`-tree paths by construction. |
| `dc purge --target /dev/nvme0n1` | **Controller-attested hardware purge** (NIST 800-88 Purge): Identify → capability attestation → strategy ladder → Sanitize Crypto/Block Erase or Format NVM crypto-erase through the real ioctl transport, with Log 0x81 completion polling, pre/post SMART-health snapshots in the certificate, and sampled zero read-back for format-crypto. Seconds instead of hours on self-encrypting media. |
| `dc execute --verify sample:N` | NIST SP 800-88 sampled verification: deterministic 1-in-N window sampling — the engine skips unsampled windows' I/O entirely (that *is* the speedup). `full` and `none` also available; cannot override a `--plan` (plan-hash binding). |

Every new path keeps the fail-closed discipline: batch aborts leave zero
journals, purge refusals never fabricate evidence, and all guards are pinned
in `r900_regression_guards.rs` + `t14_fleet_parallel_matrix.rs`.


## v0.7.0 — hardware custody, cold-bus remediation, appliance boot, forensics

- `dc approve --token <usb-node|auto> [--token2]`: officer signatures computed
  inside PIV hardware tokens (YubiKey Ed25519 / CAC ECDSA P-256) over raw
  usbfs CCID + ISO 7816-4; `is_hardware_token` claims without a verifying
  `HardwareCustodyAttestation` are refused fail-closed
  (REG-TOKEN-CUSTODY-PROOF).
- `dc purge --cold-unfreeze`: the lights-out freeze remediation ladder
  (LUN delete + host rescan, ATA-port runtime-PM cycle) with per-step
  re-probes and full certificate disclosure (REG-COLDBUS-RESET-LADDER).
- Thermal stewardship on every sanitization path: SMART 194 / NVMe Health /
  SCSI LOG SENSE 0x0D / kernel hwmon thermometers feed a governor that
  paces above 55 C and refuses certification at 70 C
  (REG-THERMAL-GOVERNOR); `--thermal-throttle-c`, `--thermal-critical-c`,
  `--no-thermal-guard` on execute and purge.
- `dc boot init|pack`: the real PID-1 bootstrap (mounts, RNDADDENTROPY
  credit, zombie reaper) and the pure-Rust cpio appliance builder with
  constituents attestation (REG-PID1-INIT-SEQUENCE, REG-APPLIANCE-IMAGE);
  `scripts/build-appliance.sh` assembles the RAM-resident ISO.
- Firmware attestation: pre/post NVMe Telemetry (0x07), ATA Device
  Statistics (GP 0x04) wear deltas, SCSI INQUIRY identity; firmware drift
  and silent-counter disclosures are signed defense warnings, raw logs are
  PDF/A-3 attachments (REG-FIRMWARE-ATTESTATION).
- Fixed: `dc approve` clap short-flag collision between `--key`/`--key2`
  (pre-v0.7.0 debug builds panicked on any `dc approve --help`).

## v0.6.0 — universal purge dispatch, defense policy gate, G-List audit

- **`dc purge` is bus-universal**: one verb dispatches to the NVMe admin
  ioctl transport, the SATA/SAT SG_IO ladder (dc-ata), or the SAS SG_IO
  ladder (dc-scsi); loop/virtio/DM/file targets are refused fail-closed
  with `PURGE_TRANSPORT_UNSUPPORTED`. The pre-0.6.0 `PURGE_NVME_ONLY`
  refusal is retired (REG-PURGE-UNIVERSAL-DISPATCH). Mechanism menu:
  `auto | sanitize-crypto | sanitize-block | format-crypto |
  security-erase-enhanced | security-erase-normal | format-unit`
  (bus-validated).
- **Defense profile enforcement gate**: `--verify sample:N` / `none` on
  defense profiles (DoD 5220.22-M & ECE, CERT-In/GoI, CSE ITSG-06, BSI
  VSITR) exits 8 BEFORE any device is probed or armed — in `execute` and
  in `plan` compilations (REG-DEFENSE-SAMPLING-REFUSED).
- **G-List audit**: SMART attr 0x05 (SATA), READ DEFECT DATA grown list
  (SAS), NVMe health log 0x02 media errors — nonzero counts on logical
  overwrites emit a `DEFENSE_WARNING` into the SIGNED certificate
  payload (stripping it invalidates the signature).
- **ISO 19005-3 archival copy**: every `execute` and `purge` run also
  writes `<stem>.pdf` — a true PDF/A-3b document embedding
  `certificate.json` and `journal.dcj` unfiltered.
