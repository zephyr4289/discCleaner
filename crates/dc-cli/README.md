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
