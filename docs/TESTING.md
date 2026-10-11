# discCleaner — Test Architecture

Modeled on the LLVM project: fast in-crate unit tests for logic, heavy
integration suites for behavior, independent **oracles** that re-implement
formats from the spec, and a `lit`-style runner tying it together.

## Layers

| Layer | Where | Cadence | What it proves |
|---|---|---|---|
| Unit tests | `#[cfg(test)] mod unit_tests` in every crate | every build | per-function contracts, bit layouts, invariants |
| Integration suites | `crates/*/tests/*.rs` (50 suites) | CI | end-to-end behavior through public APIs and the real binaries |
| Regression guards | `dc-cli/tests/r900_regression_guards.rs` | CI | every defect fixed in the hardening PR, pinned by `REG-*` name |
| Known-answer tests | `dc-testkit/src/kat.rs` | CI | RFC 8439 / 8032 / 8785, BLAKE3 — dual-verified against reference implementations AND the production crates |
| Cleanroom reproduction | `dc-testkit/src/cleanroom.rs` | CI + auditors | a wipe's stream digest can be re-derived from the seed + geometry + the normative contract doc alone |
| Lit runner | `tests/run_tests.py` | local + CI | discovery, parallel execution, PASS/FAIL/UNSUPPORTED/TIMEOUT reporting |

## Oracles (the independence principle)

`JournalOracle`, `CertOracle`, `ChaCha20Ref`, `JcsRef` re-implement formats
from their specifications. When production code and an independent oracle
agree, the agreement is evidence; if they disagree, one of them is wrong
and the test fails loudly. This caught real bugs: the oracle's zero-seeded
chain (every journal failed at record 0), the sealed record-0 signature
desynchronization, and a corrupted RFC KAT string.

## Root-privileged suites

Loop-device, LVM, and ioctl-dependent suites self-skip when EUID != 0
(they print `[SKIP]` and pass as "verified to the extent possible"). Under
root they execute fully. The lit runner reports these as UNSUPPORTED
without failing the run. CI runs the full matrix as root in the privileged
job.

## Conventions

- Test names state the invariant: `orchestrator_executes_pass_zero_exactly_once`
- Regression tests carry `REG-*` identifiers matching the comment at the
  fixed code site — grep `REG-` to walk every known historical defect
- Fixtures use the current schema and are byte-exact (ATA strings are
  byte-swapped; JSON field order is permuted deliberately to prove
  canonicalization)
- Every suite prints a cell ledger (suite, cell, expected, actual) so a
  failure names its exact contract

## Running

```sh
# everything, lit-style:
python3 tests/run_tests.py

# one layer:
cargo test --workspace --lib            # units
cargo test -p dc-cli --test t9_cert_matrix

# release-profile rig (fault injection opt-in):
cargo test --workspace --features dc-core/fault-injection,dc-io/fault-injection
```
