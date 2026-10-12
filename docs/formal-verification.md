# Formal Verification (`dc formal` + Kani harnesses)

> v0.11.0 · Frontier 3 — proving the absence of fail-open states

Unit tests and fuzzing find bugs that reachable inputs expose; they cannot
prove the **absence** of bugs. In sanitization, a fail-open bug that reports
a drive as wiped when a single block was skipped is catastrophic, so v0.11.0
adds two machine-checked layers on top of the existing suites.

```
$ dc formal check --depth 7
checker:              exhaustive-fsm-v1 (state-merged BFS)
depth:                7
distinct (state,ctx): 17
nodes explored:       17
  [PASS] INV-1 — Certified is reachable only through executions containing a successful begin_verify()
  [PASS] INV-2 — WritePermit minted only by begin_pass() from {Armed, Flushing} or begin_flush() from Executing
  [PASS] INV-3 — certify() transitions to Certified only from the Verifying state
RESULT: all invariants hold (exhaustive at this depth)

$ dc formal verify-model --windows 12
verified abstraction: count_windows — exact counters over (window, is_valid)
refinement: real StreamVerifier agrees on all 2^12 = 4096 concrete sequences
RESULT: refinement HOLDS
```

## Layer 1 — always-on exhaustive model checking (`cargo test`)

`crates/dc-verify-formal` drives the **real** `dc_core::FsmOrchestrator`
through a **state-merged exhaustive exploration**: a BFS over
`(state, observation-context)` pairs with deduplication. Because the
orchestrator's transition relation depends only on its state (and the context
only accumulates invariant facts), merging paths that reach the same
`(state, context)` is sound and complete with respect to full sequence
enumeration — every action sequence is subsumed by exactly one explored node.
Depth 7 covers the shortest accepting path (compile → approve → arm → pass →
flush → verify → certify) with all interleavings; deeper bounds only revisit
merged states.

Invariants (checked on every explored node and transition):

* **INV-1** — `Certified` reachable only with a successful `begin_verify()` in
  the history. No action order skips verification and still certifies.
* **INV-2** — the `WritePermit` (the unforgeable token required for
  destructive writes) is minted only by `begin_pass()` from `{Armed,
  Flushing}` or `begin_flush()` from `Executing` — fail-closed.
* **INV-3** — `certify()` transitions to `Certified` only from `Verifying`.

The window-accounting property ("no unverified LBA range can produce a
successful result") bottoms out in the verification counters:

1. **Spec**: `count_windows` — a 5-line pure function over
   `(window, is_valid)` observations; trivially auditable.
2. **Refinement**: `exhaustive_refinement_check` drives the REAL
   `dc_verify::StreamVerifier` and the spec over all 2ⁿ concrete validity
   patterns (n ≤ 16) and asserts exact agreement of counters and
   first-mismatch lists.

Both checks run in every `cargo test --workspace` (CI included) — sub-second,
regression-pinned.

## Layer 2 — Kani symbolic proofs (`cargo kani`)

`crates/dc-verify-formal/src/proofs.rs` contains `#[cfg(kani)]` harnesses
(invisible to normal builds; the `kani` crate resolves only under the
cargo-kani toolchain):

| harness | proves |
|---------|--------|
| `fsm_certify_requires_verifying` | INV-1 over ALL symbolic action sequences (≤ 6 steps) |
| `fsm_permit_gating` | INV-2: from ANY reached state, the minter guards accept exactly the legal states |
| `window_accounting_is_exact` | the verified abstraction: counters over any symbolic observation sequence are exact |
| `secretbuf_zeroize_wipes_every_byte` | any 8-byte secret, any path: after `zeroize_now()` the exposed memory is all-zero (idempotently) |
| `secretbuf_debug_never_leaks` | the `Debug` rendering never contains any nonzero secret byte's hex form |

The `mlock`/`munlock` page-pinning calls are stubbed inside the secret
harnesses — pinning is orthogonal to the zeroization property under proof
(and is separately exercised in the dc-core runtime tests).

### Running Kani

```
scripts/kani-run.sh            # installs cargo-kani if missing, runs all
                              # harnesses, writes proofs/proof-certificate.json
```

The GitHub workflow `.github/workflows/formal-verification.yml` re-runs the
harnesses on a weekly schedule and on demand (`workflow_dispatch`), because
Kani runs take minutes, not seconds. The emitted proof certificate
(harness × verdict) is the auditable record of what was mechanically checked.

## Scope and honesty

* The exhaustive layer is genuinely exhaustive over the merged state space
  at the configured depth; the Kani layer is bounded-model-checked (unwind
  bounds annotated per harness). Both are machine checks of the properties
  stated above — they are not a full-functional-correctness proof of the
  whole engine.
* The Kani harnesses cover the FSM guards, the accounting abstraction and
  the secret hygiene. The refinement check ties the accounting abstraction
  to the real verifier implementation on all bounded concrete inputs.
* Fail-open behavior elsewhere (kernel I/O paths, ioctl error propagation)
  remains covered by the existing fault-injection and regression suites.
