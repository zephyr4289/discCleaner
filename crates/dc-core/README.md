# dc-core — Foundations: Plans, Journals, Audit, Identity, FSM

`dc-core` is the trust anchor of discCleaner: every byte of evidence the tool
produces — journals, certificates, audit chains — derives its integrity from
the primitives defined here. It has **zero knowledge of hardware**; it is
pure data structures, cryptography, and protocol invariants.

## Why this crate is the trust anchor

| Component | Guarantee |
|---|---|
| `SanitizationPlan` + `compute_plan_hash()` | A plan is a **typed, hash-committed contract**. The JCS (RFC 8785) canonical form is hashed with BLAKE3; the hash binds every later artifact (journal header, certificate, two-officer approvals) to one immutable intent. |
| `JournalWriter` / `JournalReader` | Append-only, hash-chained crash journal (`DCJ1` format). Every record's hash chains from the previous one; the chain seed is `BLAKE3("DCJ1")`. Sealed journals add a per-record Ed25519 signature over `record ∥ prev_hash`. |
| `AuditLogger` | Tamper-evident site-wide audit chain (`DCA1` format) with `flock` mutual exclusion, append-only opens, and allocation caps on untrusted length prefixes. |
| `Guardian`-support types | `StableIdentity` survives USB re-enumeration; the comparator (§5.3 / Δ46) distinguishes hard contradictions from one-sided-absence warnings. |
| `FsmOrchestrator` / `Orchestrator` | Typestate control flow: destructive writes require a `WritePermit` that only the FSM can mint in `Executing`/`Flushing` states. |

## Module map

- `plan.rs` — plan schema (`dc-plan/1`), profiles (clear-zero / clear-random / legacy-dod3)
- `pattern.rs` — deterministic pattern sources (ChaCha20-window-v1; see
  `docs/reproduction/chacha20-window-v1.txt`, the normative reproduction contract)
- `journal.rs` — DCJ1 reader/writer, sealed signatures, crash-hook injection
- `audit.rs` — DCA1 audit chain
- `fsm.rs` / `orchestrator.rs` — execution state machines
- `identity.rs` — stable/kernel identity model
- `fleet/` — batch orchestration primitives (argv seams, reconstruction)

## Security invariants (enforced + tested)

1. **Sealed journals fail closed**: missing `operator_pubkey`, missing signing
   key on resume, or a bad signature rejects the whole journal — it is never
   silently downgraded to hash-only verification.
2. **Record 0 must be the Header** (`FIRST_RECORD_NOT_HEADER`).
3. **Bounded allocations**: hostile length prefixes hit `RECORD_TOO_LARGE`
   before any allocation.
4. **Torn tails are recoverable, zero-tails are not**: a crash mid-write
   yields a discarded tail; a power-loss zero-tail is a hard corruption.
5. **Fault-injection hooks compile only into debug/test rigs** — release
   binaries contain no env-var-driven `SIGKILL` path.

## Testing

`cargo test -p dc-core --lib` — 27 unit tests covering chain seeds, tamper
detection, sealed round-trips, audit symmetry, orchestrator pass sequencing,
and the FSM permit model. Integration coverage: `dc-cli/tests/g2_*`, `t11_*`,
`t12_*`, `t3_*`.

## Dependency policy

No hardware crates, no I/O engines. Depends only on serialization
(serde/serde_jcs), cryptography (blake3, ed25519-dalek, chacha20), and libc.
