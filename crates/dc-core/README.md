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

- `plan.rs` — plan schema (`dc-plan/1`), the standards profile catalog
  (`SanitizationProfile`: NIST 800-88 Clear ×2, CERT-In/GoI, DoD 5220.22-M
  +ECE, CSE ITSG-06, BSI VSITR, Schneier, Gutmann) with pure pass matrices,
  `VerifyLevel::Sampled` (NIST 800-88 sampled verification), and the
  `HardwarePurge` mechanism
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

## Standards profile catalog (v0.5.0)

`SanitizationProfile::CATALOG` is the single source of truth for profile →
pass-matrix translation; the CLI option and `dc profiles` render from it, so
the catalog can never drift from what executes.

| Profile | Passes | Standard reference | Flash-suitable |
|---|---|---|---|
| `nist-clear` | 1 (zero) | NIST SP 800-88r1 §4.3 Clear | yes |
| `nist-clear-random` | 1 (CSPRNG) | NIST SP 800-88r1 §4.3 Clear | yes |
| `certin-goi` | 3 (00/FF/CSPRNG) | CERT-In / GoI media sanitisation practice | yes |
| `dod-5220.22m` | 3 | US DoD 5220.22-M (superseded) | yes |
| `dod-5220.22m-ece` | 7 | US DoD 5220.22-M ECE (superseded) | no |
| `csec-itsg-06` | 3 | CSE ITSG-06 (Canada) | yes |
| `bsi-vsitr` | 7 | BSI VSITR (Germany) | yes |
| `schneier` | 7 | Schneier (1996) | yes |
| `gutmann` | 35 | Gutmann (1996) — legacy, contractual use only | no |

Legacy profiles carry a `legacy_note` that is surfaced in the plan, journal,
and certificate. `VerifyLevel` supports `Full`, `Sampled { stride }`
(deterministic 1-in-N window sampling — the engine skips unsampled windows'
I/O entirely) and `None`, with machine-stable `short_tag()` round-trips for
journal/certifacte records.
