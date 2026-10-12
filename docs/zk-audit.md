# Zero-Knowledge Audit Receipts (`dc zk`)

> v0.11.0 · Frontier 1 — Groth16 over a pure-Rust BLS12-381 implementation

Defense, finance and multi-tenant cloud operators must prove to a regulator or
customer that a 16 TB volume or physical drive was wiped to NIST SP 800-88 Purge
standards. But the raw sanitization evidence contains confidential metadata:
private drive serial numbers, internal cloud Account IDs, proprietary drive
topologies, operator identities. **The zero-knowledge receipt lets anyone
mathematically verify that the wipe was compliant — without learning any of
those values.**

```
$ dc zk setup --out-dir zk-keys/
[zk] building compliance circuit (a few seconds)...
[zk] circuit: 4659 constraints / 4663 variables
[zk] running single-party Groth16 ceremony (toxic waste is dropped in-process)...
Proving key:    zk-keys/zk-pk.json
Verifying key:  zk-keys/zk-vk.json
VK fingerprint (BLAKE3): 22a91d1d7b5819037ed432dd54da3b9e7b2860fa10314203afbbb90f7fba1313

$ dc zk prove --pk zk-keys/zk-pk.json --certificate wipe-cert.json \
              --tenant 0xtenant-id --receipt audit-proof.json
[zk] proving (this takes ~20 seconds with the pure-Rust prover)...
ZK receipt written: audit-proof.json
  circuit:    dc-zk/compliance/v1
  scheme:     groth16-bls12-381
  PROOF SIZE: 192 bytes (compressed points)

$ dc zk verify --vk zk-keys/zk-vk.json --receipt audit-proof.json \
               --expect-tenant 0xtenant-id --expect-vk-fingerprint 22a91d...
proof verified:  true
RESULT: VALID — sanitization compliance proven in zero knowledge.
```

## What the circuit proves

| side | input | binding |
|------|-------|---------|
| public | `profile_hash` | Poseidon root of the NIST SP 800-88 profile parameters |
| public | `tenant_id` | customer / tenant the audit is owed to |
| public | `ts` | sanitization timestamp |
| public | `vk_commitment` | Poseidon commitment to the operator credential (proves *an* authorized key was used, hides *which*) |
| public | `audit_root` | Poseidon root over all private fields |
| private | drive serial | ≤ 2¹²⁸, bit-decomposed (range-bound) |
| private | block merkle root | binds the verification map |
| private | pass count | constrained ≥ 1 |
| private | verified/total windows | constrained `verified == total` (fail-closed full verification) |
| private | sanitize success flag | constrained `== 1` (controller-attested purge completed) |
| private | operator secret + nonce | open the `vk_commitment` |

The compliance predicate therefore enforces: *a successful hardware purge, at
least one purge pass, and full block-level verification, under the profile /
tenant / timestamp context in the statement* — and nothing about the private
values is revealed beyond what the predicate itself implies.

## Architecture (zero new external dependencies)

* `field.rs` — Montgomery arithmetic for the 381-bit base field `Fp` and the
  255-bit scalar field `Fr` (separated schoolbook-then-reduce CIOS, slack-limb
  accumulator; every constant regenerated programmatically from a
  Python-computed ground truth and pinned by tests).
* `fp2/fp6/fp12.rs` — the standard 2-6-12 tower (u² = −1, v³ = 1+u, w² = v).
* `curve.rs` — G1/G2 with Jacobian scalar multiplication (4-bit windows,
  batch-affine table conversion), full subgroup checks, compressed point
  serialization (Fp and Fp2 square roots — the Fp2 sqrt uses the complex-method
  norm reduction).
* `pairing.rs` — optimal ate pairing: G2 untwisted into E(Fp12) via
  (x/w², y/w³), Miller loop over |x| = 0xd201000000010000, full
  (p¹²−1)/r final exponentiation. The 68-limb exponent constant is
  re-derived and asserted in tests.
* `poly.rs` — O(n²) shared-domain Lagrange interpolation (one master
  polynomial, one batch inversion for all denominators).
* `r1cs.rs` / `groth16.rs` — constraints and the setup/prove/verify pipeline.
  The H query evaluates the product polynomial A(x)B(x) − C(x) directly, so
  **no polynomial division exists anywhere in the prover** — a deliberate
  simplicity-over-pk-size choice for auditability.
* `poseidon.rs` — SNARK-friendly sponge (t = 3, RF = 8, RP = 57, S-box x⁵)
  with SHA-256-derived round constants (documented transparent deviation from
  the Grain LFSR: no cross-implementation interop is required inside a closed
  circuit family, and SHA-anchored constants cannot be backdoored). The
  in-circuit synthesizer and the evaluator are pinned to identical outputs by
  test.
* `circuit.rs` / `receipt.rs` — the compliance circuit (~4.7k constraints)
  and the portable receipt artifact.

The whole stack was validated against a Python reference prototype
(bilinearity, non-degeneracy, Groth16 end-to-end with tamper rejection) before
the Rust port; the Rust port re-verifies all of it in unit tests.

## Trust model (read this before relying on it)

Groth16 requires a structured reference string from a **trusted setup**: if
the toxic waste (τ, α, β, γ, δ) is retained, whoever holds it can forge
proofs. This release performs a **single-party ceremony** — `dc zk setup`
generates the waste inside the process, publishes the keys, and drops the
waste without persisting it. The verifying-key fingerprint in every receipt
pins *which* ceremony produced it, so a compromised setup is at least
attributable and revocable (auditors re-pin the fingerprint).

A multi-party "powers of tau" ceremony with public transcript verification is
the natural follow-up milestone; the API surface (separate `setup` / `prove`
/ `verify`, fingerprint pinning) is already shaped for it.

## What the proof does NOT do

The proof binds the *statement to the compliance predicate* under the
Poseidon commitment scheme. It does not make the underlying engine's I/O
honest — that is the role of the engine's own verification passes, whose
*counts and merkle root* are exactly what gets committed here. The ZK layer is
a privacy and composition tool on top of the existing evidence chain, not a
replacement for it.

## Performance (release build, 4659-constraint circuit)

| operation | latency | notes |
|-----------|---------|-------|
| circuit build | ~10 ms | deterministic |
| setup (ceremony) | ~30 s | one-time per key generation |
| prove | ~20 s | pure-Rust prover, no unsafe, no assembly |
| verify | ~180 ms | 3 pairings + subgroup checks |

Optimization headroom (documented for future milestones): Pippenger MSM for
the ~19k-point query combinations, Karatsuba fields, and the standard
3-chunk final exponentiation.
