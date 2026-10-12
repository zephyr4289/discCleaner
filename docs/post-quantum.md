# Post-Quantum Audit Protection (ML-DSA-44 hybrid signing)

> v0.10.0 · Frontier 3 — Cryptographic Longevity

Sanitization certificates must withstand **decades of legal scrutiny**. A classical
256-bit signature (Ed25519) is sound today — but a harvest-now-decrypt-later
adversary with a future cryptographically-relevant quantum computer could forge
audit evidence retroactively. Since v0.10.0, discCleaner signs every certificate
with a **hybrid dual signature**: Ed25519 (classical, for today's verifiers) plus
**ML-DSA-44** (FIPS 204, NIST's Module-Lattice Digital Signature Algorithm) over
the *same canonical bytes*, so both algorithms bind identical evidence.

```
$ dc keygen --out operator.sk
[+] Generated operator Ed25519 keypair
[+] Generated post-quantum ML-DSA-44 twin (hybrid signing ready)
    PQ Private Key File: operator.sk.pq
    PQ Fingerprint:      …

$ dc execute --target /dev/sda --profile nist-clear --key operator.sk
[+] Certificate hybrid-signed: Ed25519 + ML-DSA-44 (post-quantum audit protection)
```

Any certificate-signing path in the CLI (execute, purge, resume, reconstruct) and
every cloud receipt automatically upgrades to hybrid signing when the ML-DSA twin
file (`<key>.pq`) exists next to the classical key. Without it, signing is
classical-only and byte-compatible with v0.9.x certificates — deployment is
incremental, not flag-day.

## Verification policy

**Strict conjunction.** `dc-cert` refuses to call a hybrid certificate authentic
unless BOTH legs verify (`verify_signature_hybrid`):

- classical Ed25519 leg: must verify — always;
- ML-DSA-44 leg: must verify when present (absent ⇒ classical-only certificate,
  not a downgrade of an existing one — the field is additive).

Legacy verifiers that only understand Ed25519 can still check the classical leg
(the PQ block is an optional JSON field), but `dc cert verify` holds the line:
both or nothing. Tampering with any byte of the evidence breaks both legs at
once (they sign the same canonical JCS bytes).

## What `dc-pq` implements

**FIPS 202 (SHA-3 family)** — Keccak-f[1600] from the published round constants
and rotation tables; SHA3-256 and the SHAKE256 XOF. No external crypto crates:
the entire hash foundation of ML-DSA is auditable in ~200 lines.

**FIPS 204 (ML-DSA-44)** over Z_q[x]/(x^256+1), q = 8 380 417:

| parameter | value | | wire size | bytes |
|-----------|-------|-|-----------|-------|
| (k, ℓ) | (4, 4) | | public key | 1312 |
| η (secret bound) | 2 | | secret key | 2560 |
| τ (challenge weight) | 39 | | signature | 2420 |
| β = τη | 78 | | | |
| γ₁ (mask width) | 2^17 | | | |
| γ₂ | (q−1)/88 | | | |
| d (power2round) | 13 | | | |
| ω (max hint weight) | 80 | | | |

Key discipline matches the v0.9.0 hygiene standard: ML-DSA secret keys are
zeroized on drop (`Zeroize`), written with mode 0600, and loading **refuses**
group/world-readable keyfiles. The public key is re-derived from the secret
(`t₁ = HighPart(A·s₁ + s₂)`, every input lives in the sk) and cross-checked
against the stored transcript seed `tr` — a corrupt or tampered keyfile is
rejected on load.

### Implementation stance: derivation over recollection

Two deliberate engineering choices, both documented in the source:

1. **Definitional NTT.** The transform is the direct O(N²) evaluation
   `â[i] = Σⱼ a[j]·ψ^((2i+1)j)` at the 256 odd powers of ψ = 1753 (a primitive
   512th root of unity mod q) — not a bit-twiddled Cooley-Tukey butterfly
   network. Slower (irrelevant at certificate-signing rates), but the code *is*
   the math: no zeta-ordering conventions to get wrong. The negacyclic
   homomorphism (pointwise multiply ≡ ring multiply in x^256+1) is pinned by a
   property test.
2. **Brute-force-derived hint mechanism.** The 1-bit hint (recomputing the
   verifier's high bits across the ±(c·t₀ − c·s₂) error) was *derived by
   exhaustive simulation* over 200 000 honest signing tuples
   (`scripts/hint_derivation.py`): the correction direction is encoded by the
   sign of the verifier's own low part, and crossings whose direction is not
   recoverable (an extreme-tail event: |c·t₀| within ~5% of its theoretical
   maximum) are detected and rejected at signing time — a retry, never a wrong
   signature.

### Bugs the property matrix caught during development

- **Rust `%` truncates toward zero:** the NTT accumulated *negative* remainders
  on centered secrets (s₁, s₂, the challenge), silently corrupting every
  downstream product. Fixed with `rem_euclid`; caught by a range assert in
  `power2round` within seconds of appearing.
- **Centered-vs-canonical representatives:** c·s₁ returns a [0, q) ring element;
  adding it to the centered mask y without centering makes every norm check
  explode (the rejection loop never terminated). The centering helper is now
  documented at the call site.
- **Hand-remembered test vectors are wrong ~50% of the time.** Two SHA-3 KATs
  and one AWS SigV4 vector were misremembered; the implementation was correct
  each time. All vectors are now either cross-checked against Python's
  `hashlib`/`hmac` (independent implementations) or published documentation
  constants.

## Test coverage

- Keccak: SHA3-256 KATs (empty, "abc", 200-byte multi-block), SHAKE256 KAT +
  incremental-squeeze equivalence.
- NTT: roundtrip, negacyclic homomorphism, root-of-unity order properties.
- Rounding: power2round exact-identity sweep, decompose boundary sweep
  (hand-derived edge cases documented in the tests).
- Sampling: challenge weight/shape, secret bounds.
- Packing: t₁/t₀/η/z/w₁/hint roundtrips.
- Full stack: keygen→sign→verify roundtrips (deterministic seeds), signature
  tamper detection, wrong-key rejection, deterministic signing, FIPS wire-size
  checks.
- dc-cert: hybrid sign/verify matrix (both legs, tamper breaks both),
  classical-only compatibility, key-file permission discipline.
- dc-cloud: hybrid-signed receipts, tamper detection on the cloud context.

## Conformance roadmap

This implementation follows the FIPS 204 structure with the parameter set and
wire sizes of ML-DSA-44, and is validated by the component KATs and property
matrices described above. **Official NIST ACVP known-answer vectors are a
tracked follow-up** (they must be wired into CI before claiming
interoperability with other ML-DSA implementations; the hash-domain and
seed-derivation choices documented in `dc-pq::ml_dsa` are the specific spots
to reconcile). Until then: hybrid signatures produced by this build verify
within the discCleaner evidence chain (both legs are self-contained in the
certificate), and the classical leg keeps every external verifier working.
