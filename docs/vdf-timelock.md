# VDF Proof-of-Erasure — Timestamp-Spoofing-Resistant Sanitization
## (v0.12.0, Miracle 1 — `dc-vdf`)

Every disk wipe certificate ever issued carries one fatal flaw:
**timestamp spoofing**. A rogue sysadmin, compromised cloud provider or
malicious auditor can set the system clock to 2024 and forge *"this
drive was destroyed on August 15th at 14:00"*. In legal disputes,
insurance claims and sanctions enforcement, such timestamps are
routinely thrown out — because system clocks can be manipulated by
exactly the parties the certificate incriminates.

`dc-vdf` replaces trust in clocks with **immutable mathematics**.

## The construction

1. **Ceremony** (`dc vdf setup`): an RSA modulus `N = p·q` is
   generated from a **safe-prime pair** (p = 2p'+1), and the
   factorization is **zeroized in-process**. What remains is the
   public group of unknown order `Z_N*`. Because nobody — including
   the wiping machine — knows the factorization, computing
   `x^(2^T) mod N` requires `T` inherently **sequential** modular
   squarings. No amount of parallelism, money or clock-setting
   shortcuts it (the Rivest time-lock).

2. **The Drive Weave** (`dc execute --vdf-lock params.json`): the
   plan's overwrite passes are rewritten into `VdfWoven` declarations.
   Between passes, the executor advances the VDF chain:

   ```text
   x ──2^s──▶ state_1 ──2^s──▶ state_2 ──2^s──▶ … ──2^s──▶ state_n
              [pass 0]         [pass 1]                [pass n-1]
   ```

   Pass `i`'s on-media keystream is
   `ChaCha20(key = BLAKE3(state_i ‖ pass_index), nonce = window)`.
   The physical bytes on the drive ARE the timestamp: pass `i`'s data
   could not have existed before `i·s` sequential squarings elapsed
   since the run began.

3. **The proof** (Wesolowski, fused streaming): each chain link
   carries `π_i = state_{i-1}^⌊2^s/ℓ_i⌋ mod N` where `ℓ_i` is a
   Fiat–Shamir challenge prime derived from the transcript. The proof
   is computed by long-dividing `2^s` by `ℓ_i` bit-by-bit, streaming
   the quotient into a left-to-right exponentiation — no `s`-bit
   integer is ever materialized.

4. **Verification** (`dc vdf verify --certificate cert.json`): for
   every link, check `state_i ≡ π_i^{ℓ_i} · state_{i-1}^{r} (mod N)`
   with `r = 2^s mod ℓ_i` via Fermat's little theorem — two short
   modular exponentiations per pass. **Milliseconds, on any
   commodity machine, forever.**

## What the certificate proves

For a run with `n` woven passes of `s` steps each:

| Claim | Derivation |
|---|---|
| Started no earlier than `T₁` | optional **beacon anchor** (a public randomness value committed at run start — it did not exist before its publication) |
| Occupied ≥ `n·s / (adversary squaring rate)` of physical time between the first and last woven writes | the chain's states are provably `n·s` sequential squarings apart, and every pass's media bytes hash to a keystream keyed by those states |
| Completed no earlier than `T₂ = T₁ + elapsed` | conjunction of the above |

The time lower bound uses a **documented adversary model**: 20 million
2048-bit Montgomery squarings per second (a deliberate 10× margin over
fielded high-end verifier throughput — see
`dc_vdf::weave::ADVERSARY_SQUARINGS_PER_SECOND`). Auditors may
substitute their own hardware model and re-derive from the recorded
`steps_per_pass` — the mathematics is model-independent.

## Threat model and honest limitations

* **Trusted setup**: a single-party ceremony is trusted to destroy the
  factors. For adversarial deployments, run the ceremony on an
  offline air-gapped machine with two witnesses (or import an
  externally generated modulus via `dc vdf setup --modulus`). The
  wipe path only ever consumes the hex `N`. Real-time NIST randomness
  beacon integration is the v2 roadmap.
* **The VDF proves elapsed squarings, not I/O**: the media-write
  binding comes from the journal's hash-chained BeginPass descriptors
  (each records the pass's seed fingerprint
  `BLAKE3(vdf_pass_seed(state_i))`) plus the read-back verification
  stream hash. The two combined make "compute the chain elsewhere,
  then write in a rush" indistinguishable from an honest run only
  under the additional assumption that the drive held the pattern
  bytes during the write window — which the hash chain evidences.
* **Single-machine provers**: an adversary with a faster ASIC reduces
  the lower bound toward the documented adversary model, not below it.
  A 2048-bit modulus keeps that margin comfortable (≈ 1 µs/squaring
  commodity, ≈ 50 ns/squaring ASIC fantasy).

## Field use

```text
# one-time (offline machine, witnessed):
dc vdf setup --bits 2048 --hours-per-pass-ms 3600000 --out vdf-params.json

# the wipe (per-run):
dc execute --target /dev/nvme0n1 --profile dod-522022m \
           --vdf-lock vdf-params.json

# the audit (anyone, forever):
dc vdf verify --certificate dc-XYZ.cert.json
```

## Artifacts

* `vdf-params.json` — the published puzzle (scheme, modulus, steps).
* Certificate section `vdf` — modulus, challenge, per-pass states +
  Wesolowski proofs + seed fingerprints, advisory local rate.
* `dc-vdf` unit tests: Wesolowski roundtrip + tamper rejection,
  ceremony determinism, CIOS-vs-schoolbook known answers, the
  regression KAT `montgomery_modulus_above_half_r` (the 2^128−159
  prime).
