# dc-fhe — Homomorphic Verifiable Computation over Encrypted Drives

> v0.14.0, Breakthrough 2. Wipe and **prove** the wipe of an
> encrypted volume when the operator is not trusted with the key
> — the provider never decrypts, the customer never shows the key.

## The custody paradox

Customer A wants the cloud provider to wipe their encrypted
volume. Customer A refuses to hand over the key; the provider
refuses to run A's arbitrary code on the host. Software-visible
"trust me" wipes are unverifiable in **both** directions: the
customer cannot see the disk, and the provider cannot see the
data.

## The protocol

```text
Customer (holds sk)                    Provider (holds ciphertexts)
──────────────────                    ──────────────────────────
keygen: pk = (a, b = a·s + e)
issue EvalKey(pk, volume, nonce) ─────►
encrypt volume sectors,
publish commitment root M
                          wipe day:
                                       for each sector i:
                                         C'_i = (C_i ⊖ C_i) ⊕ Enc_pk(0; r'_i)
                                       π = ZK{ every C'_i admits a short
                                              encryption-of-zero witness }
                                       manifest M' = MerkleRoot(C'_i)
                      ◄──────────────  (C'_i, M', π)
verify π (batched, two polynomial products),
spot-decrypt one FS-challenged sector with sk → must be 0^N
```

### 1. The blind zeroize circuit (`fhe.rs`)

```text
C' = (C ⊖ C) ⊕ Enc_pk(0; r', e1', e2')
Dec_sk(C') = m − m + 0 = 0^N        by the circuit algebra
```

The self-subtraction is publicly verifiable arithmetic over the
stored leaf; the fresh zero-encryption re-randomizes the result.
The provider evaluates it **holding only the public key** — no
decryption, no plaintext, and the output is distributed as a fresh
encryption of zero: the provider learns nothing, not even whether
the sector ever held data. The noise accounting shows the output
sits an order of magnitude below the decryptability ceiling.

### 2. Ring-LWE encryption (`rlwe.rs`)

```text
pk = (a, b = a·s + e)                  a ← R_q uniform, s, e ← CBD(3)
Enc(m): u = a·r + e1, v = b·r + e2 + Δ·m       Δ = ⌊q/2⌋, m ∈ {0,1}^N
Dec(c): round((v − u·s)·t/q) mod t per coefficient
```

The negacyclic ring arithmetic (`poly.rs`, `R_q = Z_q[X]/(X^N+1)`)
is schoolbook — auditable, dependency-free, fast enough at the demo
parameters. Sparse ternary multiplication keeps the Fiat-Shamir
challenge evaluations at O(w·N).

### 3. The zero-knowledge layer (`zkp.rs`)

The language:

```text
L_zero(pk) = { (u, v) : ∃ short (r, e1, e2), u = a·r + e1 ∧ v = b·r + e2 }
```

Membership pins the plaintext to **zero**: an encryptor folding in
a plaintext leaves a `Δ·m` residual that no short witness can
absorb. The Sigma protocol (Lyubashevsky-style, Fiat-Shamir
compiled, rejection-sampled to the tight bound so responses are
statistically independent of the witness):

```text
T1 = a·y + f1, T2 = b·y + f2  →  c = FS(statements ‖ commitments)  →  z = y + c·r …
verify: a·z + z1 = T1 + c·u,  b·z + z2 = T2 + c·v,  ‖(z,z1,z2)‖_∞ ≤ M
```

**Batching**: all sector statements share one challenge; the
verifier may check every equation or run the **batched check** —
with FS-hashed coefficients `γ_i`,

```text
a·(Σ γ_i·z_i) + Σ γ_i·z1_i − Σ γ_i·T1_i − c·(Σ γ_i·u_i) = 0
```

**two polynomial products total** — constant time in the sector
count (the milliseconds-on-a-smartphone property). A single
cheating sector breaks the linear combination with probability
`1 − 1/q`.

### 4. The spot challenge (`protocol.rs`)

The one party holding `sk` decrypts one Fiat-Shamir-chosen sector
and must see `0^N` — anchoring the algebra to the physical volume.
The challenge index derives from the contract and the final root;
the provider cannot pre-pick a favorable sector.

## The certificate

The FHE Erasure Certificate binds: volume identity, the embedded
public key + eval-key digest (substitution caught by
recomputation), both commitment roots, the stored zeroized
ciphertext set, the ZK proof, noise margins, and the **measured**
verification time. `verify()` replays everything offline: digest
coverage, eval-key recomputation, Merkle root recomputation, and
the full ZK batch verification — no secrets needed.

```text
dc fhe simulate --volume-id vol-uuid --sectors 8 --out fhe-cert.json
dc fhe verify --cert fhe-cert.json
```

## Parameter honesty

`N = 1024, q = 65537, CBD-3` are **demo-grade**: chosen so the
whole pipeline runs in milliseconds with schoolbook arithmetic and
fits CI. A production deployment raises the parameters per the
current RLWE security literature (everything is parameterized over
`Params`). The multiplicative extension (gadget
relinearization keys) is documented as a scope boundary: the Δ²
tensor term wraps mod any single-word `q`, so real
ciphertext-ciphertext multiplication needs RNS-sized moduli —
the zeroize circuit is additive and unaffected.

## Threat model

1. **Lazy provider** — wipe claimed, ciphertexts untouched: they
   encrypt data, so they are not in `L_zero`; no accepting proof
   exists.
2. **Substitution** — wiping a decoy volume and replaying a
   genuine proof: the statement set is root-bound; the spot
   challenge binds the root to the customer's volume identity and
   issued key.
3. **Privacy** — the provider sees ciphertexts and public keys
   only; the zeroized outputs are fresh encryptions of zero,
   statistically independent of the data.
4. **Replay of a genuine certificate** — BLAKE3-digest bound,
   signable via the dc-cert hybrid Ed25519 + ML-DSA machinery.
