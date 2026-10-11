# dc-verify — Read-Back Verification and Stream Attestation

`dc-verify` implements the verification phase: full-LBA read-back, pattern
matching, and stream hashing. A wipe is not "done" because writes returned —
it is done because the media read back matches, bit for bit.

## Model

`StreamVerifier` implements `dc_io::VerifySink`. The engine feeds it every
window with a validity verdict and the raw bytes; the verifier counts
mismatches, records the first 64 failing LBAs, streams BLAKE3 (and
optionally SHA-256) over the read-back bytes, and optionally tracks entropy
diagnostics. `finalize()` produces the `VerificationReport` embedded in the
journal and certificate — the stream hash is the digest an independent
auditor can re-derive from the seed alone (see
`docs/reproduction/chacha20-window-v1.txt`).

`entropy.rs` computes fixed-point Shannon entropy and chi-square statistics
scaled by 1e6 — integer math, deterministic across machines, suitable for
certificate embedding.

## Guarantees

- **100% LBA coverage** on `VerifyLevel::Full` — no sampling shortcuts
- Mismatch LBAs are window-aligned and computed from the actual window
  geometry, not approximated
- The verifier never trusts the engine's write accounting: it only reports
  what it observed on read-back

## Testing

`cargo test -p dc-verify --lib` — 5 unit tests (mismatch accounting,
order-sensitive stream hashes, optional SHA-256 parity with `sha2`, entropy
bounds). Integration: `t8_prng_matrix` (cleanroom reproduction),
`g5_reproduction_matrix`.
