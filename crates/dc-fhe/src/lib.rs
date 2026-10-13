//! # dc-fhe — Homomorphic Verifiable Computation over Encrypted
//! Drives (v0.14.0, Breakthrough 2)
//!
//! **The custody paradox this crate kills:** Customer A wants the
//! cloud provider to wipe their encrypted volume. Customer A
//! refuses to hand over the key; the provider refuses to run the
//! customer's arbitrary code on the host. Software-visible "trust
//! me" wipes are therefore unverifiable in BOTH directions: the
//! customer cannot see the disk, and the provider cannot see the
//! data.
//!
//! dc-fhe closes the paradox with homomorphic cryptography:
//!
//! * [`poly`] — the negacyclic polynomial ring
//!   `R_q = Z_q[X]/(X^N + 1)`: centred modular arithmetic,
//!   schoolbook negacyclic multiplication, norms and digests.
//! * [`rlwe`] — Ring-LWE over that ring: keygen (public `a`,
//!   secret `s`, `b = a·s + e`), bit-plaintext encryption /
//!   decryption, centred-binomial error sampling, and noise-budget
//!   accounting.
//! * [`fhe`] — the homomorphic layer: ciphertext addition /
//!   subtraction, ciphertext-ciphertext multiplication with
//!   relinearization via the customer-supplied **evaluation
//!   key**, and the **blind zeroize circuit**:
//!
//!   ```text
//!   C' = (C ⊗ Enc_pk(0)) ⊕ Enc_pk(0; r')
//!   ```
//!
//!   The provider evaluates it in place on every sector ciphertext
//!   holding ONLY the public key. Homomorphism guarantees
//!   `Dec_sk(C') = Dec_sk(C)·0 + 0 = 0^N` for every possible
//!   secret key — the algebra of the circuit IS the proof of
//!   decryption-to-zero, and the fresh `Enc_pk(0; r')` term
//!   statistically re-randomizes the result so C' leaks nothing
//!   about whether data was ever present.
//! * [`zkp`] — the succinct zero-knowledge layer: a
//!   Lyubashevsky-style Fiat-Shamir argument of knowledge of the
//!   short encryption randomness behind every stored ciphertext,
//!   pinning each `C'_i` to the *encryption-of-zero* language.
//!   A forged ciphertext encrypting anything else admits no short
//!   witness and cannot be proven.
//! * [`protocol`] — the end-to-end customer ↔ provider run:
//!   commitment roots (BLAKE3 Merkle over the original
//!   ciphertexts), blind evaluation, proof generation,
//!   **batched verification in milliseconds**, and an optional
//!   customer spot-decryption (the one party holding sk checks a
//!   challenged sector directly — defense in depth).
//! * [`certificate`] — the **FHE Erasure Certificate** binding
//!   the original root, the final root, the proof, the noise
//!   margins and the verification timing under a BLAKE3 digest.
//!
//! ## Threat model
//!
//! 1. **Lazy provider** — wipe claimed, ciphertexts untouched:
//!    the untouched ciphertexts are not encryptions of zero
//!    (they encrypt data), so no accepting proof exists; the
//!    ZK soundness gap is the provider's per-attempt forgery
//!    probability.
//! 2. **Substitution** — provider wipes a decoy volume and
//!    replays a genuine proof: every proof statement binds the
//!    BLAKE3 Merkle root of the *stored* ciphertext set; the
//!    spot-decryption challenge binds the root to the physical
//!    volume identity.
//! 3. **Privacy** — the provider must learn NOTHING about the
//!    data: all provider-side computation runs over ciphertexts
//!    and public keys only; the zeroize output is a fresh
//!    encryption of zero (statistically independent of the
//!    original plaintext); the ZK layer is honest-verifier
//!    zero-knowledge under rejection sampling.
//! 4. **Replay of a genuine certificate** — digest-bound and
//!    signable by the dc-cert hybrid Ed25519 + ML-DSA machinery.
//!
//! ## Parameter honesty
//!
//! The defaults (`N = 1024`, `q = 65537`, CBD-3 noise) are
//! **demo-grade**: chosen so the protocol logic runs in
//! milliseconds with schoolbook arithmetic and the whole pipeline
//! fits CI. A production deployment raises `N`, `q` (RNS split)
//! and the noise parameters per the current RLWE security
//! literature; every module is parameterized over [`rlwe::Params`]
//! for exactly that swap.

pub mod certificate;
pub mod fhe;
pub mod poly;
pub mod protocol;
pub mod rlwe;
pub mod zkp;

/// FHE protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum FheError {
    #[error("ring parameter set invalid: {0}")]
    Params(String),
    #[error("homomorphic evaluation failed: {0}")]
    Eval(String),
    #[error("zero-knowledge proof rejected: {0}")]
    Proof(String),
    #[error("protocol step violated: {0}")]
    Protocol(String),
    #[error("certificate verification failed: {0}")]
    Certificate(String),
}

/// Splitmix64 stream PRNG (house pattern — carries no secrecy; the
/// PRODUCTION keygen path injects real entropy, see
/// [`rlwe::keygen_deterministic`] vs the provider randomness
/// documented in the protocol module).
pub struct SimRng {
    state: u64,
}

impl SimRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform [0, 1).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform integer in [0, bound).
    pub fn below(&mut self, bound: u64) -> u64 {
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let x = self.next_u64();
            let m = (x as u128) * (bound as u128);
            let lo = m as u64;
            if lo >= threshold {
                return (m >> 64) as u64;
            }
        }
    }
}
