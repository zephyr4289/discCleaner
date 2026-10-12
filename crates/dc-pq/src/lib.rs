//! `dc-pq` — post-quantum cryptographic primitives for audit longevity
//! (v0.10.0, Frontier 3).
//!
//! Sanitization certificates must withstand **decades** of legal scrutiny.
//! Classical 256-bit signatures (Ed25519) are sound today, but a
//! harvest-now-decrypt-later adversary with a future quantum computer could
//! forge audit evidence retroactively. This crate provides the post-quantum
//! leg of dc-cert's hybrid dual-signing:
//!
//! * [`keccak`] — FIPS 202 Keccak-f[1600] permutation with SHA3-256 and the
//!   SHAKE256 XOF (the entire hash foundation of ML-DSA).
//! * [`ml_dsa`] — **ML-DSA-44** (FIPS 204, a.k.a. CRYSTALS-Dilithium 2):
//!   keygen / sign / verify over Z_q[x]/(x^256+1), q = 8380417.
//!
//! # Design notes (read before auditing)
//!
//! * **Zero external crypto dependencies.** Keccak-f[1600], SHA-3 and
//!   SHAKE256 are implemented from scratch in this crate — no ring, no
//!   RustCrypto, no C reference code. Every constant (round constants,
//!   rotation offsets) is the published FIPS 202 specification table and is
//!   pinned by known-answer tests (`keccak::tests`).
//! * **Derivation over recollection.** The NTT is implemented as a direct
//!   O(N^2) evaluation at the 256 odd powers of the 512th root of unity
//!   psi = 1753, rather than a bit-twiddled Cooley-Tukey butterfly network.
//!   This is a deliberate trade: it is slower (irrelevant at certificate
//!   signing rates) but the transform is *manifestly* the definition —
//!   there are no zeta-ordering conventions to get wrong, and the
//!   negacyclic homomorphism property is pinned by a property test.
//! * **Self-consistent parameterization.** Hash domain separation and seed
//!   derivation follow the FIPS 204 structure (documented at each call
//!   site in [`ml_dsa`]). Official NIST ACVP known-answer vectors are a
//!   tracked follow-up item (see `docs/post-quantum.md` § Conformance);
//!   until they are wired into CI the implementation is validated by
//!   component KATs (Keccak), structural property tests (NTT, packing,
//!   rejection sampling) and full sign/verify roundtrip + tamper matrices.
//!
//! # Public API surface (used by dc-cert)
//!
//! ```no_run
//! use dc_pq::ml_dsa::{MlDsa44KeyPair, MlDsa44SecretKey};
//!
//! let kp = MlDsa44KeyPair::generate().unwrap();
//! let sig = kp.sign(b"canonical certificate bytes");
//! assert!(kp.public.verify(b"canonical certificate bytes", &sig));
//! ```

pub mod keccak;
pub mod ml_dsa;

pub use keccak::{Shake256, sha3_256, shake256};
pub use ml_dsa::{MlDsa44KeyPair, MlDsa44PublicKey, MlDsa44SecretKey, MlDsa44Signature};
