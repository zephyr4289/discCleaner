//! # dc-vdf — Cryptographic Proof-of-Erasure via Verifiable Delay
//! Functions (v0.12.0, Miracle 1)
//!
//! Every disk wipe certificate ever issued carries one fatal flaw:
//! **timestamp spoofing**. A rogue sysadmin, compromised cloud provider
//! or malicious auditor can set the system clock to 2024 and forge
//! "this drive was destroyed on August 15th at 14:00". In legal
//! disputes, insurance claims and sanctions enforcement, such
//! timestamps are routinely thrown out — because system clocks can be
//! manipulated by exactly the parties the certificate incriminates.
//!
//! dc-vdf replaces trust in clocks with **immutable mathematics**:
//!
//! * A [`ceremony`] publishes an RSA modulus `N = p·q` whose
//!   factorization is destroyed — a group of *unknown order* in which
//!   `x^(2^T) mod N` requires `T` inherently sequential modular
//!   squarings. No amount of parallelism, money or clock-setting
//!   shortcuts it, for anyone, ever (the RSA time-lock).
//! * [`weave::VdfLock`] interleaves that delay with the overwrite
//!   passes: each pass's on-media keystream is keyed by an
//!   intermediate chain **state**, so the drive physically held each
//!   state at a sequential time step — the bytes themselves are the
//!   timestamp.
//! * Each chain link carries a [`vdf::WesolowskiProver`]-produced
//!   proof (a couple of group elements) that any court, auditor or
//!   counterparty verifies in **milliseconds**, independent of system
//!   clocks, NTP, networks or the operator's honesty.
//!
//! The resulting [`weave::TimelineEvidence`] embedded in the
//! sanitization certificate proves three claims courts actually need:
//!
//! 1. the erasure **started** no earlier than an externally anchored
//!    `T₁` (beacon/publication-bound start),
//! 2. the wipe **occupied** at least `n·s / (hardware rate)` of
//!    physical sequential-squaring time between its first and last
//!    woven writes,
//! 3. it therefore **completed** no earlier than `T₂ = T₁ + elapsed`.
//!
//! Layered on: dc-zk (zero-knowledge compliance proofs), dc-cxl
//! (memory-device sanitization), the dc-cert hybrid-signature chain.
//!
//! ## Module map
//!
//! * [`bigint`] — fixed-limb big integers, CIOS Montgomery core,
//!   Miller–Rabin, safe-prime search support.
//! * [`vdf`] — Wesolowski VDF: fused streaming proof generation and
//!   the fast verifier.
//! * [`ceremony`] — safe-prime parameter generation with zeroized
//!   factors, deterministic drill mode, modulus import.
//! * [`weave`] — the executor lock (`VdfLock`), pass bindings, and
//!   the standalone timeline verifier used by `dc vdf verify`.

pub mod bigint;
pub mod ceremony;
pub mod vdf;
pub mod weave;

/// Fresh 16-byte run-binding nonce (OS entropy) — mixed into every
/// weave challenge so no two runs share a chain.
pub fn fresh_nonce() -> [u8; 16] {
    let mut n = [0u8; 16];
    let _ = getrandom::getrandom(&mut n);
    n
}

pub use bigint::{BigUint, Montgomery, is_probable_prime};
pub use ceremony::{CeremonyInfo, VdfRng, generate_modulus, validate_modulus_hex};
pub use vdf::{
    LinkProof, VdfError, WesolowskiProver, benchmark_squarings_per_second, hash_to_prime,
    verify_link,
};
pub use weave::{
    ADVERSARY_SQUARINGS_PER_SECOND, PassBinding, TimelineEvidence, TimelineVerdict, VdfLock,
    VdfParams, local_rate_note, verify_timeline,
};
