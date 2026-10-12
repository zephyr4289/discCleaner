//! Wesolowski Verifiable Delay Function over an RSA unknown-order
//! group (v0.12.0, Miracle 1).
//!
//! * **Eval**: `y = x^(2^T) mod N` — `T` sequential Montgomery
//!   squarings. Non-parallelizable: each squaring consumes the
//!   previous one's output, so T squarings cost T squaring-times on
//!   ANY hardware, forever.
//! * **Prove** (fused streaming): the proof `π = x^⌊2^T/ℓ⌋ mod N` is
//!   computed by long-dividing `2^T` by the challenge prime `ℓ` bit by
//!   bit, feeding the quotient bits straight into a left-to-right
//!   modexp. No T-bit integer is ever materialized; the extra state is
//!   a single 192-bit division remainder.
//! * **Verify**: `y ≡ π^ℓ · x^r (mod N)` with `r = 2^T mod ℓ`
//!   (Fermat: `2^T ≡ 2^(T mod ℓ−1) (mod ℓ)`), two short modexps —
//!   milliseconds on commodity hardware, independent of T.
//!
//! The challenge `ℓ = HashToPrime(N ‖ x ‖ T ‖ y)` is Fiat–Shamir
//! derived, binding the proof to the exact transcript.

use crate::bigint::{BigUint, Montgomery, is_probable_prime, passes_small_primes};
use sha2::{Digest, Sha256};

/// Production modulus width: 2048-bit RSA unknown-order group.
pub const RSA_LIMBS: usize = 32;

/// Challenge-prime width: 128-bit (verification modexps stay trivial).
pub type Challenge = BigUint<2>;

/// A single VDF link: `y = base^(2^steps) mod N` plus its Wesolowski
/// proof that exactly `steps` squarings separate `base` from `y`.
#[derive(Clone, Debug)]
pub struct LinkProof {
    pub steps: u64,
    /// Evaluation output `y` (normal form, canonical bytes).
    pub y: Vec<u8>,
    /// Wesolowski proof `π = base^⌊2^steps/ℓ⌋ mod N`.
    pub pi: Vec<u8>,
    /// Fiat–Shamir challenge prime `ℓ`.
    pub challenge: Challenge,
}

/// Errors from the VDF core.
#[derive(Debug, thiserror::Error)]
pub enum VdfError {
    #[error("modulus must be odd and between 512 and 2048 bits (got {0} bits)")]
    BadModulus(usize),
    #[error("challenge x must satisfy 1 < x < N and gcd(x, N) = 1")]
    BadChallenge,
    #[error("value out of range: {0}")]
    Range(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("entropy: {0}")]
    Entropy(String),
}

/// Hash a transcript to a 128-bit prime (top bit forced — the prime is
/// always exactly 128 bits, so `steps < 2^64 < ℓ−1` and the Fermat
/// shortcut in `verify` never wraps).
pub fn hash_to_prime(transcript: &[u8]) -> Challenge {
    let mut h = Sha256::new();
    h.update(b"dc-vdf/challenge/v1");
    h.update(transcript);
    let digest = h.finalize();
    let mut cand = [0u8; 16];
    cand.copy_from_slice(&digest[..16]);
    cand[0] |= 0x80; // exact 128-bit width
    cand[15] |= 1; // odd
    let base = BigUint::<2>::from_bytes_be(&cand);
    let mut c = base;
    // Increment by 2 until prime. The density of 128-bit primes makes
    // the expected search ~35 candidates; bound defensively.
    for _ in 0..(1 << 22) {
        if passes_small_primes(&c) && is_probable_prime::<2>(&c, 8) {
            return c;
        }
        let two = {
            let mut t = [0u64; 2];
            t[0] = 2;
            BigUint(t)
        };
        c = c.checked_add(&two).expect("128-bit prime space exhausted");
        // keep the top bit set if the add wrapped the width (it cannot:
        // overflow past 2^128 would need the counter to run away)
    }
    unreachable!("no 128-bit prime found within 2^22 candidates");
}

/// Fused streaming Wesolowski proof for one link.
///
/// Computes, in one pass over `steps`:
///   * `acc = base^⌊2^steps/ℓ⌋ mod N` (long division of 2^steps by ℓ
///     interleaved with left-to-right exponentiation), and
///   * `rem = 2^steps mod ℓ` (the division remainder, for free).
///
/// The caller supplies the already-computed evaluation `y_mont`
/// (the VDF chain advance produces it), or this function performs the
/// squarings itself when `eval_mont` is `None` (standalone puzzle mode).
pub struct WesolowskiProver<'a, const L: usize> {
    ctx: &'a Montgomery<L>,
}

impl<'a, const L: usize> WesolowskiProver<'a, L> {
    pub fn new(ctx: &'a Montgomery<L>) -> Self {
        Self { ctx }
    }

    /// Full evaluation `y = x^(2^steps) mod N` (normal form out).
    pub fn eval(
        &self,
        base: &BigUint<L>,
        steps: u64,
        progress: impl FnMut(u64) -> bool,
    ) -> BigUint<L> {
        let y_m = self
            .ctx
            .repeat_square(&self.ctx.to_mont(base), steps, progress);
        self.ctx.from_mont(&y_m)
    }

    /// Prove the link `base --(2^steps)--> y`.
    pub fn prove_link(
        &self,
        base: &BigUint<L>,
        y: &BigUint<L>,
        steps: u64,
        mut progress: impl FnMut(u64) -> bool,
    ) -> Result<LinkProof, VdfError> {
        let n = &self.ctx.n;
        if base.cmp_to(n) != std::cmp::Ordering::Less || base.is_zero() {
            return Err(VdfError::Range("base must be in [1, N)".into()));
        }
        if y.cmp_to(n) != std::cmp::Ordering::Less {
            return Err(VdfError::Range("y must be < N".into()));
        }
        let transcript = [
            n.to_bytes_be(),
            base.to_bytes_be(),
            steps.to_be_bytes().to_vec(),
            y.to_bytes_be(),
        ]
        .concat();
        let l = hash_to_prime(&transcript);

        // ---- fused streaming division + exponentiation ---------------
        // acc = Montgomery(1); rem tracks 2^i mod ℓ as i climbs to steps.
        let mut acc = self.ctx.to_mont(&BigUint::<L>::ONE);
        let mut rem = BigUint::<3>::ONE; // 192-bit headroom over 128-bit ℓ
        let l3 = {
            let mut limbs = [0u64; 3];
            limbs[0] = l.0[0];
            limbs[1] = l.0[1];
            BigUint(limbs)
        };
        for i in 0..steps {
            if i & 0xFFFFF == 0 && !progress(i) {
                return Err(VdfError::Range(
                    "VDF proof generation cancelled — run refuses to certify".into(),
                ));
            }
            acc = self.ctx.mont_sqr(&acc);
            rem.shl1(); // rem < ℓ < 2^128 pre-shift → fits 3 limbs
            if rem.cmp_to(&l3) != std::cmp::Ordering::Less {
                rem = rem.checked_sub(&l3).expect("checked before subtract");
                acc = self.ctx.mont_mul(&acc, &self.ctx.to_mont(base));
            }
        }
        // π is in Montgomery form — convert once.
        let pi = self.ctx.from_mont(&acc);

        Ok(LinkProof {
            steps,
            y: y.to_bytes_be(),
            pi: pi.to_bytes_be(),
            challenge: l,
        })
    }
}

/// Verify a Wesolowski link: `y ≡ π^ℓ · x^r (mod N)` with
/// `r = 2^steps mod ℓ` via Fermat's little theorem.
///
/// Cost: two modexps with ≤ 128-bit exponents plus one 64-round modpow
/// — microseconds, independent of how long the evaluation took.
pub fn verify_link<const L: usize>(
    ctx: &Montgomery<L>,
    base: &BigUint<L>,
    y: &BigUint<L>,
    steps: u64,
    pi: &BigUint<L>,
    l: &Challenge,
) -> bool {
    let n = &ctx.n;
    // Range + degeneracy gates.
    if base.is_zero() || pi.is_zero() {
        return false;
    }
    if base.cmp_to(n) != std::cmp::Ordering::Less
        || y.cmp_to(n) != std::cmp::Ordering::Less
        || pi.cmp_to(n) != std::cmp::Ordering::Less
    {
        return false;
    }
    if base.binary_gcd(n).cmp_to(&BigUint::<L>::ONE) != std::cmp::Ordering::Equal {
        // gcd(x, N) ≠ 1 either factors N (proof worthless) or the input
        // is malformed — reject either way.
        return false;
    }
    // ℓ must be a plausible 128-bit prime (top bit set).
    if l.0[1] >> 63 != 1 {
        return false;
    }

    // r = 2^steps mod ℓ = 2^(steps mod (ℓ−1)) mod ℓ  (Fermat; steps < ℓ−1).
    let l_minus_1 = match l.checked_sub(&BigUint::<2>::ONE) {
        Some(v) => v,
        None => return false,
    };
    // steps: u64 → BigUint<2>
    let steps_be = steps.to_be_bytes();
    let steps_b = BigUint::<2>::from_bytes_be(&steps_be);
    // (steps mod ℓ−1): since ℓ ≥ 2^127 > 2^64 > steps, this is steps.
    debug_assert!(steps_b.cmp_to(&l_minus_1) == std::cmp::Ordering::Less);
    let small_ctx = match Montgomery::<2>::new(*l) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let two = BigUint::<2>::from_bytes_be(&2u64.to_be_bytes());
    let r_small = small_ctx.from_mont(&small_ctx.modpow(&small_ctx.to_mont(&two), &steps_b));

    // Pad the small values up to the main width.
    let pad = |v: &BigUint<2>| -> BigUint<L> {
        let mut limbs = [0u64; L];
        limbs[0] = v.0[0];
        limbs[1] = v.0[1];
        BigUint(limbs)
    };
    let l_big = pad(l);
    let r_big = pad(&r_small);

    // lhs = π^ℓ · x^r mod N; compare against y.
    let base_m = ctx.to_mont(base);
    let pi_m = ctx.to_mont(pi);
    let lhs = ctx.mont_mul(&ctx.modpow(&pi_m, &l_big), &ctx.modpow(&base_m, &r_big));
    ctx.from_mont(&lhs) == *y
}

/// Measure this machine's Montgomery squaring rate for the given
/// modulus — used to calibrate `steps_per_pass` for a target duration
/// and recorded in the evidence as the honest local rate.
pub fn benchmark_squarings_per_second<const L: usize>(
    ctx: &Montgomery<L>,
    approx_seconds: u64,
) -> f64 {
    let x = BigUint::<L>::from_bytes_be(&[0x0A, 0x3F]); // arbitrary base
    let x_m = ctx.to_mont(&x);
    let batch = 50_000u64;
    let mut acc = x_m;
    let mut total: u64 = 0;
    let start = std::time::Instant::now();
    loop {
        for _ in 0..batch {
            acc = ctx.mont_sqr(&acc);
        }
        total += batch;
        if start.elapsed().as_secs() >= approx_seconds.max(1) {
            break;
        }
    }
    let _ = acc; // value intentionally unused (benchmark)
    total as f64 / start.elapsed().as_secs_f64().max(1e-9)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_modulus() -> (Montgomery<8>, BigUint<8>) {
        // 512-bit semiprime-ish odd modulus (prime here is fine for
        // arithmetic tests): 2^511 + 111 is prime? Use a known odd
        // composite without small factors: product of two 256-bit
        // primes is slow to make inline; use Mersenne-ish prime
        // 2^521 - 1 truncated to 8 limbs (= 2^521-1 needs 9 limbs) —
        // instead use 2^511 - 1 (Mersenne, 511 prime → composite)…
        // simplest robust choice: the 512-bit prime from RFC 3526
        // (group 14, 2048-bit) scaled down is overkill; use a small
        // odd modulus with no small factors found by search.
        let mut cand = BigUint::<8>::from_bytes_be(&[0xC5; 64]);
        cand.0[0] |= 1;
        while !is_probable_prime::<8>(&cand, 4) {
            let two = BigUint::<8>::from_bytes_be(&2u64.to_be_bytes());
            cand = cand.checked_add(&two).unwrap();
        }
        let ctx = Montgomery::new(cand).unwrap();
        (ctx, cand)
    }

    #[test]
    fn prove_verify_roundtrip() {
        let (ctx, _n) = test_modulus();
        let prover = WesolowskiProver::new(&ctx);
        let base = BigUint::<8>::from_bytes_be(&[0x42; 8]);
        let steps = 4096u64;
        let y = prover.eval(&base, steps, |_| true);
        let proof = prover.prove_link(&base, &y, steps, |_| true).unwrap();
        assert!(verify_link(
            &ctx,
            &base,
            &y,
            steps,
            &BigUint::<8>::from_bytes_be(&proof.pi),
            &proof.challenge
        ));

        // Tampered y must fail.
        let mut bad_y = y;
        bad_y.0[0] ^= 1;
        assert!(!verify_link(
            &ctx,
            &base,
            &bad_y,
            steps,
            &BigUint::<8>::from_bytes_be(&proof.pi),
            &proof.challenge
        ));

        // Tampered π must fail.
        let mut bad_pi = BigUint::<8>::from_bytes_be(&proof.pi);
        bad_pi.0[3] ^= 0x100;
        assert!(!verify_link(
            &ctx,
            &base,
            &y,
            steps,
            &bad_pi,
            &proof.challenge
        ));

        // Wrong step count must fail.
        assert!(!verify_link(
            &ctx,
            &base,
            &y,
            steps + 1,
            &BigUint::<8>::from_bytes_be(&proof.pi),
            &proof.challenge
        ));
    }

    #[test]
    fn hash_to_prime_is_prime_and_bound() {
        for i in 0u32..8 {
            let l = hash_to_prime(&i.to_be_bytes());
            assert!(l.0[1] >> 63 == 1, "must be 128-bit");
            assert!(l.is_odd());
            assert!(is_probable_prime::<2>(&l, 4), "must be prime");
        }
    }
}
