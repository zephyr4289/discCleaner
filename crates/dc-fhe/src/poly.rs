//! # The negacyclic polynomial ring `R_q = Z_q[X]/(X^N + 1)`.
//!
//! Elements are coefficient vectors of length `N` with entries in
//! centred representative `(-q/2, q/2]`. Multiplication is the
//! schoolbook negacyclic product — `X^N ≡ −1` — computed as
//!
//! ```text
//! c_{i+j}   += a_i·b_j   for i+j <  N
//! c_{i+j-N} -= a_i·b_j   for i+j ≥ N
//! ```
//!
//! O(N²) with u64 accumulation; at the demo parameters
//! (N = 1024, q = 65537) one multiplication is ~1 M multiply-adds
//! and runs in single-digit milliseconds, which keeps the whole
//! pipeline dependency-free and auditable. Production swaps in NTT
//! by parameter change only.

use crate::FheError;
use serde::{Deserialize, Serialize};

/// A polynomial in `R_q` (centred coefficients, length exactly N).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poly {
    pub coeffs: Vec<i64>,
}

impl Poly {
    /// The zero polynomial of degree bound `n`.
    pub fn zero(n: usize) -> Self {
        Self { coeffs: vec![0; n] }
    }

    /// Build from centred coefficients (length checked against `n`).
    pub fn from_centred(coeffs: Vec<i64>, n: usize) -> Result<Self, FheError> {
        if coeffs.len() != n {
            return Err(FheError::Params(format!(
                "coefficient vector of length {} does not match ring degree {}",
                coeffs.len(),
                n
            )));
        }
        Ok(Self { coeffs })
    }

    /// Degree bound.
    pub fn degree_bound(&self) -> usize {
        self.coeffs.len()
    }

    /// Reduce all coefficients into the centred range modulo `q`.
    pub fn centre_in_place(&mut self, q: i64) {
        for c in &mut self.coeffs {
            *c = centre_reduce(*c, q);
        }
    }

    /// Centred copy modulo `q`.
    pub fn centred(&self, q: i64) -> Self {
        let mut p = self.clone();
        p.centre_in_place(q);
        p
    }

    /// Uniform random polynomial over the centred residues of `q`.
    pub fn uniform(n: usize, q: i64, rng: &mut crate::SimRng) -> Self {
        let half = (q - 1) / 2;
        Self {
            coeffs: (0..n).map(|_| rng.below(q as u64) as i64 - half).collect(),
        }
    }

    /// Negacyclic schoolbook multiplication (centred mod `q`).
    pub fn mul(&self, other: &Self, q: i64) -> Self {
        debug_assert_eq!(self.coeffs.len(), other.coeffs.len());
        let n = self.coeffs.len();
        let mut acc = vec![0i64; n];
        // s ≥ 2^15, products < 2^30, accumulate n = 2^10 → |acc| <
        // 2^40, no overflow in i64. Larger q needs limb splitting
        // (documented in the crate preamble).
        for i in 0..n {
            let a_i = self.coeffs[i];
            if a_i == 0 {
                continue;
            }
            for j in 0..n {
                let idx = i + j;
                let prod = a_i * other.coeffs[j];
                if idx < n {
                    acc[idx] += prod;
                } else {
                    acc[idx - n] -= prod;
                }
            }
        }
        let mut out = Self { coeffs: acc };
        out.centre_in_place(q);
        out
    }

    /// Add (no reduction: callers reduce at the ring modulus).
    pub fn add(&self, other: &Self) -> Self {
        debug_assert_eq!(self.coeffs.len(), other.coeffs.len());
        Self {
            coeffs: self
                .coeffs
                .iter()
                .zip(&other.coeffs)
                .map(|(a, b)| a + b)
                .collect(),
        }
    }

    /// Subtract (no reduction).
    pub fn sub(&self, other: &Self) -> Self {
        debug_assert_eq!(self.coeffs.len(), other.coeffs.len());
        Self {
            coeffs: self
                .coeffs
                .iter()
                .zip(&other.coeffs)
                .map(|(a, b)| a - b)
                .collect(),
        }
    }

    /// Pointwise negate.
    pub fn neg(&self) -> Self {
        Self {
            coeffs: self.coeffs.iter().map(|c| -c).collect(),
        }
    }

    /// Multiply by a small integer scalar (no reduction).
    pub fn scale(&self, k: i64) -> Self {
        Self {
            coeffs: self.coeffs.iter().map(|c| c * k).collect(),
        }
    }

    /// Infinity norm of the coefficient vector.
    pub fn inf_norm(&self) -> i64 {
        self.coeffs.iter().fold(0i64, |m, c| m.max(c.abs()))
    }

    /// Canonical little-endian byte encoding (u16 residues in
    /// [0, q)); the digest input for Merkle leaves.
    pub fn to_bytes(&self, q: i64) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.coeffs.len() * 2);
        for c in &self.coeffs {
            let v = (if *c < 0 { *c + q } else { *c }) as u16;
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    /// Sparse ternary multiplication: `self * t` where `t` is given
    /// as a list of (index, sign) with signs ±1.
    ///
    /// The Fiat-Shamir challenges are sparse ternary polynomials;
    /// multiplying by them costs O(w·N) instead of O(N²).
    pub fn mul_sparse(&self, t: &[(usize, i8)], q: i64) -> Self {
        let n = self.coeffs.len();
        let mut acc = vec![0i64; n];
        for &(idx, sign) in t {
            debug_assert!(idx < n && sign.abs() == 1);
            // self * (±X^idx) with X^N = −1:
            // shifting coefficient i to position (i + idx) mod N,
            // negating when the exponent wraps.
            for i in 0..n {
                let pos = i + idx;
                let prod = self.coeffs[i] * sign as i64;
                if pos < n {
                    acc[pos] += prod;
                } else {
                    acc[pos - n] -= prod;
                }
            }
        }
        let mut out = Self { coeffs: acc };
        out.centre_in_place(q);
        out
    }
}

/// Centred reduction: map `x` into `[-(q-1)/2, (q-1)/2]` (the
/// symmetric representative; `q` is an odd prime at the demo
/// parameters).
pub fn centre_reduce(x: i64, q: i64) -> i64 {
    let mut r = x % q;
    let half = (q - 1) / 2;
    if r > half {
        r -= q;
    } else if r < -half {
        r += q;
    }
    r
}

/// Expand a seeded sparse ternary polynomial: exactly `weight`
/// non-zero positions with ±1 signs, derived deterministically from
/// a seed via a BLAKE3 counter keystream.
pub fn sparse_ternary_from_seed(seed: &[u8], n: usize, weight: usize) -> Vec<(usize, i8)> {
    let mut terms: Vec<(usize, i8)> = Vec::with_capacity(weight);
    let mut used = std::collections::HashSet::new();
    let mut block_ctr = 0u64;
    // Every BLAKE3 invocation over (seed ‖ ctr) yields 16 usable
    // bytes = 2 draws of (position ‖ sign bit); keep drawing until
    // `weight` distinct positions are filled.
    while terms.len() < weight {
        let mut input = seed.to_vec();
        input.extend_from_slice(&block_ctr.to_le_bytes());
        block_ctr += 1;
        let h = blake3::hash(&input);
        for chunk in h.as_bytes().as_chunks::<8>().0 {
            if terms.len() == weight {
                break;
            }
            let pos = u64::from_le_bytes(*chunk) as usize % n;
            if used.insert(pos) {
                let sign: i8 = if chunk[0] & 1 == 0 { 1 } else { -1 };
                terms.push((pos, sign));
            }
        }
    }
    terms
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: i64 = 65537;
    const N: usize = 1024;

    #[test]
    fn centred_reduction_lands_in_the_half_open_interval() {
        assert_eq!(centre_reduce(0, Q), 0);
        assert_eq!(centre_reduce(Q, Q), 0);
        assert_eq!(centre_reduce(Q + 3, Q), 3);
        assert_eq!(centre_reduce(-1, Q), -1);
        assert_eq!(centre_reduce((Q + 1) / 2, Q), -(Q - 1) / 2);
        for x in [-100_000, -65_537, -32_769, -32_768, 32_768, 65_536, 100_001] {
            let r = centre_reduce(x, Q);
            let half = (Q - 1) / 2;
            assert!(r >= -half && r <= half, "{x} → {r}");
        }
    }

    #[test]
    fn ring_multiplication_respects_x_n_equals_minus_one() {
        // X^N = −1: (X^0)·(X^N) should give −X^0 = −1 constant.
        let mut a = Poly::zero(N);
        let mut b = Poly::zero(N);
        a.coeffs[0] = 1;
        b.coeffs[N - 1] = 1; // X^(N-1); multiply by X to wrap
        let c = a.mul(&b, Q);
        assert_eq!(c.coeffs[0], 0);
        // X * X^(N-1) = X^N = -1:
        let mut x = Poly::zero(N);
        let mut x_n_minus_1 = Poly::zero(N);
        x.coeffs[1] = 1;
        x_n_minus_1.coeffs[N - 1] = 1;
        let prod = x.mul(&x_n_minus_1, Q);
        assert_eq!(prod.coeffs[0], -1, "X · X^(N-1) = X^N = −1");
        assert!(prod.coeffs[1..].iter().all(|&c| c == 0));
    }

    #[test]
    fn multiplication_is_commutative_and_bilinear() {
        let mut rng = crate::SimRng::new(7);
        let a = Poly::uniform(N, Q, &mut rng);
        let b = Poly::uniform(N, Q, &mut rng);
        let c = Poly::uniform(N, Q, &mut rng);
        assert_eq!(a.mul(&b, Q), b.mul(&a, Q));
        // (a + b)·c = a·c + b·c (mod q).
        let lhs = a.add(&b).centred(Q).mul(&c, Q);
        let rhs = a.mul(&c, Q).add(&b.mul(&c, Q)).centred(Q);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn uniform_polynomials_stay_centred() {
        let mut rng = crate::SimRng::new(11);
        let p = Poly::uniform(N, Q, &mut rng);
        assert_eq!(p.coeffs.len(), N);
        assert!(p.inf_norm() <= Q / 2);
        // Both halves of the residue range appear.
        let neg = p.coeffs.iter().any(|c| *c < -1000);
        let pos = p.coeffs.iter().any(|c| *c > 1000);
        assert!(neg && pos, "uniform sampler looks degenerate");
    }

    #[test]
    fn sparse_multiplication_matches_dense() {
        let mut rng = crate::SimRng::new(13);
        let a = Poly::uniform(N, Q, &mut rng);
        // A dense ternary poly with 32 nonzeros.
        let mut dense = Poly::zero(N);
        let mut terms = Vec::new();
        for _ in 0..32 {
            let pos = rng.below(N as u64) as usize;
            let sign: i8 = if rng.next_f64() < 0.5 { 1 } else { -1 };
            dense.coeffs[pos] = sign as i64;
            terms.push((pos, sign));
        }
        assert_eq!(a.mul_sparse(&terms, Q), a.mul(&dense, Q));
    }

    #[test]
    fn byte_encoding_round_trips() {
        let mut rng = crate::SimRng::new(17);
        let p = Poly::uniform(N, Q, &mut rng);
        let bytes = p.to_bytes(Q);
        assert_eq!(bytes.len(), N * 2);
        let back: Vec<i64> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                let v = u16::from_le_bytes(*c) as i64;
                if v > Q / 2 { v - Q } else { v }
            })
            .collect();
        assert_eq!(back, p.coeffs);
    }

    #[test]
    fn seeded_sparse_ternary_is_deterministic_and_well_formed() {
        let seed = [42u8; 32];
        let t1 = sparse_ternary_from_seed(&seed, N, 16);
        let t2 = sparse_ternary_from_seed(&seed, N, 16);
        assert_eq!(t1, t2, "deterministic from the seed");
        assert_eq!(t1.len(), 16);
        // Positions distinct, signs ±1.
        let mut seen = std::collections::HashSet::new();
        for &(pos, sign) in &t1 {
            assert!(pos < N);
            assert!(sign == 1 || sign == -1);
            assert!(seen.insert(pos), "duplicate position {pos}");
        }
        // Different seed → different terms (overwhelmingly likely).
        let other = sparse_ternary_from_seed(&[43u8; 32], N, 16);
        assert_ne!(t1, other);
    }
}
