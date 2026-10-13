//! Fixed-limb big-integer arithmetic over `u64` limbs (little-endian)
//! with a CIOS Montgomery multiplier — the arithmetic bedrock of the
//! Proof-of-Erasure time-lock chain (v0.12.0, Miracle 1).
//!
//! Design constraints, in order:
//! 1. **No external dependencies.** Every multiply, square, prime test
//!    and modular reduction in the VDF is auditable in this one file.
//! 2. **Constant, proof-friendly control flow.** Limb counts are const
//!    generics; a 512-bit test modulus and a 2048-bit production
//!    modulus share the identical instruction sequence, so Kani/property
//!    harnesses exercised on small widths hold for large ones.
//! 3. **No secret-dependent branches.** RSA moduli here are PUBLIC
//!    (the puzzle is the unknown factorization, not the group), so
//!    timing side channels are not in the threat model; we still keep
//!    the hot loops branch-free where it costs nothing.

// Index-oriented loops are intentional in limb arithmetic.
#![allow(clippy::needless_range_loop)]

use std::fmt;

/// A fixed-width non-negative integer of `L` little-endian `u64` limbs.
///
/// Values are canonical (no limb beyond the true magnitude carries
/// meaning); comparison is limb-wise from the top.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BigUint<const L: usize>(pub [u64; L]);

/// Volatile-scrub on drop semantics for secret-bearing widths
/// (ceremony factors). Regular use (public moduli, states, proofs)
/// never depends on this; it exists so `Zeroizing<BigUint<L>>` is
/// sound for the ceremony path.
impl<const L: usize> zeroize::Zeroize for BigUint<L> {
    fn zeroize(&mut self) {
        // Route through zeroize's own const-generic array impl so the
        // write is volatile-secured the same way as the rest of the
        // workspace's secret hygiene.
        self.0.zeroize();
    }
}

impl<const L: usize> fmt::Debug for BigUint<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BigUint(0x{})", self.to_hex())
    }
}

impl<const L: usize> BigUint<L> {
    pub const ZERO: Self = Self([0; L]);
    pub const ONE: Self = {
        let mut limbs = [0u64; L];
        limbs[0] = 1;
        Self(limbs)
    };

    /// Bit length (0 for zero).
    pub fn bits(&self) -> usize {
        for i in (0..L).rev() {
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u64; L]
    }

    pub fn is_odd(&self) -> bool {
        self.0.first().is_some_and(|l| l & 1 == 1)
    }

    pub fn bit(&self, i: usize) -> bool {
        if i >= L * 64 {
            return false;
        }
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    /// Three-way comparison (unsigned).
    pub fn cmp_to(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..L).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        std::cmp::Ordering::Equal
    }

    /// `self + other`, returning `None` on overflow past `L` limbs.
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        let mut out = [0u64; L];
        let mut carry = 0u64;
        for i in 0..L {
            let (v, c1) = self.0[i].overflowing_add(other.0[i]);
            let (v, c2) = v.overflowing_add(carry);
            out[i] = v;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry != 0 { None } else { Some(Self(out)) }
    }

    /// `self - other`; `None` if `other > self`.
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self.cmp_to(other) == std::cmp::Ordering::Less {
            return None;
        }
        let mut out = [0u64; L];
        let mut borrow = 0u64;
        for i in 0..L {
            let (v, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (v, b2) = v.overflowing_sub(borrow);
            out[i] = v;
            borrow = (b1 as u64) + (b2 as u64);
        }
        Some(Self(out))
    }

    /// `self <<= 1` returning the shifted-out bit.
    pub fn shl1(&mut self) -> u64 {
        let mut carry_out = 0u64;
        for limb in self.0.iter_mut() {
            let new_carry = *limb >> 63;
            *limb = (*limb << 1) | carry_out;
            carry_out = new_carry;
        }
        carry_out
    }

    /// `self >>= 1`.
    pub fn shr1(&mut self) {
        let mut carry_in = 0u64;
        for limb in self.0.iter_mut().rev() {
            let new_carry = *limb & 1;
            *limb = (*limb >> 1) | (carry_in << 63);
            carry_in = new_carry;
        }
    }

    pub fn trailing_zeros(&self) -> usize {
        for (i, limb) in self.0.iter().enumerate() {
            if *limb != 0 {
                return i * 64 + limb.trailing_zeros() as usize;
            }
        }
        L * 64
    }

    /// Canonical big-endian byte encoding (trimmed: no leading zero
    /// bytes; empty output encodes zero). This is the serialization used
    /// in every hash transcript — changing it changes every proof.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut full = vec![0u8; L * 8];
        for i in 0..L {
            full[L * 8 - 8 * (i + 1)..L * 8 - 8 * i].copy_from_slice(&self.0[i].to_be_bytes());
        }
        let first = full.iter().position(|&b| b != 0).unwrap_or(full.len());
        full[first..].to_vec()
    }

    /// Big-endian byte decoding (mod 2^(64·L), high bytes truncated).
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; L];
        if bytes.is_empty() {
            return Self(limbs);
        }
        let n = bytes.len();
        for i in 0..L {
            // limb i occupies bytes [n - 8*(i+1), n - 8*i) of the input
            if 8 * i >= n {
                break; // no bytes reach this or higher limbs
            }
            let hi = n.saturating_sub(8 * (i + 1));
            let lo = n - 8 * i; // safe: 8*i < n
            let mut v = 0u64;
            for &b in &bytes[hi..lo] {
                v = (v << 8) | b as u64;
            }
            limbs[i] = v;
        }
        Self(limbs)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes_be())
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let bytes = hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("hex: {e}"))?;
        if bytes.len() > L * 8 {
            return Err(format!(
                "value exceeds {} limbs ({} bytes given)",
                L,
                bytes.len()
            ));
        }
        Ok(Self::from_bytes_be(&bytes))
    }

    /// Uniform random value in `[1, bound)` (rejection sampling over
    /// OS entropy; bound must be > 1).
    pub fn random_below(bound: &Self) -> Result<Self, String> {
        if bound.cmp_to(&Self::ONE) != std::cmp::Ordering::Greater {
            return Err("bound must be > 1".into());
        }
        let top = bound.bits();
        loop {
            let mut limbs = [0u64; L];
            let whole = top / 64;
            let rem = top % 64;
            let mut buf = [0u8; 8];
            for i in 0..whole.min(L) {
                getrandom::getrandom(&mut buf).map_err(|e| format!("entropy: {e}"))?;
                limbs[i] = u64::from_be_bytes(buf);
            }
            if rem > 0 && whole < L {
                getrandom::getrandom(&mut buf).map_err(|e| format!("entropy: {e}"))?;
                limbs[whole] = u64::from_be_bytes(buf) >> (64 - rem);
            }
            let v = Self(limbs);
            if !v.is_zero() && v.cmp_to(bound) == std::cmp::Ordering::Less {
                return Ok(v);
            }
        }
    }

    /// Binary GCD (Stein). Returns `(g, a_inv_exp?)` — just `g` here;
    /// used to prove `gcd(x, N) == 1` for VDF inputs (a non-trivial
    /// gcd would factor the modulus and break the delay guarantee).
    pub fn binary_gcd(&self, other: &Self) -> Self {
        let mut a = *self;
        let mut b = *other;
        if a.is_zero() {
            return b;
        }
        if b.is_zero() {
            return a;
        }
        let za = a.trailing_zeros();
        let zb = b.trailing_zeros();
        let shift = za.min(zb);
        a.shr_n(za);
        b.shr_n(zb);
        loop {
            match a.cmp_to(&b) {
                std::cmp::Ordering::Equal => break,
                std::cmp::Ordering::Greater => {
                    a = a.checked_sub(&b).unwrap_or(a);
                    a.shr_n(a.trailing_zeros());
                }
                std::cmp::Ordering::Less => {
                    b = b.checked_sub(&a).unwrap_or(b);
                    b.shr_n(b.trailing_zeros());
                }
            }
        }
        a.shl_n(shift);
        a
    }

    /// `self >>= n` (n < 64·L is respected; larger n zeroes).
    pub fn shr_n(&mut self, n: usize) {
        if n >= L * 64 {
            *self = Self::ZERO;
            return;
        }
        for _ in 0..n {
            self.shr1();
        }
    }

    /// `self <<= n` (saturating; shifted-out bits are discarded — only
    /// used inside GCD where magnitudes are bounded).
    pub fn shl_n(&mut self, n: usize) {
        for _ in 0..n.min(L * 64) {
            self.shl1();
        }
    }
}

/// `-n^{-1} mod 2^64` for odd `n` (Newton–Raphson, 6 iterations:
/// precision doubles 1→2→4→…→64 bits).
pub const fn mont_inv64(n: u64) -> u64 {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// Montgomery arithmetic context for the modulus `n` (must be odd and
/// non-zero; RSA moduli always are).
///
/// Internals — CIOS (Coarsely Integrated Operand Scanning) with an
/// `L+2`-word accumulator:
///   * per outer step: one column multiply-accumulate of `a[i]*b`,
///     then one of `m*n`, shifting the accumulator right by one limb;
///   * after `L` steps the accumulator holds `a*b*R^{-1} mod n` plus at
///     most one high carry word; a single conditional subtraction
///     yields the canonical residue.
pub struct Montgomery<const L: usize> {
    pub n: BigUint<L>,
    pub n0inv: u64,
    /// R² mod n — converting to Montgomery form is one mont_mul.
    pub r2: BigUint<L>,
}

impl<const L: usize> Montgomery<L> {
    pub fn new(n: BigUint<L>) -> Result<Self, String> {
        if n.is_zero() || !n.is_odd() {
            return Err("Montgomery modulus must be odd and non-zero".into());
        }
        let n0inv = mont_inv64(n.0[0]);
        // R² mod n = 2^(128L) mod n, computed by 128L modular doublings
        // (add + conditional subtract — no division needed anywhere).
        let mut r2 = BigUint::<L>::ONE;
        for _ in 0..(128 * L) {
            r2 = r2.mod_double(&n);
        }
        Ok(Self { n, n0inv, r2 })
    }

    pub fn to_mont(&self, a: &BigUint<L>) -> BigUint<L> {
        self.mont_mul(a, &self.r2)
    }

    pub fn from_mont(&self, a: &BigUint<L>) -> BigUint<L> {
        let mut one = [0u64; L];
        one[0] = 1;
        self.mont_mul(a, &BigUint(one))
    }

    /// CIOS Montgomery product: returns `a·b·R^{-1} mod n`.
    ///
    /// The accumulator is a fixed `[u64; MAX_L + 2]` (const generics
    /// cannot express `L + 2` on stable Rust); every CIOS loop is
    /// bounded by `L`, so smaller widths simply leave high words zero.
    /// `MAX_L` is a compile-time ceiling — `Montgomery::new` rejects
    /// nothing here because `L ≤ MAX_L` is guaranteed at every
    /// monomorphization the workspace instantiates.
    #[inline]
    pub fn mont_mul(&self, a: &BigUint<L>, b: &BigUint<L>) -> BigUint<L> {
        const MAX_L: usize = 32; // widest workspace modulus: 2048-bit
        debug_assert!(L <= MAX_L);
        let mut t = [0u64; MAX_L + 2];
        let (a, b, n) = (&a.0, &b.0, &self.n.0);
        let ninv = self.n0inv;
        for i in 0..L {
            // ---- t += a[i] * b ------------------------------------
            let mut carry: u128 = 0;
            for j in 0..L {
                let acc = t[j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
                t[j] = acc as u64;
                carry = acc >> 64;
            }
            let acc = t[L] as u128 + carry;
            t[L] = acc as u64;
            t[L + 1] += (acc >> 64) as u64;

            // ---- t = (t + m*n) >> 64 ------------------------------
            let m = t[0].wrapping_mul(ninv);
            // t[0] + m*n[0] ≡ 0 (mod 2^64) by construction of m.
            let acc = t[0] as u128 + (m as u128) * (n[0] as u128);
            debug_assert_eq!(acc as u64, 0, "CIOS low limb must cancel");
            let mut carry: u128 = acc >> 64;
            for j in 1..L {
                let acc = t[j] as u128 + (m as u128) * (n[j] as u128) + carry;
                t[j - 1] = acc as u64;
                carry = acc >> 64;
            }
            let acc = t[L] as u128 + carry;
            t[L - 1] = acc as u64;
            t[L] = t[L + 1] + (acc >> 64) as u64;
            t[L + 1] = 0;
        }

        let mut out = [0u64; L];
        out.copy_from_slice(&t[0..L]);
        let r = BigUint(out);
        // Final reduction. The raw CIOS result is `t[L]·R + r < 2n`.
        //
        // Case t[L] == 1 (only reachable when n > R/2, e.g. 128-bit
        // moduli with the top bit set): the value is R + r, and the
        // residue is R + r − n = r + (R − n). Since r < n < R, that
        // difference lands in [R − n, R) — computable as a wrapping
        // add of r with the two's complement of n, whose carry-out
        // cancels the R term exactly.
        if t[L] != 0 {
            let mut carry = 1u64;
            let mut reduced = [0u64; L];
            for i in 0..L {
                let (tc, c1) = (!self.n.0[i]).overflowing_add(carry);
                let (v, c2) = r.0[i].overflowing_add(tc);
                reduced[i] = v;
                carry = (c1 as u64) + (c2 as u64);
            }
            return BigUint(reduced);
        }
        // Case t[L] == 0: plain conditional subtraction.
        if r.cmp_to(&self.n) == std::cmp::Ordering::Less {
            r
        } else {
            r.checked_sub(&self.n).unwrap_or(r)
        }
    }

    /// Montgomery squaring (same CIOS with b = a — kept as a distinct
    /// entry point so profilers (and future Karatsuba specialization)
    /// can see the VDF's hot loop).
    #[inline]
    pub fn mont_sqr(&self, a: &BigUint<L>) -> BigUint<L> {
        self.mont_mul(a, a)
    }

    /// `x^(2^steps) mod n` — `steps` sequential squarings. This is the
    /// non-parallelizable delay: every squaring consumes the previous
    /// one's output. A `progress` callback fires every 2^20 squarings
    /// (executor UX; return `false` to cancel, the run abandons cleanly).
    pub fn repeat_square(
        &self,
        x_mont: &BigUint<L>,
        steps: u64,
        mut progress: impl FnMut(u64) -> bool,
    ) -> BigUint<L> {
        let mut acc = *x_mont;
        for i in 0..steps {
            if i & 0xFFFFF == 0 && !progress(i) {
                // Cancellation: return the honest partial state; the
                // caller (VdfLock) refuses to certify on cancel anyway.
                break;
            }
            acc = self.mont_sqr(&acc);
        }
        acc
    }

    /// Left-to-right binary modpow over an arbitrary big-endian limb
    /// exponent (used by the verifier: π^ℓ, x^r — short exponents).
    pub fn modpow(&self, base_mont: &BigUint<L>, exp: &BigUint<L>) -> BigUint<L> {
        if exp.is_zero() {
            // x^0 = 1 (Montgomery form of 1)
            return self.to_mont(&BigUint::<L>::ONE);
        }
        let mut acc = self.to_mont(&BigUint::<L>::ONE);
        let bits = exp.bits();
        for i in (0..bits).rev() {
            acc = self.mont_sqr(&acc);
            if exp.bit(i) {
                acc = self.mont_mul(&acc, base_mont);
            }
        }
        acc
    }
}

impl<const L: usize> BigUint<L> {
    /// `2·self mod n` — safe for ANY n < 2^(64·L), including moduli
    /// with the top bit set (where the raw doubling overflows the
    /// limb width). The overflowing case reduces via two's complement:
    /// the true value is `2^(64L) + v`, and `v + (2^(64L) − n)` computed
    /// with wrapping equals `2^(64L) + v − n mod 2^(64L)`, which is the
    /// exact residue because the result is provably < 2^(64L).
    pub fn mod_double(&self, n: &BigUint<L>) -> BigUint<L> {
        let mut v = *self;
        let carry = v.shl1();
        if carry != 0 {
            // value = 2^(64L) + v_low;  subtract n using ¬n + 1.
            let mut add_carry = 1u64;
            for i in 0..L {
                let not_n = !n.0[i];
                let (t, c1) = v.0[i].overflowing_add(not_n);
                let (t, c2) = t.overflowing_add(add_carry);
                v.0[i] = t;
                add_carry = (c1 as u64) + (c2 as u64);
            }
            // The wrapped-out carry cancels the 2^(64L) term — drop it.
            return v;
        }
        if v.cmp_to(n) == std::cmp::Ordering::Less {
            v
        } else {
            v.checked_sub(n).unwrap_or(v)
        }
    }
}

/// Small-prime sieve (primes < 65536) for candidate screening —
/// shared by safe-prime search and hash-to-prime.
pub fn small_primes() -> &'static [u32] {
    use std::sync::OnceLock;
    static PRIMES: OnceLock<Vec<u32>> = OnceLock::new();
    PRIMES.get_or_init(|| {
        let n = 65536usize;
        let mut sieve = vec![true; n];
        sieve[0] = false;
        sieve[1] = false;
        let mut i = 2usize;
        while i * i < n {
            if sieve[i] {
                let mut j = i * i;
                while j < n {
                    sieve[j] = false;
                    j += i;
                }
            }
            i += 1;
        }
        (0..n).filter(|&i| sieve[i]).map(|i| i as u32).collect()
    })
}

/// Trial division screening: returns `false` if definitely composite.
pub fn passes_small_primes<const L: usize>(n: &BigUint<L>) -> bool {
    if n.is_zero() || !n.is_odd() {
        return false;
    }
    // n mod 3 / mod 5 etc. computed limb-horner (no division op).
    for &p in small_primes() {
        if p == 2 {
            continue;
        }
        let mut acc: u128 = 0;
        for limb in n.0.iter().rev() {
            // acc = (acc * 2^64 + limb) mod p  — via u128 with p < 2^32.
            // 2^64 mod p fits u32; precompute per prime is overkill at
            // this scale: use u128 mulmod inline.
            let m = (acc << 64) % (p as u128);
            acc = (m + (*limb as u128)) % (p as u128);
        }
        if acc == 0 && n.bits() > 20 {
            return false;
        }
    }
    true
}

/// Miller–Rabin round with base `a` (1 < a < n-1). `nm1 = n - 1`,
/// `d·2^s = n - 1` precomputed.
fn miller_rabin_round<const L: usize>(
    ctx: &Montgomery<L>,
    a_mont: &BigUint<L>,
    nm1: &BigUint<L>,
    d: &BigUint<L>,
    s: usize,
) -> bool {
    let mut x = ctx.modpow(a_mont, d);
    let one = ctx.to_mont(&BigUint::<L>::ONE);
    if x == one {
        return true; // probable prime signal
    }
    for _ in 0..s {
        if x == *nm1 {
            return true;
        }
        x = ctx.mont_sqr(&x);
    }
    false
}

/// Miller–Rabin with the deterministic base set {2,3,5,7,11,13,17,19,
/// 23,29,31,37} (exact below 3.3·10^24) plus `extra` random rounds.
pub fn is_probable_prime<const L: usize>(n: &BigUint<L>, extra_rounds: u32) -> bool {
    if !passes_small_primes(n) {
        return false;
    }
    // small n handled: n <= 37 prime iff in list and equal
    if n.bits() <= 6 {
        let v = n.0[0];
        return matches!(v, 2 | 3 | 5 | 7 | 11 | 13 | 17 | 19 | 23 | 29 | 31 | 37);
    }
    let Ok(ctx) = Montgomery::<L>::new(*n) else {
        return false;
    };
    let one = BigUint::<L>::ONE;
    let nm1 = match n.checked_sub(&one) {
        Some(v) => v,
        None => return false,
    };
    // s, d such that d odd, d·2^s = n−1
    let s = nm1.trailing_zeros();
    let mut d = nm1;
    d.shr_n(s);

    for &b in &[2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let a = BigUint::<L>::from_bytes_be(&b.to_be_bytes());
        if a.cmp_to(&one) != std::cmp::Ordering::Greater
            || a.cmp_to(&nm1) != std::cmp::Ordering::Less
        {
            continue;
        }
        if !miller_rabin_round(&ctx, &ctx.to_mont(&a), &ctx.to_mont(&nm1), &d, s) {
            return false;
        }
    }
    for _ in 0..extra_rounds {
        let a = match BigUint::<L>::random_below(&nm1) {
            Ok(v)
                if v.cmp_to(&BigUint::<L>::from_bytes_be(&2u64.to_be_bytes()))
                    == std::cmp::Ordering::Greater =>
            {
                v
            }
            _ => continue,
        };
        if !miller_rabin_round(&ctx, &ctx.to_mont(&a), &ctx.to_mont(&nm1), &d, s) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    type B4 = BigUint<4>; // 256-bit test width

    fn b(v: u64) -> B4 {
        let mut limbs = [0u64; 4];
        limbs[0] = v;
        BigUint(limbs)
    }

    #[test]
    fn hex_roundtrip() {
        let x = B4::from_bytes_be(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01]);
        assert_eq!(B4::from_hex(&x.to_hex()).unwrap(), x);
        assert_eq!(x.to_bytes_be(), vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01]);
    }

    #[test]
    fn montgomery_matches_schoolbook() {
        // n = 0xFFFF FFFF FFFF FFFF C7 (a 71-bit odd modulus)
        let n = B4::from_bytes_be(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7]);
        let ctx = Montgomery::new(n).unwrap();
        for (a, bd) in [(7u64, 9u64), (0x10000, 0x20000), (u32::MAX as u64, 9973)] {
            let a = b(a);
            let bd = b(bd);
            let got = ctx.from_mont(&ctx.mont_mul(&ctx.to_mont(&a), &ctx.to_mont(&bd)));
            // schoolbook reference via u128 (fits: 32-bit² products)
            let expect = (a.0[0] as u128 * bd.0[0] as u128) % (n.0[0] as u128);
            assert_eq!(got.0[0] as u128, expect, "a={a:?} b={bd:?}");
        }
    }

    #[test]
    fn modpow_matches_naive() {
        let n = b(1_000_000_007);
        let ctx = Montgomery::new(n).unwrap();
        let base = b(5);
        let exp = b(1_000_003); // prime exponent
        let got = ctx.from_mont(&ctx.modpow(&ctx.to_mont(&base), &exp));
        // naive
        let mut acc = 1u128;
        for _ in 0..exp.0[0] {
            acc = acc * (base.0[0] as u128) % (n.0[0] as u128);
        }
        assert_eq!(got.0[0] as u128, acc);
    }

    #[test]
    fn repeat_square_matches_modpow() {
        let n = b(1_000_000_007);
        let ctx = Montgomery::new(n).unwrap();
        let x = b(3);
        let steps = 200u64;
        let y = ctx.from_mont(&ctx.repeat_square(&ctx.to_mont(&x), steps, |_| true));
        // reference: exact exponent 2^steps (NOT reduced mod n — Fermat
        // does not apply to exponents, only to bases).
        let mut exp = [0u64; 4];
        exp[3] = 1 << (200 - 192); // bit 200 set
        let ref_y = ctx.from_mont(&ctx.modpow(&ctx.to_mont(&x), &BigUint(exp)));
        assert_eq!(y, ref_y);
    }

    #[test]
    fn primality_known_answers() {
        // 2^61 - 1 is prime; 2^67 - 1 is composite (193,707,721 × 761,838,257,287)
        let m61 = B4::from_bytes_be(&0x1FFF_FFFF_FFFF_FFFFu64.to_be_bytes());
        assert!(is_probable_prime::<4>(&m61, 2));
        let m67 = B4::from_bytes_be(&((1u128 << 67) - 1).to_be_bytes());
        assert!(!is_probable_prime::<4>(&m67, 2));
        let carmichael: u128 = 561;
        assert!(!is_probable_prime::<4>(
            &B4::from_bytes_be(&carmichael.to_be_bytes()),
            4
        ));
    }

    /// REGRESSION (v0.12.0): CIOS final reduction when the modulus
    /// exceeds R/2 — the raw result carries into word L and must be
    /// reduced as R + r − n via two's complement, not by dropping the
    /// carry. 2^128 − 159 (L=2, top bit set) is prime: Fermat must hold
    /// through long modpow chains of large residues.
    #[test]
    fn montgomery_modulus_above_half_r() {
        let n = {
            let mut limbs = [0u64; 2];
            limbs[1] = 0xFFFF_FFFF_FFFF_FFFF;
            limbs[0] = 0xFFFF_FFFF_FFFF_FFFF - 158; // 2^128 - 159
            BigUint(limbs)
        };
        assert!(is_probable_prime::<2>(&n, 4), "2^128-159 is prime");
        let ctx = Montgomery::new(n).unwrap();
        // Roundtrips with large residues (close to n).
        for hi in [
            0xFFFF_FFFF_FFFF_FFFEu64,
            0x8000_0000_0000_0001,
            0x1234_5678_9ABC_DEF0,
        ] {
            let a = {
                let mut limbs = [0u64; 2];
                limbs[1] = hi;
                BigUint(limbs)
            };
            let back = ctx.from_mont(&ctx.to_mont(&a));
            assert_eq!(back, a, "roundtrip with large residue {hi:#x}");
        }
        // Fermat through a long chain.
        let a = {
            let mut limbs = [0u64; 2];
            limbs[1] = 0x0123_4567_89AB_CDEF;
            limbs[0] = 0x0011_2233_4455_6677;
            BigUint(limbs)
        };
        let one = BigUint::from_bytes_be(&1u64.to_be_bytes());
        let nm1 = n.checked_sub(&one).unwrap();
        let ferm = ctx.from_mont(&ctx.modpow(&ctx.to_mont(&a), &nm1));
        assert_eq!(ferm, one, "Fermat must hold for prime 2^128-159");
    }

    #[test]
    fn gcd_basics() {
        assert_eq!(
            b(2 * 3 * 5 * 7 * 101)
                .binary_gcd(&b(2 * 3 * 11 * 13 * 101))
                .0[0],
            2 * 3 * 101
        );
        assert_eq!(b(35).binary_gcd(&b(64)).0[0], 1);
    }
}
