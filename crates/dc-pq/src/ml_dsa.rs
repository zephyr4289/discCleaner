#![allow(clippy::needless_range_loop)] // index-paired loops are definition-first math: out[i] <-> in[j] cross-references are the point

//! ML-DSA-44 (FIPS 204) — post-quantum digital signatures for audit
//! evidence that must survive decades of legal scrutiny (v0.10.0).
//!
//! ML-DSA is the NIST lattice signature standard derived from
//! CRYSTALS-Dilithium. This module implements the **ML-DSA-44** parameter
//! set (NIST security category 2) over the polynomial ring
//! Z_q[x]/(x^256 + 1) with q = 8380417:
//!
//! | parameter | value |
//! |-----------|-------|
//! | (k, l)   | (4, 4) |
//! | eta (secret coefficient bound) | 2 |
//! | tau (challenge weight)   | 39 |
//! | beta = tau * eta         | 78 |
//! | gamma1 (mask width)      | 2^17 |
//! | gamma2 (low-bits bound)  | (q-1)/88 |
//! | d (power2round split)   | 13 |
//! | omega (max hint weight)  | 80 |
//!
//! Wire sizes (matching the NIST parameter tables):
//! * public key: 32 + k*320 = **1312 bytes**
//! * secret key: 32 + 32 + 64 + l*96 + k*96 + k*416 = **2560 bytes**
//! * signature: 32 + l*576 + omega + k = **2420 bytes**
//!
//! # Hash domain layout (FIPS 204 structure)
//!
//! All hashes are SHAKE256; the internal hash `H` produces 64 bytes:
//!
//! * keygen: `(rho, sigma, K) <- SHAKE256(xi, 96)` from the 32-byte seed xi
//!   (FIPS 204 derives `(rho, sigma)` from xi and stores a random K; here
//!   K is derived from the same seed so keygen is deterministic and
//!   reproducible for testing — see `docs/post-quantum.md`).
//! * `tr = H(pk)` (64 bytes), `mu = H(tr || M')` (64 bytes)
//! * `rho' = H(K || mu)` (64 bytes) — deterministic masking (rnd = 0)
//! * `c_tilde = H(mu || Encode(w1))[0..32]`
//! * expansion streams: `SHAKE256(rho || u16le(r) || u16le(s))` for A,
//!   `SHAKE256(sigma || u16le(r) || u16le(s))` for (s1, s2),
//!   `SHAKE256(rho' || u16le(L*kappa + i))` for the i-th mask polynomial.
//! * message framing: `M' = 0x00 || M || 0x0000` (pure ML-DSA, xi = 0).
//!
//! # Implementation stance
//!
//! The NTT is the *definitional* direct evaluation
//! `a_hat[i] = sum_j a[j] * psi^((2i+1)j) mod q` at the 256 odd powers of
//! psi = 1753 (a primitive 512th root of unity mod q, so psi^256 = -1 and
//! pointwise multiplication in this domain equals negacyclic convolution
//! in the coefficient domain — exactly the ring we need). O(N^2) instead
//! of O(N log N): at certificate-signing rates the difference is
//! microseconds, and the code reads like the math.

use crate::keccak::{Shake256, shake256};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Parameters (ML-DSA-44)
// ---------------------------------------------------------------------------

pub const Q: i64 = 8_380_417;
pub const N: usize = 256;
pub const K: usize = 4; // verification rows (t, w, s2, t0 polynomials)
pub const L: usize = 4; // commitment columns (s1, y, z polynomials)
const ETA: i64 = 2;
const TAU: usize = 39;
const BETA: i64 = 78;
const GAMMA1: i64 = 131_072; // 2^17
const GAMMA2: i64 = 95_232; // (Q - 1) / 88
const OMEGA: usize = 80;
/// Primitive 512th root of unity mod q (psi^256 = q - 1).
const PSI: i64 = 1753;

pub const PUBLIC_KEY_LEN: usize = 32 + K * 320; // 1312
pub const SECRET_KEY_LEN: usize = 32 + 32 + 64 + L * 96 + K * 96 + K * 416; // 2560
pub const SIGNATURE_LEN: usize = 32 + L * 576 + OMEGA + K; // 2420

/// Maximum signing attempts before giving up (the rejection sampling loop
/// succeeds with probability ~1/7 per iteration for ML-DSA-44; 1024 attempts
/// is astronomically beyond any need and guards against a broken RNG seed).
const MAX_SIGN_ATTEMPTS: u32 = 1024;

type Poly = [i64; N];

// ---------------------------------------------------------------------------
// Modular arithmetic — all values in [0, q) for ring elements, or small
// centered integers for secrets/masks. i64 everywhere: |a*b| < 2^47.
// ---------------------------------------------------------------------------

#[inline]
fn modq(a: i64) -> i64 {
    let r = a % Q;
    if r < 0 { r + Q } else { r }
}

#[inline]
fn mulmod(a: i64, b: i64) -> i64 {
    modq(a * b)
}

/// Constant-time-ish conditional subtraction of q (keeps sums in range).
#[inline]
fn barrettish(a: i64) -> i64 {
    if a >= Q { a - Q } else { a }
}

/// Center a ring element in [0, q) into its small representative
/// (-q/2, q/2]. Products returned by the inverse NTT (c*s1, c*s2, c*t0)
/// live in [0, q); combining them with centered values (y, t0 bounds)
/// requires centering first — otherwise a true value of -1 arrives as
/// q-1 and every norm check explodes.
#[inline]
fn center(v: i64) -> i64 {
    if v > Q / 2 { v - Q } else { v }
}

/// psi^m for m in [0, 512): the odd exponents (2i+1) are the NTT evaluation
/// points; psi^512 = 1 lets exponents reduce mod 512.
const PSI_POW: [i64; 512] = build_psi_pow();

const fn build_psi_pow() -> [i64; 512] {
    let mut t = [0i64; 512];
    t[0] = 1;
    let mut i = 1;
    while i < 512 {
        t[i] = t[i - 1] * PSI % Q;
        i += 1;
    }
    t
}

/// (256)^{-1} mod q — the inverse-NTT scaling factor, computed at compile
/// time by Fermat's little theorem (q is prime): a^{-1} = a^{q-2} mod q.
const N_INV: i64 = const_powmod(256, (Q - 2) as u32);

const fn const_powmod(mut base: i64, mut exp: u32) -> i64 {
    let mut acc: i64 = 1;
    base %= Q;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % Q;
        }
        base = base * base % Q;
        exp >>= 1;
    }
    acc
}

// ---------------------------------------------------------------------------
// Number-theoretic transform — direct evaluation definition
// ---------------------------------------------------------------------------

/// Forward NTT: `out[i] = sum_j a[j] * psi^((2i+1) * j) mod q`.
///
/// Input/output values in [0, q). Inputs may be centered small values
/// (secrets, challenges) — products are reduced with `rem_euclid` because
/// Rust's `%` truncates toward zero and would leak negative coefficients
/// into the accumulator (caught by the power2round range assert during
/// development; see docs/post-quantum.md).
pub fn ntt(a: &Poly) -> Poly {
    let mut out = [0i64; N];
    for i in 0..N {
        let pw = PSI_POW[2 * i + 1]; // psi^(2i+1)
        let mut cur = 1i64;
        let mut acc = 0i64;
        for j in 0..N {
            acc += (a[j] * cur).rem_euclid(Q);
            cur = cur * pw % Q;
        }
        out[i] = acc % Q;
    }
    out
}

/// Inverse NTT: `out[j] = 256^{-1} * sum_i ah[i] * psi^(-(2i+1) * j) mod q`.
pub fn ntt_inv(ah: &Poly) -> Poly {
    let mut out = [0i64; N];
    for j in 0..N {
        // psi^(-j) = psi^(512 - j mod 512)
        let base = PSI_POW[(512 - j) % 512];
        let step = base * base % Q; // psi^(-2j)
        let mut cur = base; // psi^(-(2i+1)j) at i = 0
        let mut acc = 0i64;
        for i in 0..N {
            acc += (ah[i] * cur).rem_euclid(Q);
            cur = cur * step % Q;
        }
        out[j] = acc % Q * N_INV % Q;
    }
    out
}

/// Pointwise product of two NTT-domain polynomials (the ring product in
/// Z_q[x]/(x^256+1) maps to pointwise multiplication in the evaluation
/// domain — pinned by `tests::ntt_is_negacyclic_ring_homomorphism`).
pub fn pointwise_mul(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i64; N];
    for i in 0..N {
        out[i] = mulmod(a[i], b[i]);
    }
    out
}

/// Negacyclic polynomial product a*b mod (x^256 + 1) in the coefficient
/// domain (O(N^2) schoolbook; used to cross-check the NTT homomorphism).
pub fn negacyclic_mul(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i64; N];
    for i in 0..N {
        for j in 0..N {
            let v = mulmod(a[i], b[j]);
            if i + j < N {
                out[i + j] = barrettish(out[i + j] + v);
            } else {
                // x^(i+j) = -x^(i+j-256) in the negacyclic ring
                out[i + j - N] = modq(out[i + j - N] - v);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Rounding helpers
// ---------------------------------------------------------------------------

/// Power2round for d = 13: split rp in [0, q) into
/// (r1 in [0, 1024), r0 in [-4096, 4095]) with rp = r1 * 2^13 + r0 exactly.
///
/// Uses round-to-nearest for the high part (FIPS 204 §4.1) so the low part
/// is centered — a *centered* t0 is what keeps c*t0 products small.
pub fn power2round(rp: i64) -> (i64, i64) {
    debug_assert!((0..Q).contains(&rp));
    let r1 = (rp + 4096) >> 13;
    let r0 = rp - (r1 << 13);
    (r1, r0)
}

/// Decompose for gamma2 = (q-1)/88: split rp in [0, q) into
/// (r1 in [0, 44), r0 in [-gamma2, gamma2]) with
/// rp = r1 * 2*gamma2 + r0 (mod q).
///
/// Bucket 44 wraps to bucket 0 (q = 44 * 2*gamma2 + 1), which is exactly the
/// wrap the hint correction must reproduce.
pub fn decompose(rp: i64) -> (i64, i64) {
    debug_assert!((0..Q).contains(&rp));
    let mut r1 = (rp + GAMMA2 - 1) / (2 * GAMMA2);
    let r0;
    if r1 == 44 {
        r1 = 0;
        // rp in [q - 1 - gamma2, q): r0 = rp - (q - 1) in [-gamma2, 0]
        r0 = rp - (Q - 1);
    } else {
        r0 = rp - r1 * 2 * GAMMA2;
    }
    (r1, r0)
}

pub fn high_bits(rp: i64) -> i64 {
    decompose(rp).0
}

pub fn low_bits(rp: i64) -> i64 {
    decompose(rp).1
}

/// Apply the 1-bit hint correction to a bucket value.
///
/// Derived by exhaustive brute force over honest signing tuples (see
/// docs/post-quantum.md and `tests::hint_mechanism_property`): when a
/// bucket crossing occurred, the correction direction is encoded by the
/// sign of the VERIFIER's own low part m:
///
/// - m > 0: bucket + 1 (mod 44)
/// - m <= 0: bucket - 1 (mod 44)
///
/// Crossings whose direction is NOT recoverable this way (an extreme-tail
/// event, |c*t0| within ~5% of its theoretical maximum) are detected and
/// rejected at signing time — see the hint rejection branch in
/// `sign_internal`.
#[inline]
fn apply_hint(h: u8, w_v: i64) -> i64 {
    let (b, m) = decompose(w_v);
    if h == 1 {
        if m > 0 {
            (b + 1) % 44
        } else {
            (b + 43) % 44 // b - 1 mod 44
        }
    } else {
        b
    }
}

// ---------------------------------------------------------------------------
// Sampling / expansion
// ---------------------------------------------------------------------------

/// ExpandA: uniform matrix A in the NTT domain from seed rho
/// (`A[r][s] <- SampleNTT(SHAKE256(rho || u16le(r) || u16le(s)))`).
///
/// Rejection sampling keeps the distribution exactly uniform: a 24-bit
/// draw t is accepted for the top 23 bits (t & 0x7FFFFF) when below q.
fn sample_ntt_uniform(xof: &mut Shake256) -> Poly {
    let mut out = [0i64; N];
    let mut idx = 0;
    let mut block = [0u8; 3 * 128];
    while idx < N {
        xof.squeeze(&mut block);
        for c in block.chunks(3) {
            let t = (c[0] as u32) | ((c[1] as u32) << 8) | ((c[2] as u32) << 16);
            let v = (t & 0x7F_FFFF) as i64;
            if v < Q {
                out[idx] = v;
                idx += 1;
                if idx == N {
                    break;
                }
            }
        }
    }
    out
}

pub fn expand_a(rho: &[u8]) -> [[Poly; L]; K] {
    let mut a = [[[0i64; N]; L]; K];
    for r in 0..K {
        for s in 0..L {
            let mut xof = Shake256::new(&[
                rho,
                &(r as u16).to_le_bytes()[..],
                &(s as u16).to_le_bytes()[..],
            ]);
            a[r][s] = sample_ntt_uniform(&mut xof);
        }
    }
    a
}

/// ExpandS: small secrets in [-eta, eta] from sigma
/// (`s1[c] <- SampleEta(SHAKE256(sigma || u16le(0) || u16le(c)))`,
/// `s2[r] <- SampleEta(SHAKE256(sigma || u16le(1) || u16le(r)))`).
///
/// Three bytes yield four 6-bit draws; a draw t is accepted for t <= 2*eta
/// and maps to the centered value eta - t.
fn sample_eta_small(xof: &mut Shake256) -> Poly {
    let mut out = [0i64; N];
    let mut idx = 0;
    let mut block = [0u8; 3 * 96];
    while idx < N {
        xof.squeeze(&mut block);
        for c in block.chunks(3) {
            let word = (c[0] as u32) | ((c[1] as u32) << 8) | ((c[2] as u32) << 16);
            for shift in [0, 6, 12, 18] {
                let t = (word >> shift) & 0x3F;
                if t <= (2 * ETA) as u32 {
                    out[idx] = ETA - t as i64;
                    idx += 1;
                    if idx == N {
                        return out;
                    }
                }
            }
        }
    }
    out
}

pub fn expand_s(sigma: &[u8]) -> ([Poly; L], [Poly; K]) {
    let mut s1 = [[0i64; N]; L];
    for c in 0..L {
        let mut xof = Shake256::new(&[
            sigma,
            &0u16.to_le_bytes()[..],
            &(c as u16).to_le_bytes()[..],
        ]);
        s1[c] = sample_eta_small(&mut xof);
    }
    let mut s2 = [[0i64; N]; K];
    for r in 0..K {
        let mut xof = Shake256::new(&[
            sigma,
            &1u16.to_le_bytes()[..],
            &(r as u16).to_le_bytes()[..],
        ]);
        s2[r] = sample_eta_small(&mut xof);
    }
    (s1, s2)
}

/// ExpandMask: y_i with coefficients uniform in (-gamma1, gamma1]
/// (`SHAKE256(rho' || u16le(L*kappa + i))`, squeeze 576 bytes, unpack
/// 18-bit little-endian draws t and set y = gamma1 - t).
fn expand_mask_poly(rho_prime: &[u8], nonce: u16) -> Poly {
    let mut stream = [0u8; 576];
    let mut xof = Shake256::new(&[rho_prime, &nonce.to_le_bytes()[..]]);
    xof.squeeze(&mut stream);
    let mut out = [0i64; N];
    for j in 0..N {
        let t = unpack_u18(&stream, j);
        out[j] = GAMMA1 - t as i64;
    }
    out
}

/// SampleInBall: the sparse challenge polynomial — tau = 39 coefficients
/// of +-1 at pseudorandom positions, signs from the first 64 bits of the
/// SHAKE256(c_tilde, 256) stream, positions from the following bytes
/// (rejection: position j is accepted for j <= i).
pub fn sample_in_ball(c_tilde: &[u8]) -> Poly {
    debug_assert_eq!(c_tilde.len(), 32);
    let mut stream = [0u8; 256];
    let mut xof = Shake256::new(&[c_tilde]);
    xof.squeeze(&mut stream);

    let mut signs = stream[0] as u64
        | (stream[1] as u64) << 8
        | (stream[2] as u64) << 16
        | (stream[3] as u64) << 24
        | (stream[4] as u64) << 32
        | (stream[5] as u64) << 40
        | (stream[6] as u64) << 48
        | (stream[7] as u64) << 56;

    let mut c = [0i64; N];
    let mut pos = 8usize;
    let mut i = N - TAU;
    while i < N {
        let mut j = stream[pos] as usize;
        pos += 1;
        while j > i {
            j = stream[pos] as usize;
            pos += 1;
        }
        let sign = if signs & 1 == 1 { -1i64 } else { 1i64 };
        c[i] = c[j];
        c[j] = sign;
        signs >>= 1;
        i += 1;
    }
    c
}

// ---------------------------------------------------------------------------
// Bit packing (LSB-first, tight)
// ---------------------------------------------------------------------------

fn pack_bits_le(vals: &[i64], bits: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), vals.len() * bits / 8);
    for (j, &v) in vals.iter().enumerate() {
        let start = j * bits;
        for b in 0..bits {
            if (v >> b) & 1 == 1 {
                out[(start + b) / 8] |= 1u8 << ((start + b) % 8);
            }
        }
    }
}

fn unpack_bits_le(buf: &[u8], bits: usize, count: usize) -> Vec<i64> {
    let mut out = Vec::with_capacity(count);
    for j in 0..count {
        let start = j * bits;
        let mut v = 0i64;
        for b in 0..bits {
            let bit = (buf[(start + b) / 8] >> ((start + b) % 8)) & 1;
            v |= (bit as i64) << b;
        }
        out.push(v);
    }
    out
}

/// Unpack the j-th 18-bit little-endian value from a tightly packed stream.
fn unpack_u18(buf: &[u8], j: usize) -> u32 {
    let start = j * 18;
    let mut v = 0u32;
    for b in 0..18 {
        let bit = (buf[(start + b) / 8] >> ((start + b) % 8)) & 1;
        v |= (bit as u32) << b;
    }
    v
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

fn pack_t1(t1: &[Poly]) -> [u8; K * 320] {
    let mut out = [0u8; K * 320];
    for r in 0..K {
        pack_bits_le(&t1[r], 10, &mut out[r * 320..(r + 1) * 320]);
    }
    out
}

fn unpack_t1(buf: &[u8]) -> [Poly; K] {
    assert_eq!(buf.len(), K * 320, "t1 region");
    let mut t1 = [[0i64; N]; K];
    for r in 0..K {
        for (j, v) in unpack_bits_le(&buf[r * 320..(r + 1) * 320], 10, N)
            .into_iter()
            .enumerate()
        {
            t1[r][j] = v;
        }
    }
    t1
}

fn pack_t0(t0: &[Poly]) -> [u8; K * 416] {
    let mut out = [0u8; K * 416];
    for r in 0..K {
        let masked: Vec<i64> = t0[r].iter().map(|&v| v & 0x1FFF).collect();
        pack_bits_le(&masked, 13, &mut out[r * 416..(r + 1) * 416]);
    }
    out
}

fn unpack_t0(buf: &[u8]) -> [Poly; K] {
    assert_eq!(buf.len(), K * 416, "t0 region");
    let mut t0 = [[0i64; N]; K];
    for r in 0..K {
        for (j, v) in unpack_bits_le(&buf[r * 416..(r + 1) * 416], 13, N)
            .into_iter()
            .enumerate()
        {
            // 13-bit two's-complement sign extension
            t0[r][j] = if v > 4095 { v - 8192 } else { v };
        }
    }
    t0
}

/// Pack `s.len()` small polynomials at 3 bits per coefficient
/// (96 bytes per polynomial).
fn pack_eta(s: &[Poly]) -> Vec<u8> {
    let mut out = vec![0u8; 96 * s.len()];
    for (r, poly) in s.iter().enumerate() {
        let shifted: Vec<i64> = poly.iter().map(|&v| v + 2).collect();
        pack_bits_le(&shifted, 3, &mut out[r * 96..(r + 1) * 96]);
    }
    out
}

fn unpack_eta(buf: &[u8], count: usize) -> Vec<Poly> {
    let mut out = vec![[0i64; N]; count];
    for r in 0..count {
        for (j, v) in unpack_bits_le(&buf[r * 96..(r + 1) * 96], 3, N)
            .into_iter()
            .enumerate()
        {
            out[r][j] = v - 2;
        }
    }
    out
}

fn pack_z(z: &[Poly]) -> [u8; L * 576] {
    let mut out = [0u8; L * 576];
    for (c, poly) in z.iter().enumerate() {
        let shifted: Vec<i64> = poly.iter().map(|&v| v + GAMMA1).collect();
        pack_bits_le(&shifted, 18, &mut out[c * 576..(c + 1) * 576]);
    }
    out
}

fn unpack_z(buf: &[u8]) -> [Poly; L] {
    assert_eq!(buf.len(), L * 576, "z region");
    let mut z = [[0i64; N]; L];
    for c in 0..L {
        for (j, v) in unpack_bits_le(&buf[c * 576..(c + 1) * 576], 18, N)
            .into_iter()
            .enumerate()
        {
            z[c][j] = v - GAMMA1;
        }
    }
    z
}

fn pack_w1(w1: &[Poly]) -> [u8; K * 192] {
    let mut out = [0u8; K * 192];
    for r in 0..K {
        pack_bits_le(&w1[r], 6, &mut out[r * 192..(r + 1) * 192]);
    }
    out
}

/// Pack the hint into omega + k bytes: the first omega bytes carry the set
/// positions (flattened across the k polynomials in order), the last k
/// bytes carry the *cumulative* position count after each polynomial.
fn pack_hint(h: &[[u8; N]; K]) -> [u8; OMEGA + K] {
    let mut out = [0u8; OMEGA + K];
    let mut pos = 0usize;
    for (r, poly) in h.iter().enumerate() {
        for (j, &bit) in poly.iter().enumerate() {
            if bit == 1 {
                out[pos] = j as u8;
                pos += 1;
            }
        }
        out[OMEGA + r] = pos as u8;
    }
    out
}

fn unpack_hint(buf: &[u8]) -> ([[u8; N]; K], usize) {
    assert_eq!(buf.len(), OMEGA + K, "hint region");
    let mut h = [[0u8; N]; K];
    let mut weight = 0usize;
    let mut pos = 0usize;
    for r in 0..K {
        let end = buf[OMEGA + r] as usize;
        for idx in pos..end {
            h[r][buf[idx] as usize] = 1;
            weight += 1;
        }
        pos = end;
    }
    (h, weight)
}

// ---------------------------------------------------------------------------
// Key types (zeroized secrets, matching the v0.9.0 key-hygiene discipline)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MlDsa44PublicKey {
    bytes: [u8; PUBLIC_KEY_LEN],
}

impl MlDsa44PublicKey {
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return None;
        }
        let mut b = [0u8; PUBLIC_KEY_LEN];
        b.copy_from_slice(bytes);
        Some(MlDsa44PublicKey { bytes: b })
    }

    pub fn verify(&self, message: &[u8], signature: &MlDsa44Signature) -> bool {
        verify_internal(&self.bytes, message, &signature.bytes)
    }
}

/// ML-DSA-44 secret key — 2560 bytes of lattice secret material. Wiped with
/// volatile stores on drop (`ZeroizeOnDrop` discipline, v0.9.0 Phase 1a).
pub struct MlDsa44SecretKey {
    bytes: [u8; SECRET_KEY_LEN],
}

impl Zeroize for MlDsa44SecretKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for MlDsa44SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl MlDsa44SecretKey {
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.bytes
    }

    pub fn sign(&self, message: &[u8]) -> MlDsa44Signature {
        sign_internal(&self.bytes, message)
    }
}

#[derive(Clone)]
pub struct MlDsa44Signature {
    bytes: [u8; SIGNATURE_LEN],
}

impl MlDsa44Signature {
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIGNATURE_LEN {
            return None;
        }
        let mut b = [0u8; SIGNATURE_LEN];
        b.copy_from_slice(bytes);
        Some(MlDsa44Signature { bytes: b })
    }
}

pub struct MlDsa44KeyPair {
    pub public: MlDsa44PublicKey,
    secret: MlDsa44SecretKey,
}

impl MlDsa44KeyPair {
    /// Random keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self, dc_core::DcError> {
        let mut xi = [0u8; 32];
        getrandom::getrandom(&mut xi).map_err(|e| dc_core::DcError::Rng(e.to_string()))?;
        Ok(Self::from_seed(&xi))
    }

    /// Deterministic keypair from a 32-byte seed (reproducible for tests
    /// and for sealed-key derivation pipelines).
    pub fn from_seed(xi: &[u8; 32]) -> Self {
        let (pk, sk) = keygen_internal(xi);
        MlDsa44KeyPair {
            public: MlDsa44PublicKey { bytes: pk },
            secret: MlDsa44SecretKey { bytes: sk },
        }
    }

    pub fn sign(&self, message: &[u8]) -> MlDsa44Signature {
        self.secret.sign(message)
    }

    /// Raw public key bytes (1312).
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public.bytes
    }

    /// Raw secret key bytes (2560). Callers persisting this MUST apply the
    /// 0600 key-file discipline (see dc-cert::pq::MlDsaOperatorKey).
    pub fn secret_key_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.secret.bytes
    }

    /// Rebuild a keypair from a raw secret key. The public key is
    /// *recomputed* (t1 = HighPart(A*s1 + s2) — every input lives in the
    /// secret key) and cross-checked against the stored transcript seed
    /// `tr`; a mismatch (corrupt or tampered keyfile) is rejected.
    pub fn from_secret_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SECRET_KEY_LEN {
            return None;
        }
        let mut sk = [0u8; SECRET_KEY_LEN];
        sk.copy_from_slice(bytes);

        let rho: &[u8] = &sk[0..32];
        let s1 = unpack_eta(&sk[128..128 + L * 96], L);
        let s2 = unpack_eta(&sk[128 + L * 96..128 + L * 96 + K * 96], K);

        let a_hat = expand_a(rho);
        let s1_hat: Vec<Poly> = s1.iter().map(ntt).collect();
        let s2_hat: Vec<Poly> = s2.iter().map(ntt).collect();

        let mut t1 = [[0i64; N]; K];
        for r in 0..K {
            let mut t_hat = [0i64; N];
            for c in 0..L {
                for i in 0..N {
                    t_hat[i] = barrettish(t_hat[i] + mulmod(a_hat[r][c][i], s1_hat[c][i]));
                }
            }
            for i in 0..N {
                t_hat[i] = barrettish(t_hat[i] + s2_hat[r][i]);
            }
            let t = ntt_inv(&t_hat);
            for j in 0..N {
                t1[r][j] = power2round(t[j]).0;
            }
        }

        let mut pk = [0u8; PUBLIC_KEY_LEN];
        pk[0..32].copy_from_slice(rho);
        pk[32..].copy_from_slice(&pack_t1(&t1));

        // Integrity cross-check: the stored tr must equal H(pk).
        let mut tr = [0u8; 64];
        shake256(&pk, &mut tr);
        if tr[..] != sk[64..128] {
            return None;
        }

        Some(MlDsa44KeyPair {
            public: MlDsa44PublicKey { bytes: pk },
            secret: MlDsa44SecretKey { bytes: sk },
        })
    }
}

// ---------------------------------------------------------------------------
// Keygen
// ---------------------------------------------------------------------------

fn keygen_internal(xi: &[u8; 32]) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    // (rho, sigma, K) <- SHAKE256(xi, 96) — see module docs.
    let mut seed_exp = [0u8; 96];
    shake256(xi, &mut seed_exp);
    let rho = &seed_exp[0..32];
    let sigma = &seed_exp[32..64];
    let k_seed = &seed_exp[64..96];

    let a_hat = expand_a(rho);
    let (s1, s2) = expand_s(sigma);

    // t = A * s1 + s2  (computed in the NTT domain)
    let s1_hat: Vec<Poly> = s1.iter().map(ntt).collect();
    let s2_hat: Vec<Poly> = s2.iter().map(ntt).collect();

    let mut t = [[0i64; N]; K];
    for r in 0..K {
        let mut t_hat = [0i64; N];
        for c in 0..L {
            for i in 0..N {
                t_hat[i] = barrettish(t_hat[i] + mulmod(a_hat[r][c][i], s1_hat[c][i]));
            }
        }
        for i in 0..N {
            t_hat[i] = barrettish(t_hat[i] + s2_hat[r][i]);
        }
        t[r] = ntt_inv(&t_hat);
    }

    let mut t1 = [[0i64; N]; K];
    let mut t0 = [[0i64; N]; K];
    for r in 0..K {
        for j in 0..N {
            let (hi, lo) = power2round(t[r][j]);
            t1[r][j] = hi;
            t0[r][j] = lo;
        }
    }

    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[0..32].copy_from_slice(rho);
    pk[32..].copy_from_slice(&pack_t1(&t1));

    // tr = H(pk)
    let mut tr = [0u8; 64];
    shake256(&pk, &mut tr);

    let mut sk = [0u8; SECRET_KEY_LEN];
    sk[0..32].copy_from_slice(rho);
    sk[32..64].copy_from_slice(k_seed);
    sk[64..128].copy_from_slice(&tr);
    let s1_packed = pack_eta(&s1);
    sk[128..128 + L * 96].copy_from_slice(&s1_packed);
    let s2_packed = pack_eta(&s2);
    sk[128 + L * 96..128 + L * 96 + K * 96].copy_from_slice(&s2_packed);
    let t0_packed = pack_t0(&t0);
    sk[128 + L * 96 + K * 96..].copy_from_slice(&t0_packed);

    (pk, sk)
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

fn sign_internal(sk: &[u8; SECRET_KEY_LEN], message: &[u8]) -> MlDsa44Signature {
    let rho: &[u8] = &sk[0..32];
    let k_seed: &[u8] = &sk[32..64];
    let tr: &[u8] = &sk[64..128];
    let s1 = unpack_eta(&sk[128..128 + L * 96], L);
    let s2 = unpack_eta(&sk[128 + L * 96..128 + L * 96 + K * 96], K);
    let t0 = unpack_t0(&sk[128 + L * 96 + K * 96..]);

    let a_hat = expand_a(rho);
    let s1_hat: Vec<Poly> = s1.iter().map(ntt).collect();
    let s2_hat: Vec<Poly> = s2.iter().map(ntt).collect();
    let t0_hat: Vec<Poly> = t0.iter().map(ntt).collect();

    // M' = 0x00 || M || 0x0000  (pure ML-DSA, xi = 0)
    let m_prime: Vec<u8> = {
        let mut v = Vec::with_capacity(message.len() + 3);
        v.push(0x00);
        v.extend_from_slice(message);
        v.extend_from_slice(&[0x00, 0x00]);
        v
    };

    // mu = H(tr || M')
    let mut mu = [0u8; 64];
    shake256(&[tr, &m_prime[..]].concat(), &mut mu);

    // rho' = H(K || mu) — deterministic masking
    let mut rho_prime = [0u8; 64];
    shake256(&[k_seed, &mu[..]].concat(), &mut rho_prime);

    let mut kappa: u16 = 0;
    for _ in 0..MAX_SIGN_ATTEMPTS {
        // y = ExpandMask(rho', kappa)
        let y: Vec<Poly> = (0..L)
            .map(|i| expand_mask_poly(&rho_prime, L as u16 * kappa + i as u16))
            .collect();

        // w = A * y
        let y_hat: Vec<Poly> = y.iter().map(ntt).collect();
        let mut w = [[0i64; N]; K];
        for r in 0..K {
            let mut w_hat = [0i64; N];
            for c in 0..L {
                for i in 0..N {
                    w_hat[i] = barrettish(w_hat[i] + mulmod(a_hat[r][c][i], y_hat[c][i]));
                }
            }
            w[r] = ntt_inv(&w_hat);
        }

        // w1 = HighBits(w); c_tilde = H(mu || Encode(w1))[0..32]
        let mut w1 = [[0i64; N]; K];
        for r in 0..K {
            for j in 0..N {
                w1[r][j] = high_bits(w[r][j]);
            }
        }
        let w1_enc = pack_w1(&w1);
        let mut c_tilde_full = [0u8; 64];
        shake256(&[&mu[..], &w1_enc[..]].concat(), &mut c_tilde_full);
        let c_tilde: [u8; 32] = c_tilde_full[0..32].try_into().expect("c_tilde is 32 bytes");

        let c = sample_in_ball(&c_tilde);
        let c_hat = ntt(&c);

        // z = y + c * s1  (the product returns a [0, q) ring element —
        // center it, or a true -1 arrives as q-1 and the norm check explodes)
        let mut z = [[0i64; N]; L];
        let mut z_rejected = false;
        for ci in 0..L {
            let cs1 = ntt_inv(&pointwise_mul(&c_hat, &s1_hat[ci]));
            for j in 0..N {
                z[ci][j] = y[ci][j] + center(cs1[j]);
                if z[ci][j].abs() >= GAMMA1 - BETA {
                    z_rejected = true;
                }
            }
        }
        if z_rejected {
            kappa += L as u16;
            continue;
        }

        // r0 = LowBits(w - c*s2) with the gamma2 - beta bound
        let mut r0_rejected = false;
        let mut cs2 = [[0i64; N]; K];
        for r in 0..K {
            cs2[r] = ntt_inv(&pointwise_mul(&c_hat, &s2_hat[r]));
            for j in 0..N {
                if low_bits(modq(w[r][j] - cs2[r][j])).abs() >= GAMMA2 - BETA {
                    r0_rejected = true;
                }
            }
        }
        if r0_rejected {
            kappa += L as u16;
            continue;
        }

        // Hint construction. The verifier reconstructs
        //   w' = A*z - c*t1*2^d = w + c*t0 - c*s2
        // and must recover bucket(w) — the value the challenge committed
        // to. h = 1 marks a bucket crossing whose direction is encoded by
        // the sign of LowBits(w'); crossings with an unrecoverable
        // direction (extreme-tail c*t0) force a retry.
        let mut hint = [[0u8; N]; K];
        let mut hint_weight = 0usize;
        let mut hint_rejected = false;
        for r in 0..K {
            let ct0 = ntt_inv(&pointwise_mul(&c_hat, &t0_hat[r]));
            for j in 0..N {
                let w_v = modq(w[r][j] + ct0[j] - cs2[r][j]);
                let b_true = high_bits(w[r][j]);
                if apply_hint(1, w_v) == b_true {
                    // recoverable crossing (a no-crossing coefficient can
                    // never satisfy this: the +/-1 correction changes the
                    // bucket, and 44 does not divide 1)
                    hint[r][j] = 1;
                    hint_weight += 1;
                } else if high_bits(w_v) != b_true {
                    // crossing in the unrecoverable direction — retry
                    hint_rejected = true;
                }
            }
        }
        if hint_rejected || hint_weight > OMEGA {
            kappa += L as u16;
            continue;
        }

        // Pack the signature: c_tilde || Encode(z) || Encode(h)
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[0..32].copy_from_slice(&c_tilde);
        sig[32..32 + L * 576].copy_from_slice(&pack_z(&z));
        sig[32 + L * 576..].copy_from_slice(&pack_hint(&hint));
        return MlDsa44Signature { bytes: sig };
    }

    unreachable!(
        "ML-DSA-44 rejection loop exceeded {MAX_SIGN_ATTEMPTS} attempts — RNG or constants broken"
    );
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

fn verify_internal(pk: &[u8; PUBLIC_KEY_LEN], message: &[u8], sig: &[u8; SIGNATURE_LEN]) -> bool {
    let rho: &[u8] = &pk[0..32];
    let t1 = unpack_t1(&pk[32..]);

    let c_tilde: [u8; 32] = sig[0..32].try_into().expect("c_tilde is 32 bytes");
    let z = unpack_z(&sig[32..32 + L * 576]);
    let (hint, hint_weight) = unpack_hint(&sig[32 + L * 576..]);

    // Explicit norm checks (FIPS 204 verify):
    if hint_weight > OMEGA {
        return false;
    }
    for poly in &z {
        for &v in poly.iter() {
            if v.abs() >= GAMMA1 - BETA {
                return false;
            }
        }
    }

    let m_prime: Vec<u8> = {
        let mut v = Vec::with_capacity(message.len() + 3);
        v.push(0x00);
        v.extend_from_slice(message);
        v.extend_from_slice(&[0x00, 0x00]);
        v
    };
    // tr = H(pk) — the transcript seed (signer stored it in the secret key)
    let mut tr = [0u8; 64];
    shake256(pk, &mut tr);
    let mut mu = [0u8; 64];
    shake256(&[&tr[..], &m_prime[..]].concat(), &mut mu);

    let a_hat = expand_a(rho);
    let c = sample_in_ball(&c_tilde);
    let c_hat = ntt(&c);

    let z_hat: Vec<Poly> = z.iter().map(ntt).collect();
    let t1_scaled: Vec<Poly> = t1
        .iter()
        .map(|p| {
            let mut q = [0i64; N];
            for j in 0..N {
                q[j] = p[j] << 13; // t1 * 2^d — max 1023 * 8192 < q, fits exactly
            }
            q
        })
        .collect();
    let t1_scaled_hat: Vec<Poly> = t1_scaled.iter().map(ntt).collect();

    // w' = A*z - c * t1 * 2^d
    let mut w_prime = [[0i64; N]; K];
    for r in 0..K {
        let mut acc = [0i64; N];
        for ci in 0..L {
            for i in 0..N {
                acc[i] = barrettish(acc[i] + mulmod(a_hat[r][ci][i], z_hat[ci][i]));
            }
        }
        let ct1 = pointwise_mul(&c_hat, &t1_scaled_hat[r]);
        for i in 0..N {
            acc[i] = modq(acc[i] - ct1[i]);
        }
        w_prime[r] = ntt_inv(&acc);
    }

    // w1' = ApplyHint(h, w')
    let mut w1_prime = [[0i64; N]; K];
    for r in 0..K {
        for j in 0..N {
            w1_prime[r][j] = apply_hint(hint[r][j], w_prime[r][j]);
        }
    }

    let w1_enc = pack_w1(&w1_prime);
    let mut c_prime_full = [0u8; 64];
    shake256(&[&mu[..], &w1_enc[..]].concat(), &mut c_prime_full);

    c_prime_full[0..32] == c_tilde[..]
}

// ---------------------------------------------------------------------------
// Tests — component properties + full sign/verify matrix
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test PRNG (splitmix64) — tests must not depend on the
    /// OS CSPRNG.
    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn random_poly(state: &mut u64) -> Poly {
        let mut p = [0i64; N];
        for v in p.iter_mut() {
            *v = (splitmix(state) % Q as u64) as i64;
        }
        p
    }

    #[test]
    fn psi_order_properties() {
        // 1753 is a primitive 512th root of unity mod 8380417.
        assert_eq!(PSI_POW[0], 1);
        // psi^256 = -1
        assert_eq!(PSI_POW[256], Q - 1);
        // psi^512 = 1
        assert_eq!(PSI_POW[511] * PSI % Q, 1);
        // 256^{-1} mod q: Fermat inversion satisfies the defining identity.
        assert_eq!(N_INV * 256 % Q, 1);
    }

    #[test]
    fn ntt_roundtrip() {
        let mut rng = 0x1234_5678_9abc_def0u64;
        for _ in 0..3 {
            let a = random_poly(&mut rng);
            let restored = ntt_inv(&ntt(&a));
            assert_eq!(a, restored, "NTT inverse must restore the polynomial");
        }
    }

    /// THE structural property of this transform: pointwise multiplication
    /// in the evaluation domain equals negacyclic convolution in the
    /// coefficient domain. If psi were not a primitive 512th root (or the
    /// evaluation points were not its odd powers), this test fails.
    #[test]
    fn ntt_is_negacyclic_ring_homomorphism() {
        let mut rng = 0xfeed_face_c0de_d00du64;
        for _ in 0..2 {
            let a = random_poly(&mut rng);
            let b = random_poly(&mut rng);
            let schoolbook = negacyclic_mul(&a, &b);
            let via_ntt = ntt_inv(&pointwise_mul(&ntt(&a), &ntt(&b)));
            assert_eq!(schoolbook, via_ntt);
        }
    }

    #[test]
    fn power2round_splits_exactly() {
        let mut rng = 42u64;
        for _ in 0..1000 {
            let rp = (splitmix(&mut rng) % Q as u64) as i64;
            let (hi, lo) = power2round(rp);
            assert!((0..1024).contains(&hi));
            assert!((-4096..=4095).contains(&lo));
            assert_eq!(hi * 8192 + lo, rp);
        }
        // boundary sweeps
        for &rp in &[0i64, 4095, 4096, 8191, 8192, Q - 1] {
            let (hi, lo) = power2round(rp);
            assert_eq!(hi * 8192 + lo, rp);
        }
    }

    #[test]
    fn decompose_ranges_and_boundaries() {
        let mut rng = 7u64;
        for _ in 0..1000 {
            let rp = (splitmix(&mut rng) % Q as u64) as i64;
            let (r1, r0) = decompose(rp);
            assert!((0..44).contains(&r1));
            assert!((-GAMMA2..=GAMMA2).contains(&r0));
            // Non-wrap buckets satisfy the exact integer identity
            // rp = r1 * 2*gamma2 + r0 (the top bucket wraps through q-1:
            // bucket 44 is represented as bucket 0 with r0 = rp - (q-1)).
            if rp < 43 * 2 * GAMMA2 + GAMMA2 + 1 {
                assert_eq!(r1 * 2 * GAMMA2 + r0, rp);
            }
        }
        // bucket boundaries (derived by hand in docs/post-quantum.md)
        assert_eq!(decompose(0), (0, 0));
        assert_eq!(decompose(GAMMA2), (0, GAMMA2));
        assert_eq!(decompose(GAMMA2 + 1), (1, -GAMMA2 + 1));
        // the last non-wrapping point lands exactly on (43, gamma2)
        assert_eq!(decompose(43 * 2 * GAMMA2 + GAMMA2), (43, GAMMA2));
        // one past it wraps to bucket 0 through q-1
        assert_eq!(decompose(43 * 2 * GAMMA2 + GAMMA2 + 1), (0, -GAMMA2 + 1));
        assert_eq!(decompose(Q - 1), (0, 0));
        assert_eq!(decompose(Q - 2), (0, -1));
    }

    #[test]
    fn sample_in_ball_shape() {
        let mut rng = 99u64;
        for _ in 0..10 {
            let mut seed = [0u8; 32];
            for b in seed.iter_mut() {
                *b = splitmix(&mut rng) as u8;
            }
            let c = sample_in_ball(&seed);
            let weight: usize = c.iter().filter(|&&v| v != 0).count();
            assert_eq!(weight, TAU);
            assert!(c.iter().all(|&v| v == 0 || v == 1 || v == -1));
        }
    }

    #[test]
    fn expand_s_bounds() {
        let sigma = [0x42u8; 32];
        let (s1, s2) = expand_s(&sigma);
        for p in s1.iter().chain(s2.iter()) {
            assert!(p.iter().all(|&v| (-ETA..=ETA).contains(&v)));
        }
    }

    #[test]
    fn eta_packing_roundtrip() {
        let mut rng = 5u64;
        let s: Vec<Poly> = (0..L)
            .map(|_| {
                let mut p = [0i64; N];
                for v in p.iter_mut() {
                    *v = (splitmix(&mut rng) % 5) as i64 - 2;
                }
                p
            })
            .collect();
        let packed = pack_eta(&s);
        let unpacked = unpack_eta(&packed, L);
        assert_eq!(s, unpacked);
    }

    #[test]
    fn t0_packing_roundtrip() {
        let mut rng = 6u64;
        let t0: Vec<Poly> = (0..K)
            .map(|_| {
                let mut p = [0i64; N];
                for v in p.iter_mut() {
                    *v = (splitmix(&mut rng) % 8192) as i64 - 4096;
                }
                p
            })
            .collect();
        let packed = pack_t0(&t0);
        let unpacked = unpack_t0(&packed);
        assert_eq!(t0, unpacked);
    }

    #[test]
    fn hint_packing_roundtrip() {
        let mut rng = 11u64;
        let h: [[u8; N]; K] = core::array::from_fn(|_| {
            let mut p = [0u8; N];
            for v in p.iter_mut() {
                *v = u8::from(splitmix(&mut rng).is_multiple_of(37));
            }
            p
        });
        let packed = pack_hint(&h);
        let (unpacked, weight) = unpack_hint(&packed);
        assert_eq!(h, unpacked);
        assert_eq!(
            weight,
            h.iter()
                .map(|p| p.iter().sum::<u8>() as usize)
                .sum::<usize>()
        );
    }

    #[test]
    fn z_packing_roundtrip() {
        let mut rng = 13u64;
        // values within the signing range (-gamma1 + beta, gamma1 - beta)
        let z: Vec<Poly> = (0..L)
            .map(|_| {
                let mut p = [0i64; N];
                for v in p.iter_mut() {
                    let raw = (splitmix(&mut rng) % (2 * GAMMA1 as u64)) as i64;
                    *v = raw - GAMMA1;
                }
                p
            })
            .collect();
        let packed = pack_z(&z);
        let unpacked = unpack_z(&packed);
        assert_eq!(z, unpacked);
    }

    #[test]
    fn keygen_sign_verify_roundtrip() {
        for seed_byte in [1u8, 2, 3] {
            let xi = [seed_byte; 32];
            let kp = MlDsa44KeyPair::from_seed(&xi);
            let msg: &[u8] = b"sanitization certificate canonical bytes";
            let sig = kp.sign(msg);
            assert!(kp.public.verify(msg, &sig), "honest signature must verify");

            // deterministic: same inputs -> same bytes
            let sig2 = kp.sign(msg);
            assert_eq!(sig.as_bytes(), sig2.as_bytes());
        }
    }

    #[test]
    fn signature_tamper_detection() {
        let kp = MlDsa44KeyPair::from_seed(&[7u8; 32]);
        let msg = b"cloud sanitization receipt";
        let sig = kp.sign(msg);

        let mut bad = sig.as_bytes().to_vec();
        bad[40] ^= 0x01;
        let bad_sig = MlDsa44Signature::from_bytes(&bad).unwrap();
        assert!(
            !kp.public.verify(msg, &bad_sig),
            "flipped signature bit must fail"
        );

        let other_msg = b"cloud sanitization receipt ";
        assert!(
            !kp.public.verify(other_msg, &sig),
            "different message must fail"
        );

        let wrong_kp = MlDsa44KeyPair::from_seed(&[8u8; 32]);
        assert!(
            !wrong_kp.public.verify(msg, &sig),
            "signature under wrong public key must fail"
        );
    }

    #[test]
    fn key_sizes_match_fips_204_table() {
        let kp = MlDsa44KeyPair::from_seed(&[9u8; 32]);
        assert_eq!(kp.public.as_bytes().len(), 1312);
        assert_eq!(kp.secret.as_bytes().len(), 2560);
        let sig = kp.sign(b"size check");
        assert_eq!(sig.as_bytes().len(), 2420);
    }
}
