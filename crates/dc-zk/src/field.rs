//! Montgomery arithmetic for the two BLS12-381 fields.
//!
//! * [`Fp`] — the 381-bit base field (curve coordinates, tower base).
//! * [`Fr`] — the 255-bit scalar field (witness / circuit field for Groth16).
//!
//! Both are little-endian `[u64; N]` limb arrays in Montgomery form
//! (`a.value = a_mont * R mod m`, `R = 2^(64N)`). Multiplication uses the
//! separated schoolbook-then-reduce CIOS variant (Koç et al., "Analyzing
//! and Comparing Montgomery Multiplication Algorithms") with slack limbs
//! so no carry can ever escape; the algorithms were validated against the
//! reference Python prototype (`scripts/zk_prototype.py` in the
//! engineering workbench) before porting.
//!
//! Performance notes: this is a from-scratch, zero-dependency
//! implementation — `u128` intermediates, no assembly, no unsafe. It is
//! NOT constant-time: `dc-zk` proves statements about *already-completed*
//! sanitizations and never processes secret exponents whose timing could
//! leak witness data (the witness is statistically hidden by the `r`,`s`
//! blinding inside Groth16 itself, which is the zero-knowledge property
//! that matters here).

/// Limb-wise comparison `a >= b`.
#[inline]
fn ge<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    for i in (0..N).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a -= b` (assumes `a >= b`).
#[inline]
fn sub_assign<const N: usize>(a: &mut [u64; N], b: &[u64; N]) {
    let mut borrow = 0u128;
    for i in 0..N {
        let s = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow);
        a[i] = s as u64;
        borrow = s >> 127; // 1 if borrowed
    }
}

/// Montgomery multiplication: returns `a * b * R^{-1} mod m`.
///
/// `inv` is `-m^{-1} mod 2^64`. The accumulator carries slack limbs so
/// the per-iteration carry propagation can never run off the end.
#[inline]
fn mont_mul<const N: usize>(a: &[u64; N], b: &[u64; N], m: &[u64; N], inv: u64) -> [u64; N] {
    // t = a * b  (schoolbook, 2N limbs) + 2 slack limbs. Fixed-size
    // buffer (16 limbs covers the largest field, 2*6+2) — computed array
    // lengths over const generics are not stable, runtime indexing is.
    let mut t = [0u64; 16];
    for i in 0..N {
        let mut carry: u128 = 0;
        for j in 0..N {
            let s = t[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            t[i + j] = s as u64;
            carry = s >> 64;
        }
        // t[i+N] is untouched by all previous outer iterations (they stop
        // at i'+N-1), so the slot is still zero: store the carry directly.
        t[i + N] = carry as u64;
    }
    // Montgomery reduction: zero out the low half limb by limb.
    for i in 0..N {
        let k = t[i].wrapping_mul(inv);
        let mut carry: u128 = 0;
        for j in 0..N {
            let s = t[i + j] as u128 + (k as u128) * (m[j] as u128) + carry;
            t[i + j] = s as u64;
            carry = s >> 64;
        }
        let mut pos = i + N;
        while carry != 0 {
            let s = t[pos] as u128 + carry;
            t[pos] = s as u64;
            carry = s >> 64;
            pos += 1;
        }
    }
    debug_assert!(t[2 * N] == 0 && t[2 * N + 1] == 0, "montgomery overflow");
    let mut res = [0u64; N];
    res.copy_from_slice(&t[N..2 * N]);
    // Final conditional subtraction (result < 2m after reduction).
    while ge(&res, m) {
        sub_assign(&mut res, m);
    }
    res
}

macro_rules! define_field {
    (
        $name:ident, $n:literal,
        modulus = $mod:expr, inv = $inv:expr, r2 = $r2:expr, r = $r1:expr,
        label = $label:literal
    ) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u64; $n]);

        impl $name {
            pub const LIMBS: usize = $n;
            pub const MODULUS: [u64; $n] = $mod;
            pub const INV: u64 = $inv;
            pub const R2: [u64; $n] = $r2;
            pub const ZERO: Self = Self([0; $n]);
            /// Montgomery form of 1 (i.e. `R mod m`).
            pub const ONE: Self = Self($r1);

            #[inline]
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|&l| l == 0)
            }

            #[inline]
            pub fn add(&self, rhs: &Self) -> Self {
                let mut out = [0u64; $n];
                let mut carry: u128 = 0;
                for i in 0..$n {
                    let s = self.0[i] as u128 + rhs.0[i] as u128 + carry;
                    out[i] = s as u64;
                    carry = s >> 64;
                }
                let mut res = Self(out);
                if carry != 0 || ge(&res.0, &Self::MODULUS) {
                    sub_assign(&mut res.0, &Self::MODULUS);
                }
                res
            }

            #[inline]
            pub fn double(&self) -> Self {
                self.add(self)
            }

            #[inline]
            pub fn sub(&self, rhs: &Self) -> Self {
                let mut out = [0u64; $n];
                let mut borrow: u128 = 0;
                for i in 0..$n {
                    let s = (self.0[i] as u128)
                        .wrapping_sub(rhs.0[i] as u128)
                        .wrapping_sub(borrow);
                    out[i] = s as u64;
                    borrow = (s >> 127) as u128;
                }
                let mut res = Self(out);
                if borrow != 0 {
                    let mut carry: u128 = 0;
                    for i in 0..$n {
                        let s = res.0[i] as u128 + Self::MODULUS[i] as u128 + carry;
                        res.0[i] = s as u64;
                        carry = s >> 64;
                    }
                }
                res
            }

            #[inline]
            pub fn neg(&self) -> Self {
                if self.is_zero() {
                    Self::ZERO
                } else {
                    let mut out = Self::MODULUS;
                    sub_assign(&mut out, &self.0);
                    Self(out)
                }
            }

            #[inline]
            pub fn mul(&self, rhs: &Self) -> Self {
                Self(mont_mul(&self.0, &rhs.0, &Self::MODULUS, Self::INV))
            }

            #[inline]
            pub fn square(&self) -> Self {
                self.mul(self)
            }

            /// Raise to a power given as little-endian limbs.
            pub fn pow_limbs(&self, exp: &[u64]) -> Self {
                let mut res = Self::ONE;
                let mut started = false;
                for limb in exp.iter().rev() {
                    for bit in (0..64).rev() {
                        if started {
                            res = res.square();
                        }
                        if (limb >> bit) & 1 == 1 {
                            res = res.mul(self);
                            started = true;
                        }
                    }
                }
                res
            }

            /// Modular inverse via Fermat (both moduli are prime).
            pub fn invert(&self) -> Option<Self> {
                if self.is_zero() {
                    return None;
                }
                let mut exp = Self::MODULUS;
                let two = {
                    let mut v = [0u64; $n];
                    v[0] = 2;
                    v
                };
                sub_assign(&mut exp, &two);
                Some(self.pow_limbs(&exp))
            }

            /// Build from CANONICAL little-endian limbs (converts into
            /// Montgomery form — used by the curve generator constants).
            #[inline]
            pub fn from_canonical_limbs(raw: [u64; $n]) -> Self {
                Self(mont_mul(&raw, &Self::R2, &Self::MODULUS, Self::INV))
            }

            /// Raw integer → Montgomery form (value must fit in one limb).
            #[inline]
            fn from_u64_raw(v: u64) -> Self {
                let mut limbs = [0u64; $n];
                limbs[0] = v;
                Self(limbs).mul(&Self(Self::R2))
            }

            /// Interpret big-endian bytes as an integer, reduce mod m.
            ///
            /// Horner base-256 fold: correct for ANY input length (the
            /// Montgomery form of the accumulated value is exactly
            /// `(x mod m) * R`, so the modular reduction is implicit).
            pub fn from_be_bytes_reduced(bytes: &[u8]) -> Self {
                let b256 = Self::from_u64_raw(256);
                let mut acc = Self::ZERO;
                for &b in bytes {
                    acc = acc.mul(&b256).add(&Self::from_u64_raw(u64::from(b)));
                }
                acc
            }

            /// Canonical big-endian byte serialization (fixed size).
            pub fn to_be_bytes(&self) -> [u8; $n * 8] {
                let mut one = [0u64; $n];
                one[0] = 1;
                let canon = mont_mul(&self.0, &one, &Self::MODULUS, Self::INV);
                let mut out = [0u8; $n * 8];
                for i in 0..$n {
                    let limb = canon[$n - 1 - i];
                    out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
                }
                out
            }

            /// Parity of the canonical representative (compression sign bit).
            #[inline]
            pub fn parity(&self) -> bool {
                let mut one = [0u64; $n];
                one[0] = 1;
                let canon = mont_mul(&self.0, &one, &Self::MODULUS, Self::INV);
                canon[0] & 1 == 1
            }

            /// Random field element from OS entropy (reduced mod m).
            pub fn random() -> Self {
                let mut buf = [0u8; $n * 8 + 8];
                getrandom::getrandom(&mut buf).expect("OS entropy unavailable");
                Self::from_be_bytes_reduced(&buf)
            }

            pub fn label() -> &'static str {
                $label
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}(0x", $label)?;
                let b = self.to_be_bytes();
                let started = b.iter().position(|&x| x != 0);
                match started {
                    None => write!(f, "0")?,
                    Some(s) => {
                        write!(f, "{:x}", b[s])?;
                        for byte in &b[s + 1..] {
                            write!(f, "{:02x}", byte)?;
                        }
                    }
                }
                write!(f, ")")
            }
        }
    };
}

define_field!(
    Fp,
    6,
    modulus = [
        0xb9fe_ffff_ffff_aaab,
        0x1eab_fffe_b153_ffff,
        0x6730_d2a0_f6b0_f624,
        0x6477_4b84_f385_12bf,
        0x4b1b_a7b6_434b_acd7,
        0x1a01_11ea_397f_e69a,
    ],
    inv = 0x89f3_fffc_fffc_fffd,
    r2 = [
        0xf4df_1f34_1c34_1746,
        0x0a76_e6a6_09d1_04f1,
        0x8de5_476c_4c95_b6d5,
        0x67eb_88a9_939d_83c0,
        0x9a79_3e85_b519_952d,
        0x1198_8fe5_92ca_e3aa,
    ],
    r = [
        0x7609_0000_0002_fffd,
        0xebf4_000b_c40c_0002,
        0x5f48_9857_53c7_58ba,
        0x77ce_5853_7052_5745,
        0x5c07_1a97_a256_ec6d,
        0x15f6_5ec3_fa80_e493,
    ],
    label = "Fp"
);

define_field!(
    Fr,
    4,
    modulus = [
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ],
    inv = 0xffff_fffe_ffff_ffff,
    r2 = [
        0xc999_e990_f3f2_9c6d,
        0x2b6c_edcb_8792_5c23,
        0x05d3_1496_7254_398f,
        0x0748_d9d9_9f59_ff11,
    ],
    r = [
        0x1_ffff_fffe,
        0x5884_b7fa_0003_4802,
        0x998c_4fef_ecbc_4ff5,
        0x1824_b159_acc5_056f,
    ],
    label = "Fr"
);

impl Fp {
    /// Square root in the base field. `p ≡ 3 (mod 4)`, so
    /// `sqrt(a) = a^((p+1)/4)`; returns `None` for non-residues.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(Self::ZERO);
        }
        const SQRT_EXP: [u64; 6] = [
            0xee7f_bfff_ffff_eaab,
            0x07aa_ffff_ac54_ffff,
            0xd9cc_34a8_3dac_3d89,
            0xd91d_d2e1_3ce1_44af,
            0x92c6_e9ed_90d2_eb35,
            0x0680_447a_8e5f_f9a6,
        ];
        let cand = self.pow_limbs(&SQRT_EXP);
        if cand.square() == *self {
            Some(cand)
        } else {
            None
        }
    }

    /// Legendre symbol via Euler's criterion: `Some(true)` = residue,
    /// `Some(false)` = non-residue, `None` = zero.
    pub fn is_quadratic_residue(&self) -> Option<bool> {
        if self.is_zero() {
            return None;
        }
        const HALF_P1: [u64; 6] = [
            0xdcff_7fff_ffff_d555,
            0x0f55_ffff_58a9_ffff,
            0xb398_6950_7b58_7b12,
            0xb23b_a5c2_79c2_895f,
            0x258d_d3db_21a5_d66b,
            0x0d00_88f5_1cbf_f34d,
        ];
        Some(self.pow_limbs(&HALF_P1) == Self::ONE)
    }
}

impl Fr {
    /// Random non-zero scalar (for Groth16 blinding and setup).
    pub fn random_nonzero() -> Self {
        loop {
            let v = Self::random();
            if !v.is_zero() {
                return v;
            }
        }
    }

    /// Canonical little-endian u64 limbs of the representative.
    pub fn canonical_limbs(&self) -> [u64; 4] {
        let mut one = [0u64; 4];
        one[0] = 1;
        mont_mul(&self.0, &one, &Self::MODULUS, Self::INV)
    }

    /// Map arbitrary bytes (e.g. a BLAKE3 digest) deterministically into
    /// Fr. Horner base-256 fold — a digest-to-field binding map, not a
    /// hash in itself (preimage resistance comes from the caller's hash).
    pub fn from_hash(bytes: &[u8]) -> Self {
        Self::from_be_bytes_reduced(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fp_field_axioms() {
        let a = Fp::from_be_bytes_reduced(&[0x11; 47]);
        let b = Fp::from_be_bytes_reduced(&[0x22; 47]);
        let c = Fp::from_be_bytes_reduced(&[0x33; 47]);
        assert_eq!(a.mul(&Fp::ONE), a, "multiplicative identity");
        assert_eq!(a.add(&Fp::ZERO), a);
        assert_eq!(a.mul(&Fp::ZERO), Fp::ZERO);
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
        assert_eq!(a.sub(&a), Fp::ZERO);
        assert_eq!(a.add(&a.neg()), Fp::ZERO);
        assert_eq!(a.invert().unwrap().mul(&a), Fp::ONE);
    }

    #[test]
    fn fr_field_axioms() {
        let a = Fr::from_be_bytes_reduced(&[0x77; 31]);
        let b = Fr::from_be_bytes_reduced(&[0x88; 31]);
        assert_eq!(a.mul(&Fr::ONE), a);
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(a.invert().unwrap().mul(&a), Fr::ONE);
        let x = Fr::from_be_bytes_reduced(&[0x91; 31]);
        let y = Fr::from_be_bytes_reduced(&[0x12; 31]);
        assert_eq!(x.mul(&y.add(&x)), x.mul(&y).add(&x.square()));
    }

    #[test]
    fn fp_sqrt_round_trip() {
        // 4 = 2^2
        let two = Fp::from_be_bytes_reduced(&[2]);
        let four = two.square();
        assert_eq!(four.sqrt().unwrap().square(), four);
        // fixed non-residue (validated against the reference prototype):
        // -1 is a non-residue since p = 3 (mod 4)
        let m1 = Fp::ONE.neg();
        assert!(m1.sqrt().is_none(), "-1 must be a non-residue (p=3 mod 4)");
        let g = Fp::from_be_bytes_reduced(&[0x05; 47]);
        if g.is_quadratic_residue() == Some(true) {
            assert_eq!(g.sqrt().unwrap().square(), g);
        }
    }

    #[test]
    fn boundary_values() {
        // (m-1)^2 == 1 (mod m): m-1 in Montgomery form.
        let mm = {
            let mut raw = Fp::MODULUS;
            sub_assign(&mut raw, &[1, 0, 0, 0, 0, 0]);
            Fp(mont_mul(&raw, &Fp::R2, &Fp::MODULUS, Fp::INV))
        };
        assert_eq!(mm.mul(&mm), Fp::ONE, "(m-1)^2 == 1 (mod m)");
        // (m-1) * m == -... == m-1
        assert_eq!(mm.mul(&Fp::ONE), mm);
        let raw_one = {
            let raw = [1u64, 0, 0, 0, 0, 0];
            Fp(mont_mul(&raw, &Fp::R2, &Fp::MODULUS, Fp::INV))
        };
        assert_eq!(raw_one, Fp::ONE);
    }

    #[test]
    fn to_from_bytes_round_trip() {
        let v = Fr::from_be_bytes_reduced(&[0xab; 31]);
        let b = v.to_be_bytes();
        assert_eq!(Fr::from_be_bytes_reduced(&b), v);
        let v = Fp::from_be_bytes_reduced(&[0xcd; 47]);
        let b = v.to_be_bytes();
        assert_eq!(Fp::from_be_bytes_reduced(&b), v);
        // overlong inputs are folded correctly: value mod m must match
        let short = Fr::from_be_bytes_reduced(&[0x01, 0x02, 0x03]);
        let padded = Fr::from_be_bytes_reduced(&[0x00, 0x00, 0x01, 0x02, 0x03]);
        assert_eq!(short, padded);
    }
}
