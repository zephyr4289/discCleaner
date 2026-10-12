//! BLS12-381 group arithmetic: G1 over Fp and G2 over Fp2.
//!
//! * Curve: `E: y² = x³ + 4` (G1, over Fp).
//! * Twist: `E': y² = x³ + 4·ξ` (G2, over Fp2, ξ = 1+u).
//!
//! Scalar multiplication runs in Jacobian coordinates (no field inversion
//! until the final affine conversion); the Miller loop in
//! [`crate::pairing`] uses affine coordinates over Fp12 directly (only 64
//! iterations — inversion cost is negligible there and the code mirrors
//! the validated reference prototype line-for-line).
//!
//! Generators are the canonical BLS12-381 points (cross-verified on-curve
//! and of order r against py_ecc before porting).

use crate::field::{Fp, Fr};
use crate::fp2::Fp2;

// ---------------------------------------------------------------------------
// G1 (over Fp): y^2 = x^3 + 4
// ---------------------------------------------------------------------------

/// Affine G1 point (`infinity` flag carries the neutral element).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct G1 {
    pub x: Fp,
    pub y: Fp,
    pub infinity: bool,
}

/// Jacobian G1 point: `(X, Y, Z)` maps to affine `(X/Z², Y/Z³)`;
/// `Z = 0` is the neutral element.
#[derive(Clone, Copy)]
pub struct G1Jac {
    x: Fp,
    y: Fp,
    z: Fp,
}

impl G1 {
    /// Canonical generator (hex limbs cross-verified against py_ecc).
    pub fn generator() -> Self {
        Self {
            x: Fp::from_canonical_limbs([
                0xfb3a_f00a_db22_c6bb,
                0x6c55_e83f_f97a_1aef,
                0xa14e_3a3f_171b_ac58,
                0xc368_8c4f_9774_b905,
                0x2695_638c_4fa9_ac0f,
                0x17f1_d3a7_3197_d794,
            ]),
            y: Fp::from_canonical_limbs([
                0x0caa_2329_46c5_e7e1,
                0xd03c_c744_a288_8ae4,
                0x00db_18cb_2c04_b3ed,
                0xfcf5_e095_d5d0_0af6,
                0xa09e_30ed_741d_8ae4,
                0x08b3_f481_e3aa_a0f1,
            ]),
            infinity: false,
        }
    }

    pub fn identity() -> Self {
        Self {
            x: Fp::ZERO,
            y: Fp::ZERO,
            infinity: true,
        }
    }

    pub fn is_identity(&self) -> bool {
        self.infinity
    }

    /// On-curve check for y² = x³ + 4 (identity trivially on).
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        let b = Fp::from_be_bytes_reduced(&[4]);
        self.y.square() == self.x.square().mul(&self.x).add(&b)
    }

    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
            infinity: self.infinity,
        }
    }

    /// Full subgroup check: on-curve AND `[r]P = O` (sound: for a point on
    /// E, multiplication by the group order r lands in the r-torsion;
    /// combined with on-curve this admits only E(Fp)[r] = G1 ∪ {O}).
    pub fn in_correct_subgroup(&self) -> bool {
        if self.infinity {
            return true;
        }
        if !self.is_on_curve() {
            return false;
        }
        let r_limbs = Fr::MODULUS;
        self.mul_scalar_limbs(&r_limbs).is_identity()
    }

    /// Affine addition (assumes both on curve; `None` inputs not used —
    /// handled by `infinity` flags).
    pub fn add(&self, rhs: &Self) -> Self {
        if self.infinity {
            return *rhs;
        }
        if rhs.infinity {
            return *self;
        }
        if self.x == rhs.x {
            if self.y == rhs.y {
                return self.double();
            }
            return Self::identity();
        }
        let lambda = rhs
            .y
            .sub(&self.y)
            .mul(&rhs.x.sub(&self.x).invert().unwrap());
        let x3 = lambda.square().sub(&self.x).sub(&rhs.x);
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);
        Self {
            x: x3,
            y: y3,
            infinity: false,
        }
    }

    pub fn double(&self) -> Self {
        if self.infinity || self.y.is_zero() {
            return Self::identity();
        }
        let three = Fp::from_be_bytes_reduced(&[3]);
        let lambda = self
            .x
            .square()
            .mul(&three)
            .mul(&self.y.double().invert().unwrap());
        let x3 = lambda.square().sub(&self.x.double());
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);
        Self {
            x: x3,
            y: y3,
            infinity: false,
        }
    }

    /// Scalar multiplication by an Fr element (canonical limbs, L2R
    /// double-and-add in Jacobian coordinates).
    pub fn mul_scalar(&self, k: &Fr) -> Self {
        self.mul_scalar_limbs(&k.canonical_limbs())
    }

    pub fn mul_scalar_limbs(&self, exp: &[u64]) -> Self {
        // 4-bit fixed-window ladder: 16-entry table of affine multiples,
        // then ceil(bits/4) double-quadruples + one mixed add each.
        if self.is_identity() {
            return Self::identity();
        }
        // table[k] = k * P (sequential multiples, NOT doublings), built
        // in Jacobian coordinates and batch-converted to affine with a
        // single field inversion (Montgomery trick over 15 z-values).
        let mut jac: Vec<G1Jac> = Vec::with_capacity(16);
        jac.push(G1Jac::identity());
        let mut cur: G1Jac = G1Jac::identity().add_affine(self);
        for _ in 0..15 {
            jac.push(cur);
            cur = cur.add_affine(self);
        }
        let table = G1Jac::batch_to_affine(&jac);
        let mut acc = G1Jac::identity();
        let mut started = false;
        let nibbles: Vec<u8> = exp
            .iter()
            .rev()
            .flat_map(|limb| (0..16).rev().map(move |k| ((limb >> (k * 4)) & 0xF) as u8))
            .collect();
        for nib in nibbles {
            if started {
                acc = acc.double().double().double().double();
            }
            if nib != 0 {
                acc = acc.add_affine(&table[nib as usize]);
                started = true;
            }
        }
        acc.to_affine()
    }

    /// Uncompressed serialization: 96 bytes (x ‖ y), infinity = all zero
    /// with first byte 0x40 flag in the top bit (documented format).
    pub fn to_uncompressed(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        if self.infinity {
            out[0] = 0x40;
            return out;
        }
        out[..48].copy_from_slice(&self.x.to_be_bytes());
        out[48..].copy_from_slice(&self.y.to_be_bytes());
        out
    }

    pub fn from_uncompressed(bytes: &[u8; 96]) -> Option<Self> {
        if bytes[..48].iter().all(|&b| b == 0) && bytes[48..].iter().all(|&b| b == 0) {
            // all-zero is also accepted as identity (flag optional)
            return Some(Self::identity());
        }
        if bytes[0] & 0x40 != 0 {
            // infinity flag with zero coordinates
            if bytes[..48].iter().all(|&b| b == 0) && bytes[48..].iter().all(|&b| b == 0) {
                return Some(Self::identity());
            }
            return None;
        }
        let mut x = [0u8; 48];
        let mut y = [0u8; 48];
        x.copy_from_slice(&bytes[..48]);
        y.copy_from_slice(&bytes[48..]);
        let x = Fp::from_be_bytes_reduced(&x);
        let y = Fp::from_be_bytes_reduced(&y);
        let p = Self {
            x,
            y,
            infinity: false,
        };
        if !p.is_on_curve() {
            return None;
        }
        Some(p)
    }

    /// Compressed serialization: 48 bytes — x with top-bit flags:
    /// `0x80` = identity, `0x20` = y is odd (parity sign bit).
    pub fn to_compressed(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        if self.infinity {
            out[0] = 0x80;
            return out;
        }
        out.copy_from_slice(&self.x.to_be_bytes());
        if self.y.parity() {
            out[0] |= 0x20;
        }
        out
    }

    pub fn from_compressed(bytes: &[u8; 48]) -> Option<Self> {
        let infinity = bytes[0] & 0x80 != 0;
        let sign = bytes[0] & 0x20 != 0;
        let mut xbuf = *bytes;
        xbuf[0] &= 0x1f;
        if infinity {
            if xbuf.iter().any(|&b| b != 0) {
                return None; // identity must not carry coordinates
            }
            return Some(Self::identity());
        }
        let x = Fp::from_be_bytes_reduced(&xbuf);
        let x3b = x.square().mul(&x).add(&Fp::from_be_bytes_reduced(&[4]));
        let y = x3b.sqrt()?;
        let use_odd = y.parity() != sign;
        let y = if use_odd { y.neg() } else { y };
        Some(Self {
            x,
            y,
            infinity: false,
        })
    }
}

impl G1Jac {
    /// Batch-convert Jacobian points to affine with ONE field inversion
    /// (Montgomery trick over the z-coordinates; identity stays identity).
    pub fn batch_to_affine(pts: &[Self]) -> Vec<G1> {
        let mut zs: Vec<Fp> = pts.iter().map(|p| p.z).collect();
        // batch invert z (prefix products, one Fermat inversion)
        let n = zs.len();
        let mut prefix = vec![Fp::ONE; n + 1];
        for i in 0..n {
            prefix[i + 1] = prefix[i].mul(&zs[i]);
        }
        let inv_all = match prefix[n].invert() {
            Some(v) => v,
            None => return pts.iter().map(|p| p.to_affine()).collect(),
        };
        let mut acc = inv_all;
        for i in (0..n).rev() {
            zs[i] = acc.mul(&prefix[i]);
            acc = acc.mul(&pts[i].z);
        }
        pts.iter()
            .enumerate()
            .map(|(i, p)| {
                if p.z.is_zero() {
                    return G1::identity();
                }
                let zinv = zs[i];
                let zinv2 = zinv.square();
                let zinv3 = zinv2.mul(&zinv);
                G1 {
                    x: p.x.mul(&zinv2),
                    y: p.y.mul(&zinv3),
                    infinity: false,
                }
            })
            .collect()
    }

    pub fn identity() -> Self {
        Self {
            x: Fp::ONE,
            y: Fp::ONE,
            z: Fp::ZERO,
        }
    }

    pub fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    pub fn to_affine(&self) -> G1 {
        if self.z.is_zero() {
            return G1::identity();
        }
        let zinv = self.z.invert().unwrap();
        let zinv2 = zinv.square();
        let zinv3 = zinv2.mul(&zinv);
        G1 {
            x: self.x.mul(&zinv2),
            y: self.y.mul(&zinv3),
            infinity: false,
        }
    }

    /// Jacobian doubling (dbl-2007-bl: 8M).
    pub fn double(&self) -> Self {
        if self.z.is_zero() {
            return Self::identity();
        }
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = self.x.add(&b).square().sub(&a).sub(&c).double();
        let e = a.double().add(&a);
        let f = e.square();
        let x3 = f.sub(&d.double());
        let c8 = c.double().double().double();
        let y3 = e.mul(&d.sub(&x3)).sub(&c8);
        let z3 = self.y.add(&self.z).square().sub(&b).sub(&self.z.square());
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Mixed addition: Jacobian self + affine other (12M).
    pub fn add_affine(&self, other: &G1) -> Self {
        // The affine identity must be handled before the z==0 branch —
        // otherwise identity+identity materializes (0,0,1), an off-curve
        // point (regression pinned by `identity_scalar_edge_cases`).
        if other.infinity {
            return *self;
        }
        if self.z.is_zero() {
            return Self {
                x: other.x,
                y: other.y,
                z: Fp::ONE,
            };
        }
        let z1z1 = self.z.square();
        let u2 = other.x.mul(&z1z1);
        let s2 = other.y.mul(&z1z1).mul(&self.z);
        if self.x == u2 {
            if self.y == s2 {
                return self.double();
            }
            return Self::identity();
        }
        let h = u2.sub(&self.x);
        let hh = h.square();
        let i = hh.double().double();
        let j = h.mul(&i);
        let r = s2.sub(&self.y).double();
        let v = self.x.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&self.y.mul(&j).double());
        let z3 = self.z.add(&h).square().sub(&z1z1).sub(&hh);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

// ---------------------------------------------------------------------------
// G2 (over Fp2): y^2 = x^3 + 4*(1+u)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct G2 {
    pub x: Fp2,
    pub y: Fp2,
    pub infinity: bool,
}

#[derive(Clone, Copy)]
pub struct G2Jac {
    x: Fp2,
    y: Fp2,
    z: Fp2,
}

impl G2 {
    /// Canonical generator (hex limbs cross-verified against py_ecc).
    pub fn generator() -> Self {
        Self {
            x: Fp2 {
                c0: Fp::from_canonical_limbs([
                    0xd480_56c8_c121_bdb8,
                    0x0bac_0326_a805_bbef,
                    0xb451_0b64_7ae3_d177,
                    0xc6e4_7ad4_fa40_3b02,
                    0x2608_0527_2dc5_1051,
                    0x024a_a2b2_f08f_0a91,
                ]),
                c1: Fp::from_canonical_limbs([
                    0xe5ac_7d05_5d04_2b7e,
                    0x334c_f112_1394_5d57,
                    0xb5da_61bb_dc7f_5049,
                    0x596b_d0d0_9920_b61a,
                    0x7dac_d3a0_8827_4f65,
                    0x13e0_2b60_5271_9f60,
                ]),
            },
            y: Fp2 {
                c0: Fp::from_canonical_limbs([
                    0xe193_5486_08b8_2801,
                    0x923a_c9cc_3bac_a289,
                    0x6d42_9a69_5160_d12c,
                    0xadfd_9baa_8cbd_d3a7,
                    0x8cc9_cdc6_da2e_351a,
                    0x0ce5_d527_727d_6e11,
                ]),
                c1: Fp::from_canonical_limbs([
                    0xaaa9_075f_f05f_79be,
                    0x3f37_0d27_5cec_1da1,
                    0x2674_92ab_572e_99ab,
                    0xcb3e_287e_85a7_63af,
                    0x32ac_d2b0_2bc2_8b99,
                    0x0606_c4a0_2ea7_34cc,
                ]),
            },
            infinity: false,
        }
    }

    pub fn identity() -> Self {
        Self {
            x: Fp2::ZERO,
            y: Fp2::ZERO,
            infinity: true,
        }
    }

    pub fn is_identity(&self) -> bool {
        self.infinity
    }

    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        self.y.square() == self.x.square().mul(&self.x).add(&Fp2::b2())
    }

    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
            infinity: self.infinity,
        }
    }

    pub fn in_correct_subgroup(&self) -> bool {
        if self.infinity {
            return true;
        }
        if !self.is_on_curve() {
            return false;
        }
        self.mul_scalar_limbs(&Fr::MODULUS).is_identity()
    }

    pub fn add(&self, rhs: &Self) -> Self {
        if self.infinity {
            return *rhs;
        }
        if rhs.infinity {
            return *self;
        }
        if self.x == rhs.x {
            if self.y == rhs.y {
                return self.double();
            }
            return Self::identity();
        }
        let lambda = rhs
            .y
            .sub(&self.y)
            .mul(&rhs.x.sub(&self.x).invert().unwrap());
        let x3 = lambda.square().sub(&self.x).sub(&rhs.x);
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);
        Self {
            x: x3,
            y: y3,
            infinity: false,
        }
    }

    pub fn double(&self) -> Self {
        if self.infinity || self.y.is_zero() {
            return Self::identity();
        }
        let three = Fp2::new(Fp::from_be_bytes_reduced(&[3]), Fp::ZERO);
        let lambda = self
            .x
            .square()
            .mul(&three)
            .mul(&self.y.double().invert().unwrap());
        let x3 = lambda.square().sub(&self.x.double());
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);
        Self {
            x: x3,
            y: y3,
            infinity: false,
        }
    }

    pub fn mul_scalar(&self, k: &Fr) -> Self {
        self.mul_scalar_limbs(&k.canonical_limbs())
    }

    pub fn mul_scalar_limbs(&self, exp: &[u64]) -> Self {
        if self.is_identity() {
            return Self::identity();
        }
        // table[k] = k * P, Jacobian + batch affine (see G1 note)
        let mut jac: Vec<G2Jac> = Vec::with_capacity(16);
        jac.push(G2Jac::identity());
        let mut cur: G2Jac = G2Jac::identity().add_affine(self);
        for _ in 0..15 {
            jac.push(cur);
            cur = cur.add_affine(self);
        }
        let table = G2Jac::batch_to_affine(&jac);
        let mut acc = G2Jac::identity();
        let mut started = false;
        let nibbles: Vec<u8> = exp
            .iter()
            .rev()
            .flat_map(|limb| (0..16).rev().map(move |k| ((limb >> (k * 4)) & 0xF) as u8))
            .collect();
        for nib in nibbles {
            if started {
                acc = acc.double().double().double().double();
            }
            if nib != 0 {
                acc = acc.add_affine(&table[nib as usize]);
                started = true;
            }
        }
        acc.to_affine()
    }

    /// Uncompressed: 192 bytes (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1).
    pub fn to_uncompressed(&self) -> [u8; 192] {
        let mut out = [0u8; 192];
        if self.infinity {
            out[0] = 0x40;
            return out;
        }
        out[..48].copy_from_slice(&self.x.c0.to_be_bytes());
        out[48..96].copy_from_slice(&self.x.c1.to_be_bytes());
        out[96..144].copy_from_slice(&self.y.c0.to_be_bytes());
        out[144..].copy_from_slice(&self.y.c1.to_be_bytes());
        out
    }

    /// Compressed: 96 bytes — x with flags (`0x80` identity, `0x20` y.c1 odd).
    pub fn to_compressed(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        if self.infinity {
            out[0] = 0x80;
            return out;
        }
        out.copy_from_slice(&self.x.to_be_bytes());
        if self.y.c1.parity() {
            out[0] |= 0x20;
        }
        out
    }

    pub fn from_compressed(bytes: &[u8; 96]) -> Option<Self> {
        let infinity = bytes[0] & 0x80 != 0;
        let sign = bytes[0] & 0x20 != 0;
        let mut xbuf = *bytes;
        xbuf[0] &= 0x1f;
        if infinity {
            if xbuf.iter().any(|&b| b != 0) {
                return None;
            }
            return Some(Self::identity());
        }
        let x = Fp2::from_be_bytes(&xbuf);
        let y2 = x.square().mul(&x).add(&Fp2::b2());
        let y = y2.sqrt()?;
        let use_flip = y.c1.parity() != sign;
        let y = if use_flip { y.neg() } else { y };
        Some(Self {
            x,
            y,
            infinity: false,
        })
    }
}

impl G2Jac {
    /// Batch-convert Jacobian points to affine with ONE field inversion
    /// (see G1Jac::batch_to_affine).
    pub fn batch_to_affine(pts: &[Self]) -> Vec<G2> {
        let mut zs: Vec<Fp2> = pts.iter().map(|p| p.z).collect();
        let n = zs.len();
        let mut prefix = vec![Fp2::ONE; n + 1];
        for i in 0..n {
            prefix[i + 1] = prefix[i].mul(&zs[i]);
        }
        let inv_all = match prefix[n].invert() {
            Some(v) => v,
            None => return pts.iter().map(|p| p.to_affine()).collect(),
        };
        let mut acc = inv_all;
        for i in (0..n).rev() {
            zs[i] = acc.mul(&prefix[i]);
            acc = acc.mul(&pts[i].z);
        }
        pts.iter()
            .enumerate()
            .map(|(i, p)| {
                if p.z.is_zero() {
                    return G2::identity();
                }
                let zinv = zs[i];
                let zinv2 = zinv.square();
                let zinv3 = zinv2.mul(&zinv);
                G2 {
                    x: p.x.mul(&zinv2),
                    y: p.y.mul(&zinv3),
                    infinity: false,
                }
            })
            .collect()
    }

    pub fn identity() -> Self {
        Self {
            x: Fp2::ONE,
            y: Fp2::ONE,
            z: Fp2::ZERO,
        }
    }

    pub fn to_affine(&self) -> G2 {
        if self.z.is_zero() {
            return G2::identity();
        }
        let zinv = self.z.invert().unwrap();
        let zinv2 = zinv.square();
        let zinv3 = zinv2.mul(&zinv);
        G2 {
            x: self.x.mul(&zinv2),
            y: self.y.mul(&zinv3),
            infinity: false,
        }
    }

    pub fn double(&self) -> Self {
        if self.z.is_zero() {
            return Self::identity();
        }
        // dbl-2007-bl over Fp2
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = self.x.add(&b).square().sub(&a).sub(&c).double();
        let e = a.double().add(&a);
        let f = e.square();
        let x3 = f.sub(&d.double());
        let c8 = c.double().double().double();
        let y3 = e.mul(&d.sub(&x3)).sub(&c8);
        let z3 = self.y.add(&self.z).square().sub(&b).sub(&self.z.square());
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn add_affine(&self, other: &G2) -> Self {
        // affine identity first (see G1Jac::add_affine note)
        if other.infinity {
            return *self;
        }
        if self.z.is_zero() {
            return Self {
                x: other.x,
                y: other.y,
                z: Fp2::ONE,
            };
        }
        let z1z1 = self.z.square();
        let u2 = other.x.mul(&z1z1);
        let s2 = other.y.mul(&z1z1).mul(&self.z);
        if self.x == u2 {
            if self.y == s2 {
                return self.double();
            }
            return Self::identity();
        }
        let h = u2.sub(&self.x);
        let hh = h.square();
        let i = hh.double().double();
        let j = h.mul(&i);
        let r = s2.sub(&self.y).double();
        let v = self.x.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&self.y.mul(&j).double());
        let z3 = self.z.add(&h).square().sub(&z1z1).sub(&hh);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_on_curve_in_subgroup() {
        let g1 = G1::generator();
        assert!(g1.is_on_curve());
        assert!(g1.in_correct_subgroup(), "G1 generator must have order r");
        let g2 = G2::generator();
        assert!(g2.is_on_curve());
        assert!(g2.in_correct_subgroup(), "G2 generator must have order r");
    }

    #[test]
    fn g1_group_law() {
        let g = G1::generator();
        let two_g = g.double();
        assert!(two_g.is_on_curve());
        assert_eq!(
            g.add(&two_g),
            g.mul_scalar(&Fr::from_be_bytes_reduced(&[3]))
        );
        assert!(g.add(&g.neg()).is_identity());
        let order = {
            // r in hex (little canonical form, from the verified constants)
            let s = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";
            Fr::from_be_bytes_reduced(&hex::decode(s).unwrap())
        };
        assert!(g.mul_scalar(&order).is_identity(), "[r]G1 must be identity");
        // scalar associativity spot check: [5]G = [2]G + [3]G
        assert_eq!(
            g.mul_scalar(&Fr::from_be_bytes_reduced(&[5])),
            g.double()
                .add(&g.mul_scalar(&Fr::from_be_bytes_reduced(&[3])))
        );
    }

    #[test]
    fn g2_group_law() {
        let g = G2::generator();
        let two_g = g.double();
        assert!(two_g.is_on_curve());
        assert_eq!(
            g.add(&two_g),
            g.mul_scalar(&Fr::from_be_bytes_reduced(&[3]))
        );
        assert!(g.add(&g.neg()).is_identity());
        let order = {
            let s = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";
            Fr::from_be_bytes_reduced(&hex::decode(s).unwrap())
        };
        assert!(g.mul_scalar(&order).is_identity(), "[r]G2 must be identity");
    }

    #[test]
    fn compression_round_trip() {
        let g = G1::generator();
        let c = g.to_compressed();
        let back = G1::from_compressed(&c).unwrap();
        assert_eq!(back, g);
        let neg = g.neg();
        let c = neg.to_compressed();
        let back = G1::from_compressed(&c).unwrap();
        assert_eq!(back, neg);
        let i = G1::identity().to_compressed();
        assert!(G1::from_compressed(&i).unwrap().is_identity());
        // a mid scalar multiple exercises both parities
        let k = Fr::from_be_bytes_reduced(&[0x37; 31]);
        let p = g.mul_scalar(&k);
        assert_eq!(G1::from_compressed(&p.to_compressed()).unwrap(), p);

        let g2 = G2::generator();
        let p2 = g2.mul_scalar(&k);
        let c2 = p2.to_compressed();
        assert_eq!(G2::from_compressed(&c2).unwrap(), p2);
        let n2 = p2.neg();
        assert_eq!(G2::from_compressed(&n2.to_compressed()).unwrap(), n2);
        let i2 = G2::identity().to_compressed();
        assert!(G2::from_compressed(&i2).unwrap().is_identity());
    }

    #[test]
    fn uncompressed_round_trip() {
        let k = Fr::from_be_bytes_reduced(&[0x53; 31]);
        let p = G1::generator().mul_scalar(&k);
        let u = p.to_uncompressed();
        assert_eq!(G1::from_uncompressed(&u).unwrap(), p);
    }

    #[test]
    fn identity_scalar_edge_cases() {
        // [1]O == O and [0]G == O — the identity edge cases that once
        // materialized the off-curve point (0,0).
        let r = G1::identity().mul_scalar(&Fr::ONE);
        assert!(r.is_identity());
        assert!(r.is_on_curve());
        let r2 = G2::identity().mul_scalar(&Fr::from_be_bytes_reduced(&[3]));
        assert!(r2.is_identity());
        assert!(r2.is_on_curve());
        assert!(G1::generator().mul_scalar(&Fr::ZERO).is_identity());
        // identity + identity stays identity
        assert!(G1::identity().add(&G1::identity()).is_identity());
    }

    #[test]
    fn reject_off_curve_uncompressed() {
        let mut u = G1::generator().to_uncompressed();
        u[10] ^= 0x01; // corrupt x
        assert!(G1::from_uncompressed(&u).is_none());
    }
}
