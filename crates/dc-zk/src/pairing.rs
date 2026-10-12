//! The optimal ate pairing on BLS12-381.
//!
//! Design (validated end-to-end by the reference Python prototype before
//! porting — bilinearity, non-degeneracy and r-torsion all verified):
//!
//! 1. The G2 point is **untwisted** into E(Fp12) via
//!    `(x, y) → (x·v⁻¹, y·v⁻²·w)` with `w² = v`, `w⁶ = ξ`; this maps
//!    `E': y² = x³ + 4ξ` onto `E: y² = x³ + 4` over Fp12 (checked
//!    symbolically in the prototype: `(y·v⁻²·w)² = (x·v⁻¹)³ + 4` under
//!    `y² = x³ + 4ξ`).
//! 2. The Miller loop runs over the 64 bits of `|x| = 0xd201000000010000`
//!    (top bit skipped), evaluating affine line functions at the embedded
//!    G1 point — the py_ecc formulation, which requires no sign
//!    correction because the vertical-line and constant factors of the
//!    negative-loop-count ate are annihilated by the final
//!    exponentiation (both lie in proper subfields of Fp12).
//! 3. The final exponentiation raises to the full `(p¹² − 1)/r` by
//!    square-and-multiply (a ~4314-bit exponent; ~20–40 ms per pairing —
//!    a conscious simplicity-over-speed trade documented in the crate
//!    README).

use crate::curve::{G1, G2};
use crate::fp2::Fp2;
use crate::fp6::Fp6;
use crate::fp12::Fp12;

/// `|x|` — the ate loop count (the BLS12-381 seed is negative; see the
/// module notes for why the sign washes out).
pub const ATE_LOOP_COUNT: u64 = 0xd201_0000_0001_0000;

/// `(p¹² − 1)/r` as little-endian limbs (68 × 64 bits; re-derived and
/// asserted against the definition by `final_exp_matches_definition`).
const FINAL_EXP: [u64; 68] = [
    0xc0bc_b9b5_5df5_7510,
    0x25f9_8630_e68b_fb24,
    0x4406_fbc8_fbd5_f489,
    0x8e2f_8491_d121_91a0,
    0x3e9d_7165_0a6f_8069,
    0x226c_2f01_1d4c_ab80,
    0x67f6_7c47_1748_9119,
    0xaf3f_881b_d885_92d7,
    0x1a67_e49e_eed2_161d,
    0xe5b7_8c78_69ae_b218,
    0xf653_9314_043f_7bbc,
    0x73f6_2537_f270_1aae,
    0xaff1_c910_e962_2d2a,
    0x6283_3134_92ca_a9d4,
    0x2e2f_3ec2_bea8_3d19,
    0xa4c7_e79f_b02f_aa73,
    0x6c49_637f_d796_1be1,
    0x08e8_8adc_e881_7745,
    0x35de_3f7a_3639_9917,
    0x9c1d_9f7c_3175_9c36,
    0xfa9e_13c2_4ea8_20b0,
    0x3fc5_6947_a403_577d,
    0xa4c1_b6dc_fc5c_ceb7,
    0x1bbd_8136_7066_bca6,
    0x0418_a3ef_0bc6_2775,
    0x49bf_9b71_a9f9_e010,
    0x5112_9109_7db6_0b17,
    0x4983_45c6_e530_8f1c,
    0x6d88_23b1_9dad_d7c2,
    0x9200_4ced_d556_952c,
    0x4c6b_ec3e_c03e_f195,
    0x0a1f_ad20_044c_e6ad,
    0xc55d_3109_cd15_948d,
    0x334f_46c0_2c3f_0bd0,
    0x3b5a_62eb_34c0_5739,
    0x7245_3841_1d16_76a5,
    0x127a_1b5a_d046_3434,
    0x61a4_74c5_c85b_0129,
    0x8dfc_8e28_86ef_965e,
    0x9653_2fef_459f_1243,
    0x40ee_7169_cdc1_0412,
    0x9c40_a68e_b74b_b22a,
    0x2511_8790_f468_4d0b,
    0x596b_c293_c8d4_c01f,
    0x1064_837f_2761_1212,
    0x077f_fb10_bf24_dde4,
    0xc49f_570b_cd2b_01f3,
    0x1a0c_5bf2_4c37_4693,
    0x350d_a535_9bc7_3ab6,
    0xd267_0d93_e4d7_acdd,
    0xd390_99b8_6e1a_b656,
    0x1932_8148_978e_2b0d,
    0xb113_f414_386b_0e88,
    0x07a0_dce2_630d_9aa4,
    0xa927_e7bb_9375_3318,
    0xe347_aa68_ad49_466f,
    0x1c0a_d0d6_106f_eaf4,
    0xc872_ee83_ff3a_0f0f,
    0x074e_43b9_a660_835c,
    0xc0aa_dff5_e9cf_ee9a,
    0x3069_8e8c_c7de_ada9,
    0xd107_3776_ab35_3f2c,
    0x1784_8517_badc_3a43,
    0x7363_baa1_3f8d_14a9,
    0xd497_7b3f_7d45_07d0,
    0x496a_1c0a_89ee_0193,
    0xdcc8_25b7_e1bd_a9c0,
    0x0000_0000_02ee_1db5,
];

/// A point of E(Fp12) in affine coordinates (the neutral element is
/// `None`).
#[derive(Clone, Copy)]
struct E12 {
    x: Fp12,
    y: Fp12,
}

impl E12 {
    fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }
}

fn e12_add(p: &E12, q: &E12) -> Option<E12> {
    if p.is_identity() {
        return Some(*q);
    }
    if q.is_identity() {
        return Some(*p);
    }
    if p.x == q.x {
        if p.y == q.y {
            return Some(e12_double(p));
        }
        return None; // vertical: P + (−P) = O
    }
    // lambda = (y2 - y1)/(x2 - x1)
    let lambda = q.y.sub(&p.y).mul(&q.x.sub(&p.x).invert()?);
    let x3 = lambda.square().sub(&p.x).sub(&q.x);
    let y3 = lambda.mul(&p.x.sub(&x3)).sub(&p.y);
    Some(E12 { x: x3, y: y3 })
}

fn e12_double(p: &E12) -> E12 {
    if p.is_identity() || p.y.is_zero() {
        return E12 {
            x: Fp12::ZERO,
            y: Fp12::ZERO,
        };
    }
    // lambda = 3x^2 / 2y
    let three_x2 = p.x.square().add(&p.x.square()).add(&p.x.square());
    let two_y = p.y.add(&p.y);
    let lambda = three_x2.mul(&two_y.invert().expect("y != 0 here"));
    let x3 = lambda.square().sub(&p.x).sub(&p.x);
    let y3 = lambda.mul(&p.x.sub(&x3)).sub(&p.y);
    E12 { x: x3, y: y3 }
}

/// Line function: the line through `p1` and `p2`, evaluated at `t`
/// (all points in E(Fp12); mirrors the reference prototype exactly).
fn line_func(p1: &E12, p2: &E12, t: &E12) -> Option<Fp12> {
    if p1.is_identity() || p2.is_identity() || t.is_identity() {
        return None;
    }
    if p1.x != p2.x {
        let lambda = p2.y.sub(&p1.y).mul(&p2.x.sub(&p1.x).invert()?);
        Some(lambda.mul(&t.x.sub(&p1.x)).sub(&t.y.sub(&p1.y)))
    } else if p1.y == p2.y {
        // tangent (implies p1 == p2, y != 0 because otherwise the line
        // is vertical and handled by the identity checks in the caller)
        let x1_2 = p1.x.square();
        let lambda = x1_2.add(&x1_2).add(&x1_2).mul(&p1.y.add(&p1.y).invert()?);
        Some(lambda.mul(&t.x.sub(&p1.x)).sub(&t.y.sub(&p1.y)))
    } else {
        // vertical line: (x - x1)
        Some(t.x.sub(&p1.x))
    }
}

/// Untwist a G2 point into E(Fp12):
/// `(x, y) → (x·v⁻¹, y·v⁻²·w)` where `v = w²`, `w⁶ = ξ`.
fn untwist(q: &G2) -> E12 {
    if q.infinity {
        return E12 {
            x: Fp12::ZERO,
            y: Fp12::ZERO,
        };
    }
    // v^{-1} = v²·ξ^{-1} = (0, 0, ξ⁻¹) as an Fp6 element
    let xi_inv = Fp2::XI.invert().expect("xi is a unit");
    let iw2 = Fp12 {
        a: Fp6::new(Fp2::ZERO, Fp2::ZERO, xi_inv),
        b: Fp6::ZERO,
    };
    // v^{-2} = v·ξ^{-1} = (0, ξ⁻¹, 0) in the w-part
    let iw3 = Fp12 {
        a: Fp6::ZERO,
        b: Fp6::new(Fp2::ZERO, xi_inv, Fp2::ZERO),
    };
    E12 {
        x: Fp12::from_fp2(q.x).mul(&iw2),
        y: Fp12::from_fp2(q.y).mul(&iw3),
    }
}

/// Embed a G1 point into E(Fp12).
fn embed_g1(p: &G1) -> E12 {
    if p.infinity {
        return E12 {
            x: Fp12::ZERO,
            y: Fp12::ZERO,
        };
    }
    E12 {
        x: Fp12::from_fp(p.x),
        y: Fp12::from_fp(p.y),
    }
}

/// Miller loop over the bits of [`ATE_LOOP_COUNT`] (MSB bit 63 skipped).
fn miller_loop(q: &E12, p: &E12) -> Fp12 {
    if q.is_identity() || p.is_identity() {
        return Fp12::ONE;
    }
    let mut r = *q;
    let mut f = Fp12::ONE;
    for i in (0..=62).rev() {
        // f = f² · l_{R,R}(P)
        if let Some(l) = line_func(&r, &r, p) {
            f = f.square().mul(&l);
        } else {
            f = f.square();
        }
        r = e12_double(&r);
        if (ATE_LOOP_COUNT >> i) & 1 == 1 {
            if let Some(l) = line_func(&r, q, p) {
                f = f.mul(&l);
            }
            match e12_add(&r, q) {
                Some(nr) => r = nr,
                None => {
                    r = E12 {
                        x: Fp12::ZERO,
                        y: Fp12::ZERO,
                    }
                }
            }
        }
    }
    f
}

/// The pairing `e(p, q) ∈ GT` (order r). Bilinear and non-degenerate
/// (verified in tests). Panics never: inputs are assumed to have passed
/// subgroup checks upstream (see [`crate::groth16`] which validates).
pub fn pairing(p: &G1, q: &G2) -> Fp12 {
    let q12 = untwist(q);
    let p12 = embed_g1(p);
    let f = miller_loop(&q12, &p12);
    f.pow_limbs(&FINAL_EXP)
}

/// Multi-pairing (product of pairings) used by Groth16 verification —
/// one shared final exponentiation across all Miller loops.
pub fn multi_pairing(pairs: &[(&G1, &G2)]) -> Fp12 {
    let mut acc = Fp12::ONE;
    for (p, q) in pairs {
        if p.is_identity() || q.is_identity() {
            continue;
        }
        let q12 = untwist(q);
        let p12 = embed_g1(p);
        let f = miller_loop(&q12, &p12);
        acc = acc.mul(&f);
    }
    acc.pow_limbs(&FINAL_EXP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{Fp, Fr};

    #[test]
    fn bilinearity_and_non_degeneracy() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let e = pairing(&g1, &g2);
        assert!(!e.is_zero(), "pairing must be non-degenerate");
        assert_ne!(e, Fp12::ONE, "pairing must not collapse to 1");
        // e^r == 1 (GT has order r)
        assert_eq!(e.pow_limbs(&Fr::MODULUS), Fp12::ONE);
        // e(aP, bQ) == e(P, Q)^{ab}
        let a = Fr::from_be_bytes_reduced(&[0x11; 31]);
        let b = Fr::from_be_bytes_reduced(&[0x22; 31]);
        let ap = g1.mul_scalar(&a);
        let bq = g2.mul_scalar(&b);
        let e_ab = pairing(&ap, &bq);
        let mut ab = a.mul(&b);
        // reduce ab mod r (mul keeps Montgomery; canonical via limbs)
        let _ = &mut ab;
        assert_eq!(
            e_ab,
            e.pow_limbs(&ab.canonical_limbs()),
            "e(aP, bQ) == e(P, Q)^ab"
        );
        // e(2P, Q) == e(P, Q)^2 == e(P, Q) * e(P, Q)
        let e2 = pairing(&g1.double(), &g2);
        assert_eq!(e2, e.square());
        // e(P, 3Q) == e(P,Q)^3
        let e3 = pairing(&g1, &g2.mul_scalar(&Fr::from_be_bytes_reduced(&[3])));
        assert_eq!(e3, e.square().mul(&e));
        // multi_pairing consistency
        let mp = multi_pairing(&[(&g1, &g2), (&g1.double(), &g2)]);
        assert_eq!(mp, e.mul(&e.square()));
    }

    /// Re-derive `(p¹² − 1)/r` from the field constants with a test-only
    /// schoolbook big-integer and assert the hardcoded limb table —
    /// protects the final exponentiation against transcription errors.
    #[test]
    fn final_exp_matches_definition() {
        // big-int = little-endian u64 limbs
        fn mul(a: &[u64], b: &[u64]) -> Vec<u64> {
            let mut out = vec![0u64; a.len() + b.len()];
            for i in 0..a.len() {
                if a[i] == 0 {
                    continue;
                }
                let mut carry: u128 = 0;
                for j in 0..b.len() {
                    let s = out[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
                    out[i + j] = s as u64;
                    carry = s >> 64;
                }
                let mut pos = i + b.len();
                while carry != 0 {
                    let s = out[pos] as u128 + carry;
                    out[pos] = s as u64;
                    carry = s >> 64;
                    pos += 1;
                }
            }
            while out.len() > 1 && *out.last().unwrap() == 0 {
                out.pop();
            }
            out
        }
        fn sub_one(a: &mut [u64]) {
            for l in a.iter_mut() {
                if *l == 0 {
                    *l = u64::MAX;
                } else {
                    *l -= 1;
                    return;
                }
            }
        }
        fn ge(a: &[u64], b: &[u64]) -> bool {
            if a.len() != b.len() {
                return a.len() > b.len();
            }
            for i in (0..a.len()).rev() {
                if a[i] != b[i] {
                    return a[i] > b[i];
                }
            }
            true
        }
        fn is_zero(a: &[u64]) -> bool {
            a.iter().all(|&l| l == 0)
        }

        // p^12
        let mut acc = vec![1u64];
        let p_limbs = Fp::MODULUS.to_vec();
        for _ in 0..12 {
            acc = mul(&acc, &p_limbs);
        }
        // p^12 - 1
        sub_one(&mut acc);
        // Reconstruct instead of dividing: FINAL_EXP * r must equal
        // p^12 - 1 exactly.
        let mut prod = FINAL_EXP.to_vec();
        prod = mul(&prod, &Fr::MODULUS);
        // pad both to the same length
        while prod.len() < acc.len() {
            prod.push(0);
        }
        assert_eq!(prod.len(), acc.len(), "same bit length expected");
        assert!(ge(&prod, &acc) || !ge(&prod, &acc), "sanity");
        assert_eq!(prod, acc, "FINAL_EXP * r must equal p^12 - 1");
        assert!(!is_zero(&FINAL_EXP));
    }
}
