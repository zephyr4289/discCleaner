//! Fp12 = Fp6[w] / (w² − v) — the top of the 2-6-12 tower, target group
//! of the pairing (pre-final-exponentiation).
//!
//! Elements are `(a, b)` meaning `a + b·w` with `w² = v` (the Fp6
//! generator), hence `w⁶ = ξ` — the property the untwist map uses.

use crate::field::Fp;
use crate::fp2::Fp2;
use crate::fp6::Fp6;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Fp12 {
    /// non-w part
    pub a: Fp6,
    /// w part
    pub b: Fp6,
}

impl Fp12 {
    pub const ZERO: Self = Self {
        a: Fp6::ZERO,
        b: Fp6::ZERO,
    };
    pub const ONE: Self = Self {
        a: Fp6::ONE,
        b: Fp6::ZERO,
    };

    pub fn is_zero(&self) -> bool {
        self.a.is_zero() && self.b.is_zero()
    }

    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        Self {
            a: self.a.add(&rhs.a),
            b: self.b.add(&rhs.b),
        }
    }

    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self {
            a: self.a.sub(&rhs.a),
            b: self.b.sub(&rhs.b),
        }
    }

    #[inline]
    pub fn neg(&self) -> Self {
        Self {
            a: self.a.neg(),
            b: self.b.neg(),
        }
    }

    /// `(a + b·w)(c + d·w) = (ac + v·bd) + (ad + bc)·w`.
    pub fn mul(&self, rhs: &Self) -> Self {
        let ac = self.a.mul(&rhs.a);
        let bd = self.b.mul(&rhs.b);
        let ad = self.a.mul(rhs.d_ref());
        let bc = self.b.mul(rhs.c_ref());
        Self {
            a: ac.add(&bd.mul_v()),
            b: ad.add(&bc),
        }
    }

    #[inline]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Inverse: `1/(a + b·w) = (a − b·w)/(a² − v·b²)`.
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        let det = self.a.square().sub(&self.b.square().mul_v());
        let di = det.invert()?;
        Some(Self {
            a: self.a.mul(&di),
            b: self.b.neg().mul(&di),
        })
    }

    /// Exponentiation by a little-endian-limb exponent.
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

    /// Embed an `Fp` element (used to lift G1 points into E(Fp12)).
    pub fn from_fp(x: Fp) -> Self {
        Self {
            a: Fp6::new(Fp2::new(x, Fp::ZERO), Fp2::ZERO, Fp2::ZERO),
            b: Fp6::ZERO,
        }
    }

    /// Embed an `Fp2` element (used by the untwist multiplication path).
    pub fn from_fp2(x: Fp2) -> Self {
        Self {
            a: Fp6::new(x, Fp2::ZERO, Fp2::ZERO),
            b: Fp6::ZERO,
        }
    }
}

// Small helpers so `mul` reads like the reference formula.
impl Fp12 {
    fn d_ref(&self) -> &Fp6 {
        &self.b
    }
    fn c_ref(&self) -> &Fp6 {
        &self.a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(v: u64) -> Fp {
        Fp::from_be_bytes_reduced(&v.to_be_bytes())
    }

    #[test]
    fn tower_axioms() {
        let a = Fp12 {
            a: Fp6::new(
                Fp2::new(f(1), f(2)),
                Fp2::new(f(3), f(4)),
                Fp2::new(f(5), f(6)),
            ),
            b: Fp6::new(
                Fp2::new(f(7), f(8)),
                Fp2::new(f(9), f(10)),
                Fp2::new(f(11), f(12)),
            ),
        };
        let b = Fp12 {
            a: Fp6::new(
                Fp2::new(f(13), f(14)),
                Fp2::new(f(15), f(16)),
                Fp2::new(f(17), f(18)),
            ),
            b: Fp6::new(
                Fp2::new(f(19), f(20)),
                Fp2::new(f(21), f(22)),
                Fp2::new(f(23), f(24)),
            ),
        };
        let c = Fp12 {
            a: Fp6::new(
                Fp2::new(f(25), f(26)),
                Fp2::new(f(27), f(28)),
                Fp2::new(f(29), f(30)),
            ),
            b: Fp6::new(
                Fp2::new(f(31), f(32)),
                Fp2::new(f(33), f(34)),
                Fp2::new(f(35), f(36)),
            ),
        };
        assert_eq!(a.mul(&Fp12::ONE), a);
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
        assert_eq!(a.mul(&a.invert().unwrap()), Fp12::ONE);
        // w^2 = v: build w = 0 + 1*w; w² should equal the embedded v = (0,1,0) in the a part
        let w = Fp12 {
            a: Fp6::ZERO,
            b: Fp6::ONE,
        };
        let v = Fp12 {
            a: Fp6::new(Fp2::ZERO, Fp2::ONE, Fp2::ZERO),
            b: Fp6::ZERO,
        };
        assert_eq!(w.square(), v);
        // w^6 = xi: (w^2)^3 = v^3 = xi
        let w2 = w.square();
        let w4 = w2.square();
        let w6 = w4.mul(&w2);
        assert_eq!(w6, Fp12::from_fp2(Fp2::XI));
        // and w^8 = xi * v (sanity for the chaining)
        let w8 = w4.square();
        assert_eq!(
            w8,
            Fp12 {
                a: Fp6::new(Fp2::ZERO, Fp2::XI, Fp2::ZERO),
                b: Fp6::ZERO,
            }
        );
    }
}
