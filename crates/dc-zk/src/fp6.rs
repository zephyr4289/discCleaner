//! Fp6 = Fp2[v] / (v³ − ξ) — the middle layer of the 2-6-12 tower.
//!
//! Elements are `(c0, c1, c2)` meaning `c0 + c1·v + c2·v²` with `v³ = ξ = 1+u`.

use crate::fp2::Fp2;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Fp6 {
    pub c0: Fp2,
    pub c1: Fp2,
    pub c2: Fp2,
}

impl Fp6 {
    pub const ZERO: Self = Self {
        c0: Fp2::ZERO,
        c1: Fp2::ZERO,
        c2: Fp2::ZERO,
    };
    pub const ONE: Self = Self {
        c0: Fp2::ONE,
        c1: Fp2::ZERO,
        c2: Fp2::ZERO,
    };

    #[inline]
    pub fn new(c0: Fp2, c1: Fp2, c2: Fp2) -> Self {
        Self { c0, c1, c2 }
    }

    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero()
    }

    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.add(&rhs.c0),
            c1: self.c1.add(&rhs.c1),
            c2: self.c2.add(&rhs.c2),
        }
    }

    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.sub(&rhs.c0),
            c1: self.c1.sub(&rhs.c1),
            c2: self.c2.sub(&rhs.c2),
        }
    }

    #[inline]
    pub fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
        }
    }

    /// Schoolbook cubic multiplication with `v³ = ξ` reduction (matches
    /// the reference prototype exactly).
    pub fn mul(&self, rhs: &Self) -> Self {
        // (a0 + a1 v + a2 v²)(b0 + b1 v + b2 v²):
        //   c0 = a0b0 + ξ(a1b2 + a2b1)
        //   c1 = a0b1 + a1b0 + ξ(a2b2)
        //   c2 = a0b2 + a1b1 + a2b0
        let a0b0 = self.c0.mul(&rhs.c0);
        let a1b2 = self.c1.mul(&rhs.c2);
        let a2b1 = self.c2.mul(&rhs.c1);
        let a0b1 = self.c0.mul(&rhs.c1);
        let a1b0 = self.c1.mul(&rhs.c0);
        let a2b2 = self.c2.mul(&rhs.c2);
        let a0b2 = self.c0.mul(&rhs.c2);
        let a1b1 = self.c1.mul(&rhs.c1);
        let a2b0 = self.c2.mul(&rhs.c0);
        let xi = Fp2::XI;
        Self {
            c0: a0b0.add(&xi.mul(&a1b2.add(&a2b1))),
            c1: a0b1.add(&a1b0).add(&xi.mul(&a2b2)),
            c2: a0b2.add(&a1b1).add(&a2b0),
        }
    }

    #[inline]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Multiply by `v` (rotation with ξ wraparound): `(c0,c1,c2)·v = (ξc2, c0, c1)`.
    #[inline]
    pub fn mul_v(&self) -> Self {
        Self {
            c0: Fp2::XI.mul(&self.c2),
            c1: self.c0,
            c2: self.c1,
        }
    }

    /// Inverse via the adjugate formula (valid for the irreducible cubic).
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        // t0 = a0² − ξ a1 a2;  t1 = ξ a2² − a0 a1;  t2 = a1² − a0 a2
        let t0 = self.c0.square().sub(&Fp2::XI.mul(&self.c1.mul(&self.c2)));
        let t1 = Fp2::XI.mul(&self.c2.square()).sub(&self.c0.mul(&self.c1));
        let t2 = self.c1.square().sub(&self.c0.mul(&self.c2));
        // det = a0·t0 + ξ·(a2·t1 + a1·t2)
        let det = self
            .c0
            .mul(&t0)
            .add(&Fp2::XI.mul(&self.c2.mul(&t1).add(&self.c1.mul(&t2))));
        let di = det.invert()?;
        Some(Self {
            c0: t0.mul(&di),
            c1: t1.mul(&di),
            c2: t2.mul(&di),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fp;

    fn f(v: u64) -> Fp {
        Fp::from_be_bytes_reduced(&v.to_be_bytes())
    }

    #[test]
    fn tower_axioms() {
        let a = Fp6::new(
            Fp2::new(f(11), f(12)),
            Fp2::new(f(13), f(14)),
            Fp2::new(f(15), f(16)),
        );
        let b = Fp6::new(
            Fp2::new(f(17), f(18)),
            Fp2::new(f(19), f(20)),
            Fp2::new(f(21), f(22)),
        );
        let c = Fp6::new(
            Fp2::new(f(23), f(24)),
            Fp2::new(f(25), f(26)),
            Fp2::new(f(27), f(28)),
        );
        assert_eq!(a.mul(&Fp6::ONE), a);
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
        assert_eq!(a.mul(&a.invert().unwrap()), Fp6::ONE);
        // v^3 = xi
        let v = Fp6::new(Fp2::ZERO, Fp2::ONE, Fp2::ZERO);
        assert_eq!(v.mul(&v).mul(&v), Fp6::new(Fp2::XI, Fp2::ZERO, Fp2::ZERO));
        // (a · v) · v · v == a · v^3 == a scaled by xi
        let av3 = a.mul_v().mul_v().mul_v();
        let expected = Fp6::new(a.c0.mul(&Fp2::XI), a.c1.mul(&Fp2::XI), a.c2.mul(&Fp2::XI));
        assert_eq!(av3, expected);
    }
}
