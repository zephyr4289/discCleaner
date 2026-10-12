//! Fp2 = Fp[u] / (u² + 1) — the quadratic extension under the curve's G2
//! coordinates and the base of the 2-6-12 tower.
//!
//! `Fp2` elements are `(c0, c1)` meaning `c0 + c1·u` with `u² = −1`
//! (valid since p ≡ 3 (mod 4) makes −1 a non-residue).

use crate::field::Fp;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub const ZERO: Self = Self {
        c0: Fp::ZERO,
        c1: Fp::ZERO,
    };
    pub const ONE: Self = Self {
        c0: Fp::ONE,
        c1: Fp::ZERO,
    };
    /// ξ = 1 + u — the tower's cubic non-residue (v³ = ξ in Fp6).
    pub const XI: Self = Self {
        c0: Fp::ONE,
        c1: Fp::ONE,
    };
    /// b coefficient of the twisted curve E': y² = x³ + 4·ξ (built at use
    /// sites via [`Fp2::b2`] because 4 cannot be spelled as a Montgomery
    /// const without a runtime multiply).
    pub fn b2() -> Self {
        Self {
            c0: Fp::from_be_bytes_reduced(&[4]),
            c1: Fp::from_be_bytes_reduced(&[4]),
        }
    }

    #[inline]
    pub fn new(c0: Fp, c1: Fp) -> Self {
        Self { c0, c1 }
    }

    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.add(&rhs.c0),
            c1: self.c1.add(&rhs.c1),
        }
    }

    #[inline]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.sub(&rhs.c0),
            c1: self.c1.sub(&rhs.c1),
        }
    }

    #[inline]
    pub fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    /// Karatsuba multiplication: `(a0+a1u)(b0+b1u) = (a0b0 − a1b1) + (a0b1 + a1b0)u`.
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        let v0 = self.c0.mul(&rhs.c0);
        let v1 = self.c1.mul(&rhs.c1);
        let mid = self.c0.add(&self.c1).mul(&rhs.c0.add(&rhs.c1));
        Self {
            c0: v0.sub(&v1),
            c1: mid.sub(&v0).sub(&v1),
        }
    }

    #[inline]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Multiply by an `Fp` scalar (no cross terms).
    #[inline]
    pub fn scale(&self, k: &Fp) -> Self {
        Self {
            c0: self.c0.mul(k),
            c1: self.c1.mul(k),
        }
    }

    /// Complex-method square root in Fp2 (p ≡ 3 mod 4):
    ///
    /// For `a = α + βu`, a square root `x = ξ + ηu` satisfies
    /// `ξ² − η² = α`, `2ξη = β`. Hence `ξ² = (α ± √(α²+β²))/2` where
    /// `α²+β² = N(a) ∈ Fp`. Exactly one of the two candidates is a
    /// residue when `a` is a square. Returns `None` for non-residues.
    pub fn sqrt(&self) -> Option<Self> {
        if self.c1.is_zero() {
            // pure real: sqrt(α) or u·sqrt(−α)
            return match self.c0.sqrt() {
                Some(r) => Some(Self::new(r, Fp::ZERO)),
                None => {
                    // −α must then be a residue (a is a square iff one of
                    // α, −α is, since −1 is a non-residue in Fp)
                    let neg = self.c0.neg();
                    neg.sqrt().map(|r| Self::new(Fp::ZERO, r))
                }
            };
        }
        if self.c0.is_zero() {
            // pure imaginary: x² = βu → ξ = ±sqrt(β/2), η = ±sqrt(β/2)
            // 2ξ² = β with ξ = η.
            let beta = &self.c1;
            let two = Fp::from_be_bytes_reduced(&[2]);
            let half_beta = beta.mul(&two.invert().unwrap());
            let r = half_beta.sqrt()?;
            // verify both components: (r + ru)² = 2r²·u = β·u ✓
            let cand = Self::new(r, r);
            if cand.square() == *self {
                return Some(cand);
            }
            let cand = Self::new(r, r.neg());
            if cand.square() == *self {
                return Some(cand);
            }
            return None;
        }
        // general case
        let norm = self.c0.square().add(&self.c1.square());
        let s = norm.sqrt()?; // if a is a square, N(a) is a residue in Fp
        let two = Fp::from_be_bytes_reduced(&[2]);
        let inv_two = two.invert().unwrap();
        // candidate ξ² = (α + s)/2, else (α − s)/2
        let t1 = self.c0.add(&s).mul(&inv_two);
        let xi = match t1.sqrt() {
            Some(v) if !v.is_zero() => v,
            _ => {
                let t2 = self.c0.sub(&s).mul(&inv_two);
                let v = t2.sqrt()?;
                if v.is_zero() {
                    return None;
                }
                v
            }
        };
        let eta = self.c1.mul(&two.mul(&xi).invert().unwrap());
        let cand = Self::new(xi, eta);
        if cand.square() == *self {
            Some(cand)
        } else {
            None
        }
    }

    /// Inverse via the norm: `1/(α+βu) = (α−βu)/(α²+β²)`.
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        let norm = self.c0.square().add(&self.c1.square());
        let inv = norm.invert()?;
        Some(Self {
            c0: self.c0.mul(&inv),
            c1: self.c1.neg().mul(&inv),
        })
    }

    /// Conjugation (the p-power Frobenius on Fp2): `α+βu → α−βu`.
    #[inline]
    pub fn conjugate(&self) -> Self {
        Self {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }

    pub fn to_be_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[..48].copy_from_slice(&self.c0.to_be_bytes());
        out[48..].copy_from_slice(&self.c1.to_be_bytes());
        out
    }

    pub fn from_be_bytes(bytes: &[u8; 96]) -> Self {
        let mut c0 = [0u8; 48];
        let mut c1 = [0u8; 48];
        c0.copy_from_slice(&bytes[..48]);
        c1.copy_from_slice(&bytes[48..]);
        Self {
            c0: Fp::from_be_bytes_reduced(&c0),
            c1: Fp::from_be_bytes_reduced(&c1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tower_axioms() {
        let a = Fp2::new(
            Fp::from_be_bytes_reduced(&[0x11; 47]),
            Fp::from_be_bytes_reduced(&[0x22; 47]),
        );
        let b = Fp2::new(
            Fp::from_be_bytes_reduced(&[0x33; 47]),
            Fp::from_be_bytes_reduced(&[0x44; 47]),
        );
        let c = Fp2::new(
            Fp::from_be_bytes_reduced(&[0x55; 47]),
            Fp::from_be_bytes_reduced(&[0x66; 47]),
        );
        assert_eq!(a.mul(&Fp2::ONE), a);
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
        assert_eq!(a.mul(&a.invert().unwrap()), Fp2::ONE);
        // u^2 = -1
        let u = Fp2::new(Fp::ZERO, Fp::ONE);
        assert_eq!(u.square(), Fp2::ONE.neg());
        // (1+u)^2 = 2u
        assert_eq!(
            Fp2::XI.square(),
            Fp2::new(Fp::ZERO, Fp::from_be_bytes_reduced(&[2]))
        );
        // conjugate x norm = |x|^2
        assert_eq!(
            a.mul(&a.conjugate()),
            Fp2::new(a.c0.square().add(&a.c1.square()), Fp::ZERO)
        );
    }

    #[test]
    fn sqrt_round_trips() {
        // ξ = 1+u is a NON-square in Fp2 (its norm 2 is a non-residue in
        // Fp since p ≡ 3 (mod 8)) — pinned as the negative case.
        assert!(Fp2::XI.sqrt().is_none(), "1+u is a non-residue in Fp2");
        // a genuine square: (3 + 5u)²
        let base = Fp2::new(
            Fp::from_be_bytes_reduced(&[3]),
            Fp::from_be_bytes_reduced(&[5]),
        );
        let s = base.square();
        let r = s.sqrt().expect("squares must have roots");
        assert_eq!(r.square(), s);
        // random points
        for i in 0..8u8 {
            let a = Fp2::new(
                Fp::from_be_bytes_reduced(&[i + 1; 47]),
                Fp::from_be_bytes_reduced(&[i.wrapping_mul(7) + 3; 47]),
            );
            let sq = a.square();
            let root = sq.sqrt().expect("squares must have roots");
            assert_eq!(root.square(), sq);
        }
        // pure real and pure imaginary branches
        let pr = Fp2::new(Fp::from_be_bytes_reduced(&[9; 47]), Fp::ZERO);
        assert_eq!(pr.sqrt().unwrap().square(), pr);
        let pi = Fp2::new(Fp::ZERO, Fp::from_be_bytes_reduced(&[5; 47]));
        assert_eq!(pi.sqrt().unwrap().square(), pi);
        // non-residues: u is not a square in Fp2 (its norm -1 is a
        // non-residue in Fp)
        assert!(u_nonresidue(), "u must be a non-residue in Fp2");
    }

    fn u_nonresidue() -> bool {
        Fp2::new(Fp::ZERO, Fp::ONE).sqrt().is_none()
    }
}
