//! R1CS — the rank-1 quadratic constraint system over Fr.
//!
//! A constraint is a triple of **linear combinations** `(A, B, C)` over
//! variables `w = (w_0 … w_{m-1})` (w_0 is the constant 1), enforcing
//! `⟨A,w⟩ · ⟨B,w⟩ = ⟨C,w⟩`. The first `ℓ+1` variables (index 0 plus the
//! statement) are PUBLIC; the rest are the private witness.
//!
//! This is the exact abstraction the validated Python prototype
//! exercised; witness satisfaction is checked before proving so an
//! inconsistent witness can never reach the QAP stage.

use crate::field::Fr;
use std::collections::BTreeMap;

/// A sparse linear combination: variable index → coefficient.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LinComb {
    pub terms: BTreeMap<usize, Fr>,
}

impl LinComb {
    pub fn empty() -> Self {
        Self::default()
    }

    /// The constant `1` (variable 0).
    pub fn one() -> Self {
        Self::var(0, Fr::ONE)
    }

    pub fn var(idx: usize, coeff: Fr) -> Self {
        let mut terms = BTreeMap::new();
        terms.insert(idx, coeff);
        Self { terms }
    }

    pub fn is_empty(&self) -> bool {
        self.terms.values().all(|v| v.is_zero())
    }

    pub fn add_term(&mut self, idx: usize, coeff: Fr) {
        let e = self.terms.entry(idx).or_insert(Fr::ZERO);
        *e = e.add(&coeff);
        if e.is_zero() {
            self.terms.remove(&idx);
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = self.clone();
        for (idx, coeff) in &rhs.terms {
            out.add_term(*idx, *coeff);
        }
        out
    }

    pub fn scale(&self, k: &Fr) -> Self {
        Self {
            terms: self.terms.iter().map(|(i, c)| (*i, c.mul(k))).collect(),
        }
    }

    pub fn neg(&self) -> Self {
        self.scale(&Fr::ONE.neg())
    }

    pub fn eval(&self, witness: &[Fr]) -> Fr {
        let mut acc = Fr::ZERO;
        for (idx, coeff) in &self.terms {
            acc = acc.add(&coeff.mul(&witness[*idx]));
        }
        acc
    }
}

#[derive(Clone, Debug, Default)]
pub struct R1cs {
    /// total number of variables (including the constant 1 at index 0)
    pub num_vars: usize,
    /// number of public statement variables (indices 1..=l; index 0 is
    /// the implicit constant one and is always public)
    pub num_public: usize,
    pub a: Vec<BTreeMap<usize, Fr>>,
    pub b: Vec<BTreeMap<usize, Fr>>,
    pub c: Vec<BTreeMap<usize, Fr>>,
}

impl R1cs {
    pub fn new(num_vars: usize, num_public: usize) -> Self {
        assert!(num_public < num_vars, "more public vars than vars");
        Self {
            num_vars,
            num_public,
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
        }
    }

    /// Add one constraint `a · b = c`.
    pub fn constrain(&mut self, a: &LinComb, b: &LinComb, c: &LinComb) {
        self.a.push(a.terms.clone());
        self.b.push(b.terms.clone());
        self.c.push(c.terms.clone());
    }

    pub fn num_constraints(&self) -> usize {
        self.a.len()
    }

    /// Full witness check: does every constraint hold?
    pub fn is_satisfied_by(&self, witness: &[Fr]) -> bool {
        if witness.len() != self.num_vars {
            return false;
        }
        if witness.first() != Some(&Fr::ONE) {
            return false; // w_0 must be the constant 1
        }
        for j in 0..self.a.len() {
            let av = eval_sparse(&self.a[j], witness);
            let bv = eval_sparse(&self.b[j], witness);
            let cv = eval_sparse(&self.c[j], witness);
            if av.mul(&bv) != cv {
                return false;
            }
        }
        true
    }
}

fn eval_sparse(row: &BTreeMap<usize, Fr>, witness: &[Fr]) -> Fr {
    let mut acc = Fr::ZERO;
    for (idx, coeff) in row {
        acc = acc.add(&coeff.mul(&witness[*idx]));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_satisfaction() {
        // vars: 0 = one, 1 = x (private), 2 = t, 3 = y (public)
        let mut cs = R1cs::new(4, 1);
        let x = LinComb::var(1, Fr::ONE);
        let t = LinComb::var(2, Fr::ONE);
        let y = LinComb::var(3, Fr::ONE);
        // t = x * x
        cs.constrain(&x, &x, &t);
        // y = t * x
        cs.constrain(&t, &x, &y);
        let xv = Fr::from_be_bytes_reduced(&[5]);
        let wit = vec![Fr::ONE, xv, xv.square(), xv.square().mul(&xv)];
        assert!(cs.is_satisfied_by(&wit));
        let mut bad = wit.clone();
        bad[3] = bad[3].add(&Fr::ONE);
        assert!(!cs.is_satisfied_by(&bad));
    }
}
