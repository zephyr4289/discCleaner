//! Polynomial arithmetic over Fr — the QAP assembly substrate.
//!
//! Coefficients are little-endian (`coeffs[i]` is the coefficient of x^i).
//! All operations are O(n²) schoolbook: constraint counts in this crate
//! stay in the low thousands, where the simple code path is both fast
//! enough (sub-second proving) and dramatically easier to audit than an
//! FFT pipeline.

use crate::field::Fr;

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Poly {
    pub coeffs: Vec<Fr>,
}

impl Poly {
    pub fn zero() -> Self {
        Self { coeffs: vec![] }
    }

    pub fn one() -> Self {
        Self {
            coeffs: vec![Fr::ONE],
        }
    }

    pub fn from_coeffs(coeffs: Vec<Fr>) -> Self {
        let mut p = Self { coeffs };
        p.trim();
        p
    }

    pub fn from_constant(c: Fr) -> Self {
        Self { coeffs: vec![c] }
    }

    pub fn trim(&mut self) {
        while self.coeffs.len() > 1 && self.coeffs.last().unwrap().is_zero() {
            self.coeffs.pop();
        }
        if self.coeffs.len() == 1 && self.coeffs[0].is_zero() {
            self.coeffs.clear();
        }
    }

    pub fn degree(&self) -> Option<usize> {
        if self.coeffs.is_empty() {
            None
        } else {
            Some(self.coeffs.len() - 1)
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let n = self.coeffs.len().max(rhs.coeffs.len());
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let a = self.coeffs.get(i).copied().unwrap_or(Fr::ZERO);
            let b = rhs.coeffs.get(i).copied().unwrap_or(Fr::ZERO);
            out.push(a.add(&b));
        }
        Self::from_coeffs(out)
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let n = self.coeffs.len().max(rhs.coeffs.len());
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let a = self.coeffs.get(i).copied().unwrap_or(Fr::ZERO);
            let b = rhs.coeffs.get(i).copied().unwrap_or(Fr::ZERO);
            out.push(a.sub(&b));
        }
        Self::from_coeffs(out)
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        if self.coeffs.is_empty() || rhs.coeffs.is_empty() {
            return Self::zero();
        }
        let mut out = vec![Fr::ZERO; self.coeffs.len() + rhs.coeffs.len() - 1];
        for (i, &ai) in self.coeffs.iter().enumerate() {
            if ai.is_zero() {
                continue;
            }
            for (j, &bj) in rhs.coeffs.iter().enumerate() {
                if bj.is_zero() {
                    continue;
                }
                let idx = i + j;
                out[idx] = out[idx].add(&ai.mul(&bj));
            }
        }
        Self::from_coeffs(out)
    }

    pub fn scale(&self, k: &Fr) -> Self {
        Self::from_coeffs(self.coeffs.iter().map(|c| c.mul(k)).collect())
    }

    pub fn eval(&self, x: &Fr) -> Fr {
        let mut acc = Fr::ZERO;
        for c in self.coeffs.iter().rev() {
            acc = acc.mul(x).add(c);
        }
        acc
    }

    /// Lagrange interpolation through `(x_j, y_j)` for j = 0..n
    /// (distinct x_j). O(n²): master polynomial + synthetic division +
    /// batch-inverted denominators (exactly ONE field inversion).
    pub fn interpolate(points: &[(Fr, Fr)]) -> Self {
        let n = points.len();
        if n == 0 {
            return Self::zero();
        }
        if n == 1 {
            return Self::from_constant(points[0].1);
        }
        let xs: Vec<Fr> = points.iter().map(|p| p.0).collect();
        let ys: Vec<Fr> = points.iter().map(|p| p.1).collect();
        // master polynomial M(x) = prod_k (x - x_k)
        let mut master = Self::one();
        for &xk in &xs {
            master = master.mul(&Self::from_coeffs(vec![xk.neg(), Fr::ONE]));
        }
        // denominators d_j = prod_{k != j} (x_j - x_k)
        let mut d = Vec::with_capacity(n);
        for j in 0..n {
            let mut acc = Fr::ONE;
            for k in 0..n {
                if k != j {
                    acc = acc.mul(&xs[j].sub(&xs[k]));
                }
            }
            d.push(acc);
        }
        // batch inversion (Montgomery prefix trick): ONE Fermat inversion
        let mut prefix = vec![Fr::ONE; n + 1];
        for i in 0..n {
            prefix[i + 1] = prefix[i].mul(&d[i]);
        }
        let inv_all = prefix[n].invert().expect("distinct x_j");
        let mut inv_d = vec![Fr::ZERO; n];
        let mut acc = inv_all;
        for i in (0..n).rev() {
            // acc = 1/(d_0 .. d_i); inv_d[i] = acc * (d_0 .. d_{i-1}) = 1/d_i
            inv_d[i] = acc.mul(&prefix[i]);
            acc = acc.mul(&d[i]);
        }
        // A(x) = sum_j y_j * inv_d[j] * M(x) / (x - x_j)
        let mut result = Self::zero();
        for j in 0..n {
            let q = master.synthetic_div(&xs[j]);
            let scale = ys[j].mul(&inv_d[j]);
            result = result.add(&q.scale(&scale));
        }
        result
    }

    /// Interpolate MULTIPLE polynomials over the SAME domain in one
    /// pass: the master polynomial, denominators and their batch inverse
    /// are computed once, then each result costs only n synthetic
    /// divisions + accumulation (the prover's A/B/C case).
    pub fn interpolate_shared(xs: &[Fr], ys_list: &[Vec<Fr>]) -> Vec<Self> {
        let n = xs.len();
        assert!(ys_list.iter().all(|ys| ys.len() == n));
        if n == 0 {
            return ys_list.iter().map(|_| Self::zero()).collect();
        }
        // master polynomial
        let mut master = Self::one();
        for &xk in xs {
            master = master.mul(&Self::from_coeffs(vec![xk.neg(), Fr::ONE]));
        }
        // denominators + batch inverse (once)
        let mut d = Vec::with_capacity(n);
        for j in 0..n {
            let mut acc = Fr::ONE;
            for k in 0..n {
                if k != j {
                    acc = acc.mul(&xs[j].sub(&xs[k]));
                }
            }
            d.push(acc);
        }
        let mut prefix = vec![Fr::ONE; n + 1];
        for i in 0..n {
            prefix[i + 1] = prefix[i].mul(&d[i]);
        }
        let inv_all = prefix[n].invert().expect("distinct x_j");
        let mut inv_d = vec![Fr::ZERO; n];
        let mut acc = inv_all;
        for i in (0..n).rev() {
            inv_d[i] = acc.mul(&prefix[i]);
            acc = acc.mul(&d[i]);
        }
        // precompute quotients M(x)/(x - x_j) once
        let qs: Vec<Self> = xs.iter().map(|xj| master.synthetic_div(xj)).collect();
        // each result: sum_j y_j * inv_d[j] * q_j
        ys_list
            .iter()
            .map(|ys| {
                let mut result = Self::zero();
                for j in 0..n {
                    if ys[j].is_zero() {
                        continue;
                    }
                    let scale = ys[j].mul(&inv_d[j]);
                    result = result.add(&qs[j].scale(&scale));
                }
                result
            })
            .collect()
    }

    /// Divide by the linear factor `(x - a)` (exact division; remainder
    /// is dropped — callers guarantee divisibility or accept truncation).
    fn synthetic_div(&self, a: &Fr) -> Self {
        let n = self.coeffs.len();
        if n <= 1 {
            return Self::zero();
        }
        let mut q = vec![Fr::ZERO; n - 1];
        q[n - 2] = self.coeffs[n - 1];
        for i in (1..n - 1).rev() {
            q[i - 1] = self.coeffs[i].add(&a.mul(&q[i]));
        }
        Self::from_coeffs(q)
    }

    /// The vanishing polynomial over roots `1..=n`.
    pub fn vanishing(n: usize) -> Self {
        let mut acc = Self::one();
        let mut k = Fr::ZERO;
        for _i in 1..=n {
            k = k.add(&Fr::ONE);
            acc = acc.mul(&Self::from_coeffs(vec![k.neg(), Fr::ONE]));
        }
        acc
    }

    /// Lagrange basis value at `tau`: `prod_{k != j} (tau - k)/(j - k)`
    /// over the domain `1..=n` (used by the Groth16 setup).
    pub fn lagrange_eval_at(j: usize, n: usize, tau: &Fr) -> Fr {
        let xj = Fr::from_be_bytes_reduced(&(j as u64).to_be_bytes());
        let mut num = Fr::ONE;
        let mut den = Fr::ONE;
        for k in 1..=n {
            if k != j {
                let xk = Fr::from_be_bytes_reduced(&(k as u64).to_be_bytes());
                num = num.mul(&tau.sub(&xk));
                den = den.mul(&xj.sub(&xk));
            }
        }
        num.mul(&den.invert().expect("distinct domain points"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poly_arithmetic() {
        let p = Poly::from_coeffs(vec![
            Fr::from_be_bytes_reduced(&[3]),
            Fr::from_be_bytes_reduced(&[1]), // 3 + x
        ]);
        let q = Poly::from_coeffs(vec![
            Fr::from_be_bytes_reduced(&[5]),
            Fr::from_be_bytes_reduced(&[2]), // 5 + 2x
        ]);
        // (3+x)(5+2x) = 15 + 11x + 2x^2
        let pq = p.mul(&q);
        assert_eq!(pq.coeffs.len(), 3);
        assert_eq!(pq.coeffs[0], Fr::from_be_bytes_reduced(&[15]));
        assert_eq!(pq.coeffs[1], Fr::from_be_bytes_reduced(&[11]));
        assert_eq!(pq.coeffs[2], Fr::from_be_bytes_reduced(&[2]));
        // eval at x=2: 5 * 9 = 45
        let x = Fr::from_be_bytes_reduced(&[2]);
        assert_eq!(pq.eval(&x), Fr::from_be_bytes_reduced(&[45]));
        // add / sub round trip
        assert_eq!(p.add(&q).sub(&q), p);
    }

    #[test]
    fn interpolation_round_trip() {
        // points on y = x^2 + 7 over domain 1..=4
        let pts: Vec<(Fr, Fr)> = (1..=4)
            .map(|k| {
                let x = Fr::from_be_bytes_reduced(&(k as u64).to_be_bytes());
                (x, x.square().add(&Fr::from_be_bytes_reduced(&[7])))
            })
            .collect();
        let p = Poly::interpolate(&pts);
        for (x, y) in &pts {
            assert_eq!(p.eval(x), *y);
        }
        assert_eq!(p.degree(), Some(2));
    }

    #[test]
    fn vanishing_poly_roots() {
        let z = Poly::vanishing(4);
        for k in 1..=4u64 {
            let x = Fr::from_be_bytes_reduced(&k.to_be_bytes());
            assert!(z.eval(&x).is_zero(), "root at x = {}", k);
        }
        // degree 4
        assert_eq!(z.degree(), Some(4));
        // lagrange basis orthogonality
        let tau = Fr::from_be_bytes_reduced(&[0x77; 31]);
        for j in 1..=4usize {
            let u = Poly::lagrange_eval_at(j, 4, &tau);
            // reconstruct tau^0 and tau^1 through the basis
            let mut acc0 = Fr::ZERO;
            let mut acc1 = Fr::ZERO;
            for k in 1..=4usize {
                let uk = Poly::lagrange_eval_at(k, 4, &tau);
                acc0 = acc0.add(&uk);
                acc1 = acc1.add(&uk.mul(&Fr::from_be_bytes_reduced(&(k as u64).to_be_bytes())));
            }
            assert_eq!(acc0, Fr::ONE, "sum of basis = 1");
            assert_eq!(acc1, tau, "sum k*basis_k = tau");
            let _ = j;
            let _ = u;
        }
    }
}
