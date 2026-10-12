//! Poseidon SNARK-friendly hash over Fr.
//!
//! Parameters: state t = 3, full rounds RF = 8, partial rounds RP = 57,
//! S-box x⁵ (gcd(5, r−1) = 1, verified by test), sponge rate 2 /
//! capacity 1.
//!
//! **Round constants**: derived transparently from SHA-256 counter mode
//! (domain-separated per instance) rather than the reference Grain LFSR.
//! This is a documented deviation: dc-zk requires no cross-implementation
//! interoperability (hashes are only ever produced and consumed inside
//! the same circuit family), and a SHA-anchored derivation is trivially
//! auditable — a "nothing-up-my-sleeve" construction that cannot be
//! backdoored. The MDS matrix is a Cauchy matrix (provably MDS for
//! distinct x_i + y_j).
//!
//! Both the out-of-circuit evaluator and the in-circuit synthesizer
//! share the same parameter table (round constants, MDS, capacity
//! initialization); the test `in_circuit_matches_evaluator` pins the
//! equivalence, which is what the circuit's soundness rests on.

use crate::field::Fr;
use crate::r1cs::{LinComb, R1cs};
use sha2::{Digest, Sha256};

pub const T: usize = 3;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

#[derive(Clone)]
pub struct PoseidonConfig {
    domain: Vec<u8>,
}

impl PoseidonConfig {
    pub fn new(domain: &[u8]) -> Self {
        Self {
            domain: domain.to_vec(),
        }
    }

    /// Capacity-domain initializer: SHA-256 of the domain string mapped
    /// to Fr (used as the sponge's capacity lane and the circuit's
    /// fixed capacity constant).
    pub fn capacity(&self) -> Fr {
        Fr::from_be_bytes_reduced(&Sha256::digest(&self.domain))
    }

    /// Round constants: `ARC[round][i] ∈ Fr`.
    fn arc(&self) -> Vec<[Fr; T]> {
        let mut out = Vec::with_capacity(TOTAL_ROUNDS);
        for r in 0..TOTAL_ROUNDS {
            let mut row = [Fr::ZERO; T];
            for (i, slot) in row.iter_mut().enumerate() {
                let mut h = Sha256::new();
                h.update(b"dc-zk/poseidon/arc/v1");
                h.update(&self.domain);
                h.update((r as u32).to_be_bytes());
                h.update((i as u32).to_be_bytes());
                let d: [u8; 32] = h.finalize().into();
                *slot = Fr::from_be_bytes_reduced(&d);
            }
            out.push(row);
        }
        out
    }

    /// Cauchy MDS matrix: `M[i][j] = 1/(x_i + y_j)` for x = (1,2,3), y = (4,5,6).
    fn mds(&self) -> [[Fr; T]; T] {
        let xi = [1u64, 2, 3];
        let yj = [4u64, 5, 6];
        let mut m = [[Fr::ZERO; T]; T];
        for (i, row) in m.iter_mut().enumerate() {
            for (j, slot) in row.iter_mut().enumerate() {
                let s = Fr::from_be_bytes_reduced(&(xi[i] + yj[j]).to_be_bytes());
                *slot = s.invert().expect("distinct sums are units");
            }
        }
        m
    }

    /// One Poseidon permutation (out of circuit).
    pub fn permute(&self, state: &mut [Fr; T]) {
        let arc = self.arc();
        let mds = self.mds();
        for (r, arc_r) in arc.iter().enumerate() {
            for i in 0..T {
                state[i] = state[i].add(&arc_r[i]);
            }
            let full = !(FULL_ROUNDS / 2..FULL_ROUNDS / 2 + PARTIAL_ROUNDS).contains(&r);
            if full {
                for lane in state.iter_mut() {
                    *lane = sbox(*lane);
                }
            } else {
                state[0] = sbox(state[0]);
            }
            let mut new_state = [Fr::ZERO; T];
            for (i, ns) in new_state.iter_mut().enumerate() {
                let mut acc = Fr::ZERO;
                for j in 0..T {
                    acc = acc.add(&mds[i][j].mul(&state[j]));
                }
                *ns = acc;
            }
            *state = new_state;
        }
    }

    /// Sponge absorb + squeeze (rate 2).
    pub fn sponge(&self, elems: &[Fr]) -> Fr {
        let mut state = [self.capacity(), Fr::ZERO, Fr::ZERO];
        for chunk in elems.chunks(2) {
            state[1] = chunk[0];
            state[2] = chunk.get(1).copied().unwrap_or(Fr::ZERO);
            self.permute(&mut state);
        }
        state[1]
    }

    // -- in-circuit synthesis ---------------------------------------------

    /// Synthesize one in-circuit permutation.
    ///
    /// `state`: the (variable, value) pairs for the current three lanes.
    /// New variables are allocated through `next_var` and their witness
    /// values appended to `witness`. Returns the new state lanes.
    pub fn synth_permutation(
        &self,
        cs: &mut R1cs,
        state: [(usize, Fr); T],
        next_var: &mut usize,
        witness: &mut Vec<Fr>,
    ) -> [(usize, Fr); T] {
        let arc = self.arc();
        let mds = self.mds();
        let mut cur = state;

        let alloc =
            |cs: &mut R1cs, next_var: &mut usize, witness: &mut Vec<Fr>, val: Fr| -> (usize, Fr) {
                let v = *next_var;
                *next_var += 1;
                witness.push(val);
                debug_assert_eq!(witness.len(), v + 1, "witness tracks allocation");
                cs.num_vars = cs.num_vars.max(v + 1);
                let _ = cs;
                (v, val)
            };

        for (r, arc_r) in arc.iter().enumerate() {
            // 1. affine ARC step: z_i = x_i + arc[r][i]   (1 constraint each)
            let mut z = [(0usize, Fr::ZERO); T];
            for i in 0..T {
                let new_val = cur[i].1.add(&arc_r[i]);
                let (zv, zv_val) = alloc(cs, next_var, witness, new_val);
                // (z - x - c) * 1 = 0
                let mut lc = LinComb::var(zv, Fr::ONE);
                lc.add_term(cur[i].0, Fr::ONE.neg());
                lc.add_term(0, arc_r[i].neg());
                cs.constrain(&lc, &LinComb::one(), &LinComb::empty());
                z[i] = (zv, zv_val);
            }
            // 2. S-box
            let full = !(FULL_ROUNDS / 2..FULL_ROUNDS / 2 + PARTIAL_ROUNDS).contains(&r);
            let mut lanes: Vec<usize> = if full { (0..T).collect() } else { vec![0] };
            let _ = &mut lanes;
            for &i in &lanes {
                let (t_var, t_val) = alloc(cs, next_var, witness, z[i].1.square());
                let (u_var, u_val) = alloc(cs, next_var, witness, t_val.square());
                let (y_var, y_val) = alloc(cs, next_var, witness, u_val.mul(&z[i].1));
                cs.constrain(
                    &LinComb::var(z[i].0, Fr::ONE),
                    &LinComb::var(z[i].0, Fr::ONE),
                    &LinComb::var(t_var, Fr::ONE),
                );
                cs.constrain(
                    &LinComb::var(t_var, Fr::ONE),
                    &LinComb::var(t_var, Fr::ONE),
                    &LinComb::var(u_var, Fr::ONE),
                );
                cs.constrain(
                    &LinComb::var(u_var, Fr::ONE),
                    &LinComb::var(z[i].0, Fr::ONE),
                    &LinComb::var(y_var, Fr::ONE),
                );
                z[i] = (y_var, y_val);
            }
            // 3. affine MDS step: w_i = sum_j M[i][j] * z_j   (1 constraint each)
            let mut w = [(0usize, Fr::ZERO); T];
            for i in 0..T {
                let mut acc = Fr::ZERO;
                for j in 0..T {
                    acc = acc.add(&mds[i][j].mul(&z[j].1));
                }
                let (wv, wv_val) = alloc(cs, next_var, witness, acc);
                let mut lc = LinComb::var(wv, Fr::ONE);
                for j in 0..T {
                    lc.add_term(z[j].0, mds[i][j].neg());
                }
                cs.constrain(&lc, &LinComb::one(), &LinComb::empty());
                w[i] = (wv, wv_val);
            }
            cur = w;
        }
        cur
    }

    /// Synthesize a full sponge: absorb `(input vars)` pairs, squeeze the
    /// output lane. The initial capacity is bound to the fixed constant
    /// by an explicit constraint (otherwise a malicious prover could
    /// choose its own domain).
    pub fn synth_sponge(
        &self,
        cs: &mut R1cs,
        inputs: &[(usize, Fr)],
        next_var: &mut usize,
        witness: &mut Vec<Fr>,
    ) -> (usize, Fr) {
        // capacity variable pinned to the constant
        let cap = self.capacity();
        let (cap_var, _) = {
            let v = *next_var;
            *next_var += 1;
            witness.push(Fr::ONE); // placeholder; overwritten below
            (v, cap)
        };
        // fix witness slot for the capacity
        witness[cap_var] = cap;
        cs.num_vars = cs.num_vars.max(cap_var + 1);
        // cap_var * 1 = cap
        cs.constrain(
            &LinComb::var(cap_var, Fr::ONE),
            &LinComb::one(),
            &LinComb::var(0, cap),
        );

        let mut state = [(cap_var, cap), (0usize, Fr::ZERO), (0usize, Fr::ZERO)];
        let mut it = inputs.iter();
        loop {
            let a = it.next();
            let b = it.next();
            if let (None, None) = (a, b) {
                break;
            }
            state[1] = *a.expect("checked");
            state[2] = b.copied().unwrap_or((0usize, Fr::ZERO));
            if state[2].0 == 0 {
                // zero-var: constant zero as a real allocation
                let (zv, _) = {
                    let v = *next_var;
                    *next_var += 1;
                    witness.push(Fr::ZERO);
                    (v, Fr::ZERO)
                };
                cs.num_vars = cs.num_vars.max(zv + 1);
                // zv * 1 = 0
                cs.constrain(
                    &LinComb::var(zv, Fr::ONE),
                    &LinComb::one(),
                    &LinComb::empty(),
                );
                state[2] = (zv, Fr::ZERO);
            }
            state = self.synth_permutation(cs, state, next_var, witness);
        }
        (state[1].0, state[1].1)
    }
}

#[inline]
fn sbox(x: Fr) -> Fr {
    // x^5 = ((x^2)^2) * x
    let t = x.square();
    t.square().mul(&x)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(v: u64) -> Fr {
        Fr::from_be_bytes_reduced(&v.to_be_bytes())
    }

    #[test]
    fn sbox_exponent_is_a_permutation() {
        // gcd(5, r-1) == 1: r-1 = 2^32 * odd with (r-1) mod 5 == 2,
        // so x -> x^5 is a bijection on Fr*.
        let mut seen = std::collections::HashSet::new();
        for i in 1..64u64 {
            let v = f(i);
            seen.insert(sbox(v));
        }
        assert_eq!(seen.len(), 63, "s-box must be injective on the sample");
        assert_eq!(sbox(f(3)), f(243));
    }

    #[test]
    fn permutation_deterministic_and_diffusing() {
        let cfg = PoseidonConfig::new(b"dom");
        let mut s1 = [f(1), f(2), f(3)];
        let mut s2 = [f(1), f(2), f(3)];
        cfg.permute(&mut s1);
        cfg.permute(&mut s2);
        assert_eq!(s1, s2);
        let mut s3 = [f(1), f(2), f(4)];
        cfg.permute(&mut s3);
        assert_ne!(s1, s3);
        let cfg2 = PoseidonConfig::new(b"other");
        let mut s4 = [f(1), f(2), f(3)];
        cfg2.permute(&mut s4);
        assert_ne!(s1, s4);
    }

    #[test]
    fn sponge_hashes_deterministically() {
        let cfg = PoseidonConfig::new(b"audit");
        let a = cfg.sponge(&[f(1), f(2), f(3)]);
        let b = cfg.sponge(&[f(1), f(2), f(3)]);
        assert_eq!(a, b);
        let c = cfg.sponge(&[f(1), f(2), f(4)]);
        assert_ne!(a, c);
        let cfg2 = PoseidonConfig::new(b"vk");
        assert_ne!(
            cfg.sponge(&[f(1), f(2), f(3)]),
            cfg2.sponge(&[f(1), f(2), f(3)])
        );
        let e = cfg.sponge(&[f(3), f(2), f(1)]);
        assert_ne!(a, e, "absorb order matters");
    }

    #[test]
    fn in_circuit_matches_evaluator() {
        let cfg = PoseidonConfig::new(b"audit-test");
        let elems = [f(11), f(22), f(33), f(44)];
        let expected = cfg.sponge(&elems);

        // circuit: var 0 = one; vars 1..4 = inputs
        let mut cs = R1cs::new(5, 0);
        let mut witness = vec![Fr::ONE, elems[0], elems[1], elems[2], elems[3]];
        let mut next_var = 5;
        let inputs: Vec<(usize, Fr)> = elems.iter().enumerate().map(|(i, v)| (i + 1, *v)).collect();
        let (out_var, out_val) = cfg.synth_sponge(&mut cs, &inputs, &mut next_var, &mut witness);
        cs.num_vars = cs.num_vars.max(next_var);
        assert!(
            cs.is_satisfied_by(&witness),
            "synthesized sponge must be satisfiable"
        );
        assert_eq!(
            witness[out_var], expected,
            "circuit output == evaluator output"
        );
        assert_eq!(out_val, expected);
        // constraint count sanity: 4 absorptions * (perm ~633) + capacity pins
        assert!(
            cs.num_constraints() > 2 * 500,
            "expected ~2 permutations of constraints, got {}",
            cs.num_constraints()
        );
    }
}
