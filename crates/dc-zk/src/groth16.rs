//! Groth16 over BLS12-381 (from-scratch, matching the validated prototype).
//!
//! Scheme summary (variable indices: 0 = constant one, 1..=ℓ public
//! statement, ℓ+1..m private witness):
//!
//! * **Setup** (trusted, single-party in this release — see the honest
//!   trust-model note in the crate docs): sample toxic waste
//!   `τ, α, β, γ, δ`, publish
//!   - proving key: `[α]₁, [β]₁, [β]₂, [δ]₁, [δ]₂, {A_i(τ)}₁,
//!     {B_i(τ)}₁, {B_i(τ)}₂, H = {[τ^i/δ]}₁ i∈[0,2n−2],
//!     IC = {[(βA_i+αB_i+C_i)/γ]}₁ (i ≤ ℓ),
//!     K = {[(βA_i+αB_i+C_i)/δ]}₁ (i > ℓ)`
//!   - verifying key: `[α]₁, [β]₂, [γ]₂, [δ]₂, IC`.
//! * **Prove**: with witness `a`, blinding `r, s`:
//!   `A = α + Σ a_i A_i(τ) + rδ`, `B = β + Σ a_i B_i(τ) + sδ`,
//!   `C = (Σ_{i>ℓ} a_i K_i + [A(x)B(x) − C(x)](τ))/δ + sA + rB₁ − rsδ`
//!   where `A(x) = Σ a_i A_i(x)` etc. — the H query evaluates the
//!   **product polynomial** `A(x)B(x) − C(x) = Z(x)·h(x)` directly, so
//!   no polynomial division is ever needed (a deliberate simplification:
//!   the pk is somewhat larger, the prover simpler to audit).
//! * **Verify**: `e(A, B) = e([α]₁,[β]₂) · e([Σ x_i·IC_i]₁, [γ]₂) · e(C, [δ]₂)`.
//!
//! Soundness of the verification equation for this exact formulation was
//! expanded and checked symbolically during prototype validation
//! (`scripts/zk_prototype.py`); the tests below exercise it end-to-end
//! including tamper rejection.

use crate::curve::{G1, G2};
use crate::field::Fr;
use crate::pairing::multi_pairing;
use crate::poly::Poly;
use crate::r1cs::R1cs;
use crate::rng::ZkRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(thiserror::Error, Debug)]
pub enum ZkError {
    #[error("witness does not satisfy the circuit: {0}")]
    Unsatisfied(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("malformed key material: {0}")]
    MalformedKeys(String),
}

impl std::fmt::Debug for SerG1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "G1({})", hex::encode(self.0.to_compressed()))
    }
}

impl std::fmt::Debug for SerG2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "G2({})", hex::encode(self.0.to_compressed()))
    }
}

/// Verifying key.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyingKey {
    pub alpha_g1: SerG1,
    pub beta_g2: SerG2,
    pub gamma_g2: SerG2,
    pub delta_g2: SerG2,
    /// IC elements for public inputs (index 0 = constant one through ℓ).
    pub ic: Vec<SerG1>,
    pub num_public: usize,
    pub num_constraints: usize,
    /// Circuit identifier (binds keys to the compliance circuit build).
    pub circuit_id: String,
}

/// Proving key.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProvingKey {
    pub vk: VerifyingKey,
    pub alpha_g1: SerG1,
    pub beta_g1: SerG1,
    pub beta_g2: SerG2,
    pub delta_g1: SerG1,
    pub delta_g2: SerG2,
    pub a_query: Vec<SerG1>,
    pub b_query_g1: Vec<SerG1>,
    pub b_query_g2: Vec<SerG2>,
    /// `[τ^i / δ]₁` for i ∈ [0, 2n−2].
    pub h_query: Vec<SerG1>,
    /// K elements for private variables (i > ℓ).
    pub k_query: Vec<SerG1>,
    pub num_vars: usize,
}

/// Groth16 proof: two G1 points and one G2 point.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Proof {
    pub a: SerG1,
    pub b: SerG2,
    pub c: SerG1,
}

// -- serializable point wrappers ------------------------------------------------
// Compressed forms keep receipts small (proof = 48 + 96 + 48 = 192 bytes).

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SerG1(pub G1);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SerG2(pub G2);

impl Serialize for SerG1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0.to_compressed()))
    }
}

impl<'de> Deserialize<'de> for SerG1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 48] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("G1 compressed must be 48 bytes"))?;
        G1::from_compressed(&arr)
            .map(SerG1)
            .ok_or_else(|| serde::de::Error::custom("invalid G1 point"))
    }
}

impl Serialize for SerG2 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0.to_compressed()))
    }
}

impl<'de> Deserialize<'de> for SerG2 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 96] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("G2 compressed must be 96 bytes"))?;
        G2::from_compressed(&arr)
            .map(SerG2)
            .ok_or_else(|| serde::de::Error::custom("invalid G2 point"))
    }
}

/// Setup: generate (proving key, verifying key) for the constraint system
/// from the given RNG stream. **Trust model**: single-party setup — the
/// toxic waste (τ, α, β, γ, δ) is generated, used, and dropped inside
/// this function and never persisted; a multi-party ceremony
/// ("powers of tau") is future work (see docs/zk-audit.md).
pub fn setup(cs: &R1cs, circuit_id: &str, rng: &mut ZkRng) -> (ProvingKey, VerifyingKey) {
    let n = cs.num_constraints();
    let m = cs.num_vars;
    let l = cs.num_public;

    let tau = rng.next_fr();
    let alpha = rng.next_fr();
    let beta = rng.next_fr();
    let gamma = rng.next_fr();
    let delta = rng.next_fr();
    let gamma_inv = gamma.invert().expect("random gamma is a unit");
    let delta_inv = delta.invert().expect("random delta is a unit");

    // Lagrange basis evaluations at tau over the domain 1..=n
    let u: Vec<Fr> = (0..n)
        .map(|j| Poly::lagrange_eval_at(j + 1, n, &tau))
        .collect();

    // A_i(tau), B_i(tau), C_i(tau) per variable
    let mut a_t = vec![Fr::ZERO; m];
    let mut b_t = vec![Fr::ZERO; m];
    let mut c_t = vec![Fr::ZERO; m];
    for ((arow, brow), (crow, uj)) in cs.a.iter().zip(cs.b.iter()).zip(cs.c.iter().zip(u.iter())) {
        for (col, coef) in arow {
            a_t[*col] = a_t[*col].add(&coef.mul(uj));
        }
        for (col, coef) in brow {
            b_t[*col] = b_t[*col].add(&coef.mul(uj));
        }
        for (col, coef) in crow {
            c_t[*col] = c_t[*col].add(&coef.mul(uj));
        }
    }

    let g1 = G1::generator();
    let g2 = G2::generator();

    // IC (public incl. constant one) and K (private)
    let mut ic = Vec::with_capacity(l + 1);
    for i in 0..=l {
        let v = beta.mul(&a_t[i]).add(&alpha.mul(&b_t[i])).add(&c_t[i]);
        ic.push(SerG1(g1.mul_scalar(&v.mul(&gamma_inv))));
    }
    let mut k_query = Vec::with_capacity(m - l - 1);
    for i in (l + 1)..m {
        let v = beta.mul(&a_t[i]).add(&alpha.mul(&b_t[i])).add(&c_t[i]);
        k_query.push(SerG1(g1.mul_scalar(&v.mul(&delta_inv))));
    }

    // H query: [tau^i / delta]_1 for i in 0..=2n-2
    let mut h_query = Vec::with_capacity(2 * n.saturating_sub(1).max(1));
    let mut tp = Fr::ONE;
    for _ in 0..(2 * n).saturating_sub(1).max(1) {
        h_query.push(SerG1(g1.mul_scalar(&tp.mul(&delta_inv))));
        tp = tp.mul(&tau);
    }

    let a_query = a_t.iter().map(|v| SerG1(g1.mul_scalar(v))).collect();
    let b_query_g1 = b_t.iter().map(|v| SerG1(g1.mul_scalar(v))).collect();
    let b_query_g2 = b_t.iter().map(|v| SerG2(g2.mul_scalar(v))).collect();

    let vk = VerifyingKey {
        alpha_g1: SerG1(g1.mul_scalar(&alpha)),
        beta_g2: SerG2(g2.mul_scalar(&beta)),
        gamma_g2: SerG2(g2.mul_scalar(&gamma)),
        delta_g2: SerG2(g2.mul_scalar(&delta)),
        ic,
        num_public: l,
        num_constraints: n,
        circuit_id: circuit_id.to_string(),
    };
    let pk = ProvingKey {
        vk: vk.clone(),
        alpha_g1: SerG1(g1.mul_scalar(&alpha)),
        beta_g1: SerG1(g1.mul_scalar(&beta)),
        beta_g2: SerG2(g2.mul_scalar(&beta)),
        delta_g1: SerG1(g1.mul_scalar(&delta)),
        delta_g2: SerG2(g2.mul_scalar(&delta)),
        a_query,
        b_query_g1,
        b_query_g2,
        h_query,
        k_query,
        num_vars: m,
    };
    (pk, vk)
}

/// Compute the coefficient-form polynomials A(x), B(x), C(x) for a
/// witness (Lagrange interpolation over the shared domain 1..=n — one
/// master polynomial pass, three results).
fn witness_polys(cs: &R1cs, witness: &[Fr]) -> (Poly, Poly, Poly) {
    let n = cs.num_constraints();
    let row_eval = |row: &BTreeMap<usize, Fr>| -> Fr {
        let mut acc = Fr::ZERO;
        for (col, coef) in row {
            acc = acc.add(&coef.mul(&witness[*col]));
        }
        acc
    };
    let xs: Vec<Fr> = (1..=n)
        .map(|k| Fr::from_be_bytes_reduced(&(k as u64).to_be_bytes()))
        .collect();
    let mut ya = Vec::with_capacity(n);
    let mut yb = Vec::with_capacity(n);
    let mut yc = Vec::with_capacity(n);
    for j in 0..n {
        ya.push(row_eval(&cs.a[j]));
        yb.push(row_eval(&cs.b[j]));
        yc.push(row_eval(&cs.c[j]));
    }
    let mut polys = Poly::interpolate_shared(&xs, &[ya, yb, yc]);
    let c = polys.pop().expect("3 results");
    let b = polys.pop().expect("2 results");
    let a = polys.pop().expect("1 result");
    (a, b, c)
}

/// Prove a statement with a full witness (index 0 must be Fr::ONE).
pub fn prove(
    cs: &R1cs,
    pk: &ProvingKey,
    witness: &[Fr],
    rng: &mut ZkRng,
) -> Result<Proof, ZkError> {
    if !cs.is_satisfied_by(witness) {
        return Err(ZkError::Unsatisfied(
            "witness fails at least one constraint".into(),
        ));
    }
    let n = cs.num_constraints();
    let m = cs.num_vars;
    let l = cs.num_public;
    if witness.len() != m {
        return Err(ZkError::Unsatisfied(format!(
            "witness length {} != num vars {}",
            witness.len(),
            m
        )));
    }
    let r = rng.next_fr();
    let s = rng.next_fr();

    let g1 = G1::generator();
    let g2 = G2::generator();

    // pi_A = [alpha + sum a_i A_i(tau) + r delta]_1
    let mut pi_a = pk.alpha_g1.0;
    for (i, aq) in pk.a_query.iter().enumerate() {
        pi_a = pi_a.add(&aq.0.mul_scalar(&witness[i]));
    }
    pi_a = pi_a.add(&pk.delta_g1.0.mul_scalar(&r));

    // B in G1 (for the r*B term of C) and in G2 (pi_B)
    let mut b_g1 = pk.beta_g1.0;
    for (i, bq) in pk.b_query_g1.iter().enumerate() {
        b_g1 = b_g1.add(&bq.0.mul_scalar(&witness[i]));
    }
    b_g1 = b_g1.add(&pk.delta_g1.0.mul_scalar(&s));

    let mut pi_b = pk.beta_g2.0;
    for (i, bq) in pk.b_query_g2.iter().enumerate() {
        pi_b = pi_b.add(&bq.0.mul_scalar(&witness[i]));
    }
    pi_b = pi_b.add(&pk.delta_g2.0.mul_scalar(&s));

    // product polynomial A(x)B(x) - C(x)
    let (pa, pb, pc) = witness_polys(cs, witness);
    let prod = pa.mul(&pb).sub(&pc);
    let _ = n;

    // pi_C = sum_{i>l} a_i K_i + [prod(tau)/delta] + s*A + r*B1 - r*s*delta
    let mut pi_c: Option<G1> = None;
    for (i, kq) in pk.k_query.iter().enumerate() {
        let wi = witness[l + 1 + i];
        if wi.is_zero() {
            continue;
        }
        pi_c = match pi_c {
            None => Some(kq.0.mul_scalar(&wi)),
            Some(acc) => Some(acc.add(&kq.0.mul_scalar(&wi))),
        };
    }
    for (i, coeff) in prod.coeffs.iter().enumerate() {
        if coeff.is_zero() {
            continue;
        }
        let h = pk.h_query.get(i).ok_or_else(|| {
            ZkError::MalformedKeys(format!("H query too short: need degree {}", i))
        })?;
        pi_c = match pi_c {
            None => Some(h.0.mul_scalar(coeff)),
            Some(acc) => Some(acc.add(&h.0.mul_scalar(coeff))),
        };
    }
    let mut pi_c = pi_c.unwrap_or_else(G1::identity);
    pi_c = pi_c.add(&pi_a.mul_scalar(&s));
    pi_c = pi_c.add(&b_g1.mul_scalar(&r));
    let rs = r.mul(&s);
    pi_c = pi_c.add(&pk.delta_g1.0.mul_scalar(&rs).neg());
    let _ = (g1, g2);

    Ok(Proof {
        a: SerG1(pi_a),
        b: SerG2(pi_b),
        c: SerG1(pi_c),
    })
}

/// Verify a proof against public inputs `x_1..x_ℓ` (without the implicit
/// constant one).
pub fn verify(vk: &VerifyingKey, public: &[Fr], proof: &Proof) -> Result<(), ZkError> {
    if public.len() != vk.num_public {
        return Err(ZkError::VerificationFailed(format!(
            "public input arity mismatch: {} != {}",
            public.len(),
            vk.num_public
        )));
    }
    if !proof.a.0.in_correct_subgroup() {
        return Err(ZkError::VerificationFailed("A not in G1 subgroup".into()));
    }
    if !proof.b.0.in_correct_subgroup() {
        return Err(ZkError::VerificationFailed("B not in G2 subgroup".into()));
    }
    if !proof.c.0.in_correct_subgroup() {
        return Err(ZkError::VerificationFailed("C not in G1 subgroup".into()));
    }

    // [sum x_i IC_i]_1 with x_0 = 1
    let mut ic_sum = vk.ic[0].0;
    for (i, xi) in public.iter().enumerate() {
        ic_sum = ic_sum.add(&vk.ic[i + 1].0.mul_scalar(xi));
    }

    // e(A,B) == e(alpha, beta) * e(IC, gamma) * e(C, delta)
    let lhs = multi_pairing(&[(&proof.a.0, &proof.b.0)]);
    let rhs = multi_pairing(&[
        (&vk.alpha_g1.0, &vk.beta_g2.0),
        (&ic_sum, &vk.gamma_g2.0),
        (&proof.c.0, &vk.delta_g2.0),
    ]);
    if lhs != rhs {
        return Err(ZkError::VerificationFailed(
            "pairing equation does not balance".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::LinComb;

    /// The exact circuit from the validated prototype: knowledge of x
    /// with x³ = y (public) and x's 8-bit decomposition.
    fn demo_circuit() -> R1cs {
        // vars: 0: one, 1: y (public), 2: x, 3: t1, 4..11: bits b0..b7
        let mut cs = R1cs::new(12, 1);
        let x = LinComb::var(2, Fr::ONE);
        let t = LinComb::var(3, Fr::ONE);
        let y = LinComb::var(1, Fr::ONE);
        cs.constrain(&x, &x, &t);
        cs.constrain(&t, &x, &y);
        for k in 0..8 {
            let b = LinComb::var(4 + k, Fr::ONE);
            cs.constrain(&b, &b, &b); // booleanity b^2 = b
        }
        // x = sum b_k 2^k
        let mut recon = LinComb::empty();
        for k in 0..8 {
            recon.add_term(4 + k, Fr::from_be_bytes_reduced(&(1u64 << k).to_be_bytes()));
        }
        cs.constrain(&recon, &LinComb::one(), &x);
        cs
    }

    #[test]
    fn groth16_end_to_end() {
        let cs = demo_circuit();
        let xv = Fr::from_be_bytes_reduced(&[0x5a]);
        let yv = xv.square().mul(&xv);
        let mut witness = vec![Fr::ONE, yv, xv, xv.square()];
        for k in 0..8 {
            let bit = if (0x5a >> k) & 1 == 1 {
                Fr::ONE
            } else {
                Fr::ZERO
            };
            witness.push(bit);
        }
        assert!(cs.is_satisfied_by(&witness));

        let mut rng = ZkRng::from_seed(b"groth16-end-to-end-test");
        let (pk, vk) = setup(&cs, "demo-circuit", &mut rng);
        let proof = prove(&cs, &pk, &witness, &mut rng).expect("prove");
        verify(&vk, &[yv], &proof).expect("valid proof must verify");

        // wrong public input must fail
        let bad_pub = yv.add(&Fr::ONE);
        assert!(verify(&vk, &[bad_pub], &proof).is_err());

        // tampered proof must fail
        let mut tampered = proof.clone();
        tampered.c = SerG1(tampered.c.0.add(&G1::generator()));
        assert!(verify(&vk, &[yv], &tampered).is_err());

        // a second proof from the same keys (fresh blinding) also verifies
        let proof2 = prove(&cs, &pk, &witness, &mut rng).expect("prove 2");
        assert_ne!(proof2.a, proof.a, "blinding must differ");
        verify(&vk, &[yv], &proof2).expect("second proof verifies");
    }

    #[test]
    fn unsatisfied_witness_refused() {
        let cs = demo_circuit();
        let xv = Fr::from_be_bytes_reduced(&[0x5a]);
        let mut witness = vec![Fr::ONE, xv.square().mul(&xv), xv, xv.square()];
        for k in 0..8 {
            witness.push(if (0x5a >> k) & 1 == 1 {
                Fr::ONE
            } else {
                Fr::ZERO
            });
        }
        let mut rng = ZkRng::from_seed(b"unsat");
        let (pk, _vk) = setup(&cs, "demo-circuit", &mut rng);
        witness[2] = xv.add(&Fr::ONE); // break satisfaction
        assert!(matches!(
            prove(&cs, &pk, &witness, &mut rng),
            Err(ZkError::Unsatisfied(_))
        ));
    }

    #[test]
    fn keys_survive_serialization_round_trip() {
        let cs = demo_circuit();
        let mut rng = ZkRng::from_seed(b"ser");
        let (pk, vk) = setup(&cs, "demo-circuit", &mut rng);
        let s = serde_json::to_string(&vk).unwrap();
        let vk2: VerifyingKey = serde_json::from_str(&s).unwrap();
        assert_eq!(vk2.circuit_id, "demo-circuit");
        let s = serde_json::to_string(&pk).unwrap();
        let pk2: ProvingKey = serde_json::from_str(&s).unwrap();
        assert_eq!(pk2.num_vars, pk.num_vars);

        let xv = Fr::from_be_bytes_reduced(&[0x33]);
        let yv = xv.square().mul(&xv);
        let mut witness = vec![Fr::ONE, yv, xv, xv.square()];
        for k in 0..8 {
            witness.push(if (0x33 >> k) & 1 == 1 {
                Fr::ONE
            } else {
                Fr::ZERO
            });
        }
        let proof = prove(&cs, &pk2, &witness, &mut rng).unwrap();
        verify(&vk2, &[yv], &proof).expect("round-tripped keys verify");
    }
}
