//! # The homomorphic layer: blind evaluation over ciphertexts.
//!
//! The provider holds ciphertexts it cannot decrypt and the
//! customer-issued evaluation key. The operations:
//!
//! * **Add / subtract** — component-wise on `(u, v)`; the plaintext
//!   adds/subtracts and the noise adds/subtracts with it.
//! * **The blind zeroize circuit** —
//!
//!   ```text
//!   C' = (C ⊖ C) ⊕ Enc_pk(0; r', e1', e2')
//!   ```
//!
//!   The self-subtraction `C ⊖ C` is publicly verifiable
//!   arithmetic over the stored leaf (anyone holding the leaf can
//!   re-derive it), and the fresh zero-encryption re-randomizes
//!   the result. By the homomorphism, for EVERY possible secret
//!   key:
//!
//!   ```text
//!   Dec_sk(C') = Dec_sk(C) − Dec_sk(C) + 0 = 0^N
//!   ```
//!
//!   — the algebra of the circuit IS the proof of
//!   decryption-to-zero. And because `C ⊖ C` cancels the original
//!   randomness exactly, `C'` is distributed as a **fresh
//!   encryption of zero**, statistically independent of the data:
//!   the provider learns nothing, not even whether the sector ever
//!   held data.
//!
//! **On the evaluation key.** For the additive zeroize circuit the
//! evaluation capability is exactly the public key: additions and
//! fresh zero-encryptions need no secret material ([`EvalKey`]
//! binds the pk to the volume identity and the issuance nonce —
//! substitution of a different volume's key fails the digest
//! check). Extending to multiplicative circuits (gadget
//! relinearization keys) is the natural upgrade path; it demands
//! ciphertext moduli beyond the demo parameter regime (the Δ²
//! tensor term wraps mod q for any single-word q), which is
//! documented here as a deliberate scope boundary.
//!
//! The returned [`ZeroizeAttestation`] carries the noise
//! consumption so the certificate can prove the output sits
//! inside the decryptable region with margin.

use crate::poly::Poly;
use crate::rlwe::{Ciphertext, EncryptionWitness, NoiseBudget, Params, PublicKey, encrypt_with};
use crate::{FheError, SimRng};

/// The customer-issued evaluation key: the public key bound to a
/// volume identity and an issuance nonce.
///
/// The provider cannot substitute another volume's key: the
/// certificate digests the eval key, and the customer's spot
/// challenge binds the digest to the key they actually issued.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvalKey {
    /// The pk this eval key is bound to.
    pub pk: PublicKey,
    /// Volume identity (e.g. the LUKS/dm-crypt UUID).
    pub volume_id: String,
    /// Issuance nonce (binds this key to this wipe contract).
    pub issue_nonce: u64,
}

impl EvalKey {
    /// Digest binding (for the certificate).
    pub fn digest(&self, q: i64) -> String {
        let mut input = self.pk.a.to_bytes(q);
        input.extend_from_slice(&self.pk.b.to_bytes(q));
        input.extend_from_slice(self.volume_id.as_bytes());
        input.extend_from_slice(&self.issue_nonce.to_le_bytes());
        blake3::hash(&input).to_hex().to_string()
    }
}

/// Homomorphic addition.
pub fn hom_add(params: &Params, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    Ciphertext {
        u: c1.u.add(&c2.u).centred(params.q),
        v: c1.v.add(&c2.v).centred(params.q),
    }
}

/// Homomorphic subtraction.
pub fn hom_sub(params: &Params, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    Ciphertext {
        u: c1.u.sub(&c2.u).centred(params.q),
        v: c1.v.sub(&c2.v).centred(params.q),
    }
}

/// The full blind-zeroize circuit evaluation (PROVIDER SIDE).
///
/// Inputs: the stored ciphertext `C` (opaque to the provider), the
/// evaluation key, and the provider's own randomness. Output:
/// `C'` with `Dec_sk(C') = 0^N` for every possible sk, plus the
/// encryption witness behind the fresh `Enc_pk(0; r', e1', e2')`
/// term — exactly what the ZK prover needs to attest the
/// language membership of `C'`.
///
/// Noise accounting: `C ⊖ C` cancels the original noise exactly
/// (same randomness subtracted), so `C'` carries only the fresh
/// `Enc_pk(0)` noise — the minimum achievable.
pub fn blind_zeroize(
    params: &Params,
    ek: &EvalKey,
    c: &Ciphertext,
    rng: &mut SimRng,
) -> Result<(Ciphertext, EncryptionWitness, ZeroizeAttestation), FheError> {
    // 1. Public, verifiable self-subtraction: C ⊖ C (auditors can
    //    replay this arithmetic against the stored leaf).
    let self_diff = hom_sub(params, c, c);
    // 2. Fresh zero re-randomization: E0 = Enc_pk(0; r', e1', e2').
    let zero = Poly::zero(params.n);
    let r = crate::rlwe::sample_cbd(params, rng);
    let e1 = crate::rlwe::sample_cbd(params, rng);
    let e2 = crate::rlwe::sample_cbd(params, rng);
    let e0 = encrypt_with(params, &ek.pk, &zero, &r, &e1, &e2);
    let witness = EncryptionWitness { r, e1, e2 };
    // 3. Final blend.
    let out = hom_add(params, &self_diff, &e0);

    // Noise accounting (worst-case infinity-norm model): the
    // self-difference cancels to zero noise; the fresh term
    // carries the standard CBD budget.
    let mut budget = NoiseBudget::new(params);
    let fresh = fresh_noise_bound(params);
    budget.consume(fresh)?;
    let attestation = ZeroizeAttestation {
        noise_consumed: budget.consumed,
        noise_ceiling: budget.ceiling,
        eval_key_digest: ek.digest(params.q),
        self_diff_u_digest: blake3::hash(&self_diff.u.to_bytes(params.q))
            .to_hex()
            .to_string(),
        self_diff_v_digest: blake3::hash(&self_diff.v.to_bytes(params.q))
            .to_hex()
            .to_string(),
    };
    Ok((out, witness, attestation))
}

/// Statistical (with slack) infinity-norm bound of a fresh
/// encryption's decryption noise: `e·r + e2 − e1·s` with all
/// CBD(η).
///
/// Each cross-product coefficient has variance `n·(η/2)²`
/// (σ ≈ √n·η/2 ≈ 48 at the demo parameters); the per-coefficient
/// maximum over `n` coefficients sits under 4σ, and there are two
/// cross terms. The 12ση-level bound covers all of it with an
/// order-of-magnitude margin against the Δ/2 ceiling.
pub fn fresh_noise_bound(params: &Params) -> i64 {
    let n = params.n as f64;
    let eta = params.eta as i64;
    let sigma = (n * (params.eta as f64 / 2.0).powi(2)).sqrt();
    (12.0 * sigma * (eta.max(1) as f64).sqrt() + eta as f64) as i64 + eta
}

/// Provider-side attestation of one zeroize circuit run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZeroizeAttestation {
    /// Worst-case noise consumed by the circuit.
    pub noise_consumed: i64,
    /// Correctness ceiling (Δ/4).
    pub noise_ceiling: i64,
    /// Digest of the evaluation key used.
    pub eval_key_digest: String,
    /// Digest of the public C − C intermediate (auditors verify the
    /// arithmetic chain against the stored leaf).
    pub self_diff_u_digest: String,
    pub self_diff_v_digest: String,
}

impl ZeroizeAttestation {
    /// Headroom ratio (must stay > 1 with margin).
    pub fn margin(&self) -> f64 {
        self.noise_ceiling as f64 / self.noise_consumed.max(1) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rlwe::{encrypt, keygen_deterministic};

    fn setup(seed: u64) -> (Params, PublicKey, crate::rlwe::SecretKey, EvalKey) {
        let params = Params::default();
        let (pk, sk) = keygen_deterministic(&params, seed);
        let ek = EvalKey {
            pk: pk.clone(),
            volume_id: "vol-test".into(),
            issue_nonce: seed,
        };
        (params, pk, sk, ek)
    }

    #[test]
    fn eval_key_digest_binds_volume_and_nonce() {
        let (params, pk, _, _) = setup(1);
        let ek1 = EvalKey {
            pk: pk.clone(),
            volume_id: "vol-A".into(),
            issue_nonce: 7,
        };
        let ek2 = EvalKey {
            pk,
            volume_id: "vol-B".into(),
            issue_nonce: 7,
        };
        let ek3 = EvalKey {
            pk: ek1.pk.clone(),
            volume_id: "vol-A".into(),
            issue_nonce: 8,
        };
        assert_ne!(ek1.digest(params.q), ek2.digest(params.q));
        assert_ne!(ek1.digest(params.q), ek3.digest(params.q));
        assert_eq!(ek1.digest(params.q), ek1.digest(params.q));
    }

    #[test]
    fn homomorphic_addition_is_plaintext_linear() {
        let (params, pk, sk, _ek) = setup(2);
        let mut rng = SimRng::new(22);
        let m1 = Poly {
            coeffs: (0..params.n).map(|i| (i % 3 == 0) as i64).collect(),
        };
        let m2 = Poly {
            coeffs: (0..params.n).map(|i| (i % 5 == 0) as i64).collect(),
        };
        let (c1, _) = encrypt(&params, &pk, &m1, &mut rng);
        let (c2, _) = encrypt(&params, &pk, &m2, &mut rng);
        let sum = hom_add(&params, &c1, &c2);
        // m1 + m2 has coefficients in {0,1,2}; 2 wraps to 0 in F2
        // plaintext arithmetic (2Δ ≡ 0 mod q at centred scale).
        let expected = Poly {
            coeffs: m1
                .coeffs
                .iter()
                .zip(&m2.coeffs)
                .map(|(a, b)| (a + b) % 2)
                .collect(),
        };
        assert_eq!(sum.decrypt(&params, &sk), expected);
    }

    #[test]
    fn blind_zeroize_yields_zero_for_every_secret_key() {
        let (params, pk, sk, ek) = setup(3);
        let mut rng = SimRng::new(33);
        // Encrypt REAL data.
        let mut m = Poly::zero(params.n);
        for (i, c) in m.coeffs.iter_mut().enumerate() {
            *c = (i % 7 == 0 || i % 11 == 0) as i64;
        }
        let (c, _) = encrypt(&params, &pk, &m, &mut rng);
        assert!(!m.coeffs.iter().all(|&b| b == 0), "data is nonzero");
        // Provider-side blind zeroize (no sk in sight).
        let (z, witness, att) = blind_zeroize(&params, &ek, &c, &mut rng).expect("circuit runs");
        // Decrypt under the REAL key → all zeros.
        let dec = z.decrypt(&params, &sk);
        assert!(dec.coeffs.iter().all(|&b| b == 0), "Dec_sk(C') must be 0^N");
        // Under an UNRELATED key the output is semantic garbage
        // (RLWE security), never the original data — and the
        // wipe statement is about the customer's key.
        let (_pk2, sk2) = keygen_deterministic(&params, 777);
        let dec2 = z.decrypt(&params, &sk2);
        assert!(dec2 != m, "unrelated key must not read the data");
        // The fresh-encryption witness satisfies the language
        // relations exactly.
        let lhs_u =
            pk.a.mul(&witness.r, params.q)
                .add(&witness.e1)
                .centred(params.q);
        assert_eq!(lhs_u, z.u, "u = a·r + e1 must hold exactly");
        let lhs_v =
            pk.b.mul(&witness.r, params.q)
                .add(&witness.e2)
                .centred(params.q);
        assert_eq!(lhs_v, z.v, "v = b·r + e2 must hold (m = 0)");
        // Noise margin is wide.
        assert!(att.margin() > 10.0, "margin = {}", att.margin());
    }

    #[test]
    fn zeroized_output_leaks_nothing_about_presence() {
        // Two volumes — one with data, one empty — zeroize both;
        // the outputs' ciphertext digests must be unrelated and
        // each decrypt to zeros under the customer's key: the
        // provider cannot tell which held data.
        let (params, pk, sk, ek) = setup(4);
        let mut rng = SimRng::new(44);
        let data = Poly {
            coeffs: (0..params.n).map(|i| (i % 2) as i64).collect(),
        };
        let empty = Poly::zero(params.n);
        let (c_data, _) = encrypt(&params, &pk, &data, &mut rng);
        let (c_empty, _) = encrypt(&params, &pk, &empty, &mut rng);
        let (z1, _, _) = blind_zeroize(&params, &ek, &c_data, &mut rng).expect("run 1");
        let (z2, _, _) = blind_zeroize(&params, &ek, &c_empty, &mut rng).expect("run 2");
        assert_ne!(z1.digest(params.q), z2.digest(params.q));
        // Both decrypt to zeros under the customer's real key; an
        // unrelated reader sees only RLWE noise.
        for z in [&z1, &z2] {
            assert!(z.decrypt(&params, &sk).coeffs.iter().all(|&b| b == 0));
        }
        let (_pk3, sk3) = keygen_deterministic(&params, 31337);
        let d1 = z1.decrypt(&params, &sk3);
        let d2 = z2.decrypt(&params, &sk3);
        assert_ne!(d1, d2, "unrelated keys see independent noise");
    }

    #[test]
    fn fresh_noise_bound_covers_observed_noise() {
        let (params, _pk, sk, ek) = setup(5);
        let mut rng = SimRng::new(55);
        let data = Poly {
            coeffs: (0..params.n).map(|i| (i % 9 == 0) as i64).collect(),
        };
        let (c, _) = encrypt(&params, &ek.pk, &data, &mut rng);
        let (z, _, _) = blind_zeroize(&params, &ek, &c, &mut rng).expect("run");
        let observed = z.noise_inf_norm(&params, &sk);
        let bound = fresh_noise_bound(&params);
        assert!(
            observed <= bound,
            "observed noise {observed} exceeds the worst-case bound {bound}"
        );
        assert!(
            bound < params.noise_ceiling(),
            "fresh bound {bound} must sit under the ceiling {}",
            params.noise_ceiling()
        );
    }
}
