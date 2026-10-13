//! # Ring-LWE encryption over `R_q`.
//!
//! **Scheme (BFV-flavored, bit plaintext).** With public `a ←
//! R_q` uniform, secret `s` and errors from the centred binomial
//! distribution CBD(η):
//!
//! ```text
//! KeyGen : b = a·s + e                      (public key  pk = (a, b), sk = s)
//! Enc(m) : u = a·r + e1,  v = b·r + e2 + Δ·m   (r, e1, e2 ← CBD(η))
//! Dec(c) : m̂ = round((v − u·s) / Δ) per coefficient
//! ```
//!
//! with message coefficients `m ∈ {0, 1}` and scale
//! `Δ = ⌊q/2⌋`. Decryption noise is
//! `e·r + e2 − e1·s + Δ·(m − m̂)` — bounded well below `Δ/2` at
//! the demo parameters, leaving a wide margin for homomorphic
//! operations.
//!
//! **Noise budget.** [`NoiseBudget`] tracks the (worst-case)
//! infinity-norm budget consumed by homomorphic operations; when
//! it approaches `Δ/4` the ciphertext is undecryptable. The
//! zeroize circuit in [`crate::fhe`] reports its consumption so
//! the certificate can prove the output stays inside the
//! decryptable region — "Dec_sk(C') = 0^N holds for EVERY key the
//! customer could hold, with margin".

use crate::poly::{Poly, centre_reduce};
use crate::{FheError, SimRng};

/// Ring-LWE parameter set.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Params {
    /// Ring degree (power of two).
    pub n: usize,
    /// Ciphertext modulus (prime, fits i64 with room to multiply).
    pub q: i64,
    /// Centred-binomial noise parameter η (per side).
    pub eta: u32,
}

impl Default for Params {
    fn default() -> Self {
        // Demo-grade; see the crate preamble for the production
        // upgrade path.
        Self {
            n: 1024,
            q: 65537,
            eta: 3,
        }
    }
}

impl Params {
    /// Plaintext scale Δ = ⌊q/2⌋.
    pub fn delta(&self) -> i64 {
        self.q / 2
    }

    /// Decryption noise ceiling for correctness: Δ/4.
    pub fn noise_ceiling(&self) -> i64 {
        self.delta() / 2
    }

    /// Validate the parameter set.
    pub fn validate(&self) -> Result<(), FheError> {
        if !self.n.is_power_of_two() || self.n < 256 {
            return Err(FheError::Params(format!(
                "ring degree {} must be a power of two ≥ 256",
                self.n
            )));
        }
        if self.q <= 0 || !is_prime(self.q as u64) {
            return Err(FheError::Params(format!(
                "modulus {} must be a positive prime",
                self.q
            )));
        }
        // Overflow guard: |coeff| < q/2 < 2^31 keeps i64 products
        // with n < 2^13 accumulation safe.
        if self.q >= 1 << 31 {
            return Err(FheError::Params(format!(
                "modulus {} too large for schoolbook i64 accumulation",
                self.q
            )));
        }
        if self.eta == 0 || self.eta > 16 {
            return Err(FheError::Params(format!(
                "CBD parameter {} outside 1..=16",
                self.eta
            )));
        }
        Ok(())
    }
}

/// A (deterministic) primality check — parameter sets are small.
fn is_prime(x: u64) -> bool {
    if x < 2 {
        return false;
    }
    if x.is_multiple_of(2) {
        return x == 2;
    }
    let mut d = 3u64;
    while d * d <= x {
        if x.is_multiple_of(d) {
            return false;
        }
        d += 2;
    }
    true
}

/// Sample a CBD(η) polynomial: each coefficient is the difference
/// of two η-bit population counts (kernel variance η/2).
pub fn sample_cbd(params: &Params, rng: &mut SimRng) -> Poly {
    let mut coeffs = Vec::with_capacity(params.n);
    for _ in 0..params.n {
        let mut acc = 0i64;
        for _ in 0..params.eta {
            let x = rng.next_f64() < 0.5;
            let y = rng.next_f64() < 0.5;
            acc += (x as i64) - (y as i64);
        }
        coeffs.push(acc);
    }
    Poly::from_centred(coeffs, params.n).expect("length is exact")
}

/// The secret + error triple behind one encryption.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptionWitness {
    pub r: Poly,
    pub e1: Poly,
    pub e2: Poly,
}

/// A public key `pk = (a, b = a·s + e)`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    pub a: Poly,
    pub b: Poly,
}

impl PublicKey {
    /// Digest binding (for the certificate).
    pub fn digest(&self, q: i64) -> String {
        let mut input = self.a.to_bytes(q);
        input.extend_from_slice(&self.b.to_bytes(q));
        blake3::hash(&input).to_hex().to_string()
    }
}

/// The customer's key material. The secret never leaves the
/// customer (the provider only ever sees the [`PublicKey`] and the
/// relinearization key).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretKey {
    pub s: Poly,
    /// The relinearization seed: encodes s² under pk for the
    /// evaluation key (see [`crate::fhe::EvalKey`]).
    pub sk_digest: String,
}

/// Deterministic keygen (the provider never runs this; the
/// customer may derive it from an offline seed).
pub fn keygen_deterministic(params: &Params, seed: u64) -> (PublicKey, SecretKey) {
    let mut rng = SimRng::new(seed);
    let a = Poly::uniform(params.n, params.q, &mut rng);
    let s = sample_cbd(params, &mut rng);
    let e = sample_cbd(params, &mut rng);
    let b = a.mul(&s, params.q).add(&e).centred(params.q);
    let pk = PublicKey { a, b };
    let sk = SecretKey {
        sk_digest: pk.digest(params.q),
        s,
    };
    (pk, sk)
}

/// A ciphertext `c = (u, v)` encrypting a bit-vector plaintext.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Ciphertext {
    pub u: Poly,
    pub v: Poly,
}

/// Encrypt a {0,1} coefficient plaintext under `pk`.
pub fn encrypt(
    params: &Params,
    pk: &PublicKey,
    m: &Poly,
    rng: &mut SimRng,
) -> (Ciphertext, EncryptionWitness) {
    let r = sample_cbd(params, rng);
    let e1 = sample_cbd(params, rng);
    let e2 = sample_cbd(params, rng);
    let c = encrypt_with(params, pk, m, &r, &e1, &e2);
    (c, EncryptionWitness { r, e1, e2 })
}

/// Encrypt with an explicit witness (used by the ZK prover).
pub fn encrypt_with(
    params: &Params,
    pk: &PublicKey,
    m: &Poly,
    r: &Poly,
    e1: &Poly,
    e2: &Poly,
) -> Ciphertext {
    let u = pk.a.mul(r, params.q).add(e1).centred(params.q);
    let v =
        pk.b.mul(r, params.q)
            .add(e2)
            .add(&m.scale(params.delta()))
            .centred(params.q);
    Ciphertext { u, v }
}

impl Ciphertext {
    /// Decrypt under `sk`: per-coefficient rounding of
    /// `(v − u·s)/Δ` back to {0,1}.
    pub fn decrypt(&self, params: &Params, sk: &SecretKey) -> Poly {
        let noise = self.v.sub(&self.u.mul(&sk.s, params.q)).centred(params.q);
        let half = params.delta();
        Poly {
            coeffs: noise
                .coeffs
                .iter()
                .map(|c| {
                    let centred = centre_reduce(*c, params.q);
                    // |centred| ≈ noise + Δ·m: m = 1 sits at ±Δ.
                    if centred.abs() >= half / 2 { 1 } else { 0 }
                })
                .collect(),
        }
    }

    /// Decryption noise amplitude (infinity norm of the noise part
    /// of `v - u*s`, i.e. distance of each centred coefficient to
    /// the nearest valid plaintext point {0, +/-Delta}).
    pub fn noise_inf_norm(&self, params: &Params, sk: &SecretKey) -> i64 {
        let noise = self.v.sub(&self.u.mul(&sk.s, params.q)).centred(params.q);
        let delta = params.delta();
        let mut m = 0i64;
        for c in &noise.coeffs {
            let centred = centre_reduce(*c, params.q).abs();
            // Nearest of 0 or Delta (centred range caps at q/2 ~ Delta).
            let d = centred.min((delta - centred).abs());
            m = m.max(d);
        }
        m
    }

    /// Digest binding (Merkle leaves).
    pub fn digest(&self, q: i64) -> String {
        let mut input = self.u.to_bytes(q);
        input.extend_from_slice(&self.v.to_bytes(q));
        blake3::hash(&input).to_hex().to_string()
    }
}

/// Noise budget accounting for homomorphic circuits.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NoiseBudget {
    /// Worst-case noise infinity norm consumed so far.
    pub consumed: i64,
    /// The correctness ceiling (Δ/4).
    pub ceiling: i64,
}

impl NoiseBudget {
    pub fn new(params: &Params) -> Self {
        Self {
            consumed: 0,
            ceiling: params.noise_ceiling(),
        }
    }

    /// Remaining headroom.
    pub fn headroom(&self) -> i64 {
        self.ceiling - self.consumed
    }

    /// Consume; error when the budget is blown.
    pub fn consume(&mut self, amount: i64) -> Result<(), FheError> {
        self.consumed += amount;
        if self.consumed >= self.ceiling {
            return Err(FheError::Eval(format!(
                "noise budget exhausted: {amount} consumed reaches ceiling {}",
                self.ceiling
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_validate() {
        assert!(Params::default().validate().is_ok());
        assert!(
            Params {
                n: 1000,
                ..Params::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Params {
                q: 65536, // not prime
                ..Params::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn keygen_is_deterministic_per_seed() {
        let params = Params::default();
        let (pk1, sk1) = keygen_deterministic(&params, 1234);
        let (pk2, sk2) = keygen_deterministic(&params, 1234);
        assert_eq!(pk1.a, pk2.a);
        assert_eq!(pk1.b, pk2.b);
        assert_eq!(sk1.s, sk2.s);
        let (pk3, _) = keygen_deterministic(&params, 1235);
        assert_ne!(pk1.a, pk3.a);
    }

    #[test]
    fn encryption_round_trips_a_random_bit_vector() {
        let params = Params::default();
        let (pk, sk) = keygen_deterministic(&params, 99);
        let mut rng = SimRng::new(5);
        let m = Poly {
            coeffs: (0..params.n)
                .map(|_| if rng.next_f64() < 0.5 { 0 } else { 1 })
                .collect(),
        };
        let (c, _w) = encrypt(&params, &pk, &m, &mut rng);
        let m2 = c.decrypt(&params, &sk);
        assert_eq!(m, m2, "decryption must recover the plaintext exactly");
        // Noise far below the ceiling.
        let noise = c.noise_inf_norm(&params, &sk);
        assert!(
            noise < params.noise_ceiling() / 4,
            "fresh noise {noise} vs ceiling {}",
            params.noise_ceiling()
        );
    }

    #[test]
    fn encrypting_zero_gives_a_deterministic_language_member() {
        // The ZK statement: Enc(0; r, e1, e2) satisfies u = a·r+e1,
        // v = b·r+e2 exactly (no Δ term).
        let params = Params::default();
        let (pk, sk) = keygen_deterministic(&params, 21);
        let mut rng = SimRng::new(6);
        let zero = Poly::zero(params.n);
        let (c, w) = encrypt(&params, &pk, &zero, &mut rng);
        // Relation check (mod q, centred).
        let lhs_u = pk.a.mul(&w.r, params.q).add(&w.e1).centred(params.q);
        assert_eq!(lhs_u, c.u, "u = a·r + e1 must hold exactly");
        let lhs_v = pk.b.mul(&w.r, params.q).add(&w.e2).centred(params.q);
        assert_eq!(lhs_v, c.v, "v = b·r + e2 must hold (m = 0)");
        // And it decrypts to zero.
        assert!(c.decrypt(&params, &sk).coeffs.iter().all(|&b| b == 0));
    }

    #[test]
    fn wrong_key_decrypts_to_garbage() {
        let params = Params::default();
        let (pk, _sk) = keygen_deterministic(&params, 1);
        let (_other_pk, other_sk) = keygen_deterministic(&params, 2);
        let mut rng = SimRng::new(7);
        let mut m = Poly::zero(params.n);
        for c in &mut m.coeffs {
            *c = if rng.next_f64() < 0.5 { 0 } else { 1 };
        }
        let (c, _) = encrypt(&params, &pk, &m, &mut rng);
        let wrong = c.decrypt(&params, &other_sk);
        assert_ne!(m, wrong, "unrelated key must not decrypt");
    }

    #[test]
    fn noise_budget_enforcement() {
        let params = Params::default();
        let mut nb = NoiseBudget::new(&params);
        assert!(nb.headroom() > 0);
        assert!(nb.consume(100).is_ok());
        assert_eq!(nb.consumed, 100);
        let ceiling = nb.ceiling;
        assert!(nb.consume(ceiling).is_err(), "must refuse past the ceiling");
    }

    #[test]
    fn cbd_sampler_has_the_right_magnitude() {
        let params = Params::default();
        let mut rng = SimRng::new(3);
        let p = sample_cbd(&params, &mut rng);
        // CBD(3): coefficients in [-3, 3], variance 1.5.
        assert!(p.inf_norm() <= 3);
        let var: f64 = p
            .coeffs
            .iter()
            .map(|c| (*c as f64) * (*c as f64))
            .sum::<f64>()
            / params.n as f64;
        assert!((0.8..2.2).contains(&var), "CBD(3) empirical variance {var}");
    }
}
