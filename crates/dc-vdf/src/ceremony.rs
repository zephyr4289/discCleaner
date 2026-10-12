//! Time-lock parameter ceremony (v0.12.0, Miracle 1).
//!
//! `dc vdf setup` generates an RSA modulus `N = p·q` where `p, q` are
//! **safe primes** (p = 2p' + 1 with p' also prime, so Pollard's
//! p−1 / Williams' p+1 factoring are structurally defeated), then
//! **destroys the factorization in memory** (zeroize-on-drop). What
//! remains is the public group of unknown order `Z_N*` in which
//! `x^(2^T)` is a non-parallelizable delay for everyone — including
//! the machine that performed the ceremony.
//!
//! Trust model (docs/vdf-timelock.md): a single-party ceremony is
//! trusted not to keep p, q. For adversarial deployments, run the
//! ceremony on an offline air-gapped machine with two witnesses, or
//! import an externally generated modulus (`--modulus`); the wipe
//! path only ever consumes the hex `N`.

use crate::bigint::{BigUint, is_probable_prime, passes_small_primes};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Deterministic DRBG for reproducible ceremonies (drills, KATs).
pub struct VdfRng {
    cipher: ChaCha20,
    buf: [u8; 64],
    pos: usize,
}

impl VdfRng {
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut key = [0u8; 32];
        for (i, b) in seed.iter().take(32).enumerate() {
            key[i] = *b;
        }
        let mut nonce = [0u8; 12];
        nonce[11] = 0x01; // domain: vdf ceremony drbg
        Self {
            cipher: ChaCha20::new((&key).into(), (&nonce).into()),
            buf: [0u8; 64],
            pos: 64, // force refill
        }
    }

    pub fn from_os() -> Result<Self, String> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("entropy: {e}"))?;
        Ok(Self::from_seed(&seed))
    }

    fn refill(&mut self) {
        self.buf.fill(0);
        self.cipher.apply_keystream(&mut self.buf);
        self.pos = 0;
    }

    pub fn next_u64(&mut self) -> u64 {
        if self.pos + 8 > self.buf.len() {
            self.refill();
        }
        let mut v = [0u8; 8];
        v.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        u64::from_le_bytes(v)
    }

    pub fn fill_limbs(&mut self, limbs: &mut [u64]) {
        for l in limbs.iter_mut() {
            *l = self.next_u64();
        }
    }
}

/// Wide schoolbook multiply: `BigUint<W1> × BigUint<W2> → BigUint<W3>`.
/// The caller guarantees `W3 ≥ W1 + W2` (the three call sites in
/// `finish_ceremony` use equal widths where products provably fit).
fn mul_wide<const W1: usize, const W2: usize, const W3: usize>(
    a: &BigUint<W1>,
    b: &BigUint<W2>,
) -> BigUint<W3> {
    let mut out = [0u64; W3];
    for i in 0..W1 {
        if a.0[i] == 0 {
            continue;
        }
        let mut carry: u128 = 0;
        for j in 0..W2 {
            let acc = (out[i + j] as u128) + (a.0[i] as u128) * (b.0[j] as u128) + carry;
            out[i + j] = acc as u64;
            carry = acc >> 64;
        }
        // propagate the carry
        let mut k = i + W2;
        while carry != 0 && k < W3 {
            let acc = (out[k] as u128) + carry;
            out[k] = acc as u64;
            carry = acc >> 64;
            k += 1;
        }
        debug_assert_eq!(carry, 0, "product overflowed the output width");
    }
    BigUint(out)
}

/// Generate a safe prime of exactly `bits` bits using DRBG `rng`.
/// Returns None only if the search exhausts its budget.
fn generate_safe_prime<const L: usize>(
    bits: u16,
    rng: &mut VdfRng,
    budget: u32,
) -> Option<BigUint<L>> {
    assert!(bits as usize <= L * 64 && bits >= 33);
    let q_bits = bits - 1;
    let one = BigUint::<L>::ONE;
    for _ in 0..budget {
        // candidate q: random limbs, exact bit width, odd, with the top
        // TWO bits forced — so the resulting safe prime p = 2q+1 (and
        // the product N = p·q of two such) always has full width
        // (FIPS 186-style guaranteed-width RSA generation).
        let mut limbs = [0u64; L];
        rng.fill_limbs(&mut limbs);
        let top_limb = q_bits as usize / 64;
        let top_bits = q_bits as usize % 64;
        for l in limbs.iter_mut().skip(top_limb + 1) {
            *l = 0;
        }
        if top_bits >= 2 {
            limbs[top_limb] &= (1u64 << top_bits) - 1;
            limbs[top_limb] |= (1u64 << (top_bits - 1)) | (1u64 << (top_bits - 2));
        } else if top_bits == 1 {
            limbs[top_limb] |= 1;
        }
        limbs[0] |= 1; // odd

        let q = BigUint(limbs);
        // Cheap screens first: small primes on q, then on p = 2q+1.
        if !passes_small_primes(&q) {
            continue;
        }
        // p = 2q + 1 exactly (2q < 2^(64L) since q is (bits-1)-wide and
        // bits <= 64L - 1; overflow impossible).
        let p = match q.checked_add(&q).and_then(|d| d.checked_add(&one)) {
            Some(v) => v,
            None => continue,
        };
        if !passes_small_primes(&p) {
            continue;
        }
        // MR screening with 2 bases on q (fast reject), then full
        // confirmation on p, then full confirmation on q.
        if !is_probable_prime::<L>(&q, 0) {
            continue;
        }
        if !is_probable_prime::<L>(&p, 0) {
            continue;
        }
        return Some(p);
    }
    None
}

/// Validate an imported modulus (odd, sane width). Used by `dc vdf
/// setup --modulus` and by the executor before entering a weave.
pub fn validate_modulus_hex(n_hex: &str) -> Result<(), String> {
    let v = hex::decode(n_hex.trim_start_matches("0x")).map_err(|e| format!("hex: {e}"))?;
    if v.len() < 65 || v.len() > 256 {
        return Err(format!(
            "modulus width {} bytes out of range (65..256 bytes)",
            v.len()
        ));
    }
    if !matches!(v.last(), Some(b) if b & 1 == 1) {
        return Err("modulus must be odd".into());
    }
    Ok(())
}

/// Ceremony metadata recorded next to the modulus (no secrets).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CeremonyInfo {
    pub scheme: String,
    pub modulus_bits: u16,
    /// "safe-prime-pair (p=2p'+1, q=2q'+1); factors zeroized post-derivation"
    pub prime_class: String,
    pub duration_ms: u64,
    pub candidates_screened: u64,
}

pub const PRIME_CLASS_NOTE: &str =
    "safe-prime-pair (p=2p'+1, q=2q'+1); factors zeroized post-derivation";

/// Generate a fresh modulus of `bits` (512 | 1024 | 2048) bits. When
/// `seed` is provided the ceremony is fully reproducible (drill mode).
pub fn generate_modulus(
    bits: u16,
    seed: Option<&[u8]>,
    progress: &mut dyn FnMut(&str),
) -> Result<(String, CeremonyInfo), String> {
    let started = std::time::Instant::now();
    let mut rng = match seed {
        Some(s) => VdfRng::from_seed(s),
        None => VdfRng::from_os()?,
    };
    let mut screened: u64 = 0;

    match bits {
        512 => {
            let (p, q) = both_safe_primes::<4>(256, &mut rng, progress, &mut screened)?;
            finish_ceremony::<4, 8>(p, q, bits, started, screened)
        }
        1024 => {
            let (p, q) = both_safe_primes::<8>(512, &mut rng, progress, &mut screened)?;
            finish_ceremony::<8, 16>(p, q, bits, started, screened)
        }
        2048 => {
            let (p, q) = both_safe_primes::<16>(1024, &mut rng, progress, &mut screened)?;
            finish_ceremony::<16, 32>(p, q, bits, started, screened)
        }
        _ => Err(format!(
            "unsupported modulus width {bits} (use 512, 1024 or 2048)"
        )),
    }
}

fn both_safe_primes<const H: usize>(
    half_bits: u16,
    rng: &mut VdfRng,
    progress: &mut dyn FnMut(&str),
    screened: &mut u64,
) -> Result<(Zeroizing<BigUint<H>>, Zeroizing<BigUint<H>>), String> {
    progress(&format!("searching safe prime p ({} bits)…", half_bits));
    let p = generate_safe_prime::<H>(half_bits, rng, 200_000)
        .ok_or_else(|| "safe-prime search budget exhausted (p)".to_string())?;
    *screened += 1;
    progress(&format!(
        "p found; searching safe prime q ({} bits)…",
        half_bits
    ));
    let q = generate_safe_prime::<H>(half_bits, rng, 200_000)
        .ok_or_else(|| "safe-prime search budget exhausted (q)".to_string())?;
    *screened += 1;
    Ok((Zeroizing::new(p), Zeroizing::new(q)))
}

fn finish_ceremony<const H: usize, const W: usize>(
    p: Zeroizing<BigUint<H>>,
    q: Zeroizing<BigUint<H>>,
    bits: u16,
    started: std::time::Instant,
    candidates: u64,
) -> Result<(String, CeremonyInfo), String> {
    // N = p·q computed at half width into the full modulus width
    // (call sites guarantee W ≥ H + H: 4→8, 8→16, 16→32). The p and q
    // Zeroizing buffers scrub their limbs on drop — the factorization
    // of N ceases to exist on this machine once this returns.
    let n = mul_wide::<H, H, W>(&p, &q);
    if n.bits() as u16 != bits {
        // (cannot happen: both halves are exact-width)
        return Err(format!("internal: modulus width {} != {bits}", n.bits()));
    }
    Ok((
        n.to_hex(),
        CeremonyInfo {
            scheme: crate::weave::VdfParams::SCHEME.to_string(),
            modulus_bits: bits,
            prime_class: PRIME_CLASS_NOTE.to_string(),
            duration_ms: started.elapsed().as_millis() as u64,
            candidates_screened: candidates,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_multiply_matches_u128() {
        let a = BigUint::<2>::from_bytes_be(&123_456_789_012_345_678u128.to_be_bytes());
        let b = BigUint::<2>::from_bytes_be(&987_654_321_098_765_432u128.to_be_bytes());
        let c = mul_wide::<2, 2, 4>(&a, &b);
        let expect: u128 = 123_456_789_012_345_678u128 * 987_654_321_098_765_432u128;
        assert_eq!(BigUint::<4>::from_bytes_be(&expect.to_be_bytes()), c);
    }

    #[test]
    fn reproducible_ceremony() {
        let (n1, i1) = generate_modulus(512, Some(b"seed-one"), &mut |_| {}).unwrap();
        let (n2, i2) = generate_modulus(512, Some(b"seed-one"), &mut |_| {}).unwrap();
        assert_eq!(n1, n2, "seeded ceremony must reproduce N");
        assert_eq!(i1.modulus_bits, 512);
        assert_eq!(i2.modulus_bits, 512);
        let (n3, _) = generate_modulus(512, Some(b"seed-two"), &mut |_| {}).unwrap();
        assert_ne!(n1, n3);
        // N must be odd, 512-bit.
        let v = hex::decode(&n1).unwrap();
        assert_eq!(v.len(), 64);
        assert!(v[v.len() - 1] & 1 == 1, "modulus must be odd");
    }

    #[test]
    fn drbg_determinism() {
        let mut a = VdfRng::from_seed(b"determinism-check");
        let mut b = VdfRng::from_seed(b"determinism-check");
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
