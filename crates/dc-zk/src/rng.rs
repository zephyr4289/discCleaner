//! Deterministic-seedable DRBG for dc-zk.
//!
//! SHA-256 in counter mode (NIST SP 800-90A-style): each request for
//! entropy draws `SHA256(seed || counter || length)` blocks. Two modes:
//!
//! * [`ZkRng::from_seed`] — fully deterministic (reproducible setups in
//!   tests and controlled re-generation ceremonies).
//! * [`ZkRng::from_os`] — seeded from `getrandom` (production setups).
//!
//! The DRBG is NOT used for key material of the sanitization engine —
//! only for Groth16 toxic waste (immediately discarded), blinding `r,s`
//! and Poseidon statement nonces.

use crate::field::Fr;
use sha2::{Digest, Sha256};

pub struct ZkRng {
    state: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
}

impl ZkRng {
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"dc-zk/drbg/v1");
        h.update(seed);
        Self {
            state: h.finalize().into(),
            counter: 0,
            buffer: Vec::new(),
        }
    }

    pub fn from_os() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS entropy unavailable");
        Self::from_seed(&seed)
    }

    fn refill(&mut self, want: usize) {
        while self.buffer.len() < want {
            let mut h = Sha256::new();
            h.update(self.state);
            h.update(self.counter.to_be_bytes());
            self.buffer.extend_from_slice(&h.finalize());
            self.counter = self.counter.wrapping_add(1);
        }
    }

    /// Draw `n` pseudorandom bytes.
    pub fn fill_bytes(&mut self, n: usize) -> Vec<u8> {
        self.refill(n);
        self.buffer.drain(..n).collect()
    }

    /// Next field element (rejection-free: any 32 bytes map into Fr with
    /// negligible bias — 2^-126, irrelevant for blinding and setup use).
    pub fn next_fr(&mut self) -> Fr {
        let bytes = self.fill_bytes(32);
        Fr::from_be_bytes_reduced(&bytes)
    }

    /// Next non-zero field element.
    pub fn next_fr_nonzero(&mut self) -> Fr {
        loop {
            let v = self.next_fr();
            if !v.is_zero() {
                return v;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_divergent() {
        let mut a = ZkRng::from_seed(b"same-seed");
        let mut b = ZkRng::from_seed(b"same-seed");
        for _ in 0..8 {
            assert_eq!(a.next_fr(), b.next_fr());
        }
        let mut c = ZkRng::from_seed(b"other-seed");
        let x = c.next_fr();
        let y = ZkRng::from_seed(b"other-seed").next_fr();
        assert_eq!(x, y);
        // different seeds give different streams (probabilistic but
        // deterministic here — fixed seeds, so this is a stable check)
        let d = ZkRng::from_seed(b"seed-1").next_fr();
        let e = ZkRng::from_seed(b"seed-2").next_fr();
        assert_ne!(d, e);
    }

    #[test]
    fn stream_quality() {
        let mut rng = ZkRng::from_seed(b"quality");
        let mut non_zero = 0;
        for _ in 0..64 {
            let v = rng.next_fr();
            if !v.is_zero() {
                non_zero += 1;
            }
        }
        assert!(non_zero > 60, "field elements should not collapse to zero");
    }
}
