//! Deterministic PRNG (xorshift64*) for reproducible rig scenarios.
//!
//! Every simulated dead drive is built from a seed so a given demo session can
//! be replayed byte-for-byte: NAND contents, bad-block placement, marginal
//! erase blocks and the proof sampler all draw from one stream.

#[derive(Clone)]
pub struct XorShift {
    state: u64,
}

impl XorShift {
    pub fn new(seed: u64) -> Self {
        XorShift {
            state: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next_u64() % n
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next_u64().to_le_bytes();
            let take = (buf.len() - i).min(8);
            buf[i..i + take].copy_from_slice(&v[..take]);
            i += take;
        }
    }

    /// ASCII-flavoured "classified" fill: high-entropy bytes with occasional
    /// plaintext markers, so pre-erasure dumps look like a real filesystem.
    pub fn fill_forensic(&mut self, buf: &mut [u8]) {
        self.fill(buf);
        // ~1 in 64 pages gets a recognizable marker block.
        for chunk in buf.chunks_mut(64) {
            if self.below(64) == 0 && chunk.len() >= 8 {
                chunk[..7].copy_from_slice(b"TOPSECR");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let mut a = XorShift::new(42);
        let mut b = XorShift::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = XorShift::new(43);
        assert_ne!(XorShift::new(42).next_u64(), c.next_u64());
    }

    #[test]
    fn nonzero_state_always() {
        assert_ne!(XorShift::new(0).next_u64(), 0);
        assert_ne!(XorShift::new(u64::MAX).next_u64(), 0);
    }
}
