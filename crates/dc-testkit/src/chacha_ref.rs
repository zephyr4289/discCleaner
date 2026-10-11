//! Hand-rolled RFC 8439 ChaCha20 Reference Implementation
//! Pure Rust, zero external crypto crates, explicit Little-Endian semantics.

pub struct ChaCha20Ref {
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
}

impl ChaCha20Ref {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut key_words = [0u32; 8];
        for (i, w) in key_words.iter_mut().enumerate() {
            *w = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }

        let mut nonce_words = [0u32; 3];
        for (i, w) in nonce_words.iter_mut().enumerate() {
            *w = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
        }

        Self {
            key: key_words,
            nonce: nonce_words,
            counter,
        }
    }

    /// One ChaCha20 quarter round over state slots (a, b, c, d).
    ///
    /// Takes INDICES into the 16-word working state rather than four
    /// `&mut u32` references — the reference form cannot express "four
    /// distinct slots of the same array" to the borrow checker (E0499),
    /// which previously left this rig uncompilable.
    #[inline(always)]
    fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    }

    pub fn block(&self, counter: u32) -> [u8; 64] {
        // RFC 8439 §2.3 State initialization constants "expand 32-byte k"
        let state = [
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574,
            self.key[0],
            self.key[1],
            self.key[2],
            self.key[3],
            self.key[4],
            self.key[5],
            self.key[6],
            self.key[7],
            counter,
            self.nonce[0],
            self.nonce[1],
            self.nonce[2],
        ];

        let mut working = state;

        // 20 rounds = 10 double rounds
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);

            // Diagonal rounds
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        let mut out = [0u8; 64];
        for i in 0..16 {
            let sum = working[i].wrapping_add(state[i]);
            out[i * 4..(i + 1) * 4].copy_from_slice(&sum.to_le_bytes());
        }

        out
    }

    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        let mut offset = 0;
        while offset < buf.len() {
            let block = self.block(self.counter);
            self.counter = self.counter.wrapping_add(1);

            let take = (buf.len() - offset).min(64);
            for i in 0..take {
                buf[offset + i] ^= block[i];
            }
            offset += take;
        }
    }
}
