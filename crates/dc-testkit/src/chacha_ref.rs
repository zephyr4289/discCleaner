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
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            key_words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let mut nonce_words = [0u32; 3];
        for (i, chunk) in nonce.chunks_exact(4).enumerate() {
            nonce_words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        Self {
            key: key_words,
            nonce: nonce_words,
            counter,
        }
    }

    #[inline(always)]
    fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
        *a = a.wrapping_add(*b);
        *d = (*d ^ *a).rotate_left(16);
        *c = c.wrapping_add(*d);
        *b = (*b ^ *c).rotate_left(12);
        *a = a.wrapping_add(*b);
        *d = (*d ^ *a).rotate_left(8);
        *c = c.wrapping_add(*d);
        *b = (*b ^ *c).rotate_left(7);
    }

    pub fn block(&self, counter: u32) -> [u8; 64] {
        // RFC 8439 §2.3 State initialization constants "expand 32-byte k"
        let mut state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            self.key[0], self.key[1], self.key[2], self.key[3],
            self.key[4], self.key[5], self.key[6], self.key[7],
            counter, self.nonce[0], self.nonce[1], self.nonce[2],
        ];

        let mut working = state;

        // 20 rounds = 10 double rounds
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working[0], &mut working[4], &mut working[8], &mut working[12]);
            Self::quarter_round(&mut working[1], &mut working[5], &mut working[9], &mut working[13]);
            Self::quarter_round(&mut working[2], &mut working[6], &mut working[10], &mut working[14]);
            Self::quarter_round(&mut working[3], &mut working[7], &mut working[11], &mut working[15]);

            // Diagonal rounds
            Self::quarter_round(&mut working[0], &mut working[5], &mut working[10], &mut working[15]);
            Self::quarter_round(&mut working[1], &mut working[6], &mut working[11], &mut working[12]);
            Self::quarter_round(&mut working[2], &mut working[7], &mut working[8], &mut working[13]);
            Self::quarter_round(&mut working[3], &mut working[4], &mut working[9], &mut working[14]);
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
