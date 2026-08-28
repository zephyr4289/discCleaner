//! Official Known Answer Tests (KATs) for RFC 8439 and BLAKE3

use crate::chacha_ref::ChaCha20Ref;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

pub struct KnownAnswerTests;

impl KnownAnswerTests {
    /// RFC 8439 §2.3.2 Block Function Test Vector
    pub fn verify_rfc8439_block_vector() -> Result<(), String> {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1u32;

        let expected_hex = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3e459fa4fa9109b4ac52774054a778c7294e88380d18d5beae199e122ec92ac41da7f3d";

        let chacha = ChaCha20Ref::new(&key, &nonce, counter);
        let block = chacha.block(counter);
        let block_hex = hex::encode(block);

        if block_hex != expected_hex {
            return Err(format!(
                "ChaCha20Ref RFC 8439 §2.3.2 block mismatch! Computed: {}, Expected: {}",
                block_hex, expected_hex
            ));
        }

        // Also verify through tool's chacha20 crate dependency path (Δ58)
        let mut dep_cipher = ChaCha20::new((&key).into(), (&nonce).into());
        let mut buf = [0u8; 64];
        // Apply block 1 (seek to block 1)
        use chacha20::cipher::StreamCipherSeek;
        dep_cipher.seek(64);
        dep_cipher.apply_keystream(&mut buf);
        let dep_hex = hex::encode(buf);
        if dep_hex != expected_hex {
            return Err(format!(
                "chacha20 crate RFC 8439 §2.3.2 block mismatch! Computed: {}, Expected: {}",
                dep_hex, expected_hex
            ));
        }

        Ok(())
    }

    /// Official BLAKE3 Test Vector on empty string
    pub fn verify_blake3_kat() -> Result<(), String> {
        let expected_empty_hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let computed = blake3::hash(b"").to_hex().to_string();

        if computed != expected_empty_hash {
            return Err(format!(
                "BLAKE3 KAT mismatch! Computed: {}, Expected: {}",
                computed, expected_empty_hash
            ));
        }

        Ok(())
    }
}
