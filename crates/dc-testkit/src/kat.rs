//! Official Known Answer Tests (KATs) for RFC 8439, RFC 8032, RFC 8785, and BLAKE3

use crate::chacha_ref::ChaCha20Ref;
use crate::jcs_ref::JcsRef;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

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

    /// RFC 8032 §7.1 Test Vector 1 (PureEd25519)
    pub fn verify_rfc8032_ed25519_kat() -> Result<(), String> {
        let priv_seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let expected_pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let msg = b"";
        let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

        let signing_key = SigningKey::from_bytes(priv_seed.as_slice().try_into().unwrap());
        let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
        if pub_hex != expected_pub {
            return Err(format!("Ed25519 public key mismatch! Computed: {}, Expected: {}", pub_hex, expected_pub));
        }

        let sig = signing_key.sign(msg);
        let sig_hex = hex::encode(sig.to_bytes());
        if sig_hex != expected_sig {
            return Err(format!("Ed25519 signature mismatch! Computed: {}, Expected: {}", sig_hex, expected_sig));
        }

        let vk: VerifyingKey = signing_key.verifying_key();
        if vk.verify(msg, &sig).is_err() {
            return Err("Ed25519 self-verification failed on RFC 8032 KAT!".to_string());
        }

        Ok(())
    }

    /// RFC 8785 §3.2.3 JCS Sorting & Escaping Test Vector
    pub fn verify_rfc8785_jcs_examples() -> Result<(), String> {
        let input_json = r#"{"b": 1, "a": 2, "c": [3, 2, 1]}"#;
        let expected_canonical = r#"{"a":2,"b":1,"c":[3,2,1]}"#;

        let val: serde_json::Value = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
        let computed = JcsRef::canonicalize(&val)?;

        if computed != expected_canonical {
            return Err(format!(
                "JCS canonicalization mismatch! Computed: '{}', Expected: '{}'",
                computed, expected_canonical
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
