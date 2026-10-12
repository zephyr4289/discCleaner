//! HMAC-SHA256 (RFC 2104) — the MAC under AWS Signature Version 4.
//! Workspace `sha2` provides the compression function; the construction is
//! spelled out here so the signing ladder has no hidden layers.

use sha2::{Digest, Sha256};

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // Keys longer than the block size are hashed first (RFC 2104 §2);
    // AWS keys never exceed it, but the rule costs two lines.
    let key_block = if key.len() > 64 {
        let h = Sha256::digest(key);
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&h);
        b
    } else {
        let mut b = [0u8; 64];
        b[..key.len()].copy_from_slice(key);
        b
    };

    let mut inner = Sha256::new();
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&out);
    mac
}

/// Hex-encoded SHA-256 (SigV4 canonical hashes).
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 1 — HMAC-SHA256 with a 20-byte key.
    #[test]
    fn rfc4231_case_1() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// RFC 4231 test case 2 — HMAC-SHA256 with an ASCII key ("Jefe").
    #[test]
    fn rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// SHA-256 of the empty string — the canonical SigV4 empty-payload hash.
    #[test]
    fn empty_sha256() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
