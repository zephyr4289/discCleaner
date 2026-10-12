//! HMAC-SHA256 verification chain (v0.8.0, Vector 2).
//!
//! The defense gap this closes: on a compromised host, a ring-0 rootkit
//! can rewrite every byte the *userspace* verifier looks at — read-back
//! buffers, hash state, journal records. Software cannot attest software.
//!
//! The vault session key is generated inside the KVM enclave (under SEV/
//! TDX, transparent RAM to the guest and ciphertext to the host). The
//! verification evidence of the sanitization run is then chained with
//! `HMAC-SHA256(key, ...)`:
//!
//! ```text
//!   chain[0] = HMAC(key, "DCVAULT1" || session_fingerprint)
//!   chain[n] = HMAC(key, chain[n-1] || record[n])
//! ```
//!
//! The certificate embeds the chain head and the key fingerprint. An
//! auditor recomputing the chain from the (signed) records needs the key —
//! and the key never existed outside encrypted guest memory. A rootkit
//! that shims the verifier can produce *different* records, but then the
//! recomputed chain head will not match the certificate, and if it replays
//! the recorded chain head, its altered records cannot reproduce it.

use sha2::{Digest as _, Sha256};

const BLOCK: usize = 64;
const LABEL: &[u8] = b"DCVAULT1";

/// Plain HMAC-SHA256 (FIPS 198-1) — no external MAC crate needed.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        // Keys longer than the block get hashed first.
        let d: [u8; 32] = Sha256::digest(key).into();
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest: [u8; 32] = inner.finalize().into();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// RFC 4231 test-vector key ("Jefe").
pub fn chain_head_for(key: &[u8], session_fingerprint: &[u8]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(LABEL.len() + session_fingerprint.len());
    msg.extend_from_slice(LABEL);
    msg.extend_from_slice(session_fingerprint);
    hmac_sha256(key, &msg)
}

/// The live chain — seal verification records under the vault key.
#[derive(Clone)]
pub struct VerificationChain {
    key: [u8; 32], // derived subkey; the full 64-byte key never persists
    head: [u8; 32],
    records: u64,
}

impl VerificationChain {
    pub fn new(session_key: &[u8], session_fingerprint: &[u8]) -> Self {
        // Subkey derivation: the chain key is domain-separated from the
        // raw session key material.
        let subkey = hmac_sha256(session_key, b"DCVAULT-CHAIN-KEY");
        let head = chain_head_for(&subkey, session_fingerprint);
        Self {
            key: subkey,
            head,
            records: 0,
        }
    }

    /// Fold one record into the chain (record = canonical bytes of one
    /// pass/block verification event, in signing order).
    pub fn seal(&mut self, record: &[u8]) -> [u8; 32] {
        let mut msg = Vec::with_capacity(32 + record.len());
        msg.extend_from_slice(&self.head);
        msg.extend_from_slice(record);
        self.head = hmac_sha256(&self.key, &msg);
        self.records += 1;
        self.head
    }

    pub fn head_hex(&self) -> String {
        hex::encode(self.head)
    }

    pub fn records(&self) -> u64 {
        self.records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 §4, Test Case 2.
    #[test]
    fn hmac_matches_rfc4231_vector() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// RFC 4231 §4, Test Case 1 (key = 0x0b × 20).
    #[test]
    fn hmac_matches_rfc4231_case1() {
        let mac = hmac_sha256(&[0x0bu8; 20], b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// RFC 4231 §4, Test Case 6 (oversized key is hashed first).
    #[test]
    fn hmac_matches_rfc4231_case6() {
        let mac = hmac_sha256(
            &[0xaau8; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex::encode(mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn chain_is_order_sensitive_and_key_sensitive() {
        let mut c1 = VerificationChain::new(&[1u8; 64], b"fp");
        let mut c2 = VerificationChain::new(&[1u8; 64], b"fp");
        c1.seal(b"record-a");
        c1.seal(b"record-b");
        c2.seal(b"record-b");
        c2.seal(b"record-a");
        assert_ne!(
            c1.head_hex(),
            c2.head_hex(),
            "reordered records must diverge"
        );

        let mut c3 = VerificationChain::new(&[2u8; 64], b"fp");
        c3.seal(b"record-a");
        c3.seal(b"record-b");
        assert_ne!(
            c1.head_hex(),
            c3.head_hex(),
            "different vault keys must diverge"
        );

        // Deterministic replay: same key + same records → same head.
        let mut c4 = VerificationChain::new(&[1u8; 64], b"fp");
        c4.seal(b"record-a");
        c4.seal(b"record-b");
        assert_eq!(c1.head_hex(), c4.head_hex());
        assert_eq!(c4.records(), 2);
    }
}
