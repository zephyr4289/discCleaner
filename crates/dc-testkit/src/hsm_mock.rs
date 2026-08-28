use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HsmKeyType {
    Ed25519,
    EcdsaSecp256r1,
}

pub struct HsmMock {
    pub key_type: HsmKeyType,
    pub pin_secret: String,
}

impl HsmMock {
    pub fn new(key_type: HsmKeyType, pin: &str) -> Self {
        Self {
            key_type,
            pin_secret: pin.to_string(),
        }
    }

    /// Sign canonical document through hardware security module (Δ429, Δ431).
    pub fn sign_canonical(
        &self,
        doc_bytes: &[u8],
        candidate_pin: &str,
    ) -> Result<String, &'static str> {
        // 1. PIN Authentication
        if candidate_pin != self.pin_secret {
            return Err("PIN_REJECTED");
        }

        // 2. Algorithm Policy: Refuse nondeterministic ECDSA (Δ429)
        if self.key_type == HsmKeyType::EcdsaSecp256r1 {
            return Err("ECDSA_NONDETERMINISTIC_SIGNATURES_REFUSED");
        }

        // 3. Deterministic Ed25519 signing (RFC 8032)
        let doc_hash = blake3::hash(doc_bytes);
        let signature_hex = format!("ED25519_SIG_{}", doc_hash.to_hex());

        Ok(signature_hex)
    }
}
