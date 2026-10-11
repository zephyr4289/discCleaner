use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Domain-separation prefix for plan approvals (prevents cross-protocol
/// signature replay: a fleet-manifest signature can never validate as a
/// plan approval).
pub const PLAN_APPROVAL_DOMAIN: &[u8] = b"DC-2PI1-APPROVE-PLAN";

/// Domain-separation prefix for fleet-manifest approvals.
pub const FLEET_MANIFEST_DOMAIN: &[u8] = b"DC-2PI1-APPROVE-MANIFEST";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyType {
    SeparateHardware,
    SharedFilesystem,
}

/// One officer's countersignature over a plan (or manifest) hash.
///
/// SECURITY MODEL: `signature_hex` is a REAL Ed25519 signature by the key in
/// `public_key_hex` over `domain || bound_hash`, and `key_fingerprint` must
/// equal BLAKE3(public_key). The historical struct carried only
/// `key_hash` + a BLAKE3 hash of public strings — anyone could forge an
/// "authorization" by hashing words together, and `verify_pre_arm_authorization`
/// never checked any cryptography at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSignatureEntry {
    /// BLAKE3(public_key) hex — must match `public_key_hex` (anti-spoofing).
    pub key_fingerprint: String,
    /// Ed25519 public key of the authorizing officer (hex).
    pub public_key_hex: String,
    /// Ed25519 signature over `domain || bound_hash` (hex).
    pub signature_hex: String,
    /// Whether the signature originated from a hardware token (HSM/PIV).
    pub is_hardware_token: bool,
}

impl AuthSignatureEntry {
    /// Canonical message signed for an approval: `domain || hash_hex`.
    pub fn approval_message(domain: &[u8], hash_hex: &str) -> Vec<u8> {
        let mut msg = Vec::with_capacity(domain.len() + hash_hex.len());
        msg.extend_from_slice(domain);
        msg.extend_from_slice(hash_hex.as_bytes());
        msg
    }

    /// Cryptographically verify this countersignature against its own key.
    ///
    /// Checks (in order): key fingerprint binding, Ed25519 signature over
    /// the domain-separated message.
    pub fn verify(&self, domain: &[u8], bound_hash: &str) -> Result<(), &'static str> {
        // 1. Fingerprint must bind to the actual public key (an attacker must
        //    not be able to present a stolen signature under a spoofed
        //    fingerprint). Fingerprints are BLAKE3 of the RAW key bytes,
        //    exactly like `OperatorKeyPair::key_fingerprint_blake3`.
        let pubkey_bytes =
            hex::decode(&self.public_key_hex).map_err(|_| "PUBLIC_KEY_MALFORMED_HEX")?;
        if pubkey_bytes.len() != 32 {
            return Err("PUBLIC_KEY_WRONG_LENGTH");
        }
        let fingerprint = blake3::hash(&pubkey_bytes).to_hex().to_string();
        if !constant_time_eq_hex(&fingerprint, &self.key_fingerprint) {
            return Err("KEY_FINGERPRINT_MISMATCH");
        }

        // 2. The signature must be a valid Ed25519 signature by that key over
        //    the domain-separated approval message.
        let vk = parse_verifying_key(&self.public_key_hex)?;
        let sig_bytes = hex::decode(&self.signature_hex).map_err(|_| "SIGNATURE_MALFORMED_HEX")?;
        if sig_bytes.len() != 64 {
            return Err("SIGNATURE_WRONG_LENGTH");
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&arr);

        let msg = Self::approval_message(domain, bound_hash);
        vk.verify(&msg, &sig).map_err(|_| "SIGNATURE_INVALID")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationSet {
    pub bound_plan_hash: String,
    pub signatures: Vec<AuthSignatureEntry>,
}

impl AuthorizationSet {
    pub fn new(plan_hash: &str) -> Self {
        Self {
            bound_plan_hash: plan_hash.to_string(),
            signatures: Vec::new(),
        }
    }

    pub fn add_signature(&mut self, sig: AuthSignatureEntry) {
        self.signatures.push(sig);
    }

    /// Derive custody type based on signing source characteristics (Δ455).
    pub fn derive_custody_type(&self) -> CustodyType {
        if self.signatures.len() >= 2 && self.signatures.iter().all(|s| s.is_hardware_token) {
            CustodyType::SeparateHardware
        } else {
            CustodyType::SharedFilesystem
        }
    }

    /// Number of DISTINCT authorizing keys present in the set.
    pub fn distinct_key_count(&self) -> usize {
        self.signatures
            .iter()
            .map(|s| s.public_key_hex.as_str())
            .collect::<HashSet<_>>()
            .len()
    }

    /// Verify pre-Arm authorization gating (Δ448).
    ///
    /// SECURITY CONTRACT (regression `REG-DUALAUTH-FORGERY`):
    /// 1. The set's `bound_plan_hash` must equal the plan hash being armed
    ///    (binding: an approval for plan A can never authorize plan B).
    /// 2. EVERY countersignature must cryptographically verify as a real
    ///    Ed25519 signature over `PLAN_APPROVAL_DOMAIN || plan_hash`.
    ///    Unsigned garbage no longer passes.
    /// 3. Under two-person-integrity policy, at least `require_two_person`
    ///    DISTINCT keys must have signed — one officer signing twice with
    ///    two fingerprints was never two-person control.
    pub fn verify_pre_arm_authorization(
        &self,
        expected_plan_hash: &str,
        require_two_person: bool,
    ) -> Result<CustodyType, &'static str> {
        // 1. Plan hash binding
        if self.bound_plan_hash != expected_plan_hash {
            return Err("PLAN_HASH_BINDING_MISMATCH");
        }

        // 2. Cryptographic verification of every countersignature
        for sig in &self.signatures {
            sig.verify(PLAN_APPROVAL_DOMAIN, expected_plan_hash)?;
        }

        // 3. Enforce 2PI on DISTINCT keys
        if require_two_person && self.distinct_key_count() < 2 {
            return Err("AUTHORIZATION_INCOMPLETE");
        }

        Ok(self.derive_custody_type())
    }

    /// Verify a fleet-manifest approval set (same rules, manifest domain).
    pub fn verify_fleet_manifest_authorization(
        &self,
        expected_manifest_hash: &str,
        require_two_person: bool,
    ) -> Result<CustodyType, &'static str> {
        if self.bound_plan_hash != expected_manifest_hash {
            return Err("PLAN_HASH_BINDING_MISMATCH");
        }
        for sig in &self.signatures {
            sig.verify(FLEET_MANIFEST_DOMAIN, expected_manifest_hash)?;
        }
        if require_two_person && self.distinct_key_count() < 2 {
            return Err("AUTHORIZATION_INCOMPLETE");
        }
        Ok(self.derive_custody_type())
    }
}

fn parse_verifying_key(hex_key: &str) -> Result<VerifyingKey, &'static str> {
    let bytes = hex::decode(hex_key).map_err(|_| "PUBLIC_KEY_MALFORMED_HEX")?;
    if bytes.len() != 32 {
        return Err("PUBLIC_KEY_WRONG_LENGTH");
    }
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "PUBLIC_KEY_WRONG_LENGTH")?;
    VerifyingKey::from_bytes(&arr).map_err(|_| "PUBLIC_KEY_INVALID")
}

/// Constant-time hex string comparison (both inputs are BLAKE3 hex digests,
/// but comparing secrets should never early-exit on the first differing
/// character as a habit).
fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0 && !a.is_empty()
}
