use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyType {
    SeparateHardware,
    SharedFilesystem,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSignatureEntry {
    pub key_hash: String,
    pub signature_hex: String,
    pub is_hardware_token: bool,
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

    /// Verify pre-Arm authorization gating (Δ448).
    pub fn verify_pre_arm_authorization(
        &self,
        expected_plan_hash: &str,
        require_two_person: bool,
    ) -> Result<CustodyType, &'static str> {
        // 1. Check plan hash binding
        if self.bound_plan_hash != expected_plan_hash {
            return Err("PLAN_HASH_BINDING_MISMATCH");
        }

        // 2. Enforce 2PI signature count
        if require_two_person && self.signatures.len() < 2 {
            return Err("AUTHORIZATION_INCOMPLETE");
        }

        Ok(self.derive_custody_type())
    }
}
