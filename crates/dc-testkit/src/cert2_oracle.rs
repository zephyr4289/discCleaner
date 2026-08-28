use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NistSanitizationClass {
    Clear = 1,
    Purge = 2,
    Destroy = 3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedMechanism {
    pub name: String,
    pub nist_class: NistSanitizationClass,
    pub tool_verified: bool,
    pub controller_attested: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterrogationContract {
    pub log_page_id: u8,
    pub raw_bytes_hex: String,
    pub blake3_hash: String,
    pub verification_command: String,
    pub expected_sstat: u16,
}

pub struct Cert2Oracle;

impl Cert2Oracle {
    /// Calculate composite NIST sanitization classification as min over executed mechanisms (Δ308, INV13).
    pub fn derive_min_nist_class(executed: &[ExecutedMechanism]) -> NistSanitizationClass {
        if executed.is_empty() {
            return NistSanitizationClass::Clear;
        }

        executed
            .iter()
            .map(|m| m.nist_class)
            .min()
            .unwrap_or(NistSanitizationClass::Clear)
    }

    /// Verify an auditor interrogation contract against live controller observations (Δ310).
    pub fn verify_interrogation_contract(
        contract: &InterrogationContract,
        observed_sstat: u16,
        observed_raw_bytes: &[u8],
    ) -> bool {
        let observed_hash = blake3::hash(observed_raw_bytes).to_hex().to_string();
        contract.expected_sstat == observed_sstat && contract.blake3_hash == observed_hash
    }
}
