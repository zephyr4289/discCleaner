use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cert2Document {
    pub schema_version: u32,
    pub target_device: String,
    pub target_serial: String,
    pub nist_sanitization_class: String,
    pub executed_mechanisms: Vec<String>,
    pub interrogation_contract: Option<String>,
    pub issued_at_utc: u64,
}
