use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningSiteId {
    ExecuteCert,
    ReconstructCert,
    FleetReport,
    StickInstallCert,
    EvidencePackage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningKeySourceKind {
    KeyFile { path: String },
    Hsm { interface: String, touch_required: bool },
}

pub struct KeyStoreRegistry;

impl KeyStoreRegistry {
    /// Derive signature_method disclosure strictly from concrete source instance (Δ436).
    pub fn derive_signature_method(src_kind: &SigningKeySourceKind) -> String {
        match src_kind {
            SigningKeySourceKind::KeyFile { .. } => "ed25519-keyfile".to_string(),
            SigningKeySourceKind::Hsm { interface, touch_required } => {
                format!("ed25519-hsm-{}-touch:{}", interface, touch_required)
            }
        }
    }
}
