use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpalSscType {
    Opal2_0,
    Pyrite,
    Enterprise,
    Unknown,
}

pub struct DiscoveryTree;

impl DiscoveryTree {
    /// Classify Level 0 Discovery response into SSC feature profile (Δ359).
    pub fn classify_level0(feature_code: u16) -> OpalSscType {
        match feature_code {
            0x0200 | 0x0203 => OpalSscType::Opal2_0,
            0x0302 | 0x0303 => OpalSscType::Pyrite,
            0x0100 => OpalSscType::Enterprise,
            _ => OpalSscType::Unknown,
        }
    }
}
