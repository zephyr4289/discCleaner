use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadOnlyCandidate {
    pub device_nodes: Vec<String>, // e.g. ["/dev/sr0", "/dev/sdb"] in hybrid setups
    pub marker_content_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootAttestation {
    pub matched: bool,
    pub protected_nodes: Vec<String>,
    pub marker_hash: String,
    pub method: String,
}

pub struct BootAttestor;

impl BootAttestor {
    /// Content-based boot-medium attestation with hybrid node registration (Δ414).
    pub fn attest_boot_medium(
        candidates: &[ReadOnlyCandidate],
        expected_marker_hash: &str,
    ) -> BootAttestation {
        let mut protected = Vec::new();
        let mut matched = false;

        for cand in candidates {
            // Require exact full-hash match (no prefix mercy)
            if cand.marker_content_hash == expected_marker_hash {
                matched = true;
                for node in &cand.device_nodes {
                    if !protected.contains(node) {
                        protected.push(node.clone());
                    }
                }
            }
        }

        BootAttestation {
            matched,
            protected_nodes: protected,
            marker_hash: expected_marker_hash.to_string(),
            method: "ContentHashConstituentsManifest".to_string(),
        }
    }
}
