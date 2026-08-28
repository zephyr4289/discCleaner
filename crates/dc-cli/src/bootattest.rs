use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstituentsManifest {
    pub kernel_hash: String,
    pub initramfs_hash: String,
    pub binary_hash: String,
    pub census_manifest_hash: String,
}

impl ConstituentsManifest {
    /// Compute cryptographic BLAKE3 hash of all image constituents (Δ412).
    pub fn compute_constituents_hash(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.kernel_hash.as_bytes());
        hasher.update(self.initramfs_hash.as_bytes());
        hasher.update(self.binary_hash.as_bytes());
        hasher.update(self.census_manifest_hash.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}
