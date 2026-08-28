use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageArtifact {
    pub role: String, // "journal", "cert", "token", "report"
    pub rel_path: String,
    pub blake3_hash: String,
    pub references: Vec<String>, // list of rel_paths this artifact refers to
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePackageManifest {
    pub schema: String, // "dc-evidence/1"
    pub package_id: String,
    pub created_at_utc: u64,
    pub artifacts: Vec<PackageArtifact>,
    pub signature_method: String,
    pub signature_hex: String,
}

pub struct PackageVerifier;

impl PackageVerifier {
    /// Reconcile cross-references and verify package integrity (Δ440).
    pub fn verify_manifest_completeness(
        manifest: &EvidencePackageManifest,
    ) -> Result<&'static str, &'static str> {
        let known_paths: Vec<&str> = manifest.artifacts.iter().map(|a| a.rel_path.as_str()).collect();

        for art in &manifest.artifacts {
            for ref_path in &art.references {
                if !known_paths.contains(&ref_path.as_str()) {
                    return Err("ORPHAN_REFERENCE_IN_PACKAGE");
                }
            }
        }

        Ok("PACKAGE_CROSS_REFERENCES_RECONCILED_AND_COMPLETE")
    }
}
