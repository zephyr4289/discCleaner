use dc_cert::{EvidencePackageManifest, PackageArtifact, PackageVerifier};

pub struct EvidenceVerbs;

impl EvidenceVerbs {
    /// Classify trust anchor verification verdict into the 3-outcome taxonomy (Δ439).
    pub fn evaluate_tsa_verdict(has_root_in_bundle: bool, signature_valid_at_t: bool) -> &'static str {
        if !has_root_in_bundle {
            "UNKNOWN_AUTHORITY"
        } else if signature_valid_at_t {
            "VALID"
        } else {
            "INVALID"
        }
    }

    /// Package evidence directory into dc-evidence/1 manifest with cross-reference validation (Δ440).
    pub fn package_evidence(
        package_id: &str,
        artifacts: Vec<PackageArtifact>,
        signature_method: &str,
        signature_hex: &str,
        timestamp_utc: u64,
    ) -> Result<EvidencePackageManifest, &'static str> {
        let manifest = EvidencePackageManifest {
            schema: "dc-evidence/1".to_string(),
            package_id: package_id.to_string(),
            created_at_utc: timestamp_utc,
            artifacts,
            signature_method: signature_method.to_string(),
            signature_hex: signature_hex.to_string(),
        };

        PackageVerifier::verify_manifest_completeness(&manifest)?;

        Ok(manifest)
    }
}
