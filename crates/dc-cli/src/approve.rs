use dc_cert::AuthSignatureEntry;

pub struct PlanApprover;

impl PlanApprover {
    /// Countersign a compiled plan specification before Arm (Δ448).
    pub fn countersign_plan(plan_hash: &str, key_hash: &str, is_hsm: bool) -> AuthSignatureEntry {
        let sig_payload = format!("APPROVE_PLAN_{}_BY_{}", plan_hash, key_hash);
        let sig_hex = blake3::hash(sig_payload.as_bytes()).to_hex().to_string();

        AuthSignatureEntry {
            key_hash: key_hash.to_string(),
            signature_hex: sig_hex,
            is_hardware_token: is_hsm,
        }
    }

    /// Countersign a fleet manifest at batch commit (Δ454).
    pub fn countersign_fleet_manifest(
        manifest_hash: &str,
        key_hash: &str,
        is_hsm: bool,
    ) -> AuthSignatureEntry {
        let sig_payload = format!("APPROVE_MANIFEST_{}_BY_{}", manifest_hash, key_hash);
        let sig_hex = blake3::hash(sig_payload.as_bytes()).to_hex().to_string();

        AuthSignatureEntry {
            key_hash: key_hash.to_string(),
            signature_hex: sig_hex,
            is_hardware_token: is_hsm,
        }
    }
}
