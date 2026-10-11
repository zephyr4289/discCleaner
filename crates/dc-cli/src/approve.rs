use dc_cert::{AuthSignatureEntry, OperatorKeyPair, FLEET_MANIFEST_DOMAIN, PLAN_APPROVAL_DOMAIN};
use ed25519_dalek::Signer;

pub struct PlanApprover;

impl PlanApprover {
    /// Countersign a compiled plan specification before Arm (Δ448).
    ///
    /// SECURITY (regression `REG-DUALAUTH-FORGERY`): this is a REAL Ed25519
    /// signature by `keypair` over `DC-2PI1-APPROVE-PLAN || plan_hash`.
    /// The historical implementation "signed" by hashing the public strings
    /// `format!("APPROVE_PLAN_{}_BY_{}", plan_hash, key_hash)` with BLAKE3 —
    /// a value anyone could compute without possessing any key, which made
    /// the two-person-integrity gate forgeable by construction.
    pub fn countersign_plan(
        plan_hash: &str,
        keypair: &OperatorKeyPair,
        is_hardware_token: bool,
    ) -> AuthSignatureEntry {
        let msg = AuthSignatureEntry::approval_message(PLAN_APPROVAL_DOMAIN, plan_hash);
        let sig = keypair.signing_key.sign(&msg);

        AuthSignatureEntry {
            key_fingerprint: keypair.key_fingerprint_blake3(),
            public_key_hex: keypair.public_key_hex(),
            signature_hex: hex::encode(sig.to_bytes()),
            is_hardware_token,
        }
    }

    /// Countersign a fleet manifest at batch commit (Δ454). Same cryptographic
    /// construction as `countersign_plan`, under the manifest domain so a
    /// plan approval can never be replayed as a manifest approval.
    pub fn countersign_fleet_manifest(
        manifest_hash: &str,
        keypair: &OperatorKeyPair,
        is_hardware_token: bool,
    ) -> AuthSignatureEntry {
        let msg = AuthSignatureEntry::approval_message(FLEET_MANIFEST_DOMAIN, manifest_hash);
        let sig = keypair.signing_key.sign(&msg);

        AuthSignatureEntry {
            key_fingerprint: keypair.key_fingerprint_blake3(),
            public_key_hex: keypair.public_key_hex(),
            signature_hex: hex::encode(sig.to_bytes()),
            is_hardware_token,
        }
    }
}
