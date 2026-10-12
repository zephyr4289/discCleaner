//! ZK audit receipts: the portable artifact a regulator/customer verifies.

use crate::circuit::{
    CIRCUIT_ID, ComplianceStatement, ComplianceWitness, NUM_PUBLIC, audit_root_of, vk_commitment_of,
};
use crate::field::Fr;
use crate::groth16::{self, Proof, ProvingKey, VerifyingKey, ZkError};
use crate::rng::ZkRng;
use serde::{Deserialize, Serialize};

/// A verifiable zero-knowledge compliance receipt.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct ZkReceipt {
    pub schema: String,
    pub circuit_id: String,
    pub scheme: String,
    /// Groth16 proof (compressed points: 48 + 96 + 48 = 192 bytes).
    pub proof: Proof,
    /// The public statement (hex, canonical Fr encodings, 5 × 32 bytes).
    pub statement: PublicStatementHex,
    /// BLAKE3 of the canonical verifying key — binds the receipt to the
    /// exact key generation that produced it.
    pub vk_fingerprint: String,
    /// BLAKE3 of the SanitizationCertificate this receipt accompanies
    /// (the evidence-chain splice point; see docs/zk-audit.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_hash: Option<String>,
    /// Blake3 of the audit-log the witness was derived from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log_hash: Option<String>,
    pub generated_at_unix: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PublicStatementHex {
    pub profile_hash: String,
    pub tenant_id: String,
    pub ts: String,
    pub vk_commitment: String,
    pub audit_root: String,
}

impl PublicStatementHex {
    pub fn from_statement(s: &ComplianceStatement) -> Self {
        Self {
            profile_hash: hex::encode(s.profile_hash.to_be_bytes()),
            tenant_id: hex::encode(s.tenant_id.to_be_bytes()),
            ts: hex::encode(s.ts.to_be_bytes()),
            vk_commitment: hex::encode(s.vk_commitment.to_be_bytes()),
            audit_root: hex::encode(s.audit_root.to_be_bytes()),
        }
    }

    pub fn to_statement(&self) -> Option<ComplianceStatement> {
        Some(ComplianceStatement {
            profile_hash: Fr::from_be_bytes_reduced(&hex::decode(&self.profile_hash).ok()?),
            tenant_id: Fr::from_be_bytes_reduced(&hex::decode(&self.tenant_id).ok()?),
            ts: Fr::from_be_bytes_reduced(&hex::decode(&self.ts).ok()?),
            vk_commitment: Fr::from_be_bytes_reduced(&hex::decode(&self.vk_commitment).ok()?),
            audit_root: Fr::from_be_bytes_reduced(&hex::decode(&self.audit_root).ok()?),
        })
    }
}

/// Fingerprint a verifying key (BLAKE3 over its canonical JSON).
pub fn vk_fingerprint(vk: &VerifyingKey) -> String {
    let canon = serde_json::to_string(vk).unwrap_or_default();
    let mut h = blake3::Hasher::new();
    h.update(canon.as_bytes());
    h.update(vk.circuit_id.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

/// Prove compliance: statement + witness → receipt.
pub fn prove_compliance(
    pk: &ProvingKey,
    stmt: &ComplianceStatement,
    w: &ComplianceWitness,
    rng: &mut ZkRng,
    certificate_hash: Option<String>,
    audit_log_hash: Option<String>,
) -> Result<ZkReceipt, ZkError> {
    if pk.vk.circuit_id != CIRCUIT_ID {
        return Err(ZkError::MalformedKeys(format!(
            "proving key is for circuit {}, expected {}",
            pk.vk.circuit_id, CIRCUIT_ID
        )));
    }
    // cross-check the statement's derived roots against the witness
    let root = audit_root_of(w, stmt);
    let vk_c = vk_commitment_of(&w.operator_secret, &w.nonce);
    if root != stmt.audit_root {
        return Err(ZkError::Unsatisfied(
            "statement audit_root does not match the witness".into(),
        ));
    }
    if vk_c != stmt.vk_commitment {
        return Err(ZkError::Unsatisfied(
            "statement vk_commitment does not match the operator secret".into(),
        ));
    }
    let cs = crate::circuit::compliance_circuit();
    let witness = crate::circuit::build_witness(stmt, w);
    let proof = groth16::prove(&cs, pk, &witness, rng)?;
    Ok(ZkReceipt {
        schema: "dc-zk/receipt/v1".to_string(),
        circuit_id: CIRCUIT_ID.to_string(),
        scheme: "groth16-bls12-381".to_string(),
        proof,
        statement: PublicStatementHex::from_statement(stmt),
        vk_fingerprint: vk_fingerprint(&pk.vk),
        certificate_hash,
        audit_log_hash,
        generated_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

/// Outcome of receipt verification.
#[derive(Debug, PartialEq)]
pub struct ReceiptVerification {
    pub is_valid: bool,
    pub circuit_id: String,
    pub scheme: String,
    pub proof_verified: bool,
    pub vk_fingerprint_matches: bool,
    pub statement: Option<ComplianceStatement>,
    pub generated_at_unix: u64,
    pub error: Option<String>,
}

/// Verify a receipt against a verifying key (and an expected key
/// fingerprint when the caller pins the trusted setup).
pub fn verify_receipt(vk: &VerifyingKey, receipt: &ZkReceipt) -> ReceiptVerification {
    let mk = |proof_verified: bool, error: Option<String>| ReceiptVerification {
        is_valid: proof_verified && error.is_none(),
        circuit_id: receipt.circuit_id.clone(),
        scheme: receipt.scheme.clone(),
        proof_verified,
        vk_fingerprint_matches: receipt.vk_fingerprint == vk_fingerprint(vk),
        statement: receipt.statement.to_statement(),
        generated_at_unix: receipt.generated_at_unix,
        error,
    };
    if receipt.circuit_id != vk.circuit_id {
        return mk(
            false,
            Some(format!(
                "circuit id mismatch: receipt {} vs key {}",
                receipt.circuit_id, vk.circuit_id
            )),
        );
    }
    if receipt.vk_fingerprint != vk_fingerprint(vk) {
        return mk(false, Some("verifying key fingerprint mismatch".into()));
    }
    let Some(stmt) = receipt.statement.to_statement() else {
        return mk(false, Some("malformed public statement".into()));
    };
    let public = stmt.to_public_list();
    debug_assert_eq!(public.len(), NUM_PUBLIC);
    match groth16::verify(vk, &public, &receipt.proof) {
        Ok(()) => mk(true, None),
        Err(e) => mk(false, Some(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (ComplianceStatement, ComplianceWitness) {
        let w = ComplianceWitness {
            serial: [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4],
            block_root: Fr::from_be_bytes_reduced(&[0x37; 31]),
            passes: 2,
            verified_blocks: 8192,
            total_blocks: 8192,
            sanitize_success: true,
            operator_secret: Fr::from_be_bytes_reduced(&[0x88; 31]),
            nonce: Fr::from_be_bytes_reduced(&[0x66; 31]),
        };
        let stmt = ComplianceStatement {
            profile_hash: Fr::from_be_bytes_reduced(&[0x11; 31]),
            tenant_id: Fr::from_be_bytes_reduced(&[0x22; 31]),
            ts: Fr::from_be_bytes_reduced(&1_770_000_000u64.to_be_bytes()),
            vk_commitment: vk_commitment_of(&w.operator_secret, &w.nonce),
            audit_root: Fr::ZERO,
        };
        let stmt = ComplianceStatement {
            audit_root: audit_root_of(&w, &stmt),
            ..stmt
        };
        (stmt, w)
    }

    /// Full Groth16 lifecycle on the compliance circuit (~30 s release,
    /// tens of minutes in debug) — released from the default debug CI run:
    /// `cargo test -p dc-zk --release -- --ignored`.
    #[test]
    #[ignore = "expensive: full-circuit setup+prove; run in release"]
    fn full_compliance_prove_and_verify() {
        let (stmt, w) = sample();
        let mut rng = ZkRng::from_seed(b"receipt-test");
        let cs = crate::circuit::compliance_circuit();
        let (pk, vk) = groth16::setup(&cs, CIRCUIT_ID, &mut rng);

        let receipt = prove_compliance(&pk, &stmt, &w, &mut rng, Some("cafe1234".into()), None)
            .expect("prove");
        assert_eq!(receipt.circuit_id, CIRCUIT_ID);

        // serialized size claim: compressed proof ≈ 192 bytes
        let proof_hex_len = serde_json::to_string(&receipt.proof).unwrap().len();
        assert!(
            proof_hex_len < 600,
            "proof JSON (hex) should stay tiny: {}",
            proof_hex_len
        );

        let res = verify_receipt(&vk, &receipt);
        assert!(res.is_valid, "receipt must verify: {:?}", res.error);
        assert!(res.proof_verified);
        assert!(res.vk_fingerprint_matches);
        assert_eq!(res.statement, Some(stmt.clone()));

        // tamper: mutate one statement hex char
        let mut bad = receipt.clone();
        bad.statement.ts = hex::encode(Fr::from_be_bytes_reduced(&[99]).to_be_bytes());
        let res = verify_receipt(&vk, &bad);
        assert!(!res.is_valid, "tampered statement must fail");

        // tamper: swap in another key's fingerprint
        let mut rng2 = ZkRng::from_seed(b"other");
        let (_pk2, vk2) = groth16::setup(&cs, CIRCUIT_ID, &mut rng2);
        let res = verify_receipt(&vk2, &receipt);
        assert!(!res.is_valid, "receipt under a different setup must fail");

        // JSON round trip
        let s = serde_json::to_string(&receipt).unwrap();
        let back: ZkReceipt = serde_json::from_str(&s).unwrap();
        assert_eq!(back, receipt);
        let res = verify_receipt(&vk, &back);
        assert!(res.is_valid);
    }

    /// Requires a full Groth16 setup — run in release:
    /// `cargo test -p dc-zk --release -- --ignored`.
    #[test]
    #[ignore = "expensive: full-circuit setup; run in release"]
    fn non_compliant_witness_cannot_prove() {
        let (stmt, w) = sample();
        let mut rng = ZkRng::from_seed(b"non-compliant");
        let cs = crate::circuit::compliance_circuit();
        let (pk, _vk) = groth16::setup(&cs, CIRCUIT_ID, &mut rng);
        let bad = crate::circuit::ComplianceWitness {
            verified_blocks: w.verified_blocks - 100,
            ..clone_w(&w)
        };
        let bad_stmt = ComplianceStatement {
            audit_root: audit_root_of(&bad, &stmt),
            ..stmt.clone()
        };
        assert!(prove_compliance(&pk, &bad_stmt, &bad, &mut rng, None, None).is_err());
    }

    fn clone_w(w: &ComplianceWitness) -> crate::circuit::ComplianceWitness {
        crate::circuit::ComplianceWitness {
            serial: w.serial,
            block_root: w.block_root,
            passes: w.passes,
            verified_blocks: w.verified_blocks,
            total_blocks: w.total_blocks,
            sanitize_success: w.sanitize_success,
            operator_secret: w.operator_secret,
            nonce: w.nonce,
        }
    }
}
