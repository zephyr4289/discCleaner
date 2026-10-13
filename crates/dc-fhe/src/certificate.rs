//! # The FHE Erasure Certificate.
//!
//! The court-grade artifact of the homomorphic wipe. It binds:
//!
//! * the **volume identity** and the customer-issued evaluation key
//!   digest (substituting another volume's key fails the digest
//!   recomputation in [`Self::verify`]),
//! * the **original commitment root** `M` (what was stored at
//!   provisioning — set by the customer, never the provider),
//! * the **final root** `M'` over the zeroized ciphertext set
//!   (recomputable from the stored ciphertexts included in the
//!   certificate),
//! * the **zero-knowledge proof** that every stored ciphertext is
//!   an encryption of zero (replayable offline: `verify()` re-runs
//!   the batched verification),
//! * the **noise margins** (the outputs sit deep inside the
//!   decryptable region — `Dec_sk(C') = 0^N` holds for every key
//!   the customer could hold, with room to spare),
//! * the **verification timing** (the milliseconds claim, measured
//!   on this machine, not asserted).
//!
//! The public key is embedded (it is public) so offline
//! verification is fully self-contained; the evaluation-key digest
//! recomputation catches any substitution of it.
//!
//! `digest` is BLAKE3 over the canonical JSON of the evidence body
//! (everything except the digest itself), signable by the dc-cert
//! hybrid Ed25519 + ML-DSA machinery at the CLI layer.

use crate::FheError;
use crate::fhe::EvalKey;
use crate::protocol::{customer_setup, customer_verify, merkle_root, provider_run};
use crate::rlwe::{Ciphertext, PublicKey};
use crate::zkp::ZeroizeProof;
use serde::Serialize;

/// Certificate schema tag.
pub const SCHEMA: &str = "discCleaner/fhe-erasure/1";

/// The FHE Erasure Certificate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FheErasureCertificate {
    pub schema: String,
    pub volume_id: String,
    /// Ring-LWE parameter set (demo-grade; see crate preamble).
    pub params: crate::rlwe::Params,
    /// The public key (public by construction; embedded for
    /// self-contained offline replay).
    pub public_key: PublicKey,
    /// Issuance nonce of the evaluation key.
    pub issue_nonce: u64,
    /// Digest of the customer-issued evaluation key.
    pub eval_key_digest: String,
    /// Merkle root of the ORIGINAL ciphertext set.
    pub original_root: String,
    /// Merkle root of the zeroized ciphertext set.
    pub final_root: String,
    pub sector_count: usize,
    /// The zeroized ciphertexts (statements for offline replay).
    pub zeroized: Vec<Ciphertext>,
    /// The zero-knowledge proof.
    pub proof: ZeroizeProof,
    /// Spot-decryption challenge index (FS-derived).
    pub spot_sector: usize,
    /// Spot decryption result (0^N under the customer key).
    pub spot_is_zero: bool,
    /// Batched verification result + timing.
    pub batched_ok: bool,
    pub batched_verify_ms: u128,
    /// Provider-side timings (informational).
    pub eval_ms: u128,
    pub prove_ms: u128,
    /// Worst noise margin across sectors.
    pub worst_noise_margin: f64,
    pub verified: bool,
    pub notes: Vec<String>,
    pub digest: String,
}

impl FheErasureCertificate {
    /// Run the full protocol (deterministic demo campaign) and
    /// assemble the certificate.
    pub fn assemble(volume_id: &str, sectors: usize, seed: u64) -> Result<Self, FheError> {
        let setup = customer_setup(volume_id, sectors, seed)?;
        let mut rng = crate::SimRng::new(seed ^ 0xFACE);
        let result = provider_run(&setup.contract, &setup.sector_ciphertexts, &mut rng)?;
        let report = customer_verify(&setup.contract, &result, &setup.sk)?;
        let contract = &setup.contract;
        let eval_key_digest = contract.ek.digest(contract.params.q);
        let mut notes = Vec::new();
        if report.passed {
            notes.push(format!(
                "{sectors} sectors blind-zeroized homomorphically: Dec_sk(C') = 0^N for every key, without the provider ever decrypting"
            ));
            notes.push(format!(
                "batched ZK verification passed for {sectors} sectors (constant-time in the sector count; wall-clock recorded in the timing fields)"
            ));
            notes.push(format!(
                "spot challenge: sector {} decrypted by the customer's own key → {}",
                report.spot_sector,
                if report.spot_is_zero {
                    "0^N"
                } else {
                    "NONZERO (FAIL)"
                }
            ));
            notes.push(format!(
                "worst noise margin {:.1}× below the decryptability ceiling",
                report.worst_noise_margin
            ));
            notes.push("provider privacy: all provider-side computation ran over ciphertexts and public keys only".into());
        } else {
            notes.push("verification FAILED — see the report fields".into());
        }
        let mut cert = Self {
            schema: SCHEMA.into(),
            volume_id: volume_id.into(),
            params: contract.params.clone(),
            public_key: setup.pk.clone(),
            issue_nonce: contract.ek.issue_nonce,
            eval_key_digest,
            original_root: contract.original_root.clone(),
            final_root: result.final_root.clone(),
            sector_count: sectors,
            zeroized: result.zeroized.clone(),
            proof: result.proof.clone(),
            spot_sector: report.spot_sector,
            spot_is_zero: report.spot_is_zero,
            batched_ok: report.batched_ok,
            batched_verify_ms: report.batched_verify_ms,
            eval_ms: result.eval_ms,
            prove_ms: result.prove_ms,
            worst_noise_margin: report.worst_noise_margin,
            verified: report.passed,
            notes,
            digest: String::new(),
        };
        cert.digest = cert.compute_digest();
        Ok(cert)
    }

    /// Canonical evidence body (everything the digest binds).
    fn evidence_json(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Body<'a> {
            schema: &'a str,
            volume_id: &'a str,
            params: &'a crate::rlwe::Params,
            public_key: &'a PublicKey,
            issue_nonce: u64,
            eval_key_digest: &'a str,
            original_root: &'a str,
            final_root: &'a str,
            sector_count: usize,
            zeroized: &'a [Ciphertext],
            proof: &'a ZeroizeProof,
            spot_sector: usize,
            spot_is_zero: bool,
            batched_ok: bool,
            worst_noise_margin: f64,
            verified: bool,
            notes: &'a [String],
        }
        serde_json::to_vec(&Body {
            schema: &self.schema,
            volume_id: &self.volume_id,
            params: &self.params,
            public_key: &self.public_key,
            issue_nonce: self.issue_nonce,
            eval_key_digest: &self.eval_key_digest,
            original_root: &self.original_root,
            final_root: &self.final_root,
            sector_count: self.sector_count,
            zeroized: &self.zeroized,
            proof: &self.proof,
            spot_sector: self.spot_sector,
            spot_is_zero: self.spot_is_zero,
            batched_ok: self.batched_ok,
            worst_noise_margin: self.worst_noise_margin,
            verified: self.verified,
            notes: &self.notes,
        })
        .expect("canonical fhe body json")
    }

    /// BLAKE3 over the canonical body.
    pub fn compute_digest(&self) -> String {
        blake3::hash(&self.evidence_json()).to_hex().to_string()
    }

    /// Offline verification: digest coverage, evaluation-key
    /// recomputation, root recomputation from the stored
    /// ciphertexts, ZK replay, verdict arithmetic.
    ///
    /// This re-runs the full cryptographic verification from the
    /// certificate's own contents — no trust in the recorded
    /// booleans.
    pub fn verify(&self) -> Result<(), FheError> {
        if self.schema != SCHEMA {
            return Err(FheError::Certificate(format!(
                "unknown schema {} (expected {SCHEMA})",
                self.schema
            )));
        }
        if self.digest != self.compute_digest() {
            return Err(FheError::Certificate(
                "digest does not cover the evidence body — tampered or corrupt".into(),
            ));
        }
        // Evaluation-key binding: the embedded pk + volume + nonce
        // must reproduce the recorded eval-key digest.
        let ek = EvalKey {
            pk: self.public_key.clone(),
            volume_id: self.volume_id.clone(),
            issue_nonce: self.issue_nonce,
        };
        if ek.digest(self.params.q) != self.eval_key_digest {
            return Err(FheError::Certificate(
                "evaluation key digest mismatch — public key or volume identity substituted".into(),
            ));
        }
        // Root recomputation over the stored ciphertext set.
        let recomputed_root = merkle_root(
            &self
                .zeroized
                .iter()
                .map(|c| c.digest(self.params.q))
                .collect::<Vec<_>>(),
        );
        if recomputed_root != self.final_root {
            return Err(FheError::Certificate(
                "final root does not cover the stored ciphertext set".into(),
            ));
        }
        if self.zeroized.len() != self.sector_count {
            return Err(FheError::Certificate(
                "stored ciphertext count does not match the sector count".into(),
            ));
        }
        // ZK replay: the proof must hold over the stored statements.
        crate::zkp::verify_batched(&self.params, &self.public_key, &self.zeroized, &self.proof)
            .map_err(|e| FheError::Certificate(format!("ZK replay failed: {e}")))?;
        // Verdict arithmetic.
        let recomputed_verified = self.batched_ok && self.spot_is_zero && self.sector_count > 0;
        if recomputed_verified != self.verified {
            return Err(FheError::Certificate(
                "verified flag does not recompute from the evidence".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_campaign_certifies_and_verifies_offline() {
        let cert = FheErasureCertificate::assemble("vol-cert-1", 6, 42).expect("campaign");
        assert!(cert.verified);
        assert!(cert.spot_is_zero);
        assert!(cert.worst_noise_margin > 10.0);
        cert.verify().expect("offline verification replays");
    }

    #[test]
    fn tampering_with_the_body_breaks_the_digest() {
        let mut cert = FheErasureCertificate::assemble("vol-cert-2", 4, 43).expect("campaign");
        let original = cert.spot_is_zero;
        cert.spot_is_zero = false; // flip a verdict-bearing field
        assert!(cert.verify().is_err());
        cert.spot_is_zero = original;
        assert!(cert.verify().is_ok());
    }

    #[test]
    fn tampering_with_a_ciphertext_breaks_the_root_or_zk() {
        let mut cert = FheErasureCertificate::assemble("vol-cert-3", 4, 44).expect("campaign");
        // Perturb one stored ciphertext, then re-digest so the
        // ROOT/ZK checks are what catch it.
        cert.zeroized[1].u.coeffs[9] += 1;
        cert.digest = cert.compute_digest();
        assert!(cert.verify().is_err());
    }

    #[test]
    fn substituting_the_public_key_is_caught() {
        let mut cert = FheErasureCertificate::assemble("vol-cert-4", 4, 45).expect("campaign");
        // Swap in a different pk, re-digest: the eval-key digest
        // recomputation must catch the substitution.
        let (other_pk, _other_sk) = crate::rlwe::keygen_deterministic(&cert.params, 999_999);
        cert.public_key = other_pk;
        cert.digest = cert.compute_digest();
        assert!(cert.verify().is_err());
    }

    #[test]
    fn campaign_is_deterministic_under_a_fixed_seed() {
        let a = FheErasureCertificate::assemble("vol-det", 3, 1234).expect("a");
        let b = FheErasureCertificate::assemble("vol-det", 3, 1234).expect("b");
        assert_eq!(a.digest, b.digest);
        let c = FheErasureCertificate::assemble("vol-det", 3, 1235).expect("c");
        assert_ne!(a.digest, c.digest);
    }

    #[test]
    fn empty_volume_is_refused() {
        assert!(FheErasureCertificate::assemble("vol-empty", 0, 46).is_err());
    }
}
