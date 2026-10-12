//! `dc-zk` — zero-knowledge audit receipts for sanitization compliance
//! (v0.11.0, Frontier 1).
//!
//! Defense, finance and multi-tenant cloud operators must prove to a
//! regulator or customer that a 16 TB volume or physical drive was wiped
//! to NIST SP 800-88 Purge / IEEE 2883 standards — but the raw
//! sanitization evidence contains confidential metadata: drive serial
//! numbers, internal cloud Account IDs, host topologies, operator
//! identities. This crate produces **Groth16 zero-knowledge succinct
//! non-interactive arguments** over a pure-Rust, zero-dependency
//! BLS12-381 implementation:
//!
//! * **private inputs** — drive serial, block-verification merkle root,
//!   pass count, verified/total block counts, controller sanitize status,
//!   operator credential, blinding nonce;
//! * **public inputs** — NIST profile hash, tenant ID, timestamp,
//!   operator key commitment, Poseidon audit root;
//! * **output** — a ~192-byte compressed proof (three group elements)
//!   that anyone can verify mathematically, learning *only* that the
//!   sanitization was compliant.
//!
//! # Architecture
//!
//! * [`field`], [`fp2`], [`fp6`], [`fp12`] — Montgomery arithmetic and the
//!   2-6-12 tower (u² = −1, v³ = 1+u, w² = v).
//! * [`curve`] — G1/G2 with Jacobian scalar multiplication, subgroup
//!   checks, compressed point serialization (Fp/Fp2 square roots).
//! * [`pairing`] — optimal ate pairing: untwist into E(Fp12), Miller loop
//!   over |x| = 0xd201000000010000, full final exponentiation
//!   (p¹²−1)/r. Validated against a reference prototype before porting.
//! * [`poly`], [`r1cs`], [`groth16`] — R1CS and the Groth16
//!   setup/prove/verify pipeline (H query over the product polynomial
//!   A(x)B(x) − C(x); no polynomial division anywhere).
//! * [`poseidon`] — SNARK-friendly sponge (t = 3, RF = 8, RP = 57, x⁵)
//!   with SHA-256-derived round constants (transparent, auditable,
//!   documented deviation from the Grain LFSR).
//! * [`circuit`] — the compliance circuit (range checks, verified == total,
//!   sanitize_success == 1, passes ≥ 1, Poseidon bindings).
//! * [`receipt`] — the portable receipt artifact + verification API.
//!
//! # Trust model (honest, documented)
//!
//! Groth16 requires a structured reference string generated in a
//! **trusted setup**: if the toxic waste (τ, α, β, δ) is retained, fake
//! proofs become possible. This release performs a **single-party
//! ceremony** — [`groth16::setup`] generates the waste inside the process,
//! publishes the keys and drops the waste (never persisted, zeroized
//! drop). The verifying-key fingerprint in every receipt pins WHICH
//! ceremony produced it, so a compromised setup is at least attributable.
//! A multi-party "powers of tau" ceremony with public transcript
//! verification is the natural follow-up milestone; the API surface here
//! (separate `setup` / `prove` / `verify`) is already shaped for it.
//!
//! # Verification procedure for auditors
//!
//! 1. Obtain the operator's `zk-vk.json` (verifying key) and pin its
//!    BLAKE3 fingerprint out-of-band.
//! 2. Obtain the `zk-receipt.json` artifact alongside the certificate.
//! 3. `dc zk verify --vk zk-vk.json --receipt zk-receipt.json
//!    --expect-tenant <id> --expect-profile <name> [--expect-ts-window
//!    <lo>:<hi>]` — the command cross-checks the public statement against
//!    the certificate context and verifies the Groth16 pairing equation.
//!
//! # What the proof guarantees (and does not)
//!
//! The proof binds the *statement values to the compliance predicate*
//! under the Poseidon commitment scheme: the audit root commits to the
//! private fields, and the circuit enforces the compliance relations over
//! the committed values. It does NOT make the underlying engine's I/O
//! honest — that is the role of the engine's own verification passes,
//! whose *counts and merkle root* are what gets committed here. See
//! docs/zk-audit.md for the full composition argument.

pub mod circuit;
pub mod curve;
pub mod field;
pub mod fp12;
pub mod fp2;
pub mod fp6;
pub mod groth16;
pub mod pairing;
pub mod poly;
pub mod poseidon;
pub mod r1cs;
pub mod receipt;
pub mod rng;

pub use circuit::{
    CIRCUIT_ID, ComplianceStatement, ComplianceWitness, audit_root_of, build_witness,
    compliance_circuit, vk_commitment_of,
};
pub use groth16::{Proof, ProvingKey, SerG1, SerG2, VerifyingKey, ZkError, prove, setup, verify};
pub use receipt::{
    PublicStatementHex, ReceiptVerification, ZkReceipt, prove_compliance, verify_receipt,
    vk_fingerprint,
};
pub use rng::ZkRng;

/// The scalar field (circuit/witness field) — re-exported for statement
/// builders at the CLI and future integrations.
pub use field::{Fp, Fr};

/// Convenience: one-shot setup for the compliance circuit from OS entropy.
pub fn setup_compliance_keys_from_os() -> (ProvingKey, VerifyingKey) {
    let cs = compliance_circuit();
    let mut rng = ZkRng::from_os();
    setup(&cs, CIRCUIT_ID, &mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fr;

    /// End-to-end: setup from OS entropy, prove a compliant sanitization,
    /// verify the receipt. Full-circuit latency — run in release:
    /// `cargo test -p dc-zk --release -- --ignored`.
    #[test]
    #[ignore = "expensive: full-circuit setup+prove; run in release"]
    fn end_to_end_os_entropy() {
        let cs = compliance_circuit();
        let mut rng = ZkRng::from_os();
        let (pk, vk) = setup(&cs, CIRCUIT_ID, &mut rng);
        let w = ComplianceWitness {
            serial: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            block_root: Fr::from_be_bytes_reduced(&[0xab; 31]),
            passes: 1,
            verified_blocks: 65536,
            total_blocks: 65536,
            sanitize_success: true,
            operator_secret: Fr::random(),
            nonce: Fr::random(),
        };
        let stmt = ComplianceStatement {
            profile_hash: Fr::from_be_bytes_reduced(&[0xcd; 31]),
            tenant_id: Fr::from_be_bytes_reduced(&[0xef; 31]),
            ts: Fr::from_be_bytes_reduced(&1_770_000_000u64.to_be_bytes()),
            vk_commitment: vk_commitment_of(&w.operator_secret, &w.nonce),
            audit_root: Fr::ZERO,
        };
        let stmt = ComplianceStatement {
            audit_root: audit_root_of(&w, &stmt),
            ..stmt
        };
        let receipt = prove_compliance(&pk, &stmt, &w, &mut rng, None, None).unwrap();
        let res = verify_receipt(&vk, &receipt);
        assert!(
            res.is_valid,
            "OS-entropy end-to-end must verify: {:?}",
            res.error
        );
    }
}
