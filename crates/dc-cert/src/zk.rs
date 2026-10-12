//! Zero-knowledge audit statement (v0.11.0, Frontier 1).
//!
//! When a sanitization is accompanied by a Groth16 ZK receipt
//! (`dc zk prove`), the certificate carries this binding statement:
//! the five public inputs of the compliance circuit plus the BLAKE3
//! fingerprint of the receipt artifact itself. An auditor verifies with
//! `dc zk verify --vk <key> --receipt <file>` — the pairing equation
//! proves the compliance predicate held for SOME witness consistent
//! with these public values, without revealing the drive serial, block
//! topology or operator identity.
//!
//! All field elements are canonical big-endian Fr encodings, hex.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkAuditStatement {
    /// Circuit identifier the receipt was produced under
    /// (e.g. "dc-zk/compliance/v1").
    pub circuit_id: String,
    /// Scheme tag (e.g. "groth16-bls12-381").
    pub scheme: String,
    /// Poseidon root of the NIST profile parameters (hex, 32 bytes).
    pub profile_hash: String,
    /// Customer / tenant identity the audit is owed to (hex).
    pub tenant_id: String,
    /// Sanitization timestamp as a field element (hex).
    pub ts: String,
    /// Poseidon commitment to the operator credential (hex).
    pub vk_commitment: String,
    /// Poseidon audit root over the private witness fields (hex).
    pub audit_root: String,
    /// BLAKE3 of the receipt artifact (JSON bytes).
    pub receipt_blake3: String,
    /// BLAKE3 of the verifying key the receipt was checked against.
    pub vk_fingerprint: String,
}
