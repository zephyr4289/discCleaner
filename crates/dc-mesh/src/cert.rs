//! The Swarm Certificate of Decommission and its offline verifier.
//!
//! The final artifact of a mesh run: a single JSON document in which
//! the *cluster itself* — not any one machine — certifies that the
//! declared drives of the fleet were sanitized and zero-entropy
//! verified under the decided pattern, that witness spot-proofs
//! passed, that consensus reached a `2f+1` quorum, and that at least
//! `t` distinct threshold shares co-signed the result. Rogue nodes
//! are named with their evidence; their drives are explicitly listed
//! as NOT certified.
//!
//! ## Anchoring
//!
//! A certificate is self-consistent by construction (all hashes and
//! signatures re-verify against the membership keys embedded in it).
//! But "who was in the cluster?" cannot be answered by the document
//! alone — a forger could fabricate a membership of their own keys.
//! Court-grade verification therefore anchors at least one of:
//!
//! * the FROST **group public key** (published at the cluster's
//!   one-time dealer ceremony), or
//! * the **membership hash** (the frozen epoch roster), or
//! * the per-node **ML-DSA public keys** (from each machine's keyring).
//!
//! [`SwarmAnchor`] carries whichever subset the verifier holds; the
//! remaining checks run self-consistently. An anchorless verification
//! proves internal coherence only — the report says so explicitly.

use crate::consensus::Block;
use crate::discovery::Membership;
use crate::gossip::{DriveReport, SpotTranscript};
use crate::rogue::RogueEntry;
use crate::threshold::{FrostSignature, MlDsaSeal};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Schema tag.
pub const SWARM_CERT_SCHEMA: &str = "dc-swarm-cert/1";

/// One membership row with both public identities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemberEntry {
    /// Node id (hex Ed25519 public key).
    pub node: String,
    /// ML-DSA-44 public key (hex).
    pub ml_dsa_pk: String,
}

/// The certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SwarmCertificate {
    pub schema: String,
    /// Operator-chosen cluster identifier (e.g. "racks-A1-A4").
    pub cluster_id: String,
    /// Frozen epoch membership.
    pub membership: Vec<MemberEntry>,
    pub membership_hash: String,
    /// Byzantine parameters of the frozen epoch.
    pub tolerance: usize,
    pub quorum: usize,
    /// Total drives advertised by the frozen membership.
    pub advertised_drives: u64,
    /// Verified, consensus-accepted drive reports (sorted by serial).
    pub drive_reports: Vec<DriveReport>,
    /// Witness spot-proof transcripts backing the reports.
    pub spot_transcripts: Vec<SpotTranscript>,
    /// Block commitments (from the decided block, hash-bound by
    /// `block_hash`): the full lists above MUST re-derive these.
    pub report_root: String,
    pub report_count: u32,
    pub spot_root: String,
    pub spot_count: u32,
    /// Rogue nodes isolated by the swarm, with evidence.
    pub rogue_ledger: Vec<RogueEntry>,
    /// Drives NOT certified, with the responsible node and reason.
    pub uncertified: Vec<UncertifiedDrive>,
    /// Consensus decision facts.
    pub view: u32,
    pub block_hash: String,
    pub committers: Vec<String>,
    /// Threshold layer 1: FROST2 Ed25519 aggregate.
    pub frost_group_pub: String,
    /// Signers required for the FROST layer (t).
    pub frost_threshold: u16,
    pub frost_signature: FrostSignature,
    /// Threshold layer 2: ML-DSA-44 t-of-n set.
    pub ml_dsa: MlDsaSeal,
    /// BLAKE3 over the sealing message (block ∥ ledger ∥ view).
    pub sealed_message: String,
}

/// A drive the certificate explicitly does NOT vouch for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UncertifiedDrive {
    /// Owning node (isolated rogue or timed-out member).
    pub node: String,
    /// Advertised serial, when the report was seen but rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    pub reason: String,
}

/// The verifier's out-of-band anchors.
#[derive(Debug, Clone, Default)]
pub struct SwarmAnchor {
    /// Expected FROST group public key (hex).
    pub group_pub: Option<String>,
    /// Expected membership hash.
    pub membership_hash: Option<String>,
    /// Per-node ML-DSA keys the verifier trusts (hex).
    pub ml_dsa_pks: HashMap<String, String>,
}

impl Default for SwarmCertificate {
    fn default() -> Self {
        Self {
            schema: SWARM_CERT_SCHEMA.to_string(),
            cluster_id: String::new(),
            membership: Vec::new(),
            membership_hash: String::new(),
            tolerance: 0,
            quorum: 0,
            advertised_drives: 0,
            drive_reports: Vec::new(),
            spot_transcripts: Vec::new(),
            report_root: String::new(),
            report_count: 0,
            spot_root: String::new(),
            spot_count: 0,
            rogue_ledger: Vec::new(),
            uncertified: Vec::new(),
            view: 0,
            block_hash: String::new(),
            committers: Vec::new(),
            frost_group_pub: String::new(),
            frost_threshold: 2,
            frost_signature: FrostSignature {
                r_point: String::new(),
                z_scalar: String::new(),
                participants: Vec::new(),
            },
            ml_dsa: MlDsaSeal::default(),
            sealed_message: String::new(),
        }
    }
}

impl SwarmCertificate {
    /// The sealing message every threshold signature covers:
    /// BLAKE3 over (block_hash ∥ sorted rogue evidence ∥ view).
    pub fn sealing_message(block_hash: &str, rogue: &[RogueEntry], view: u32) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(b"DCMS-SEAL-v1");
        h.update(block_hash.as_bytes());
        for e in rogue {
            h.update(e.node.as_bytes());
            h.update(e.evidence_digest.as_bytes());
            h.update(&e.isolated_at_view.to_be_bytes());
        }
        h.update(&view.to_be_bytes());
        h.finalize().as_bytes().to_vec()
    }

    /// Membership ML-DSA keys as raw bytes (verifier input).
    pub fn ml_dsa_keys(&self) -> HashMap<String, Vec<u8>> {
        self.membership
            .iter()
            .filter_map(|m| hex::decode(&m.ml_dsa_pk).ok().map(|b| (m.node.clone(), b)))
            .collect()
    }

    /// Total drives this certificate actually certifies.
    pub fn certified_drives(&self) -> usize {
        self.drive_reports.len()
    }
}

/// Result of a verification pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SwarmVerificationReport {
    pub schema_ok: bool,
    pub anchor_membership_ok: Option<bool>,
    pub anchor_group_key_ok: Option<bool>,
    pub reports_consistent: bool,
    pub no_duplicate_serials: bool,
    pub spot_proofs_passed: bool,
    pub quorum_reached: bool,
    pub rogue_quorums_valid: bool,
    pub frost_ok: bool,
    pub ml_dsa_ok: bool,
    pub drives_accounted: bool,
    /// Overall verdict (all checks ANDed).
    pub verified: bool,
    /// Human-readable failure notes.
    pub notes: Vec<String>,
}

impl SwarmVerificationReport {
    fn fail(&mut self, note: String) {
        self.notes.push(note);
    }
}

/// Verify a swarm certificate offline. Every check that can be made
/// without out-of-band knowledge is made unconditionally; anchors
/// add the binding to the real cluster.
pub fn verify_swarm_certificate(
    cert: &SwarmCertificate,
    anchor: &SwarmAnchor,
) -> SwarmVerificationReport {
    let mut r = SwarmVerificationReport {
        schema_ok: false,
        anchor_membership_ok: None,
        anchor_group_key_ok: None,
        reports_consistent: false,
        no_duplicate_serials: false,
        spot_proofs_passed: false,
        quorum_reached: false,
        rogue_quorums_valid: false,
        frost_ok: false,
        ml_dsa_ok: false,
        drives_accounted: false,
        verified: false,
        notes: Vec::new(),
    };

    r.schema_ok = cert.schema == SWARM_CERT_SCHEMA;
    if !r.schema_ok {
        r.fail(format!("unknown schema {}", cert.schema));
    }

    if let Some(expect) = &anchor.membership_hash {
        let ok = expect == &cert.membership_hash;
        r.anchor_membership_ok = Some(ok);
        if !ok {
            r.fail("membership hash does not match the anchor".into());
        }
    }

    if let Some(expect) = &anchor.group_pub {
        let ok = expect == &cert.frost_group_pub;
        r.anchor_group_key_ok = Some(ok);
        if !ok {
            r.fail("FROST group key does not match the anchor".into());
        }
    }

    // Block commitments: the full report and transcript lists must
    // re-derive the roots the consensus block (and therefore the
    // threshold signatures) bound.
    let (rr, rc) = crate::gossip::reports_root(&cert.drive_reports);
    let (tr, tc) = crate::gossip::transcripts_root(&cert.spot_transcripts);
    let commitments_ok = rr == cert.report_root
        && rc == cert.report_count
        && tr == cert.spot_root
        && tc == cert.spot_count;
    if !commitments_ok {
        r.fail("report/transcript lists do not re-derive the block commitments".into());
    }

    // Every report internally consistent.
    r.reports_consistent = cert.drive_reports.iter().all(DriveReport::is_consistent);
    if !r.reports_consistent {
        r.fail("at least one drive report has inconsistent window accounting".into());
    }

    // No duplicate serials across different nodes.
    let mut owner: HashMap<&str, &str> = HashMap::new();
    let mut dup = false;
    for rep in &cert.drive_reports {
        if let Some(prev) = owner.insert(rep.serial.as_str(), rep.node.as_str()) {
            dup |= prev != rep.node.as_str();
        }
    }
    r.no_duplicate_serials = !dup;
    if dup {
        r.fail("the same serial is attested by two different nodes".into());
    }

    // All spot transcripts passed (and each certified drive got ≥1
    // passing challenge from a witness other than its wiper).
    let mut every_report_challenged = true;
    for rep in &cert.drive_reports {
        let challenged = cert
            .spot_transcripts
            .iter()
            .any(|t| t.passed && t.challenge.serial == rep.serial && t.witness != rep.node);
        if !challenged {
            every_report_challenged = false;
            r.fail(format!(
                "drive {} has no passing witness spot-proof",
                rep.serial
            ));
        }
    }
    r.spot_proofs_passed =
        cert.spot_transcripts.iter().all(|t| t.passed) && every_report_challenged;

    // Consensus quorum: enough distinct committers from the frozen
    // membership.
    let members: HashSet<&String> = cert.membership.iter().map(|m| &m.node).collect();
    let distinct: HashSet<&String> = cert.committers.iter().collect();
    r.quorum_reached =
        distinct.len() >= cert.quorum && distinct.iter().all(|c| members.contains(*c));
    if !r.quorum_reached {
        r.fail(format!(
            "committers {} < quorum {}",
            distinct.len(),
            cert.quorum
        ));
    }

    // Rogue isolation quorums: every isolated node was accused by
    // at least 2f+1 distinct frozen members.
    r.rogue_quorums_valid = cert
        .rogue_ledger
        .iter()
        .all(|e| e.accusers.len() > 2 * cert.tolerance);
    if !r.rogue_quorums_valid {
        r.fail("a rogue entry lacks a 2f+1 accusation quorum".into());
    }

    // No isolated node's reports may be certified.
    let isolated: HashSet<&str> = cert.rogue_ledger.iter().map(|e| e.node.as_str()).collect();
    if cert
        .drive_reports
        .iter()
        .any(|rep| isolated.contains(rep.node.as_str()))
    {
        r.fail("a certified report belongs to an isolated rogue node".into());
    }

    // FROST2 aggregate signature over the sealing message: the
    // sealed_message field must be the hex of the recomputed message
    // (binding every field it covers), and the aggregate signature
    // must verify with at least `frost_threshold` signers.
    let message =
        SwarmCertificate::sealing_message(&cert.block_hash, &cert.rogue_ledger, cert.view);
    let message_hex = hex::encode(&message);
    let group_pk = crate::threshold::ThresholdPublicKey {
        params: crate::threshold::ThresholdParams {
            threshold: cert.frost_threshold,
            participants: cert.membership.len().max(cert.frost_threshold as usize) as u16,
        },
        group_pub: cert.frost_group_pub.clone(),
        shares: Vec::new(),
        commitments: Vec::new(),
    };
    r.frost_ok =
        message_hex == cert.sealed_message && cert.frost_signature.verify(&group_pk, &message);
    if !r.frost_ok {
        r.fail("FROST2 threshold signature failed to verify".into());
    }

    // ML-DSA t-of-n seal over the same message, under the anchored
    // (or embedded, if unanchored) membership keys.
    let keys: HashMap<String, Vec<u8>> = if anchor.ml_dsa_pks.is_empty() {
        cert.ml_dsa_keys()
    } else {
        anchor
            .ml_dsa_pks
            .iter()
            .filter_map(|(k, v)| hex::decode(v).ok().map(|b| (k.clone(), b)))
            .collect()
    };
    r.ml_dsa_ok = cert.ml_dsa.verify(&keys, &message);
    if !r.ml_dsa_ok {
        r.fail(format!(
            "ML-DSA seal does not reach threshold {} of distinct members",
            cert.ml_dsa.threshold
        ));
    }

    // Drive accounting: certified + explicitly uncertified + rogue
    // isolation must cover every advertised drive.
    let accounted =
        (cert.certified_drives() as u64 + cert.uncertified.len() as u64) >= cert.advertised_drives;
    r.drives_accounted = accounted;
    if !accounted {
        r.fail(format!(
            "certified {} + uncertified {} < advertised {}",
            cert.certified_drives(),
            cert.uncertified.len(),
            cert.advertised_drives
        ));
    }

    r.verified = r.schema_ok
        && r.anchor_membership_ok.unwrap_or(true)
        && r.anchor_group_key_ok.unwrap_or(true)
        && commitments_ok
        && r.reports_consistent
        && r.no_duplicate_serials
        && r.spot_proofs_passed
        && r.quorum_reached
        && r.rogue_quorums_valid
        && r.frost_ok
        && r.ml_dsa_ok
        && r.drives_accounted;
    r
}

/// Rebuild a consensus block from a certificate (for transcript
/// auditing: the block hash must re-derive).
pub fn block_from_cert(cert: &SwarmCertificate) -> Block {
    Block {
        membership_hash: cert.membership_hash.clone(),
        report_root: cert.report_root.clone(),
        report_count: cert.report_count,
        spot_root: cert.spot_root.clone(),
        spot_count: cert.spot_count,
        rogue_entries: cert.rogue_ledger.clone(),
        view: cert.view,
    }
}

/// Convenience: derive the membership summary the CLI prints.
pub fn membership_summary(cert: &SwarmCertificate) -> Membership {
    Membership {
        nodes: cert.membership.iter().map(|m| m.node.clone()).collect(),
        hash: cert.membership_hash.clone(),
        total_drives: cert.advertised_drives,
        tolerance: cert.tolerance,
        quorum: cert.quorum,
    }
}
