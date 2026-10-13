//! Byzantine rogue detection, accusation and isolation.
//!
//! Four misbehaviors have distinct, cryptographically checkable
//! signatures. Each produces a signed [`Accusation`]; when `2f+1`
//! distinct members accuse the same node for the same evidence
//! digest, the ledger records an isolated [`RogueEntry`] and the
//! consensus live-set shrinks (quorums recompute — see
//! [`crate::consensus::Consensus::apply_isolation`]).
//!
//! | kind | evidence | catch mechanism |
//! |------|----------|----------------|
//! | [`RogueKind::Equivocation`] | two signed PROPOSALs, same view, different hashes | any receiver keeps both |
//! | [`RogueKind::DuplicateSerial`] | two nodes attesting the same physical serial | gossip store cross-check |
//! | [`RogueKind::FailedSpotProof`] | (challenge, proof) pair whose bytes do not match the declared pattern | witness spot check |
//! | [`RogueKind::Timeout`] | view-change recorded while the node never answered challenges | absence ledger |
//!
//! The ledger is *append-only* and serialized verbatim into the final
//! swarm certificate: the cluster names its liars, with the evidence
//! to convict them, inside the very document they tried to forge.

use serde::{Deserialize, Serialize};

/// The class of misbehavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RogueKind {
    /// Two different block proposals signed by the same node in one view.
    Equivocation,
    /// The same physical serial attested by two different nodes.
    DuplicateSerial,
    /// Spot-proof bytes did not match the declared final pattern.
    FailedSpotProof,
    /// Silent through view changes; never answered challenges.
    Timeout,
}

impl RogueKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            RogueKind::Equivocation => "equivocation",
            RogueKind::DuplicateSerial => "duplicate_serial",
            RogueKind::FailedSpotProof => "failed_spot_proof",
            RogueKind::Timeout => "timeout",
        }
    }
}

/// One member's signed accusation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Accusation {
    /// Accuser node (hex Ed25519 pk; the wire frame carries its sig).
    pub accuser: String,
    /// Accused node.
    pub accused: String,
    pub kind: RogueKind,
    /// BLAKE3 over the evidence body — accusation votes for the
    /// same (accused, kind, digest) triple aggregate toward isolation.
    pub evidence_digest: String,
    /// Auditable evidence (challenge/proof pair, dual proposals, or
    /// serial claim pair), as canonical JSON.
    pub evidence: String,
}

/// An isolation verdict (appended to the final certificate).
///
/// Entries enter the consensus block (and therefore its hash) ONLY
/// through their [`RogueEntry::canonical`] projection — the
/// per-accuser evidence bytes differ from node to node (each witness
/// catches the same lie with its own nonce) and must never perturb
/// the block hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RogueEntry {
    pub node: String,
    pub kind: RogueKind,
    pub evidence_digest: String,
    pub evidence: String,
    /// Distinct members that signed accusations backing this entry.
    pub accusers: Vec<String>,
    /// View at which isolation took effect.
    pub isolated_at_view: u32,
}

/// The collective, append-only audit trail of misbehavior.
#[derive(Debug, Clone, Default)]
pub struct RogueLedger {
    pub entries: Vec<RogueEntry>,
    accusations: Vec<Accusation>,
}

impl RogueEntry {
    /// The canonical, evidence-independent projection: identical on
    /// every node regardless of which accusation arrived first
    /// locally. This is the ONLY form that enters blocks, hashes
    /// and threshold signatures.
    pub fn canonical(&self) -> RogueEntry {
        let mut accusers = self.accusers.clone();
        accusers.sort();
        let digest_input = format!(
            "{}|{}|{}|{}",
            self.node,
            self.kind.as_str(),
            accusers.join(","),
            self.isolated_at_view
        );
        RogueEntry {
            node: self.node.clone(),
            kind: self.kind,
            evidence_digest: blake3::hash(digest_input.as_bytes()).to_hex().to_string(),
            evidence: String::new(),
            accusers,
            isolated_at_view: self.isolated_at_view,
        }
    }
}

impl RogueLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// File an accusation. Returns the current number of DISTINCT
    /// accusers for this (accused, kind) pair.
    ///
    /// Aggregation is deliberately by (accused, kind), not by exact
    /// evidence bytes: every witness catches the same misbehavior via
    /// its own challenge (fresh nonce, its own window), so evidence
    /// payloads legitimately differ accuser-to-accuser. The evidence
    /// itself is kept verbatim in the accusation record for audit.
    pub fn accuse(
        &mut self,
        accuser: &str,
        accused: &str,
        kind: RogueKind,
        evidence: String,
        evidence_digest: String,
    ) -> usize {
        let distinct = self
            .accusations
            .iter()
            .filter(|a| a.accused == accused && a.kind == kind)
            .map(|a| a.accuser.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();
        // Idempotent per (accuser, evidence): the same accuser
        // re-signing the same evidence does not double-count.
        let duplicate = self
            .accusations
            .iter()
            .any(|a| a.accuser == accuser && a.evidence_digest == evidence_digest);
        if !duplicate {
            self.accusations.push(Accusation {
                accuser: accuser.to_string(),
                accused: accused.to_string(),
                kind,
                evidence_digest: evidence_digest.clone(),
                evidence,
            });
            distinct + 1
        } else {
            distinct
        }
    }

    /// Attempt isolation for an accused node: succeeds when
    /// `distinct accusers >= required_quorum` and the node is not
    /// already isolated. Returns the new ledger entry on success.
    pub fn try_isolate(
        &mut self,
        accused: &str,
        kind: RogueKind,
        evidence_digest: &str,
        required_quorum: usize,
        view: u32,
    ) -> Option<RogueEntry> {
        if self.entries.iter().any(|e| e.node == accused) {
            return None; // already isolated
        }
        let accusers: Vec<String> = self
            .accusations
            .iter()
            .filter(|a| a.accused == accused && a.kind == kind)
            .map(|a| a.accuser.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        if accusers.len() < required_quorum {
            return None;
        }
        // Any matching accusation's evidence stands for the entry
        // (prefer the one the isolating caller holds).
        let evidence = self
            .accusations
            .iter()
            .find(|a| {
                a.accused == accused && a.kind == kind && a.evidence_digest == evidence_digest
            })
            .or_else(|| {
                self.accusations
                    .iter()
                    .find(|a| a.accused == accused && a.kind == kind)
            })
            .map(|a| a.evidence.clone())
            .unwrap_or_default();
        let mut accusers = accusers;
        accusers.sort();
        let entry = RogueEntry {
            node: accused.to_string(),
            kind,
            evidence_digest: evidence_digest.to_string(),
            evidence,
            accusers,
            isolated_at_view: view,
        };
        self.entries.push(entry.clone());
        Some(entry)
    }

    /// All accusations (for the certificate appendix).
    pub fn accusations(&self) -> &[Accusation] {
        &self.accusations
    }

    /// Is this node already isolated?
    pub fn is_isolated(&self, node: &str) -> bool {
        self.entries.iter().any(|e| e.node == node)
    }

    /// Digest helper: BLAKE3 over an evidence body.
    pub fn digest_of(evidence: &str) -> String {
        blake3::hash(evidence.as_bytes()).to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev_json(x: u32) -> String {
        format!("{{\"challenge\":{x}}}")
    }

    #[test]
    fn accusations_aggregate_by_distinct_accusers() {
        let mut ledger = RogueLedger::new();
        let digest = RogueLedger::digest_of(&ev_json(1));
        assert_eq!(
            ledger.accuse(
                "a",
                "rogue",
                RogueKind::FailedSpotProof,
                ev_json(1),
                digest.clone()
            ),
            1
        );
        // Same accuser re-signing: no double count.
        assert_eq!(
            ledger.accuse(
                "a",
                "rogue",
                RogueKind::FailedSpotProof,
                ev_json(1),
                digest.clone()
            ),
            1
        );
        assert_eq!(
            ledger.accuse(
                "b",
                "rogue",
                RogueKind::FailedSpotProof,
                ev_json(1),
                digest.clone()
            ),
            2
        );
        assert_eq!(
            ledger.accuse(
                "c",
                "rogue",
                RogueKind::FailedSpotProof,
                ev_json(1),
                digest.clone()
            ),
            3
        );
    }

    #[test]
    fn isolation_requires_quorum_and_is_idempotent() {
        let mut ledger = RogueLedger::new();
        let digest = RogueLedger::digest_of(&ev_json(7));
        for accuser in ["a", "b"] {
            ledger.accuse(
                accuser,
                "bad",
                RogueKind::Equivocation,
                ev_json(7),
                digest.clone(),
            );
        }
        // 2 of 3 required: not yet.
        assert!(
            ledger
                .try_isolate("bad", RogueKind::Equivocation, &digest, 3, 1)
                .is_none()
        );
        ledger.accuse(
            "c",
            "bad",
            RogueKind::Equivocation,
            ev_json(7),
            digest.clone(),
        );
        let entry = ledger
            .try_isolate("bad", RogueKind::Equivocation, &digest, 3, 4)
            .expect("isolated");
        assert_eq!(entry.node, "bad");
        assert_eq!(entry.accusers.len(), 3);
        assert_eq!(entry.isolated_at_view, 4);
        // Idempotent: second attempt is a no-op.
        assert!(
            ledger
                .try_isolate("bad", RogueKind::Equivocation, &digest, 3, 5)
                .is_none()
        );
        assert!(ledger.is_isolated("bad"));
        assert!(!ledger.is_isolated("good"));
    }

    #[test]
    fn per_witness_evidence_still_aggregates_by_kind() {
        // Each witness catches the same lie via its OWN challenge
        // (different nonce/window) — the evidence bytes differ, the
        // verdict must still aggregate.
        let mut ledger = RogueLedger::new();
        let d1 = RogueLedger::digest_of(&ev_json(1));
        let d2 = RogueLedger::digest_of(&ev_json(2));
        ledger.accuse("a", "r", RogueKind::FailedSpotProof, ev_json(1), d1.clone());
        ledger.accuse("b", "r", RogueKind::FailedSpotProof, ev_json(2), d2.clone());
        let entry = ledger
            .try_isolate("r", RogueKind::FailedSpotProof, &d1, 2, 0)
            .expect("2 distinct accusers of the same kind isolate");
        assert_eq!(entry.accusers.len(), 2);
    }
}
