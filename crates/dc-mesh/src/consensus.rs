//! PBFT-family rotating-speaker consensus over the mesh.
//!
//! This is a **single-shot** consensus (one block: the fleet's final
//! decommission record) in the PBFT tradition — rotating proposer
//! ("speaker"), two voting phases, `2f+1` quorums, view-change on
//! timeout:
//!
//! ```text
//!   speaker ──PROPOSAL(view, block)──▶ all
//!   all    ──PREPARE(view, H(block))─▶ all      (after local validation)
//!   all    ──COMMIT(view, H(block))──▶ all      (after seeing 2f+1 PREPARE)
//!   decided when 2f+1 COMMIT for the same hash in the same view
//! ```
//!
//! Differences from full PBFT, documented deliberately:
//!
//! * **Single decision.** A decommission swarm decides one block —
//!   the complete set of drive reports + spot transcripts + rogue
//!   ledger at seal time. No total-order log is needed.
//! * **Deterministic speaker.** `speaker(view) = H(membership ∥ view)
//!   mod n` over the sorted frozen membership — no leader election,
//!   nothing to campaign over.
//! * **View change by timeout.** If a view makes no progress for
//!   `view_timeout_ticks`, every node broadcasts CHANGE_VIEW; on
//!   `f+1` of them (or local timeout), `view+1` begins with the next
//!   deterministic speaker. A crashed or stalling speaker is simply
//!   waited out — no data is lost, only time.
//! * **Local validation before PREPARE.** A node only PREPAREs a block
//!   whose reports are signature-consistent, spot-proofs pass, window
//!   accounting closes, no duplicate serials exist among the honest
//!   set, and the membership hash matches the frozen epoch.
//!
//! With `n = 3f+1` this tolerates `f` Byzantine members: safety (no
//! two honest nodes decide different blocks) and liveness (a decision
//! is reached once messages flow and at most `f` members are faulty).
//!
//! ## Safety argument (sketch)
//!
//! Two different blocks can each collect `2f+1` COMMITs in the same
//! view only if `2(2f+1) - n > f` nodes voted for both — i.e. more
//! than `f` nodes equivocated in that view, contradicting the fault
//! bound. The `view` is included in every vote hash, so votes do not
//! carry across views. Equivocation evidence (two PROPOSALs from the
//! same speaker in one view) is exported to [`crate::rogue`].

use crate::discovery::Membership;
use crate::gossip::DriveReport;
use crate::rogue::RogueLedger;
use crate::{MeshError, decision_quorum};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Equivocation evidence: (node, digest_a, digest_b) — two signed
/// proposals with different hashes from one sender in one view.
pub type EquivocationEvidence = (String, String, String);

/// The consensus payload under decision.
///
/// A block is a compact COMMITMENT, not a data dump: it binds the
/// drive-report set and the witness-transcript set by canonical
/// BLAKE3 roots (computed over the sorted canonical JSON of each
/// element) so a 500-node fleet's block stays a few hundred bytes —
/// one L2 frame. The full reports and transcripts ride in the final
/// certificate, where every verifier recomputes the roots and checks
/// them against this hash-bound commitment.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub membership_hash: String,
    /// Root over the sorted canonical drive reports (all of them).
    pub report_root: String,
    pub report_count: u32,
    /// Root over the sorted canonical passing spot transcripts.
    pub spot_root: String,
    pub spot_count: u32,
    /// Canonical rogue entries (small, hash-stable).
    pub rogue_entries: Vec<crate::rogue::RogueEntry>,
    pub view: u32,
}

impl Block {
    /// Canonical hash: BLAKE3 over the canonical JSON.
    pub fn hash(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("block json");
        blake3::hash(&canonical).to_hex().to_string()
    }
}

/// Which phase this node is in for the current view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for a proposal (or to broadcast ours as speaker).
    AwaitProposal,
    /// Proposal seen, collecting PREPARE votes.
    Prepared,
    /// 2f+1 PREPAREs seen, collecting COMMIT votes.
    Committing,
    /// 2f+1 COMMITs seen — decided.
    Decided,
}

/// Consensus state machine (one node's local view of the protocol).
pub struct Consensus {
    me: String,
    membership: Membership,
    /// Deterministic speaker order seed = membership hash.
    membership_hash: String,
    /// Isolated (rogue) nodes, removed from the live quorum set.
    isolated: HashSet<String>,
    view: u32,
    phase: Phase,
    proposal: Option<Block>,
    proposal_hash: Option<String>,
    /// Proposal digests SEEN from each node this view — two different
    /// digests from one node = equivocation evidence.
    seen_proposals: HashMap<String, Vec<String>>,
    /// Signed vote registry: (view, "prepare"|"commit", hash) → voters.
    prepare_votes: HashMap<String, HashSet<String>>,
    commit_votes: HashMap<String, HashSet<String>>,
    change_view_votes: HashSet<String>,
    view_timeout_ticks: u32,
    ticks_in_view: u32,
    /// The decided block hash. Committers are read LIVE from the
    /// vote registry so the list converges to every voter that
    /// committed — identical on every node, unlike a decision-time
    /// snapshot (which depends on delivery order).
    decided: Option<String>,
}

impl Consensus {
    pub fn new(me: String, membership: &Membership, view_timeout_ticks: u32) -> Self {
        Self {
            me,
            membership: membership.clone(),
            membership_hash: membership.hash.clone(),
            isolated: HashSet::new(),
            view: 0,
            phase: Phase::AwaitProposal,
            proposal: None,
            proposal_hash: None,
            seen_proposals: HashMap::new(),
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            change_view_votes: HashSet::new(),
            view_timeout_ticks,
            ticks_in_view: 0,
            decided: None,
        }
    }

    /// The live decision: (hash, sorted committers). Present only
    /// once 2f+1 COMMITs landed for one hash in one view.
    pub fn decision(&self) -> Option<(String, Vec<String>)> {
        let hash = self.decided.as_ref()?;
        let mut committers: Vec<String> = self
            .commit_votes
            .get(hash)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        committers.sort();
        Some((hash.clone(), committers))
    }

    /// The live (non-isolated) node count.
    fn live_n(&self) -> usize {
        self.membership
            .nodes
            .iter()
            .filter(|n| !self.isolated.contains(*n))
            .count()
    }

    /// Quorum over the live set (recomputed after isolations).
    fn quorum(&self) -> usize {
        decision_quorum(self.live_n())
    }

    /// Deterministic speaker for a view: BLAKE3(membership ∥ view)
    /// selects an index into the sorted live membership.
    pub fn speaker_of(&self, view: u32) -> String {
        let live: Vec<&String> = self
            .membership
            .nodes
            .iter()
            .filter(|n| !self.isolated.contains(*n))
            .collect();
        if live.is_empty() {
            return self.me.clone();
        }
        let mut h = Hasher::new();
        h.update(self.membership_hash.as_bytes());
        h.update(&view.to_be_bytes());
        let idx = u64::from_be_bytes(h.finalize().as_bytes()[..8].try_into().expect("8 bytes"))
            as usize
            % live.len();
        (*live[idx]).clone()
    }

    /// Am I the speaker for the current view?
    pub fn am_speaker(&self) -> bool {
        self.speaker_of(self.view) == self.me
    }

    /// Whether this node should isolate a rogue (delegated from the
    /// rogue module once 2f+1 accusation votes land).
    pub fn apply_isolation(&mut self, node: &str) {
        if self.isolated.insert(node.to_string()) {
            // A member left the live set: all phase state is suspect —
            // restart the view cleanly so quorums recompute.
            self.enter_view(self.view + 1);
        }
    }

    fn enter_view(&mut self, view: u32) {
        self.view = view;
        self.phase = Phase::AwaitProposal;
        self.proposal = None;
        self.proposal_hash = None;
        self.prepare_votes.clear();
        self.commit_votes.clear();
        self.change_view_votes.clear();
        self.seen_proposals.clear();
        self.ticks_in_view = 0;
    }

    /// Build the block this speaker would propose now: a compact
    /// commitment over the reports and transcripts the speaker holds.
    pub fn build_proposal(
        &self,
        reports: &[DriveReport],
        transcripts: &[crate::gossip::SpotTranscript],
        rogue_ledger: &RogueLedger,
    ) -> Block {
        let (report_root, report_count) = crate::gossip::reports_root(reports);
        let (spot_root, spot_count) = crate::gossip::transcripts_root(transcripts);
        let mut rogue_entries: Vec<crate::rogue::RogueEntry> = rogue_ledger
            .entries
            .iter()
            .map(crate::rogue::RogueEntry::canonical)
            .collect();
        // Canonical order: isolation order may differ from node to
        // node (accusations arrive in wire order), but the BLOCK HASH
        // must be identical on every proposer and voter — sort by
        // node id so the decided bytes are order-independent.
        rogue_entries.sort_by(|a, b| a.node.cmp(&b.node));
        Block {
            membership_hash: self.membership_hash.clone(),
            report_root,
            report_count,
            spot_root,
            spot_count,
            rogue_entries,
            view: self.view,
        }
    }

    /// Record that `from` signed a proposal with this hash in the
    /// current view, and detect equivocation.
    ///
    /// This runs BEFORE any local block validation on purpose:
    /// two different signed proposals from one sender in one view
    /// are equivocation evidence regardless of whether either block
    /// is itself valid — a node that drops an invalid mutant before
    /// recording its digest lets the equivocator smuggle the pair
    /// past detection.
    ///
    /// Returns the PREVIOUSLY SEEN differing digest when `from` has
    /// already proposed different bytes this view (the caller turns
    /// that pair into a signed accusation).
    pub fn note_proposal_digest(&mut self, from: &str, hash: &str) -> Option<String> {
        let digests = self.seen_proposals.entry(from.to_string()).or_default();
        if let Some(other) = digests.iter().find(|d| **d != hash) {
            return Some(other.clone());
        }
        if !digests.contains(&hash.to_string()) {
            digests.push(hash.to_string());
        }
        None
    }

    /// A proposal arrived. Returns (prepared_now, equivocation_evidence).
    ///
    /// `equivocation_evidence` is `Some((node, digest_a, digest_b))`
    /// when the same node proposed two different blocks this view.
    pub fn on_proposal(
        &mut self,
        from: &str,
        block: &Block,
    ) -> Result<(bool, Option<EquivocationEvidence>), MeshError> {
        if self.decided.is_some() {
            return Ok((false, None));
        }
        if block.membership_hash != self.membership_hash {
            return Err(MeshError::Consensus(format!(
                "proposal membership hash {} != frozen {}",
                block.membership_hash, self.membership_hash
            )));
        }
        // View synchronization: a proposal for a later view means we
        // are behind (we were stuck in Executing while the swarm
        // rotated). Adopt the new view, then evaluate normally.
        if block.view > self.view {
            self.enter_view(block.view);
        }
        let hash = block.hash();
        let digests = self.seen_proposals.entry(from.to_string()).or_default();
        if let Some(other) = digests.iter().find(|d| **d != hash) {
            let ev = (from.to_string(), other.clone(), hash.clone());
            return Ok((false, Some(ev)));
        }
        if !digests.contains(&hash) {
            digests.push(hash.clone());
        }

        let am_speaker = self.speaker_of(self.view) == from;
        let right_view = block.view == self.view;
        let fresh = self.proposal.is_none();
        if !(am_speaker && right_view && fresh) {
            return Ok((false, None));
        }
        self.proposal = Some(block.clone());
        self.proposal_hash = Some(hash.clone());
        self.phase = Phase::Prepared; // speaker implicitly prepared its own
        self.record_vote("prepare", &hash, &self.me.clone());
        Ok((true, None))
    }

    /// A PREPARE/COMMIT vote arrived. Returns the phase transition:
    /// `EnteredCommit` (enough PREPAREs) or `Decided` (enough
    /// COMMITs). Votes for the decided hash keep being recorded so
    /// the committer list converges to every voter — identical on
    /// every node.
    pub fn on_vote(&mut self, kind: &str, from: &str, view: u32, hash: &str) -> VotingOutcome {
        // View synchronization: adopt a higher view seen in votes so
        // a node that was busy challenging does not strand itself in
        // a stale view (its votes would then be ignored by peers).
        if view > self.view {
            self.enter_view(view);
        }
        if view != self.view {
            return VotingOutcome::Ignored;
        }
        if self.isolated.contains(from) {
            return VotingOutcome::Ignored;
        }
        let q = self.quorum();
        match kind {
            "prepare" => {
                // Record every prepare vote (pre- and post-decision).
                let voters = self.prepare_votes.entry(hash.to_string()).or_default();
                voters.insert(from.to_string());
                let hash_ok = self.proposal_hash.as_deref() == Some(hash);
                let voters = voters.len();
                if !hash_ok || self.decided.is_some() {
                    return VotingOutcome::Ignored;
                }
                if self.phase == Phase::Prepared && voters >= q {
                    self.phase = Phase::Committing;
                    self.record_vote("commit", hash, &self.me.clone());
                    return VotingOutcome::EnteredCommit;
                }
            }
            "commit" => {
                // Record every commit vote, INCLUDING after the
                // decision: the committer list must converge.
                let voters = self.commit_votes.entry(hash.to_string()).or_default();
                voters.insert(from.to_string());
                let hash_ok = self.proposal_hash.as_deref() == Some(hash)
                    || self.decided.as_deref() == Some(hash);
                let voters = voters.len();
                if !hash_ok || self.decided.is_some() {
                    return VotingOutcome::Ignored;
                }
                if self.phase == Phase::Committing && voters >= q {
                    self.phase = Phase::Decided;
                    self.decided = Some(hash.to_string());
                    return VotingOutcome::Decided;
                }
            }
            _ => {}
        }
        VotingOutcome::Counting
    }

    fn record_vote(&mut self, kind: &str, hash: &str, node: &str) {
        let table = match kind {
            "prepare" => &mut self.prepare_votes,
            _ => &mut self.commit_votes,
        };
        table
            .entry(hash.to_string())
            .or_default()
            .insert(node.to_string());
    }

    /// CHANGE_VIEW vote arrived.
    pub fn on_change_view(&mut self, from: &str) -> bool {
        self.change_view_votes.insert(from.to_string());
        let f = self.membership.tolerance;
        self.change_view_votes.len() > f
    }

    /// Time tick: true when the view timed out and rotated.
    pub fn tick(&mut self) -> bool {
        if self.decided.is_some() {
            return false;
        }
        self.ticks_in_view += 1;
        if self.ticks_in_view >= self.view_timeout_ticks {
            self.enter_view(self.view + 1);
            return true;
        }
        false
    }

    pub fn view(&self) -> u32 {
        self.view
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn block(&self) -> Option<&Block> {
        self.proposal.as_ref()
    }

    pub fn block_hash(&self) -> Option<&str> {
        self.proposal_hash.as_deref()
    }

    pub fn decided(&self) -> bool {
        self.decided.is_some()
    }

    pub fn isolated(&self) -> &HashSet<String> {
        &self.isolated
    }

    pub fn membership(&self) -> &Membership {
        &self.membership
    }

    /// Live-set quorum (post-isolation).
    pub fn current_quorum(&self) -> usize {
        self.quorum()
    }
}

/// Result of ingesting a vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VotingOutcome {
    Ignored,
    Counting,
    EnteredCommit,
    Decided,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rogue::RogueLedger;

    fn membership(n: usize) -> Membership {
        let nodes: Vec<String> = (0..n).map(|i| format!("n{i:02}")).collect();
        Membership {
            hash: membership_hash(&nodes),
            nodes,
            total_drives: n as u64,
            tolerance: crate::byzantine_tolerance(n),
            quorum: decision_quorum(n),
        }
    }

    fn membership_hash(nodes: &[String]) -> String {
        let mut h = Hasher::new();
        for n in nodes {
            h.update(n.as_bytes());
        }
        h.finalize().to_hex().to_string()
    }

    fn ledger() -> RogueLedger {
        RogueLedger::new()
    }

    #[test]
    fn happy_path_four_nodes_decide() {
        let m = membership(4);
        let c0 = Consensus::new("n00".into(), &m, 10);
        // Find the speaker of view 0.
        let speaker = c0.speaker_of(0);
        let mut cs: Vec<Consensus> = (0..4)
            .map(|i| Consensus::new(format!("n{i:02}"), &m, 10))
            .collect();
        let block = c0.build_proposal(&[], &[], &ledger());

        // The speaker broadcasts the proposal: EVERY node validates and
        // accepts it (the "am_speaker" check is about the proposer, not
        // about us).
        for c in &mut cs {
            let (prepared, ev) = c.on_proposal(&speaker, &block).expect("proposal");
            assert!(ev.is_none());
            assert!(prepared, "every replica accepts a valid speaker proposal");
        }

        // Everyone broadcasts PREPARE for the block hash.
        let h = block.hash();
        for voter in 0..4 {
            for c in &mut cs {
                let _ = c.on_vote("prepare", &format!("n{voter:02}"), 0, &h);
            }
        }
        // With 4 prepare votes (incl. speaker self), everyone entered commit.
        assert!(cs.iter().all(|c| c.phase() == Phase::Committing));

        // Everyone broadcasts COMMIT.
        for voter in 0..4 {
            for c in &mut cs {
                let _ = c.on_vote("commit", &format!("n{voter:02}"), 0, &h);
            }
        }
        assert!(cs.iter().all(|c| c.decided()));
        // The committer list is LIVE: after all four commit
        // broadcasts every node lists exactly the four voters.
        assert!(
            cs.iter()
                .all(|c| c.decision().expect("decision").1.len() == 4)
        );
    }

    #[test]
    fn one_byzantine_node_tolerated() {
        // n=4, f=1: nodes n00..n03, n03 is byzantine and never votes.
        let m = membership(4);
        let mut cs: Vec<Consensus> = (0..4)
            .map(|i| Consensus::new(format!("n{i:02}"), &m, 10))
            .collect();
        let speaker = cs[0].speaker_of(0);
        let block = cs[0].build_proposal(&[], &[], &ledger());
        for c in &mut cs {
            let _ = c.on_proposal(&speaker, &block).expect("proposal");
        }
        let h = block.hash();
        // Only 3 honest nodes vote.
        for voter in 0..3 {
            for c in cs.iter_mut() {
                let _ = c.on_vote("prepare", &format!("n{voter:02}"), 0, &h);
            }
        }
        for voter in 0..3 {
            for c in cs.iter_mut() {
                let _ = c.on_vote("commit", &format!("n{voter:02}"), 0, &h);
            }
        }
        // Quorum = 3 → decided despite the silent byzantine.
        assert!(cs.iter().take(3).all(|c| c.decided()));
        assert!(cs[0].decision().expect("decision").1.len() >= 3);
    }

    #[test]
    fn note_digest_detects_equivocation_before_validation() {
        // The mutant is invalid — validation would drop it — but the
        // digest pair must still be recorded as evidence.
        let m = membership(4);
        let mut c = Consensus::new("n00".into(), &m, 10);
        assert!(c.note_proposal_digest("n01", "aaaa").is_none());
        assert_eq!(c.note_proposal_digest("n01", "bbbb"), Some("aaaa".into()));
        // Idempotent re-note of the same digest is not evidence.
        assert!(c.note_proposal_digest("n01", "aaaa").is_none());
        // Different senders are independent.
        assert!(c.note_proposal_digest("n02", "cccc").is_none());
    }

    #[test]
    fn equivocation_is_flagged() {
        let m = membership(4);
        let mut c = Consensus::new("n00".into(), &m, 10);
        let speaker = c.speaker_of(0);
        let b1 = c.build_proposal(&[], &[], &ledger());
        let mut b2 = b1.clone();
        b2.report_count += 1; // divergent content → divergent hash
        let (_, ev) = c.on_proposal(&speaker, &b1).expect("p1");
        assert!(ev.is_none());
        let (accepted, ev) = c.on_proposal(&speaker, &b2).expect("p2");
        assert!(!accepted);
        let (node, d1, d2) = ev.expect("equivocation evidence");
        assert_eq!(node, speaker);
        assert_ne!(d1, d2);
    }

    #[test]
    fn view_timeout_rotates_speaker() {
        let m = membership(4);
        let mut c = Consensus::new("n00".into(), &m, 5);
        let v0 = c.view();
        for _ in 0..5 {
            let _ = c.tick();
        }
        assert_eq!(c.view(), v0 + 1);
        assert_eq!(c.phase(), Phase::AwaitProposal);
    }

    #[test]
    fn wrong_membership_hash_rejected() {
        let m = membership(4);
        let mut c = Consensus::new("n00".into(), &m, 5);
        let mut block = c.build_proposal(&[], &[], &ledger());
        block.membership_hash = "deadbeef".to_string();
        assert!(c.on_proposal(&c.speaker_of(0), &block).is_err());
    }

    #[test]
    fn isolation_rotates_and_recomputes_quorum() {
        let m = membership(7); // n=7, f=2, quorum 5
        let mut c = Consensus::new("n00".into(), &m, 5);
        assert_eq!(c.current_quorum(), 5);
        c.apply_isolation("n03");
        c.apply_isolation("n06");
        // Live set is 5 → f=1, quorum 3.
        assert_eq!(c.current_quorum(), 3);
        assert_eq!(c.isolated().len(), 2);
    }
}
