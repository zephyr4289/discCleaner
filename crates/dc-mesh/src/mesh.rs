//! The mesh node: one `dc` instance's full lifecycle on the swarm,
//! and the deterministic `SwarmSim` driver.
//!
//! [`MeshNode`] runs one node end-to-end:
//!
//! ```text
//! DISCOVERING ──freeze──▶ EXECUTING ──ready──▶ SEALING ──decided+sealed──▶ CERTIFIED
//!    broadcast HELLO       wipe drives,        propose/vote,
//!                          gossip reports,      FROST round 1/2,
//!                          challenge/verify    ML-DSA partials,
//!                          (as every node       assemble swarm cert
//!                           does for its peers)
//! ```
//!
//! Wipers and witnesses are the same code path — every node wipes the
//! drives it advertised and challenges the drives its peers
//! reported. Misbehavior is scriptable for drills and CI:
//!
//! * [`NodeBehavior::Honest`] — wipe, report honestly, answer spot
//!   proofs from the media, challenge peers, vote, co-sign.
//! * [`NodeBehavior::Liar`] — reports "wiped" instantly but answers
//!   spot proofs with bytes that are NOT the declared pattern
//!   (caught by every witness; isolated with `failed_spot_proof`).
//! * [`NodeBehavior::Silent`] — freezes membership, then goes dark:
//!   no reports, no answers (isolated via `timeout` once its peers
//!   stop waiting).
//! * [`NodeBehavior::Equivocator`] — when it is the speaker, sends
//!   different blocks to the peers (isolated via `equivocation`;
//!   every receiver keeps both signed proposals as evidence).
//!
//! [`SwarmSim`] drives N nodes over a [`crate::transport::VirtualLan`]
//! in fixed order with a tick between rounds: same seed, same rogue
//! behavior, same certificate bytes. It powers `dc mesh simulate`,
//! the CI suite and the drill books.

use crate::consensus::{Consensus, VotingOutcome};
use crate::discovery::{Discovery, HelloBody};
use crate::frame::{MeshFrame, MsgType};
use crate::gossip::{DriveReport, GossipStore, SpotChallenge, SpotProof, SpotTranscript};
use crate::rogue::{RogueKind, RogueLedger};
use crate::threshold::{
    CoordinatorSession, FrostSignature, MlDsaSeal, MlDsaSealEntry, RoundOneCommitment,
    RoundTwoShare, ShareSecret, SignerSession, ThresholdParams, ThresholdPublicKey,
};
use crate::transport::MeshTransport;
use crate::{MeshError, decision_quorum};
use dc_core::Pattern;
use dc_pq::MlDsa44KeyPair;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Scripted behavior of a node (drills, CI, red-team rehearsals).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeBehavior {
    Honest,
    Liar,
    Silent,
    Equivocator,
}

/// A simulated drive spec.
#[derive(Debug, Clone)]
pub struct SimDriveSpec {
    pub serial: String,
    /// Capacity in windows (simulation granularity).
    pub capacity_windows: u64,
    /// Window size in 512-byte sectors.
    pub window_sectors: u32,
}

/// Node configuration.
#[derive(Debug, Clone)]
pub struct MeshNodeConfig {
    pub behavior: NodeBehavior,
    pub drives: Vec<SimDriveSpec>,
    /// Final surface pattern all drives are wiped to.
    pub pattern: Pattern,
    /// FROST threshold override (None → default_for(n)).
    pub threshold: Option<ThresholdParams>,
    pub expected_nodes: Option<usize>,
    pub discovery_silence_ticks: u32,
    pub view_timeout_ticks: u32,
    pub spot_challenges_per_drive: u32,
    pub challenge_deadline_ticks: u64,
    pub report_deadline_ticks: u64,
    /// Deterministic RNG seed.
    pub seed: u64,
    /// Deterministic FROST nonce derivation for drills and CI replay
    /// (`dc mesh simulate`): each signer's round-1 nonces are drawn
    /// from a PRNG seeded with (this seed, share index, tick).
    /// `None` (production default) draws from the OS CSPRNG via
    /// [`crate::threshold::SignerSession::round1`] — nonce reuse in
    /// Schnorr leaks the share, so live deployments must NEVER set
    /// this.
    pub seal_determinism: Option<u64>,
}

impl Default for MeshNodeConfig {
    fn default() -> Self {
        Self {
            behavior: NodeBehavior::Honest,
            drives: Vec::new(),
            pattern: Pattern::Zero,
            threshold: None,
            expected_nodes: None,
            discovery_silence_ticks: 3,
            view_timeout_ticks: 5,
            spot_challenges_per_drive: 2,
            challenge_deadline_ticks: 4,
            report_deadline_ticks: 12,
            seed: 0,
            seal_determinism: None,
        }
    }
}

/// Lifecycle position of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Discovering,
    Executing,
    Sealing,
    Certified,
}

/// Vote wire body (PREPARE/COMMIT).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteBody {
    pub kind: String,
    pub view: u32,
    pub hash: String,
}

/// Accusation wire body (frame signer is the accuser).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuseWire {
    pub accused: String,
    pub kind: String,
    pub evidence: String,
    pub evidence_digest: String,
}

/// Isolation wire body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolateWire {
    pub node: String,
    pub kind: String,
    pub digest: String,
    pub accusers: Vec<String>,
    pub view: u32,
}

/// Seal round-2 wire body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealShareWire {
    pub frost: RoundTwoShare,
    /// ML-DSA-44 signature over the sealing message (hex).
    pub ml_dsa: String,
}

/// A simulated physical drive.
#[derive(Debug, Clone)]
struct SimDrive {
    spec: SimDriveSpec,
    /// Backing store: window_sectors * 512 bytes per written window.
    backing: Vec<u8>,
    windows_written: u64,
    wiped: bool,
}

/// A pending challenge this node issued as witness.
#[derive(Debug, Clone)]
struct PendingChallenge {
    challenge: SpotChallenge,
}

/// Tiny deterministic RNG (xorshift64*) — challenge windows only.
struct DetRng(u64);

impl DetRng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

/// One node in the swarm.
pub struct MeshNode {
    name: String,
    signing: SigningKey,
    ml: MlDsa44KeyPair,
    transport: Box<dyn MeshTransport>,
    cfg: MeshNodeConfig,
    state: NodeState,
    tick: u64,
    discovery: Discovery,
    gossip: GossipStore,
    consensus: Option<Consensus>,
    rogue: RogueLedger,
    sim_drives: Vec<SimDrive>,
    reports_sent: bool,
    frost_public: ThresholdPublicKey,
    frost_share: Option<ShareSecret>,
    seal_commitments: Vec<RoundOneCommitment>,
    seal_shares: Vec<SealShareWire>,
    seal_commit_sent: bool,
    seal_share_sent: bool,
    /// Transcripts accumulated from all witnesses (gossiped).
    transcripts: Vec<SpotTranscript>,
    /// Witness-side pending challenges: nonce → challenge.
    pending: HashMap<String, PendingChallenge>,
    /// Challenge count already issued per serial (idempotence).
    challenged: HashMap<String, usize>,
    certificate: Option<crate::cert::SwarmCertificate>,
    rng: DetRng,
    /// View we last broadcast a proposal for (idempotence).
    last_proposed_view: Option<u32>,
    /// The live FROST signing session — created at round 1, consumed
    /// at round 2. A Schnorr session's nonces MUST be the ones its
    /// commitments published; regenerating them between rounds is the
    /// textbook way to produce an unverifiable (and, with reuse, a
    /// key-leaking) signature.
    seal_session: Option<SignerSession>,
}

impl MeshNode {
    /// Build a node. `frost_share` assigns the dealer-distributed
    /// signing share (index = 1-based position in sorted membership).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        signing: SigningKey,
        ml: MlDsa44KeyPair,
        transport: Box<dyn MeshTransport>,
        frost_public: ThresholdPublicKey,
        frost_share: Option<ShareSecret>,
        cfg: MeshNodeConfig,
    ) -> Self {
        let drives = cfg.drives.clone();
        let me = HelloBody {
            node: name.clone(),
            ml_dsa_pk: hex::encode(ml.public_key_bytes()),
            drives: drives.len() as u32,
            seq: 0,
        };
        let discovery = Discovery::new(
            me,
            transport.mac(),
            cfg.expected_nodes,
            cfg.discovery_silence_ticks,
        );
        let sim_drives = drives
            .into_iter()
            .map(|spec| SimDrive {
                spec,
                backing: Vec::new(),
                windows_written: 0,
                wiped: false,
            })
            .collect();
        let rng = DetRng(cfg.seed ^ 0x9E3779B97F4A7C15);
        Self {
            name,
            signing,
            ml,
            transport,
            cfg,
            state: NodeState::Discovering,
            tick: 0,
            discovery,
            gossip: GossipStore::new(),
            consensus: None,
            rogue: RogueLedger::new(),
            sim_drives,
            reports_sent: false,
            frost_public,
            frost_share,
            seal_commitments: Vec::new(),
            seal_shares: Vec::new(),
            seal_commit_sent: false,
            seal_share_sent: false,
            transcripts: Vec::new(),
            pending: HashMap::new(),
            challenged: HashMap::new(),
            certificate: None,
            rng,
            last_proposed_view: None,
            seal_session: None,
        }
    }

    pub fn id(&self) -> &str {
        &self.name
    }

    pub fn state(&self) -> NodeState {
        self.state
    }

    pub fn certificate(&self) -> Option<&crate::cert::SwarmCertificate> {
        self.certificate.as_ref()
    }

    pub fn rogue_ledger(&self) -> &RogueLedger {
        &self.rogue
    }

    pub fn known_reports(&self) -> usize {
        self.gossip.len()
    }

    pub fn behavior(&self) -> NodeBehavior {
        self.cfg.behavior
    }

    // -- transport helpers --------------------------------------------------

    fn send_frame(
        &mut self,
        dst: [u8; 6],
        msg: MsgType,
        view: u32,
        payload: &[u8],
    ) -> Result<(), MeshError> {
        let frame = MeshFrame {
            view,
            node: self.signing.verifying_key().to_bytes(),
            msg,
            payload: payload.to_vec(),
        };
        let wire = frame.encode_signed(&self.signing);
        self.transport.send(dst, &wire)
    }

    fn broadcast(&mut self, msg: MsgType, view: u32, payload: &[u8]) -> Result<(), MeshError> {
        let frame = MeshFrame {
            view,
            node: self.signing.verifying_key().to_bytes(),
            msg,
            payload: payload.to_vec(),
        };
        let wire = frame.encode_signed(&self.signing);
        self.transport.broadcast(&wire)?;
        Ok(())
    }

    fn route_to(&self, node: &str) -> [u8; 6] {
        self.discovery.route_to(node)
    }

    // -- main loop ----------------------------------------------------------

    /// Advance one tick: drain the inbox, act on state.
    pub fn step(&mut self) -> Result<(), MeshError> {
        self.tick += 1;
        self.drain_inbox()?;
        match self.state {
            NodeState::Discovering => self.step_discovering()?,
            NodeState::Executing | NodeState::Sealing => self.step_active()?,
            NodeState::Certified => {}
        }
        Ok(())
    }

    fn drain_inbox(&mut self) -> Result<(), MeshError> {
        loop {
            let Some((src_mac, wire)) = self.transport.recv(0)? else {
                return Ok(());
            };
            let (frame, _sig) = MeshFrame::decode_verify(&wire)?;
            let from = hex::encode(frame.node);
            // Isolated nodes are cut off from all further protocol
            // participation — their frames are dropped unread.
            if self.rogue.is_isolated(&from) || from == self.name {
                continue;
            }
            self.dispatch(frame.msg, &from, src_mac, frame.view, &frame.payload)?;
        }
    }

    fn dispatch(
        &mut self,
        msg: MsgType,
        from: &str,
        src_mac: [u8; 6],
        view: u32,
        payload: &[u8],
    ) -> Result<(), MeshError> {
        match msg {
            MsgType::Hello | MsgType::HelloAck => {
                let fresh = self.discovery.ingest(msg, src_mac, payload)?;
                if fresh && self.state != NodeState::Discovering {
                    let body = self.discovery.hello_ack_body();
                    self.send_frame(src_mac, MsgType::HelloAck, view, &body)?;
                }
            }
            MsgType::DriveReport => {
                let report: DriveReport = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("drive report: {e}")))?;
                if report.node != from {
                    // Identity mismatch: the frame signer is not the
                    // reporter. Drop and accuse.
                    self.accuse(
                        from,
                        RogueKind::DuplicateSerial,
                        &format!(
                            "{{\"mismatch\": true, \"reporter\": \"{}\", \"signer\": \"{from}\"}}",
                            report.node
                        ),
                    )?;
                    return Ok(());
                }
                let (fresh, duplicate) = self.gossip.ingest(&report);
                if duplicate {
                    let other = self
                        .gossip
                        .get(&report.serial)
                        .map(|r| r.node.clone())
                        .unwrap_or_default();
                    self.accuse(
                        from,
                        RogueKind::DuplicateSerial,
                        &format!(
                            "{{\"serial\": \"{}\", \"also_claimed_by\": \"{other}\"}}",
                            report.serial
                        ),
                    )?;
                    return Ok(());
                }
                if fresh {
                    self.issue_challenges(&report)?;
                }
            }
            MsgType::Challenge => {
                let ch: SpotChallenge = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("challenge: {e}")))?;
                self.answer_challenge(&ch)?;
            }
            MsgType::SpotProof => {
                let proof: SpotProof = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("spot proof: {e}")))?;
                self.handle_proof(from, &proof)?;
            }
            MsgType::Transcript => {
                let t: SpotTranscript = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("transcript: {e}")))?;
                if !self
                    .transcripts
                    .iter()
                    .any(|x| x.challenge.nonce == t.challenge.nonce && x.witness == t.witness)
                {
                    self.transcripts.push(t);
                }
            }
            MsgType::Proposal => {
                let block: crate::consensus::Block = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("proposal: {e}")))?;
                // 1. Equivocation bookkeeping FIRST, before any local
                //    validation: two DIFFERENT signed proposals from
                //    one sender in one view are evidence regardless of
                //    whether either block is valid. Dropping an invalid
                //    mutant before recording its digest would let the
                //    equivocator smuggle the pair past detection.
                if let Some(other) = self
                    .consensus
                    .as_mut()
                    .and_then(|c| c.note_proposal_digest(from, &block.hash()))
                {
                    // Canonicalize evidence: sort the two digests so
                    // every receiver produces the SAME evidence bytes
                    // and the accusations aggregate.
                    let (lo, hi) = if other <= block.hash() {
                        (other, block.hash())
                    } else {
                        (block.hash(), other)
                    };
                    let evidence = format!(
                        "{{\"view\": {view}, \"digest_a\": \"{lo}\", \"digest_b\": \"{hi}\"}}"
                    );
                    self.accuse(from, RogueKind::Equivocation, &evidence)?;
                    return Ok(());
                }
                // 2. Local validation BEFORE accepting the block into
                //    the consensus state: the proposal's roots must
                //    bind exactly the report set and transcript set we
                //    independently hold...
                {
                    let reports: Vec<DriveReport> = self
                        .gossip
                        .all()
                        .into_iter()
                        .filter(|r| !self.rogue.is_isolated(&r.node))
                        .cloned()
                        .collect();
                    let (r_root, r_count) = crate::gossip::reports_root(&reports);
                    let transcripts: Vec<SpotTranscript> = self
                        .transcripts
                        .iter()
                        .filter(|t| t.passed)
                        .cloned()
                        .collect();
                    let (t_root, t_count) = crate::gossip::transcripts_root(&transcripts);
                    let roots_ok = block.report_root == r_root
                        && block.report_count == r_count
                        && block.spot_root == t_root
                        && block.spot_count == t_count;
                    // ...and the block must carry EVERY isolation we
                    // have already ruled: a decision that omits a
                    // live rogue verdict is stale by definition —
                    // refuse to PREPARE it and let view change retry.
                    // (One-directional on purpose: a block may carry
                    // entries we have not yet ruled ourselves; we
                    // learn them from the block's accuser set.)
                    let mine: HashSet<&String> =
                        self.rogue.entries.iter().map(|e| &e.node).collect();
                    let theirs: HashSet<&String> =
                        block.rogue_entries.iter().map(|e| &e.node).collect();
                    let ledger_ok = mine.is_subset(&theirs);
                    if !(block.report_count == 0 && block.spot_count == 0)
                        && !(roots_ok && ledger_ok)
                    {
                        return Ok(()); // silently divergent view — view change will retry
                    }
                }
                let (accepted, _equivocation, cur_view) = match self.consensus.as_mut() {
                    Some(c) => {
                        let (a, e) = c.on_proposal(from, &block)?;
                        (a, e, c.view())
                    }
                    None => (false, None, 0),
                };
                if accepted {
                    let body = VoteBody {
                        kind: "prepare".into(),
                        view: cur_view,
                        hash: block.hash(),
                    };
                    let payload = serde_json::to_vec(&body).expect("vote json");
                    self.broadcast(MsgType::Prepare, cur_view, &payload)?;
                }
            }
            MsgType::Prepare | MsgType::Commit => {
                let vote: VoteBody = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("vote: {e}")))?;
                let outcome = match self.consensus.as_mut() {
                    Some(c) => c.on_vote(&vote.kind, from, vote.view, &vote.hash),
                    None => VotingOutcome::Ignored,
                };
                match outcome {
                    VotingOutcome::EnteredCommit => {
                        let body = VoteBody {
                            kind: "commit".into(),
                            view: vote.view,
                            hash: vote.hash.clone(),
                        };
                        let payload = serde_json::to_vec(&body).expect("vote json");
                        self.broadcast(MsgType::Commit, vote.view, &payload)?;
                    }
                    VotingOutcome::Decided => {
                        self.state = NodeState::Sealing;
                    }
                    _ => {}
                }
            }
            MsgType::ChangeView | MsgType::Heartbeat | MsgType::PeerList => {
                // Reserved for v1; timeouts drive rotation deterministically.
            }
            MsgType::Accuse => {
                let wire: AccuseWire = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("accuse: {e}")))?;
                let kind = kind_from_str(&wire.kind)?;
                let count = self.rogue.accuse(
                    from,
                    &wire.accused,
                    kind,
                    wire.evidence.clone(),
                    wire.evidence_digest.clone(),
                );
                self.maybe_isolate(&wire.accused, kind, &wire.evidence_digest, count)?;
            }
            MsgType::Isolate => {
                let wire: IsolateWire = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("isolate: {e}")))?;
                let kind = kind_from_str(&wire.kind)?;
                if !self.rogue.is_isolated(&wire.node) {
                    let q = self.frozen_quorum();
                    if let Some(_entry) =
                        self.rogue
                            .try_isolate(&wire.node, kind, &wire.digest, q, wire.view)
                    {
                        if let Some(c) = self.consensus.as_mut() {
                            c.apply_isolation(&wire.node);
                        }
                        self.drop_pending_for(&wire.node);
                    }
                }
            }
            MsgType::SealCommit => {
                let c: RoundOneCommitment = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("seal commit: {e}")))?;
                if !self.seal_commitments.iter().any(|x| x.signer == c.signer) {
                    self.seal_commitments.push(c);
                }
            }
            MsgType::SealShare => {
                let s: SealShareWire = serde_json::from_slice(payload)
                    .map_err(|e| MeshError::Frame(format!("seal share: {e}")))?;
                if !self
                    .seal_shares
                    .iter()
                    .any(|x| x.frost.signer == s.frost.signer)
                {
                    self.seal_shares.push(s);
                }
            }
        }
        Ok(())
    }

    // -- state steps --------------------------------------------------------

    fn step_discovering(&mut self) -> Result<(), MeshError> {
        let (hello, frozen) = self.discovery.step();
        if let Some(body) = hello {
            self.broadcast(MsgType::Hello, 0, &body)?;
        }
        if frozen && let Some(membership) = self.discovery.membership().cloned() {
            let params = self
                .cfg
                .threshold
                .unwrap_or_else(|| ThresholdParams::default_for(membership.nodes.len()));
            self.cfg.threshold = Some(params);
            self.consensus = Some(Consensus::new(
                self.name.clone(),
                &membership,
                self.cfg.view_timeout_ticks,
            ));
            self.state = NodeState::Executing;
        }
        Ok(())
    }

    fn frozen_quorum(&self) -> usize {
        self.discovery
            .membership()
            .map(|m| decision_quorum(m.nodes.len()))
            .unwrap_or(3)
    }

    /// One tick of the active lifecycle (Executing or Sealing — both
    /// run the consensus clock and the witness deadlines; the split
    /// is only about whether we may yet propose).
    fn step_active(&mut self) -> Result<(), MeshError> {
        // 1. Wipe simulation (honest nodes; liars skip to forging).
        if self.state == NodeState::Executing && !self.reports_sent {
            match self.cfg.behavior {
                NodeBehavior::Liar => {
                    self.reports_sent = true;
                    let snapshots: Vec<SimDrive> = self.sim_drives.clone();
                    for drive in &snapshots {
                        let report = self.forge_report(drive);
                        // The fabric never echoes our own broadcasts back:
                        // self-ingest so readiness accounting closes.
                        let _ = self.gossip.ingest(&report);
                        let payload = serde_json::to_vec(&report).expect("report json");
                        self.broadcast(MsgType::DriveReport, 1, &payload)?;
                    }
                }
                NodeBehavior::Silent => {}
                NodeBehavior::Honest | NodeBehavior::Equivocator => {
                    if !self.sim_drives.is_empty() {
                        let pattern = self.cfg.pattern.clone();
                        for drive in self.sim_drives.iter_mut() {
                            if !drive.wiped {
                                Self::wipe_chunk(&pattern, drive);
                            }
                        }
                        if self.sim_drives.iter().all(|d| d.wiped) {
                            self.reports_sent = true;
                            let snapshots: Vec<SimDrive> = self.sim_drives.clone();
                            let reports: Vec<DriveReport> = snapshots
                                .iter()
                                .map(|drive| self.honest_report(drive))
                                .collect();
                            for report in &reports {
                                // Fabric never echoes our own broadcast:
                                // self-ingest for readiness accounting.
                                let _ = self.gossip.ingest(report);
                            }
                            for report in &reports {
                                let payload = serde_json::to_vec(report).expect("report json");
                                self.broadcast(MsgType::DriveReport, 1, &payload)?;
                            }
                        }
                    } else {
                        // Witness-only node: nothing to wipe.
                        self.reports_sent = true;
                    }
                }
            }
        }

        // 2. Witness deadlines: unanswered challenges and missing
        //    reports become Timeout accusations.
        if self.state == NodeState::Executing {
            self.enforce_deadlines()?;
        }

        // 3. Readiness (Executing only): all expected reports in and
        //    every one independently verified → we may propose/vote.
        let ready = self.state == NodeState::Executing && self.is_ready();

        // 4. Consensus clock: rotate stalled views, accuse stalling
        //    speakers — but ONLY when we ourselves were ready: a
        //    node still challenging cannot know whether the speaker
        //    had anything to propose, and accusing an honest speaker
        //    mid-challenge would isolate a healthy member. Views keep
        //    rotating regardless (liveness does not depend on the
        //    accusation).
        self.consensus_clock(ready)?;

        if ready {
            self.state = NodeState::Sealing;
        }

        // 5. Sealing rounds (once decided).
        if self.state == NodeState::Sealing {
            self.step_seal()?;
        }
        Ok(())
    }

    fn consensus_clock(&mut self, was_ready: bool) -> Result<(), MeshError> {
        let rotated = match self.consensus.as_mut() {
            Some(c) => c.tick(),
            None => false,
        };
        if rotated && was_ready {
            let stalled_view = self.consensus.as_ref().map(|c| c.view() - 1).unwrap_or(0);
            let speaker = self
                .consensus
                .as_ref()
                .map(|c| c.speaker_of(stalled_view))
                .unwrap_or_default();
            if !speaker.is_empty() && speaker != self.name {
                // We were READY and the speaker still never proposed:
                // a genuine stall. Evidence binds the view.
                let evidence = format!(
                    "{{\"stalled_view\": {stalled_view}, \"role\": \"speaker\", \"accuser_ready\": true}}"
                );
                self.accuse(&speaker, RogueKind::Timeout, &evidence)?;
            }
        }
        Ok(())
    }

    /// One tick of physical wipe work on one drive. An associated
    /// function on purpose: no `&self` borrow, so the caller can
    /// hold a mutable drive while supplying the pattern by value.
    fn wipe_chunk(pattern: &Pattern, drive: &mut SimDrive) -> bool {
        // Write one window per drive per tick (line-rate stand-in).
        if drive.windows_written < drive.spec.capacity_windows {
            let w = drive.windows_written;
            let len = drive.spec.window_sectors as usize * 512;
            if drive.backing.len() < (w as usize + 1) * len {
                drive.backing.resize((w as usize + 1) * len, 0);
            }
            let start = w as usize * len;
            let src = dc_core::create_pattern_source(pattern);
            src.fill(w, &mut drive.backing[start..start + len]);
            drive.windows_written += 1;
            if drive.windows_written >= drive.spec.capacity_windows {
                drive.wiped = true;
                return true;
            }
        }
        false
    }

    fn honest_report(&self, drive: &SimDrive) -> DriveReport {
        // Evidence is claimed over the pattern surface: for an honest
        // node the readback backing IS the pattern bytes, so the
        // digests are identical either way. A drive whose backing is
        // absent (never wiped — the liar's fabrication path) claims
        // the digests the pattern WOULD produce; the witness spot-
        // proofs are what expose that the media never held them.
        let mut digests: Vec<[u8; 32]> = Vec::new();
        let src = dc_core::create_pattern_source(&self.cfg.pattern);
        for w in 0..drive.spec.capacity_windows {
            let len = drive.spec.window_sectors as usize * 512;
            let start = w as usize * len;
            let d = if drive.backing.len() >= start + len {
                blake3::hash(&drive.backing[start..start + len])
            } else {
                let mut buf = vec![0u8; len];
                src.fill(w, &mut buf);
                blake3::hash(&buf)
            };
            digests.push(*d.as_bytes());
        }
        let refs: Vec<&[u8]> = digests.iter().map(|d| d.as_slice()).collect();
        DriveReport {
            node: self.name.clone(),
            serial: drive.spec.serial.clone(),
            wwn: None,
            bus: "SIM".to_string(),
            capacity_lbas: drive.spec.capacity_windows * drive.spec.window_sectors as u64,
            window_sectors: drive.spec.window_sectors,
            windows_total: drive.spec.capacity_windows,
            windows_verified: drive.spec.capacity_windows,
            pattern: self.cfg.pattern.clone(),
            evidence_root: crate::gossip::evidence_root(&refs),
            view: 1,
        }
    }

    fn forge_report(&self, drive: &SimDrive) -> DriveReport {
        // The lie: claim verification the media never underwent.
        self.honest_report(drive)
    }

    fn issue_challenges(&mut self, report: &DriveReport) -> Result<(), MeshError> {
        let want = self.cfg.spot_challenges_per_drive as usize;
        let have = self.challenged.get(&report.serial).copied().unwrap_or(0);
        for i in have..want {
            let nonce = format!("{}-{}-{}", self.name, report.serial, i);
            let window = self.rng.below(report.windows_total);
            let challenge = SpotChallenge {
                serial: report.serial.clone(),
                window,
                window_sectors: report.window_sectors,
                nonce: nonce.clone(),
                deadline_tick: self.tick + self.cfg.challenge_deadline_ticks,
            };
            let dst = self.route_to(&report.node);
            let payload = serde_json::to_vec(&challenge).expect("challenge json");
            self.send_frame(dst, MsgType::Challenge, 1, &payload)?;
            self.pending.insert(nonce, PendingChallenge { challenge });
            self.challenged.insert(report.serial.clone(), i + 1);
        }
        Ok(())
    }

    fn answer_challenge(&mut self, ch: &SpotChallenge) -> Result<(), MeshError> {
        if self.cfg.behavior == NodeBehavior::Silent {
            return Ok(()); // goes dark
        }
        let Some(drive) = self
            .sim_drives
            .iter()
            .find(|d| d.spec.serial == ch.serial)
            .cloned()
        else {
            return Ok(());
        };
        let len = ch.window_sectors as usize * 512;
        let start = ch.window as usize * len;
        let data: Vec<u8> = if self.cfg.behavior == NodeBehavior::Liar {
            // The lie materialized: bytes that are NOT the pattern.
            (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
        } else if drive.backing.len() >= start + len {
            drive.backing[start..start + len].to_vec()
        } else {
            vec![0u8; len]
        };
        // Base64 expansion ≈ 4/3: send raw bytes when the envelope
        // fits, digest-binding otherwise.
        let proof = if crate::gossip::b64_encode(&data).len() + 512 <= crate::MAX_FRAME_PAYLOAD {
            SpotProof::honest(&ch.serial, ch.window, &ch.nonce, &data)
        } else {
            SpotProof::digest_form(&ch.serial, ch.window, &ch.nonce, &data)
        };
        let payload = serde_json::to_vec(&proof).expect("proof json");
        // Replies go to broadcast: the nonce binds the answer to the
        // single witness that asked, everyone else drops it.
        self.broadcast(MsgType::SpotProof, 1, &payload)?;
        Ok(())
    }

    fn handle_proof(&mut self, from: &str, proof: &SpotProof) -> Result<(), MeshError> {
        let Some(pending) = self.pending.remove(&proof.nonce) else {
            return Ok(()); // not ours (broadcast proof)
        };
        let Some(report) = self.gossip.get(&proof.serial).cloned() else {
            return Ok(());
        };
        if report.node != from {
            return Ok(()); // proof must come from the wiper itself
        }
        let transcript = SpotTranscript::verify(
            self.name.as_str(),
            from,
            &pending.challenge,
            Some(proof),
            &report,
        );
        if transcript.passed {
            let payload = serde_json::to_vec(&transcript).expect("transcript json");
            self.broadcast(MsgType::Transcript, 1, &payload)?;
            self.transcripts.push(transcript);
        } else {
            // Canonical evidence — identical across witnesses for the
            // same failure (binding mismatch on the same challenge).
            let evidence = serde_json::json!({
                "serial": transcript.challenge.serial,
                "window": transcript.challenge.window,
                "nonce": transcript.challenge.nonce,
                "proof_binding": transcript.proof.as_ref().map(|p| p.binding.clone()),
                "reason": transcript.reason,
            })
            .to_string();
            self.accuse(from, RogueKind::FailedSpotProof, &evidence)?;
        }
        Ok(())
    }

    fn enforce_deadlines(&mut self) -> Result<(), MeshError> {
        // 1. Challenge deadlines (witness side).
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| self.tick > p.challenge.deadline_tick)
            .map(|(n, _)| n.clone())
            .collect();
        for nonce in expired {
            let p = self.pending.remove(&nonce).expect("just filtered");
            let target = self
                .gossip
                .get(&p.challenge.serial)
                .map(|r| r.node.clone())
                .unwrap_or_default();
            if !target.is_empty() && !self.rogue.is_isolated(&target) {
                let evidence = format!(
                    "{{\"nonce\": \"{}\", \"serial\": \"{}\", \"deadline_tick\": {}}}",
                    p.challenge.nonce, p.challenge.serial, p.challenge.deadline_tick
                );
                self.accuse(&target, RogueKind::Timeout, &evidence)?;
            }
        }

        // 2. Report deadlines: members whose drives never reported.
        let Some(membership) = self.discovery.membership().cloned() else {
            return Ok(());
        };
        if self.tick > self.cfg.report_deadline_ticks {
            for peer in membership.nodes.iter() {
                if *peer == self.name || self.rogue.is_isolated(peer) {
                    continue;
                }
                let advertised = self.discovery.peer(peer).map(|p| p.drives).unwrap_or(0);
                if advertised > 0 && self.gossip.by_node(peer).is_empty() {
                    let evidence = format!(
                        "{{\"node\": \"{peer}\", \"advertised\": {advertised}, \"reported\": 0, \"tick\": {}}}",
                        self.tick
                    );
                    self.accuse(peer, RogueKind::Timeout, &evidence)?;
                }
            }
        }
        Ok(())
    }

    fn accuse(&mut self, accused: &str, kind: RogueKind, evidence: &str) -> Result<(), MeshError> {
        if accused == self.name || self.rogue.is_isolated(accused) {
            return Ok(());
        }
        let digest = RogueLedger::digest_of(evidence);
        let count = self.rogue.accuse(
            &self.name.clone(),
            accused,
            kind,
            evidence.to_string(),
            digest.clone(),
        );
        let wire = AccuseWire {
            accused: accused.to_string(),
            kind: kind.as_str().to_string(),
            evidence: evidence.to_string(),
            evidence_digest: digest.clone(),
        };
        let payload = serde_json::to_vec(&wire).expect("accuse json");
        self.broadcast(MsgType::Accuse, 1, &payload)?;
        self.maybe_isolate(accused, kind, &digest, count)?;
        Ok(())
    }

    fn maybe_isolate(
        &mut self,
        accused: &str,
        kind: RogueKind,
        digest: &str,
        count: usize,
    ) -> Result<(), MeshError> {
        let q = self.frozen_quorum();
        if count >= q {
            let entry = self.rogue.try_isolate(accused, kind, digest, q, 1);
            if let Some(entry) = entry {
                if let Some(c) = self.consensus.as_mut() {
                    c.apply_isolation(accused);
                }
                let wire = IsolateWire {
                    node: accused.to_string(),
                    kind: kind.as_str().to_string(),
                    digest: digest.to_string(),
                    accusers: entry.accusers.clone(),
                    view: entry.isolated_at_view,
                };
                let payload = serde_json::to_vec(&wire).expect("isolate json");
                self.broadcast(MsgType::Isolate, 1, &payload)?;
                self.drop_pending_for(accused);
            }
        }
        Ok(())
    }

    fn drop_pending_for(&mut self, node: &str) {
        let serials: Vec<String> = self
            .gossip
            .all()
            .iter()
            .filter(|r| r.node == node)
            .map(|r| r.serial.clone())
            .collect();
        self.pending
            .retain(|_, p| !serials.contains(&p.challenge.serial));
    }

    /// Readiness: all expected reports in, all our challenges
    /// resolved, at least one passing witness per report.
    fn is_ready(&self) -> bool {
        let Some(membership) = self.discovery.membership() else {
            return false;
        };
        if !self.reports_sent {
            return false;
        }
        let mut expected = membership.total_drives;
        for peer in membership.nodes.iter() {
            if self.rogue.is_isolated(peer) {
                expected = expected.saturating_sub(
                    self.discovery
                        .peer(peer)
                        .map(|p| p.drives as u64)
                        .unwrap_or(0),
                );
            }
        }
        let certified = self
            .gossip
            .all()
            .into_iter()
            .filter(|r| !self.rogue.is_isolated(&r.node))
            .count() as u64;
        if certified < expected {
            return false;
        }
        // Every non-isolated report has ≥1 passing transcript from
        // some witness (ours or gossiped).
        for r in self.gossip.all() {
            if self.rogue.is_isolated(&r.node) {
                continue;
            }
            let has_pass = self
                .transcripts
                .iter()
                .any(|t| t.passed && t.challenge.serial == r.serial && t.witness != r.node);
            if !has_pass {
                return false;
            }
        }
        self.pending.is_empty()
    }

    // -- sealing (proposing + threshold co-signing) --------------------------

    fn consensus_step_sealing(&mut self) -> Result<(), MeshError> {
        // Proposal when we are the speaker of the current view.
        let (am_speaker, decided, cur_view, have_block) = match self.consensus.as_ref() {
            Some(c) => (c.am_speaker(), c.decided(), c.view(), c.block().is_some()),
            None => (false, false, 0, false),
        };
        let equivocating = self.cfg.behavior == NodeBehavior::Equivocator;
        if (am_speaker || equivocating)
            && !decided
            && !have_block
            && self.last_proposed_view != Some(cur_view)
        {
            self.last_proposed_view = Some(cur_view);
            let reports: Vec<DriveReport> = self
                .gossip
                .all()
                .into_iter()
                .filter(|r| !self.rogue.is_isolated(&r.node))
                .cloned()
                .collect();
            let transcripts: Vec<SpotTranscript> = self
                .transcripts
                .iter()
                .filter(|t| t.passed)
                .cloned()
                .collect();
            let block = match self.consensus.as_mut() {
                Some(c) => c.build_proposal(&reports, &transcripts, &self.rogue),
                None => return Ok(()),
            };
            let payload = serde_json::to_vec(&block).expect("block json");
            if equivocating {
                // The drill: broadcast a divergent block alongside the
                // honest one — in EVERY view, speaker or not. Every
                // receiver keeps both signed proposals as textbook
                // equivocation evidence (two different hashes signed
                // by the same key in the same view).
                let mut mutant = block.clone();
                mutant.report_count = block.report_count.wrapping_add(1);
                let mutant_payload = serde_json::to_vec(&mutant).expect("block json");
                self.broadcast(MsgType::Proposal, cur_view, &mutant_payload)?;
                self.broadcast(MsgType::Proposal, cur_view, &payload)?;
            } else if self.cfg.behavior == NodeBehavior::Silent {
                // Silent nodes never propose: let the view time out.
            } else {
                self.broadcast(MsgType::Proposal, cur_view, &payload)?;
                // The speaker accepts its own proposal (implicit
                // PREPARE), starting the voting rounds.
                if let Some(c) = self.consensus.as_mut() {
                    let _ = c.on_proposal(&self.name.clone(), &block)?;
                }
            }
        }
        Ok(())
    }

    fn step_seal(&mut self) -> Result<(), MeshError> {
        self.consensus_step_sealing()?;

        let decided = self
            .consensus
            .as_ref()
            .map(|c| c.decided())
            .unwrap_or(false);
        if !decided {
            return Ok(());
        }

        let seal_set = self.seal_set();
        let t = seal_set.len();

        // Round 1: members of the seal set broadcast their FROST
        // commitment once. The fabric never echoes our own broadcast:
        // self-record so every node aggregates over the SAME
        // participant set (byte-identical certificates depend on it).
        let my_index = self.frost_share.as_ref().map(|s| s.index);
        let in_set = my_index.map(|i| seal_set.contains(&i)).unwrap_or(false);
        if !self.seal_commit_sent && in_set {
            self.seal_commit_sent = true;
            let secret = self.frost_share.clone().expect("checked");
            let mut session = match self.cfg.seal_determinism {
                // Drill path: derive the nonce pair from a PRNG seeded
                // per (swarm seed, share index, tick) so a replayed
                // simulation reproduces byte-identical certificates.
                Some(sd) => {
                    let seed = sd ^ ((secret.index as u64) << 32) ^ (self.tick << 16);
                    SignerSession::round1_with_rng(secret, &mut SimRng(seed))
                }
                // Production path: OS entropy, always.
                None => SignerSession::round1(secret),
            };
            let commitment = session.commitment();
            self.seal_session = Some(session);
            if !self
                .seal_commitments
                .iter()
                .any(|x| x.signer == commitment.signer)
            {
                self.seal_commitments.push(commitment.clone());
            }
            let payload = serde_json::to_vec(&commitment).expect("commit json");
            self.broadcast(MsgType::SealCommit, 1, &payload)?;
        }

        // Round 2: once EVERY seal-set commitment is in, send our
        // share + PQ partial.
        let set_commits = self
            .seal_commitments
            .iter()
            .filter(|c| seal_set.contains(&c.signer))
            .count();
        if !self.seal_share_sent && in_set && set_commits >= t {
            self.seal_share_sent = true;
            let message = self.sealing_message();
            let session = self.seal_session.take();
            if let Some(share) = self
                .coordinator()
                .zip(session)
                .and_then(|(c, s)| s.round2(&c).ok())
            {
                let wire = SealShareWire {
                    frost: share,
                    ml_dsa: hex::encode(self.ml.sign(&message).as_bytes()),
                };
                if !self
                    .seal_shares
                    .iter()
                    .any(|x| x.frost.signer == wire.frost.signer)
                {
                    self.seal_shares.push(wire.clone());
                }
                let payload = serde_json::to_vec(&wire).expect("share json");
                self.broadcast(MsgType::SealShare, 1, &payload)?;
            }
        }

        // Aggregation: every seal-set share (each carrying an ML-DSA
        // partial) collected → assemble the certificate.
        let set_shares = self
            .seal_shares
            .iter()
            .filter(|s| seal_set.contains(&s.frost.signer))
            .count();
        if set_shares >= t && t > 0 && self.certificate.is_none() {
            self.assemble_certificate()?;
        }
        Ok(())
    }

    /// The sealing message is derived from the DECIDED BLOCK's
    /// canonical rogue entries — every node computes identical bytes
    /// from the same block, never from its local ledger view.
    fn sealing_message(&self) -> Vec<u8> {
        let (block_hash, view, entries) = self
            .consensus
            .as_ref()
            .and_then(|c| {
                c.block_hash().map(|h| {
                    (
                        h.to_string(),
                        c.view(),
                        c.block().expect("hash implies block").rogue_entries.clone(),
                    )
                })
            })
            .unwrap_or_default();
        crate::cert::SwarmCertificate::sealing_message(&block_hash, &entries, view)
    }

    /// The deterministic seal set: the `t` lowest share indices among
    /// LIVE members (frozen membership minus isolated rogues), by
    /// sorted membership order.
    ///
    /// Every node derives the same set from the same ledger state, so
    /// the FROST ρ/R/λ computations bind to identical inputs on every
    /// machine — "whoever arrived first" would produce divergent
    /// signatures and non-identical certificates.
    ///
    /// STRICTLY live members: an isolated member never delivers its
    /// commitment or share, so admitting one into the set would pin
    /// the `set_commits >= t` / `set_shares >= t` gates above a
    /// participant that can never answer — a permanent seal deadlock.
    fn seal_set(&self) -> Vec<u16> {
        let Some(membership) = self.discovery.membership() else {
            return Vec::new();
        };
        let t = self
            .cfg
            .threshold
            .map(|p| p.threshold as usize)
            .unwrap_or(2);
        membership
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| !self.rogue.is_isolated(n))
            .map(|(i, _)| (i + 1) as u16) // 1-based share index
            .take(t)
            .collect()
    }

    fn coordinator(&self) -> Option<CoordinatorSession> {
        let parts = self.seal_set();
        if parts.is_empty() {
            return None;
        }
        let pk = self.frost_public.clone();
        let message = self.sealing_message();
        let mut coord = CoordinatorSession::new(pk, &parts, &message).ok()?;
        for c in self.seal_commitments.clone() {
            if parts.contains(&c.signer) {
                coord.ingest_commitment(c);
            }
        }
        Some(coord)
    }

    fn assemble_certificate(&mut self) -> Result<(), MeshError> {
        let Some(consensus) = self.consensus.as_ref() else {
            return Ok(());
        };
        let Some((block_hash, committers)) = consensus.decision() else {
            return Ok(());
        };
        let Some(membership) = self.discovery.membership() else {
            return Ok(());
        };
        let block = consensus.block().expect("decided block").clone();

        let t = self.cfg.threshold.map(|p| p.threshold).unwrap_or(2);
        let seal_set = self.seal_set();
        let shares: Vec<RoundTwoShare> = self
            .seal_shares
            .iter()
            .filter(|s| seal_set.contains(&s.frost.signer))
            .map(|s| s.frost.clone())
            .collect();
        let mut coord = CoordinatorSession::new(
            self.frost_public.clone(),
            &seal_set,
            &self.sealing_message(),
        )?;
        for c in self.seal_commitments.clone() {
            if seal_set.contains(&c.signer) {
                coord.ingest_commitment(c);
            }
        }
        let frost_sig = coord.aggregate(&shares)?;

        let message = self.sealing_message();
        let mut ml_entries: Vec<MlDsaSealEntry> = self
            .seal_shares
            .iter()
            .filter_map(|s| {
                let idx = s.frost.signer;
                self.share_index_to_node(idx).map(|node| MlDsaSealEntry {
                    node,
                    signature: s.ml_dsa.clone(),
                })
            })
            .collect();
        // Canonical order: arrival order differs per node (each node
        // records its own share first), so sort by member id — the
        // certificate must be byte-identical on every assembler.
        ml_entries.sort_by(|a, b| a.node.cmp(&b.node));
        let ml_seal = MlDsaSeal {
            threshold: t,
            entries: ml_entries,
        };

        // Uncertified drives: one entry per advertised drive of every
        // isolated member (the swarm refuses to vouch for them).
        let mut uncertified = Vec::new();
        for entry in &self.rogue.entries {
            let drives = self.advertised_drives_of(&entry.node);
            for d in 0..drives {
                uncertified.push(crate::cert::UncertifiedDrive {
                    node: entry.node.clone(),
                    serial: Some(format!("{}#{d}", "unverified")),
                    reason: format!(
                        "node isolated by 2f+1 swarm verdict ({}); drive {d} unverifiable",
                        entry.kind.as_str()
                    ),
                });
            }
        }
        // Canonical order (byte-identical certificates across nodes —
        // isolation order itself may differ from node to node).
        uncertified.sort_by(|a, b| (&a.node, &a.serial).cmp(&(&b.node, &b.serial)));

        let cert = crate::cert::SwarmCertificate {
            schema: crate::cert::SWARM_CERT_SCHEMA.to_string(),
            cluster_id: format!(
                "sim-{}",
                membership.hash.chars().take(12).collect::<String>()
            ),
            membership: membership
                .nodes
                .iter()
                .map(|n| {
                    let pk = if n == &self.name {
                        // The peer table has no row for ourselves.
                        hex::encode(self.ml.public_key_bytes())
                    } else {
                        self.discovery
                            .peer(n)
                            .map(|p| p.ml_dsa_pk.clone())
                            .unwrap_or_default()
                    };
                    crate::cert::MemberEntry {
                        node: n.clone(),
                        ml_dsa_pk: pk,
                    }
                })
                .collect(),
            membership_hash: membership.hash.clone(),
            tolerance: membership.tolerance,
            quorum: membership.quorum,
            advertised_drives: membership.total_drives,
            drive_reports: self
                .gossip
                .all()
                .into_iter()
                .filter(|r| !self.rogue.is_isolated(&r.node))
                .cloned()
                .collect(),
            // Canonical order: by challenge nonce, the exact key
            // `transcripts_root` sorts by — arrival order differs per
            // node (own-witness transcripts first).
            spot_transcripts: {
                let mut ts: Vec<SpotTranscript> = self
                    .transcripts
                    .iter()
                    .filter(|t| t.passed)
                    .cloned()
                    .collect();
                ts.sort_by(|a, b| a.challenge.nonce.cmp(&b.challenge.nonce));
                ts
            },
            report_root: block.report_root.clone(),
            report_count: block.report_count,
            spot_root: block.spot_root.clone(),
            spot_count: block.spot_count,
            rogue_ledger: block.rogue_entries.clone(),
            uncertified,
            view: block.view,
            block_hash: block_hash.to_string(),
            committers: committers.to_vec(),
            frost_group_pub: self.frost_public.group_pub.clone(),
            frost_threshold: t,
            frost_signature: FrostSignature {
                r_point: frost_sig.r_point.clone(),
                z_scalar: frost_sig.z_scalar.clone(),
                participants: frost_sig.participants.clone(),
            },
            ml_dsa: ml_seal,
            sealed_message: hex::encode(&message),
        };

        // A node that assembles an invalid certificate is itself
        // faulty — refuse to certify and surface the failure.
        let report =
            crate::cert::verify_swarm_certificate(&cert, &crate::cert::SwarmAnchor::default());
        if !report.verified {
            return Err(MeshError::Lifecycle(format!(
                "assembled certificate failed self-verification: {:?}",
                report.notes
            )));
        }
        self.certificate = Some(cert);
        self.state = NodeState::Certified;
        Ok(())
    }

    fn share_index_to_node(&self, index: u16) -> Option<String> {
        // Share 1..n map to the sorted frozen membership.
        let membership = self.discovery.membership()?;
        if index == 0 || index as usize > membership.nodes.len() {
            return None;
        }
        Some(membership.nodes[(index - 1) as usize].clone())
    }

    /// Advertised drive count of a member — including OURSELVES: a
    /// node isolated by the swarm still assembles the shared
    /// certificate (documenting its own conviction), and the peer
    /// table has no row for `self` (the HELLO never loops back).
    fn advertised_drives_of(&self, node: &str) -> u32 {
        if node == self.name {
            self.discovery.me().drives
        } else {
            self.discovery.peer(node).map(|p| p.drives).unwrap_or(0)
        }
    }
}

fn kind_from_str(s: &str) -> Result<RogueKind, MeshError> {
    match s {
        "equivocation" => Ok(RogueKind::Equivocation),
        "duplicate_serial" => Ok(RogueKind::DuplicateSerial),
        "failed_spot_proof" => Ok(RogueKind::FailedSpotProof),
        "timeout" => Ok(RogueKind::Timeout),
        _ => Err(MeshError::Frame(format!("unknown rogue kind {s}"))),
    }
}

// ---------------------------------------------------------------------------
// SwarmSim — the deterministic drill driver
// ---------------------------------------------------------------------------

/// Whole-simulation configuration.
#[derive(Debug, Clone)]
pub struct SwarmSimConfig {
    /// Total nodes (n).
    pub nodes: usize,
    /// Byzantine actors: (node index, behavior), sorted-by-pubkey order.
    pub byzantine: Vec<(usize, NodeBehavior)>,
    /// Drives per wiper node (0 → witness-only node).
    pub drives_per_node: u32,
    /// Windows per drive.
    pub windows_per_drive: u64,
    pub pattern: Pattern,
    pub threshold: Option<ThresholdParams>,
    pub seed: u64,
}

impl Default for SwarmSimConfig {
    fn default() -> Self {
        Self {
            nodes: 7,
            byzantine: Vec::new(),
            drives_per_node: 2,
            windows_per_drive: 3,
            pattern: Pattern::Zero,
            threshold: None,
            seed: 42,
        }
    }
}

/// A deterministic swarm over a virtual LAN.
pub struct SwarmSim {
    lan: crate::transport::VirtualLan,
    nodes: Vec<MeshNode>,
    max_ticks: u64,
    pub ticks_run: u64,
}

impl SwarmSim {
    pub fn new(config: &SwarmSimConfig) -> Result<Self, MeshError> {
        let lan = crate::transport::VirtualLan::new();
        // Node identities, sorted by Ed25519 pubkey → deterministic
        // share distribution and naming.
        let mut ids: Vec<(String, SigningKey, MlDsa44KeyPair)> = Vec::new();
        for i in 0..config.nodes {
            let mut seed = [0u8; 32];
            seed[..8]
                .copy_from_slice(&(config.seed ^ (i as u64).wrapping_mul(0x9E37)).to_be_bytes());
            let signing = SigningKey::from_bytes(&seed);
            let mut ml_seed = [0u8; 32];
            ml_seed[..8]
                .copy_from_slice(&(config.seed ^ (i as u64).wrapping_mul(0x517C)).to_be_bytes());
            let ml = MlDsa44KeyPair::from_seed(&ml_seed);
            let id = hex::encode(signing.verifying_key().to_bytes());
            ids.push((id, signing, ml));
        }
        ids.sort_by(|a, b| a.0.cmp(&b.0));

        // Dealer ceremony over the full membership.
        let params = config
            .threshold
            .unwrap_or_else(|| ThresholdParams::default_for(config.nodes));
        let dealer = crate::threshold::dealer_keygen(&mut SimRng(config.seed), params)?;

        let mut nodes = Vec::new();
        for (i, (id, signing, ml)) in ids.into_iter().enumerate() {
            let behavior = config
                .byzantine
                .iter()
                .find(|(bi, _)| *bi == i)
                .map(|(_, b)| *b)
                .unwrap_or(NodeBehavior::Honest);
            let drives: Vec<SimDriveSpec> = (0..config.drives_per_node)
                .map(|d| SimDriveSpec {
                    serial: format!("SIM-{i:03}-D{d}"),
                    capacity_windows: config.windows_per_drive,
                    window_sectors: 4,
                })
                .collect();
            let cfg = MeshNodeConfig {
                behavior,
                drives,
                pattern: config.pattern.clone(),
                threshold: Some(params),
                expected_nodes: Some(config.nodes),
                discovery_silence_ticks: 3,
                view_timeout_ticks: 5,
                spot_challenges_per_drive: 2,
                challenge_deadline_ticks: 4,
                report_deadline_ticks: 12,
                seed: config.seed ^ (i as u64 + 1),
                // Drills replay byte-identically: same seed → same
                // nonce derivation → same certificate bytes.
                seal_determinism: Some(config.seed ^ 0x000D_C5EA_17ED),
            };
            let nic = lan.join().for_node(signing.verifying_key().to_bytes());
            let share = dealer.secrets.get(i).cloned();
            let node = MeshNode::new(
                id,
                signing,
                ml,
                Box::new(nic),
                dealer.public.clone(),
                share,
                cfg,
            );
            nodes.push(node);
        }
        Ok(Self {
            lan,
            nodes,
            max_ticks: 400,
            ticks_run: 0,
        })
    }

    pub fn node_states(&self) -> Vec<(&str, NodeState)> {
        self.nodes.iter().map(|n| (n.id(), n.state())).collect()
    }

    pub fn nodes(&self) -> &[MeshNode] {
        &self.nodes
    }

    /// Run to completion (all honest nodes certified) or max ticks.
    pub fn run(&mut self) -> Result<(), MeshError> {
        for _ in 0..self.max_ticks {
            for node in &mut self.nodes {
                node.step()?;
            }
            self.lan.tick();
            self.ticks_run += 1;
            let honest_done = self
                .nodes
                .iter()
                .all(|n| n.behavior() != NodeBehavior::Honest || n.state() == NodeState::Certified);
            if honest_done {
                return Ok(());
            }
        }
        Err(MeshError::Lifecycle(format!(
            "simulation did not converge in {} ticks",
            self.max_ticks
        )))
    }

    /// The (identical) certificates the honest nodes assembled.
    pub fn certificates(&self) -> Vec<&crate::cert::SwarmCertificate> {
        self.nodes
            .iter()
            .filter(|n| n.state() == NodeState::Certified)
            .filter_map(|n| n.certificate())
            .collect()
    }
}

/// Deterministic dealer RNG for ceremonies (drills and CI; production
/// ceremonies use the OS CSPRNG path).
struct SimRng(u64);

impl rand_core::CryptoRng for SimRng {}

impl rand_core::RngCore for SimRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_honest_nodes_converge() {
        let mut sim = SwarmSim::new(&SwarmSimConfig::default()).expect("sim");
        sim.run().expect("convergence");
        let certs = sim.certificates();
        assert_eq!(certs.len(), 7, "every honest node certifies");
        let c = certs[0];
        assert_eq!(c.drive_reports.len(), 14); // 7 nodes × 2 drives
        assert!(c.rogue_ledger.is_empty());
        assert_eq!(c.certified_drives(), 14);
        assert!(c.uncertified.is_empty());
        // The committer list is live: it converges to EVERY member
        // that committed — at least the 2f+1 quorum, here all 7.
        assert!(
            c.committers.len() >= 5,
            "committers: {}",
            c.committers.len()
        );
    }

    #[test]
    fn liar_is_caught_isolated_and_named() {
        let cfg = SwarmSimConfig {
            byzantine: vec![(3, NodeBehavior::Liar)],
            ..SwarmSimConfig::default()
        };
        let mut sim = SwarmSim::new(&cfg).expect("sim");
        sim.run().expect("convergence with a liar");
        let certs = sim.certificates();
        assert!(!certs.is_empty());
        let c = certs[0];
        assert_eq!(c.rogue_ledger.len(), 1, "the liar must be named");
        assert_eq!(c.rogue_ledger[0].kind, RogueKind::FailedSpotProof);
        // 6 honest nodes × 2 drives = 12 certified; liar's 2 excluded.
        assert_eq!(c.certified_drives(), 12);
        assert_eq!(c.uncertified.len(), 2);
        // Full verification still passes with the rogue ledger.
        let report = crate::cert::verify_swarm_certificate(
            c,
            &crate::cert::SwarmAnchor {
                group_pub: Some(c.frost_group_pub.clone()),
                membership_hash: Some(c.membership_hash.clone()),
                ml_dsa_pks: HashMap::new(),
            },
        );
        assert!(report.verified, "notes: {:?}", report.notes);
    }

    #[test]
    fn silent_node_is_timed_out_and_named() {
        let cfg = SwarmSimConfig {
            byzantine: vec![(1, NodeBehavior::Silent)],
            ..SwarmSimConfig::default()
        };
        let mut sim = SwarmSim::new(&cfg).expect("sim");
        sim.run().expect("convergence with a silent node");
        let certs = sim.certificates();
        assert!(!certs.is_empty());
        let c = certs[0];
        assert_eq!(c.rogue_ledger.len(), 1);
        assert_eq!(c.rogue_ledger[0].kind, RogueKind::Timeout);
        assert_eq!(c.certified_drives(), 12);
    }

    #[test]
    fn equivocator_is_exposed() {
        let cfg = SwarmSimConfig {
            byzantine: vec![(5, NodeBehavior::Equivocator)],
            ..SwarmSimConfig::default()
        };
        let mut sim = SwarmSim::new(&cfg).expect("sim");
        sim.run().expect("convergence with an equivocator");
        let certs = sim.certificates();
        assert!(!certs.is_empty());
        let c = certs[0];
        // The equivocator may or may not have been the deciding
        // speaker before isolation, but it MUST be named once caught.
        assert!(
            c.rogue_ledger
                .iter()
                .any(|e| e.kind == RogueKind::Equivocation),
            "ledger: {:?}",
            c.rogue_ledger
        );
    }

    #[test]
    fn certificates_are_identical_across_nodes() {
        let mut sim = SwarmSim::new(&SwarmSimConfig::default()).expect("sim");
        sim.run().expect("convergence");
        let certs = sim.certificates();
        for c in certs.iter().skip(1) {
            assert_eq!(*c, certs[0], "all honest nodes seal identical bytes");
        }
    }

    #[test]
    fn four_node_minimum_quorum() {
        let cfg = SwarmSimConfig {
            nodes: 4,
            drives_per_node: 1,
            windows_per_drive: 2,
            ..SwarmSimConfig::default()
        };
        let mut sim = SwarmSim::new(&cfg).expect("sim");
        sim.run().expect("convergence at n=4");
        let certs = sim.certificates();
        assert_eq!(certs.len(), 4);
        assert!(certs[0].committers.len() >= 3); // ≥ 2f+1 of 4
        assert_eq!(certs[0].certified_drives(), 4);
    }

    #[test]
    fn deterministic_replay() {
        let mut a = SwarmSim::new(&SwarmSimConfig::default()).expect("sim");
        a.run().expect("convergence");
        let mut b = SwarmSim::new(&SwarmSimConfig::default()).expect("sim");
        b.run().expect("convergence");
        assert_eq!(a.ticks_run, b.ticks_run);
        let (ca, cb) = (a.certificates(), b.certificates());
        assert!(!ca.is_empty());
        assert_eq!(ca[0], cb[0]);
    }
}
