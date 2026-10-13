//! # dc-mesh — Autonomous Multi-Node Consensus & Byzantine
//! Sanitization Swarm (v0.13.0, Frontier 1)
//!
//! **The paradigm:** wipe a 500-node hyperscaler cluster without any
//! central server or orchestrator.
//!
//! When a data center row is decommissioned — or an entire Kubernetes
//! or Ceph storage cluster retired — sysadmins traditionally lean on
//! centralized orchestrators (Ansible, PXE boot servers, a jump box
//! with a script). If that orchestrator is compromised, or simply
//! goes down mid-run, rogue nodes can secretly skip drives and report
//! false success. Every certificate in the fleet then inherits the
//! trust assumptions of one machine. That is the exact opposite of
//! what a decommission proof needs.
//!
//! dc-mesh replaces the orchestrator with **the swarm itself**:
//!
//! * [`frame`] — a wire protocol carried **directly inside L2 Ethernet
//!   frames** (EtherType `0x88B5`, the IEEE Std 802 local-experimental
//!   range). No IP stack, no ARP, no TCP, no ports: the `dc` instances
//!   speak to each other at the same layer the switches forward.
//! * [`discovery`] — nodes find their peers by signed broadcast
//!   HELLO/HELLO_ACK exchanges and freeze an epoch membership set
//!   once `2f+1` peers have answered.
//! * [`transport`] — pluggable transports: a real `AF_PACKET` raw
//!   Ethernet socket on Linux (`CAP_NET_RAW`, see docs/SECURITY.md)
//!   and a deterministic in-memory `VirtualLan` that powers CI, drills
//!   and `dc mesh simulate` — including scripted Byzantine actors.
//! * [`gossip`] — epidemic anti-entropy dissemination of per-drive
//!   [`gossip::DriveReport`] attestations: device identity, pattern,
//!   verified-window counts and a BLAKE3 root over the readback
//!   evidence, each individually Ed25519-signed by its node.
//! * [`consensus`] — a PBFT-family rotating-speaker consensus
//!   (PRE-PROPOSE / PREPARE / COMMIT with view-change) that tolerates
//!   `f < n/3` Byzantine members. The decided block contains every
//!   drive report **plus** the witness spot-proof transcripts.
//! * [`rogue`] — Byzantine rogue detection: equivocation, duplicate
//!   serial claims, failed spot-proofs and timeouts produce signed
//!   accusations; `2f+1` accusation votes isolate a node into the
//!   collective [`rogue::RogueLedger`] and deny it consensus.
//! * [`threshold`] — the final **Swarm Certificate of
//!   Decommission** is co-signed by the cluster, not by a machine:
//!   FROST2 threshold Schnorr over Ed25519 (a single aggregate
//!   signature from `t` of `n` shares, no single party ever holds the
//!   group key) *and* an ML-DSA-44 post-quantum t-of-n signature set
//!   (each partial independently verifiable, quantum-resistant).
//! * [`mesh`] — the [`mesh::MeshNode`] orchestration: DISCOVERING →
//!   MEMBERSHIP → EXECUTING → CHALLENGED (witness spot-proofs of
//!   zero-entropy claims) → CONSENSUS → SEALED → CERTIFIED.
//!
//! ## Threat model
//!
//! 1. **Lying node** — claims drives wiped when they were not: caught
//!    by witness-issued random spot-proof challenges (fresh nonce, fresh
//!    LBA window, readback must hash to the expected final pattern).
//! 2. **Equivocator** — sends different proposals to different peers:
//!    both signed proposals are undeniable equivocation evidence.
//! 3. **Silent node** — stops responding: view-change proceeds, the
//!    node is recorded absent, consensus completes without it.
//! 4. **Serial spoofing across nodes** — two nodes reporting the same
//!    physical drive identity: flagged as duplicate claim, fed into
//!    the rogue ledger (and cross-referenced with dc-sonar PUF evidence
//!    when enrolled).
//! 5. **Compromised orchestrator** — there is none. Removing the
//!    single point of trust is the point of the crate.
//!
//!    ## What the certificate proves
//!
//!    The resulting [`cert::SwarmCertificate`] is verifiable offline by
//!    any third party with the membership public keys: that every
//!    declared drive in the cluster was wiped and zero-entropy verified
//!    under the decided pattern, that all spot-proof challenges passed,
//!    that the quorum reached consensus, and that at least `t` distinct
//!    threshold shares co-signed the result — with any rogue nodes
//!    explicitly named and their evidence attached.

pub mod cert;
pub mod consensus;
pub mod discovery;
pub mod frame;
pub mod gossip;
pub mod mesh;
pub mod rogue;
pub mod threshold;
pub mod transport;

/// Protocol magic at the head of every L2 payload.
pub const MAGIC: [u8; 4] = *b"DCMS";

/// Wire protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// IEEE Std 802 local-experimental EtherType 1 (0x88B5).
///
/// Chosen deliberately from the range reserved for local/site
/// experimental use: a dc-mesh fabric is a *closed* L2 segment (a
/// decommission VLAN), never routed, and must never collide with any
/// production ethertype. Site network teams should confirm no other
/// local experiment claims 0x88B5 on the sanitization VLAN.
pub const ETHERTYPE_DC_MESH: u16 = 0x88B5;

/// Maximum payload of one protocol envelope.
///
/// Discovery, gossip and consensus stay under ~1.2 KB (classical
/// MTU). The seal phase carries ML-DSA-44 partial signatures
/// (2420 bytes, hex-expanded ≈ 4.8 KB), so the envelope ceiling is
/// 5120 bytes — the sanitization VLAN must therefore enable jumbo
/// frames (MTU ≥ 9000), which every hyperscaler ToR supports on
/// dedicated storage/decommission VLANs.
pub const MAX_FRAME_PAYLOAD: usize = 5120;

/// Standard Erasure of Accountability errors local to the swarm layer.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("frame decode error: {0}")]
    Frame(String),
    #[error("signature verification failed for node {node}")]
    BadSignature { node: String },
    #[error("consensus failure: {0}")]
    Consensus(String),
    #[error("threshold signing failure: {0}")]
    Threshold(String),
    #[error("rogue node action refused: {0}")]
    Rogue(String),
    #[error("mesh lifecycle error: {0}")]
    Lifecycle(String),
    #[error("I/O error on mesh transport: {0}")]
    Transport(String),
}

/// Minimum nodes for any Byzantine tolerance (`n >= 3f+1` with `f>=1`).
pub const MIN_BYZ_CLUSTER: usize = 4;

/// Derive the Byzantine tolerance `f` for a membership of `n` nodes.
pub const fn byzantine_tolerance(n: usize) -> usize {
    (n.saturating_sub(1)) / 3
}

/// Derive the PBFT-family decision quorum `2f+1` for `n` nodes.
pub const fn decision_quorum(n: usize) -> usize {
    2 * byzantine_tolerance(n) + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_math_is_pbft_standard() {
        // n=4 → f=1, quorum 3; n=7 → f=2, quorum 5; n=10 → f=3, quorum 7.
        assert_eq!(byzantine_tolerance(4), 1);
        assert_eq!(decision_quorum(4), 3);
        assert_eq!(byzantine_tolerance(7), 2);
        assert_eq!(decision_quorum(7), 5);
        assert_eq!(byzantine_tolerance(10), 3);
        assert_eq!(decision_quorum(10), 7);
        // Degenerate clusters tolerate nothing.
        assert_eq!(byzantine_tolerance(1), 0);
        assert_eq!(byzantine_tolerance(2), 0);
    }
}
