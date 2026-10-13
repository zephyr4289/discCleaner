//! Peer discovery and membership freezing.
//!
//! A dc-mesh segment is ad-hoc: nodes boot with no knowledge of each
//! other. Each one periodically broadcasts a signed [`HelloBody`]
//! carrying its Ed25519 identity, ML-DSA-44 public key, MAC, advertised
//! drive count and a freshness nonce. Peers answer with HELLO_ACK
//! (the same body) so reachability is bidirectional.
//!
//! Membership **freezes** into an epoch the first time either
//! (a) `expected_nodes` peers have answered (operator-declared fleet
//! size, e.g. 500), or (b) `silence_ticks` rounds pass without a new
//! peer appearing (organic discovery). The frozen set — sorted by node
//! id, hashed with BLAKE3 — is the `membership_hash` that every later
//! consensus view, spot-proof and threshold signature is bound to.
//! Membership is *additive-frozen*: nodes discovered after the freeze
//! are latched as `late` and excluded from the quorum but recorded in
//! the certificate (a node that boots late cannot shrink the quorum
//! retroactively).

use crate::frame::{BROADCAST_MAC, Mac, MsgType};
use crate::{MeshError, decision_quorum};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HELLO / HELLO_ACK body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HelloBody {
    /// Ed25519 public key (hex) — the node's wire identity.
    pub node: String,
    /// ML-DSA-44 public key (hex) for post-quantum seal shares.
    pub ml_dsa_pk: String,
    /// Advertised local drive count (0 for pure witnesses).
    pub drives: u32,
    /// Monotonic hello counter (staleness detection).
    pub seq: u32,
}

/// A discovered peer, liveness-tracked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerInfo {
    pub node: String,
    pub ml_dsa_pk: String,
    pub mac: Mac,
    pub drives: u32,
    pub last_seen_tick: u64,
    pub late: bool,
}

/// Membership discovery state machine.
pub struct Discovery {
    me: HelloBody,
    my_mac: Mac,
    peers: HashMap<String, PeerInfo>,
    tick: u64,
    hello_seq: u32,
    expected_nodes: Option<usize>,
    silence_ticks: u32,
    ticks_since_new_peer: u32,
    frozen: Option<Membership>,
}

/// The frozen epoch membership.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Membership {
    /// Sorted node ids (hex).
    pub nodes: Vec<String>,
    /// BLAKE3 over the sorted ids, hex.
    pub hash: String,
    /// Total drives the membership advertised.
    pub total_drives: u64,
    /// Byzantine tolerance f for this membership size.
    pub tolerance: usize,
    /// Decision quorum 2f+1.
    pub quorum: usize,
}

impl Discovery {
    pub fn new(
        me: HelloBody,
        my_mac: Mac,
        expected_nodes: Option<usize>,
        silence_ticks: u32,
    ) -> Self {
        Self {
            me,
            my_mac,
            peers: HashMap::new(),
            tick: 0,
            hello_seq: 0,
            expected_nodes,
            silence_ticks,
            ticks_since_new_peer: 0,
            frozen: None,
        }
    }

    /// Advance one discovery round. Returns frames to transmit
    /// (broadcast HELLO until frozen) and whether the epoch froze.
    pub fn step(&mut self) -> (Option<Vec<u8>>, bool) {
        self.tick += 1;
        if self.frozen.is_some() {
            return (None, true);
        }
        self.ticks_since_new_peer += 1;

        self.hello_seq += 1;
        let mut hello = self.me.clone();
        hello.seq = self.hello_seq;
        let payload = serde_json::to_vec(&hello).expect("hello json");
        let froze_now = self.check_freeze();
        (Some(payload), froze_now)
    }

    /// Ingest an inbound HELLO/HELLO_ACK. Returns whether a NEW peer
    /// appeared (the driver answers fresh HELLOs with HELLO_ACK).
    pub fn ingest(&mut self, _msg: MsgType, from_mac: Mac, body: &[u8]) -> Result<bool, MeshError> {
        let hello: HelloBody = serde_json::from_slice(body)
            .map_err(|e| MeshError::Frame(format!("hello body: {e}")))?;
        if hello.node == self.me.node {
            // Our own broadcast echoed back by the fabric.
            return Ok(false);
        }
        let known = self.peers.contains_key(&hello.node);
        if known {
            // Refresh liveness; no HELLO_ACK needed for a known peer.
            if let Some(p) = self.peers.get_mut(&hello.node) {
                p.last_seen_tick = self.tick;
            }
            return Ok(false);
        }
        // Unknown peer: register it. After the membership freeze the
        // peer is latched `late` — recorded, but never in the quorum.
        if self.frozen.is_some() {
            self.peers.insert(
                hello.node.clone(),
                PeerInfo {
                    node: hello.node.clone(),
                    ml_dsa_pk: hello.ml_dsa_pk.clone(),
                    mac: from_mac,
                    drives: hello.drives,
                    last_seen_tick: self.tick,
                    late: true,
                },
            );
            return Ok(false);
        }
        self.peers.insert(
            hello.node.clone(),
            PeerInfo {
                node: hello.node.clone(),
                ml_dsa_pk: hello.ml_dsa_pk.clone(),
                mac: from_mac,
                drives: hello.drives,
                last_seen_tick: self.tick,
                late: false,
            },
        );
        self.ticks_since_new_peer = 0;
        self.check_freeze();
        Ok(true)
    }

    /// Build our HELLO_ACK body for a fresh peer.
    pub fn hello_ack_body(&self) -> Vec<u8> {
        let mut ack = self.me.clone();
        ack.seq = self.hello_seq;
        serde_json::to_vec(&ack).expect("ack json")
    }

    fn check_freeze(&mut self) -> bool {
        if self.frozen.is_some() {
            return true;
        }
        let n = self.peers.len() + 1; // + self
        let expected = match self.expected_nodes {
            Some(e) => n >= e,
            None => self.ticks_since_new_peer >= self.silence_ticks,
        };
        if expected && n >= crate::MIN_BYZ_CLUSTER {
            let mut nodes: Vec<String> = self.peers.keys().cloned().collect();
            nodes.push(self.me.node.clone());
            nodes.sort();
            let total_drives: u64 =
                self.peers.values().map(|p| p.drives as u64).sum::<u64>() + self.me.drives as u64;
            let mut hasher = Hasher::new();
            for id in &nodes {
                hasher.update(id.as_bytes());
            }
            self.frozen = Some(Membership {
                hash: hasher.finalize().to_hex().to_string(),
                nodes,
                total_drives,
                tolerance: crate::byzantine_tolerance(n),
                quorum: decision_quorum(n),
            });
            return true;
        }
        false
    }

    pub fn membership(&self) -> Option<&Membership> {
        self.frozen.as_ref()
    }

    pub fn peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    pub fn peer(&self, node: &str) -> Option<&PeerInfo> {
        self.peers.get(node)
    }

    /// Re-derive a membership hash from a sorted node-id list
    /// (verification-side helper).
    pub fn hash_of(nodes: &[String]) -> String {
        let mut hasher = Hasher::new();
        for id in nodes {
            hasher.update(id.as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }

    /// The MAC to reach a peer (or broadcast if unknown).
    pub fn route_to(&self, node: &str) -> Mac {
        self.peers.get(node).map(|p| p.mac).unwrap_or(BROADCAST_MAC)
    }

    /// Our own advertised body.
    pub fn me(&self) -> &HelloBody {
        &self.me
    }

    pub fn my_mac(&self) -> Mac {
        self.my_mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(node: &str, drives: u32) -> HelloBody {
        HelloBody {
            node: node.to_string(),
            ml_dsa_pk: format!("{node}-pq"),
            drives,
            seq: 0,
        }
    }

    fn discovery(n_peers: usize, expected: Option<usize>) -> Discovery {
        let mut d = Discovery::new(hello("aaa", 2), [2, 0, 0, 0, 0, 1], expected, 3);
        for i in 0..n_peers {
            let id = format!("{:03}", 200 + i);
            let body = serde_json::to_vec(&hello(&id, 1)).expect("json");
            d.ingest(MsgType::Hello, [2, 0, 0, 0, 0, 2 + i as u8], &body)
                .expect("ingest");
        }
        d
    }

    #[test]
    fn freezes_on_expected_size() {
        let mut d = discovery(3, Some(5)); // self + 3 peers = 4 of 5
        assert!(d.membership().is_none());
        let body = serde_json::to_vec(&hello("204", 1)).expect("json");
        d.ingest(MsgType::Hello, [2, 0, 0, 0, 0, 9], &body)
            .expect("ingest");
        let m = d.membership().expect("frozen at 5th node");
        assert_eq!(m.nodes.len(), 5);
        assert_eq!(m.tolerance, 1);
        assert_eq!(m.quorum, 3);
        assert_eq!(m.total_drives, 2 + 4);
    }

    #[test]
    fn freezes_on_silence() {
        let mut d = discovery(3, None);
        for _ in 0..3 {
            d.step();
        }
        assert!(d.membership().is_some(), "silence timeout must freeze");
        let m = d.membership().expect("frozen");
        assert_eq!(m.nodes.len(), 4);
    }

    #[test]
    fn late_arrivals_are_latched_not_counted() {
        let mut d = discovery(3, Some(4));
        d.step();
        assert_eq!(d.membership().expect("frozen").nodes.len(), 4);

        let late = serde_json::to_vec(&hello("zzz", 9)).expect("json");
        assert!(
            !d.ingest(MsgType::Hello, [2, 9, 9, 9, 9, 9], &late)
                .expect("ingest")
        );
        assert_eq!(
            d.membership().expect("frozen").nodes.len(),
            4,
            "late peer excluded"
        );
        assert!(d.peer("zzz").expect("late peer").late);
    }

    #[test]
    fn membership_hash_is_canonical() {
        let mut d = discovery(3, None);
        for _ in 0..3 {
            d.step();
        }
        let m = d.membership().expect("frozen");
        let mut nodes = m.nodes.clone();
        nodes.sort();
        assert_eq!(Discovery::hash_of(&nodes), m.hash);
    }

    #[test]
    fn self_echo_ignored() {
        let mut d = Discovery::new(hello("aaa", 0), [0; 6], None, 2);
        let body = serde_json::to_vec(&hello("aaa", 0)).expect("json");
        assert!(
            !d.ingest(MsgType::HelloAck, [1, 1, 1, 1, 1, 1], &body)
                .expect("ingest")
        );
        assert_eq!(d.peers().count(), 0);
    }
}
