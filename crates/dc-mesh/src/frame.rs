//! L2 Ethernet frame codec and the signed protocol envelope.
//!
//! dc-mesh never builds an IP header. Every message is carried as the
//! payload of a raw Ethernet frame tagged with the local-experimental
//! EtherType [`crate::ETHERTYPE_DC_MESH`] and enveloped as:
//!
//! ```text
//! ┌────────────┬─────────┬──────────┬─────────┬────────┬──────────┬───────────┐
//! │ magic DCMS │ ver = 1 │ msg type │ view:32 │ node32 │ len:32   │ payload   │
//! ├────────────┴─────────┴──────────┴─────────┴────────┴──────────┴───────────┤
//! │ Ed25519 signature (64 B) over the canonical header + payload                   │
//! └──────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The signature is computed over the *exact canonical byte encoding*
//! of header+payload, so any byte flipped on the wire is caught
//! before dispatch. Frames exceeding [`crate::MAX_FRAME_PAYLOAD`] are
//! refused at decode time (the wire never carries them).

use crate::{MAGIC, MeshError, PROTOCOL_VERSION};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Broadcast MAC — used for discovery and gossip fan-out.
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// A 48-bit Ethernet address (stored big-endian on the wire).
pub type Mac = [u8; 6];

/// Every protocol message type on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MsgType {
    /// Membership discovery: `discovery` HELLO.
    Hello = 1,
    /// Discovery reply.
    HelloAck = 2,
    /// Full peer-table anti-entropy push (gossip).
    PeerList = 3,
    /// Per-drive wipe attestation (gossip).
    DriveReport = 4,
    /// Witness-issued random spot-proof challenge.
    Challenge = 5,
    /// Wiper's answer to a spot-proof challenge.
    SpotProof = 6,
    /// Rotating-speaker block proposal.
    Proposal = 7,
    /// PBFT-family prepare vote.
    Prepare = 8,
    /// PBFT-family commit vote.
    Commit = 9,
    /// View-change request (timeout / fault).
    ChangeView = 10,
    /// Signed accusation of a rogue node.
    Accuse = 11,
    /// Isolation verdict (carries 2f+1 accusations).
    Isolate = 12,
    /// FROST2 round-1 nonce commitments.
    SealCommit = 13,
    /// FROST2 round-2 signature share (+ optional ML-DSA partial).
    SealShare = 14,
    /// Liveness ping carrying monotonic tick counters.
    Heartbeat = 15,
    /// Gossip of a PASSING witness spot-proof transcript (v0.13.0).
    Transcript = 16,
}

impl MsgType {
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => MsgType::Hello,
            2 => MsgType::HelloAck,
            3 => MsgType::PeerList,
            4 => MsgType::DriveReport,
            5 => MsgType::Challenge,
            6 => MsgType::SpotProof,
            7 => MsgType::Proposal,
            8 => MsgType::Prepare,
            9 => MsgType::Commit,
            10 => MsgType::ChangeView,
            11 => MsgType::Accuse,
            12 => MsgType::Isolate,
            13 => MsgType::SealCommit,
            14 => MsgType::SealShare,
            15 => MsgType::Heartbeat,
            16 => MsgType::Transcript,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            MsgType::Hello => "HELLO",
            MsgType::HelloAck => "HELLO_ACK",
            MsgType::PeerList => "PEERLIST",
            MsgType::DriveReport => "DRIVE_REPORT",
            MsgType::Challenge => "CHALLENGE",
            MsgType::SpotProof => "SPOT_PROOF",
            MsgType::Proposal => "PROPOSAL",
            MsgType::Prepare => "PREPARE",
            MsgType::Commit => "COMMIT",
            MsgType::ChangeView => "CHANGE_VIEW",
            MsgType::Accuse => "ACCUSE",
            MsgType::Isolate => "ISOLATE",
            MsgType::SealCommit => "SEAL_COMMIT",
            MsgType::SealShare => "SEAL_SHARE",
            MsgType::Heartbeat => "HEARTBEAT",
            MsgType::Transcript => "TRANSCRIPT",
        }
    }
}

/// A fully-decoded, signature-verified inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshFrame {
    /// Protocol view/epoch the message belongs to.
    pub view: u32,
    /// Sender's Ed25519 public key (node identity on the wire).
    pub node: [u8; 32],
    /// Message type.
    pub msg: MsgType,
    /// Type-dependent payload (canonical bytes).
    pub payload: Vec<u8>,
}

impl MeshFrame {
    /// Canonical signing input: header + payload with no signature.
    fn canonical(view: u32, node: &[u8; 32], msg: MsgType, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 1 + 1 + 4 + 32 + 4 + payload.len());
        buf.extend_from_slice(&MAGIC);
        buf.push(PROTOCOL_VERSION);
        buf.push(msg as u8);
        buf.extend_from_slice(&view.to_be_bytes());
        buf.extend_from_slice(node);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// Encode + sign a frame for the wire. Returns the L2 payload
    /// bytes to hand to the transport (header ∥ payload ∥ signature).
    pub fn encode_signed(&self, signing: &SigningKey) -> Vec<u8> {
        let canonical = Self::canonical(self.view, &self.node, self.msg, &self.payload);
        let sig = signing.sign(&canonical).to_bytes();
        let mut out = canonical;
        out.extend_from_slice(&sig);
        out
    }

    /// Decode + verify a wire payload. The Ed25519 signature covers
    /// every header field and the payload — a flipped MAC, view or
    /// node id anywhere fails here.
    pub fn decode_verify(wire: &[u8]) -> Result<(MeshFrame, Signature), MeshError> {
        // 4 magic + 1 ver + 1 type + 4 view + 32 node + 4 len + 64 sig.
        if wire.len() < 4 + 1 + 1 + 4 + 32 + 4 + 64 {
            return Err(MeshError::Frame("truncated envelope".into()));
        }
        if wire[0..4] != MAGIC {
            return Err(MeshError::Frame("bad magic (not a DCMS frame)".into()));
        }
        if wire[4] != PROTOCOL_VERSION {
            return Err(MeshError::Frame(format!(
                "unsupported protocol version {}",
                wire[4]
            )));
        }
        let msg = MsgType::from_u8(wire[5])
            .ok_or_else(|| MeshError::Frame(format!("unknown message type {}", wire[5])))?;
        let mut view = [0u8; 4];
        view.copy_from_slice(&wire[6..10]);
        let mut node = [0u8; 32];
        node.copy_from_slice(&wire[10..42]);
        let mut len = [0u8; 4];
        len.copy_from_slice(&wire[42..46]);
        let plen = u32::from_be_bytes(len) as usize;

        let body_len = 4 + 1 + 1 + 4 + 32 + 4 + plen;
        if wire.len() < body_len + 64 {
            return Err(MeshError::Frame("payload length exceeds frame".into()));
        }
        if plen > crate::MAX_FRAME_PAYLOAD {
            return Err(MeshError::Frame(format!(
                "payload {} exceeds wire limit {}",
                plen,
                crate::MAX_FRAME_PAYLOAD
            )));
        }
        let (canonical, sig_bytes) = wire.split_at(body_len);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes[..64]);
        let sig = Signature::from_bytes(&sig_arr);

        let vk = VerifyingKey::from_bytes(&node).map_err(|_| MeshError::BadSignature {
            node: hex::encode(node),
        })?;
        vk.verify(canonical, &sig)
            .map_err(|_| MeshError::BadSignature {
                node: hex::encode(node),
            })?;

        let payload = canonical[46..].to_vec();
        Ok((
            MeshFrame {
                view: u32::from_be_bytes(view),
                node,
                msg,
                payload,
            },
            sig,
        ))
    }
}

/// An outbound raw Ethernet frame: destination MAC + protocol payload.
#[derive(Debug, Clone)]
pub struct EthFrame {
    pub dst: Mac,
    /// dc-mesh L2 payload (an encoded, signed MeshFrame).
    pub payload: Vec<u8>,
}

impl EthFrame {
    /// Serialize to a full Ethernet frame (header + payload). The
    /// source MAC is stamped by the transport at send time — the
    /// protocol authenticates nodes by Ed25519 key, never by MAC.
    pub fn to_bytes(&self, src: Mac) -> Vec<u8> {
        let mut out = Vec::with_capacity(14 + self.payload.len());
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(&src);
        out.extend_from_slice(&crate::ETHERTYPE_DC_MESH.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a full Ethernet frame; returns (src, dst, payload).
    pub fn parse(bytes: &[u8]) -> Result<(Mac, Mac, &[u8]), MeshError> {
        if bytes.len() < 14 {
            return Err(MeshError::Frame(
                "ethernet frame shorter than header".into(),
            ));
        }
        let et = u16::from_be_bytes([bytes[12], bytes[13]]);
        if et != crate::ETHERTYPE_DC_MESH {
            return Err(MeshError::Frame(format!(
                "ethertype {et:#06x} is not DC-MESH {:#06x}",
                crate::ETHERTYPE_DC_MESH
            )));
        }
        Ok((
            bytes[6..12].try_into().expect("src mac slice"),
            bytes[0..6].try_into().expect("dst mac slice"),
            &bytes[14..],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        let mut b = [0u8; 32];
        b[0] = seed;
        SigningKey::from_bytes(&b)
    }

    #[test]
    fn roundtrip_sign_and_verify() {
        let sk = key(7);
        let f = MeshFrame {
            view: 9,
            node: sk.verifying_key().to_bytes(),
            msg: MsgType::Proposal,
            payload: b"block-hash-xyz".to_vec(),
        };
        let wire = f.encode_signed(&sk);
        let (decoded, _sig) = MeshFrame::decode_verify(&wire).expect("verify");
        assert_eq!(decoded, f);
    }

    #[test]
    fn tampered_bit_fails() {
        let sk = key(1);
        let f = MeshFrame {
            view: 3,
            node: sk.verifying_key().to_bytes(),
            msg: MsgType::Prepare,
            payload: vec![0xAA; 64],
        };
        let mut wire = f.encode_signed(&sk);
        // Flip one bit inside the payload.
        wire[60] ^= 0x01;
        assert!(matches!(
            MeshFrame::decode_verify(&wire),
            Err(MeshError::BadSignature { .. })
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let sk = key(2);
        let f = MeshFrame {
            view: 1,
            node: [9u8; 32], // NOT the signer's key
            msg: MsgType::Hello,
            payload: b"x".to_vec(),
        };
        let wire = f.encode_signed(&sk);
        assert!(MeshFrame::decode_verify(&wire).is_err());
    }

    #[test]
    fn eth_frame_roundtrip() {
        let ef = EthFrame {
            dst: BROADCAST_MAC,
            payload: b"payload".to_vec(),
        };
        let src: Mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let bytes = ef.to_bytes(src);
        let (got_src, got_dst, pl) = EthFrame::parse(&bytes).expect("parse");
        assert_eq!(got_src, src);
        assert_eq!(got_dst, BROADCAST_MAC);
        assert_eq!(pl, b"payload".to_vec());
    }

    #[test]
    fn oversize_payload_rejected() {
        let sk = key(3);
        let f = MeshFrame {
            view: 0,
            node: sk.verifying_key().to_bytes(),
            msg: MsgType::PeerList,
            payload: vec![0u8; crate::MAX_FRAME_PAYLOAD + 1],
        };
        let wire = f.encode_signed(&sk);
        assert!(matches!(
            MeshFrame::decode_verify(&wire),
            Err(MeshError::Frame(_))
        ));
    }
}
