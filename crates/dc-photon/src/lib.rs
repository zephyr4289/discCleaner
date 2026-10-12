//! dc-photon — the Bidirectional Optical Air-Gap Protocol, "Photon Bridge"
//! (v0.8.0, Vector 3).
//!
//! The highest-classification facilities forbid plugging *anything* into
//! a machine that has touched classified data: no USB media, no network
//! cable, no wireless. Yet the signed certificate, TPM quote and audit
//! journal must leave the room for archival and command review.
//!
//! The photon bridge solves the exfiltration problem with light:
//! the terminal renders an endless, animated stream of fountain-coded QR
//! frames; an auditor holds an approved scanning device (or camera) up to
//! the screen and captures evidence purely via photons. Nothing physical
//! crosses the SCIF boundary — 100% compliance with air-gap
//! non-spillage directives.
//!
//! Architecture (see `frame.rs` for the wire layout):
//! - The evidence package is split into blocks and LT-fountain encoded
//!   (`lt.rs`) — the receiver needs ANY k·(1+ε) symbols, in any order,
//!   tolerating blurred or skipped frames.
//! - Each frame batches several symbols plus a stream identity header
//!   (BLAKE3-truncated) and payload digest.
//! - Each frame becomes one QR code (`qr.rs`, byte mode, ECC-M) rendered
//!   as terminal half-block art (`stream.rs`).
//!
//! The certificate embeds a photon manifest (fountain parameters, payload
//! digest, frame geometry) so the receiving side can prove what it
//! captured matches what was signed.

pub mod frame;
pub mod lt;
pub mod qr;
pub mod stream;

pub use frame::{Frame, FrameHeader, FrameReassembler, FrameStream, HEADER_LEN};
pub use lt::{LtDecoder, LtEncoder, LtError};
pub use qr::{MAX_BYTE_PAYLOAD_V10_M, QrError, QrMatrix, encode as encode_qr};
pub use stream::{PhotonRenderer, RenderedPhotonFrame};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum PhotonStreamError {
    #[error("frame from a different stream — mixing prohibited")]
    StreamMismatch,
    #[error("fountain decode error: {0}")]
    Lt(#[from] LtError),
    #[error("payload BLAKE3 mismatch after reassembly")]
    HashMismatch,
    #[error("QR payload too large: {0}")]
    QrTooLarge(#[from] QrError),
}

/// The manifest embedded into the certificate: everything the receiving
/// auditor needs to validate a capture session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhotonManifest {
    /// BLAKE3 of the payload (hex, 32 bytes → 64 chars).
    pub payload_blake3: String,
    /// Truncated stream id (first 4 bytes of the digest, LE, hex).
    pub stream_id: String,
    /// Payload length in bytes.
    pub payload_len: u64,
    /// Fountain block size.
    pub block_size: u32,
    /// Symbols per frame.
    pub symbols_per_frame: u32,
    /// Fountain stream seed (must match transmitter and receiver).
    pub stream_seed: String,
    /// QR version ceiling in use (10 at level M unless tiny payloads).
    pub qr_version_ceiling: u8,
}

impl PhotonManifest {
    pub fn for_stream(stream: &FrameStream) -> Self {
        Self {
            payload_blake3: hex::encode(stream.payload_blake3()),
            stream_id: format!("{:08x}", stream.stream_id()),
            payload_len: 0, // filled by the caller with the real length
            block_size: 0,
            symbols_per_frame: 0,
            stream_seed: String::new(),
            qr_version_ceiling: 10,
        }
    }

    pub fn field_lines(&self) -> Vec<(String, String)> {
        vec![
            ("Photon payload BLAKE3".into(), self.payload_blake3.clone()),
            ("Photon stream id".into(), self.stream_id.clone()),
            (
                "Photon payload bytes".into(),
                format!("{}", self.payload_len),
            ),
            ("Photon block size".into(), format!("{}", self.block_size)),
            (
                "Photon symbols/frame".into(),
                format!("{}", self.symbols_per_frame),
            ),
            ("Photon stream seed".into(), self.stream_seed.clone()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_field_lines_cover_identity() {
        let m = PhotonManifest {
            payload_blake3: "ab".repeat(32),
            stream_id: "cafebabe".into(),
            payload_len: 20480,
            block_size: 48,
            symbols_per_frame: 6,
            stream_seed: "000000005eed0001".into(),
            qr_version_ceiling: 10,
        };
        let lines = m.field_lines();
        assert!(
            lines
                .iter()
                .any(|(k, v)| k.contains("BLAKE3") && v.len() == 64)
        );
        assert!(lines.iter().any(|(k, _)| k.contains("stream id")));
    }
}
