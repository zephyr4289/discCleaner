//! Photon frame format (v0.8.0, Vector 3).
//!
//! One frame = the binary payload of one animated QR. Frames carry a fixed
//! header plus a batch of fountain symbols; any sufficiently large subset
//! of frames reconstructs the payload (LT fountain — see `lt.rs`).
//!
//! ```text
//! offset  size  field
//!      0     4  magic "DCPH" (0x44 43 50 48)
//!      4     1  version = 1
//!      5     4  stream_id (BLAKE3 of payload, truncated LE)
//!      9     4  payload_len (LE)
//!     13    32  payload BLAKE3 (verification digest)
//!     45     4  first symbol id in this frame (LE)
//!     49     1  symbol count in this frame
//!     50     2  symbol size (LE)
//!     52   ...  symbols: count × [4-byte symbol id + symbol_size bytes]
//!           (symbol ids are implicit = first + 0..count — but stored
//!            explicitly for lossy-frame tolerance: a partially decoded
//!            frame is dropped whole, so ids stay contiguous per frame)
//! ```
use crate::lt::LtDecoder;
use crate::{LtError, QrError};
use blake3::Hasher as Blake3;

pub const FRAME_MAGIC: [u8; 4] = *b"DCPH";
pub const FRAME_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 52;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub stream_id: u32,
    pub payload_len: u32,
    pub payload_blake3: [u8; 32],
    pub first_symbol: u32,
    pub symbol_count: u8,
    pub symbol_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    /// (symbol_id, bytes) — ids first..first+count.
    pub symbols: Vec<(u32, Vec<u8>)>,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            HEADER_LEN + self.symbols.len() * (4 + self.header.symbol_size as usize),
        );
        out.extend_from_slice(&FRAME_MAGIC);
        out.push(FRAME_VERSION);
        out.extend_from_slice(&self.header.stream_id.to_le_bytes());
        out.extend_from_slice(&self.header.payload_len.to_le_bytes());
        out.extend_from_slice(&self.header.payload_blake3);
        out.extend_from_slice(&self.header.first_symbol.to_le_bytes());
        out.push(self.header.symbol_count);
        out.extend_from_slice(&self.header.symbol_size.to_le_bytes());
        for (id, bytes) in &self.symbols {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, PhotonFrameError> {
        if buf.len() < HEADER_LEN {
            return Err(PhotonFrameError::Truncated);
        }
        if buf[0..4] != FRAME_MAGIC {
            return Err(PhotonFrameError::BadMagic);
        }
        if buf[4] != FRAME_VERSION {
            return Err(PhotonFrameError::BadVersion(buf[4]));
        }
        let header = FrameHeader {
            stream_id: u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
            payload_len: u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]),
            payload_blake3: buf[13..45].try_into().expect("32 bytes"),
            first_symbol: u32::from_le_bytes([buf[45], buf[46], buf[47], buf[48]]),
            symbol_count: buf[49],
            symbol_size: u16::from_le_bytes([buf[50], buf[51]]),
        };
        let need = HEADER_LEN + header.symbol_count as usize * (4 + header.symbol_size as usize);
        if buf.len() < need {
            return Err(PhotonFrameError::Truncated);
        }
        let mut symbols = Vec::with_capacity(header.symbol_count as usize);
        let mut off = HEADER_LEN;
        for i in 0..header.symbol_count as usize {
            let id = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            let end = off + 4 + header.symbol_size as usize;
            symbols.push((id, buf[off + 4..end].to_vec()));
            off = end;
            let _ = i;
        }
        Ok(Self { header, symbols })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PhotonFrameError {
    #[error("frame truncated")]
    Truncated,
    #[error("bad frame magic")]
    BadMagic,
    #[error("unsupported frame version {0}")]
    BadVersion(u8),
}

/// Frame factory bound to one payload + encoder.
pub struct FrameStream {
    encoder: crate::lt::LtEncoder,
    payload_blake3: [u8; 32],
    stream_id: u32,
    payload_len: usize,
    symbols_per_frame: u8,
    next_symbol: u32,
}

impl FrameStream {
    /// Build the frame factory for one payload. `symbols_per_frame` is the
    /// REQUESTED batch; it is clamped down so one frame + header fits a
    /// v10-M QR (213 bytes). Errors when even a single symbol cannot fit.
    pub fn new(
        payload: &[u8],
        block_size: usize,
        symbols_per_frame: u8,
        seed: u64,
    ) -> Result<Self, LtError> {
        let per_symbol = 4usize + block_size;
        let room = crate::qr::MAX_BYTE_PAYLOAD_V10_M.saturating_sub(HEADER_LEN);
        if per_symbol > room {
            return Err(LtError::Invalid(format!(
                "block size {block_size} leaves no room in a v10-M QR (need ≤ {} bytes/symbol)",
                room.saturating_sub(4)
            )));
        }
        let max_batch = (room / per_symbol) as u8;
        let symbols_per_frame = symbols_per_frame.clamp(1, max_batch.max(1));
        let encoder = crate::lt::LtEncoder::new(payload, block_size, seed)?;
        let mut h = Blake3::new();
        h.update(payload);
        let digest: [u8; 32] = h.finalize().into();
        let stream_id = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        Ok(Self {
            encoder,
            payload_blake3: digest,
            stream_id,
            payload_len: payload.len(),
            symbols_per_frame: symbols_per_frame.max(1),
            next_symbol: 0,
        })
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub fn stream_seed(&self) -> u64 {
        self.encoder.stream_seed()
    }

    pub fn block_size(&self) -> usize {
        self.encoder.block_size()
    }

    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub fn payload_blake3(&self) -> &[u8; 32] {
        &self.payload_blake3
    }

    pub fn num_blocks(&self) -> usize {
        self.encoder.num_blocks()
    }

    /// Effective symbols per frame after QR-capacity clamping.
    pub fn symbols_per_frame(&self) -> u8 {
        self.symbols_per_frame
    }

    /// Build the next frame (endless fountain).
    pub fn next_frame(&mut self) -> Frame {
        let count = self.symbols_per_frame as usize;
        let mut symbols = Vec::with_capacity(count);
        let first = self.next_symbol;
        for i in 0..count {
            let id = self.next_symbol + i as u32;
            symbols.push((id, self.encoder.encode(id as u64)));
        }
        self.next_symbol += count as u32;
        Frame {
            header: FrameHeader {
                stream_id: self.stream_id,
                payload_len: self.payload_len as u32,
                payload_blake3: self.payload_blake3,
                first_symbol: first,
                symbol_count: count as u8,
                symbol_size: self.encoder.block_size() as u16,
            },
            symbols,
        }
    }
}

/// Receiver-side reassembly across frames (one stream). The stream seed is
/// shared out-of-band (manifest + on-screen footer): frames themselves bind
/// identity via `stream_id` = first 4 bytes of the payload BLAKE3.
pub struct FrameReassembler {
    decoder: Option<LtDecoder>,
    payload_blake3: Option<[u8; 32]>,
    payload_len: usize,
    stream_id: u32,
    frames_seen: u32,
    stream_seed: u64,
}

impl FrameReassembler {
    /// `stream_seed` must match the transmitter's (`FrameStream::new`).
    pub fn new(stream_seed: u64) -> Self {
        Self {
            decoder: None,
            payload_blake3: None,
            payload_len: 0,
            stream_id: 0,
            frames_seen: 0,
            stream_seed,
        }
    }

    /// Feed a captured frame; returns the verified payload once complete.
    pub fn push_frame(&mut self, frame: &Frame) -> Result<Option<Vec<u8>>, PhotonStreamError> {
        if let Some(expected) = self.payload_blake3 {
            if expected != frame.header.payload_blake3 || self.stream_id != frame.header.stream_id {
                return Err(PhotonStreamError::StreamMismatch);
            }
        } else {
            self.payload_blake3 = Some(frame.header.payload_blake3);
            self.stream_id = frame.header.stream_id;
            self.payload_len = frame.header.payload_len as usize;
            let block_size = frame.header.symbol_size as usize;
            let k = self.payload_len.div_ceil(block_size).max(1);
            self.decoder = Some(LtDecoder::new(k, block_size, self.stream_seed));
        }
        self.frames_seen += 1;
        let decoder = self.decoder.as_mut().expect("set above");
        for (id, bytes) in &frame.symbols {
            decoder
                .push_symbol(*id as u64, bytes)
                .map_err(PhotonStreamError::Lt)?;
        }
        if decoder.resolved_count() < decoder.num_blocks() {
            return Ok(None);
        }
        let decoder = self.decoder.take().expect("set above");
        let mut full = decoder.finish().map_err(PhotonStreamError::Lt)?;
        full.truncate(self.payload_len);
        // Verify the payload hash end-to-end.
        let mut h = Blake3::new();
        h.update(&full);
        let digest: [u8; 32] = h.finalize().into();
        if digest != self.payload_blake3.expect("set above") {
            return Err(PhotonStreamError::HashMismatch);
        }
        Ok(Some(full))
    }

    pub fn frames_seen(&self) -> u32 {
        self.frames_seen
    }

    pub fn progress(&self) -> Option<(usize, usize)> {
        self.decoder
            .as_ref()
            .map(|d| (d.resolved_count(), d.num_blocks()))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let frame = Frame {
            header: FrameHeader {
                stream_id: 0xABBACAFE,
                payload_len: 1234,
                payload_blake3: [7u8; 32],
                first_symbol: 40,
                symbol_count: 3,
                symbol_size: 8,
            },
            symbols: vec![(40, vec![1u8; 8]), (41, vec![2u8; 8]), (42, vec![3u8; 8])],
        };
        let bytes = frame.encode();
        let back = Frame::decode(&bytes).unwrap();
        assert_eq!(back, frame);
        assert_eq!(bytes.len(), HEADER_LEN + 3 * 12);
    }

    #[test]
    fn truncated_and_bad_magic_are_clean_errors() {
        assert!(matches!(
            Frame::decode(&[0u8; 10]),
            Err(PhotonFrameError::Truncated)
        ));
        let mut buf = vec![0u8; HEADER_LEN + 12];
        buf[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(
            Frame::decode(&buf),
            Err(PhotonFrameError::BadMagic)
        ));
    }

    #[test]
    fn full_pipeline_bytes_frames_symbols_payload() {
        let payload: Vec<u8> = (0..8000u32).map(|i| (i * 131 + 17) as u8).collect();
        let seed = 0x5EED_0001u64;
        let mut stream = FrameStream::new(&payload, 48, 6, seed).unwrap();
        // With 48-byte blocks: per symbol = 52 bytes; 213-52 = 161 room
        // → batch clamps to 3 symbols/frame.
        assert_eq!(stream.symbols_per_frame(), 3);
        let mut rx = FrameReassembler::new(seed);
        // Simulate capture loss: drop every 3rd frame.
        let mut result = None;
        for i in 0..6000 {
            let frame = stream.next_frame();
            if i % 3 == 2 {
                continue; // scanner missed this one
            }
            if let Some(p) = rx.push_frame(&frame).unwrap() {
                result = Some(p);
                break;
            }
        }
        let out = result.expect("reassembly completes under 33% frame loss");
        assert_eq!(out, payload);
        assert!(rx.frames_seen() > 0);
    }
}
