//! Big-endian marshal/unmarshal primitives (TPM 2.0 Part 1 §9).
//!
//! The TPM transports every multi-byte field big-endian. `Writer` builds
//! command buffers; `Reader` parses responses with bounds-checked,
//! allocation-capped reads — a malformed or truncated response can never
//! panic the parser or force unbounded allocation.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("truncated TPM structure: need {need} bytes at offset {offset}, have {have}")]
    Truncated {
        offset: usize,
        need: usize,
        have: usize,
    },
    #[error("oversized TPM2B field: {len} bytes exceeds cap {cap}")]
    Oversized { len: usize, cap: usize },
    #[error("unexpected TPM structure value: {what} (got {value:#06x})")]
    Unexpected { what: &'static str, value: u16 },
}

pub type WireResult<T> = Result<T, WireError>;

/// Hard cap on any single TPM2B field we are willing to allocate for
/// (largest structure we parse is TPMT_PUBLIC at ~1 KiB; 4 KiB is generous).
pub const TPM2B_CAP: usize = 4096;

/// Big-endian command builder.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// `TPM2B_*`: u16 length prefix + raw bytes.
    pub fn tpm2b(&mut self, bytes: &[u8]) -> &mut Self {
        self.u16(bytes.len() as u16);
        self.buf.extend_from_slice(bytes);
        self
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Finalize with the command header: big-endian tag, total command
    /// size (header 10 bytes + body) and the Part-3 command code.
    pub fn into_command(&mut self, tag: u16, command_code: u32) -> Vec<u8> {
        let body = std::mem::take(&mut self.buf);
        let mut out = Vec::with_capacity(body.len() + 10);
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&command_code.to_be_bytes());
        out.extend_from_slice(&body);
        let total = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&total);
        out
    }

    /// Borrow the accumulated body (for length computation).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Take ownership of the accumulated body.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Bounds-checked big-endian response parser.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Remaining bytes after the cursor.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Current absolute offset (for error reporting).
    pub fn offset(&self) -> usize {
        self.pos
    }

    fn take(&mut self, n: usize) -> WireResult<&'a [u8]> {
        if self.remaining() < n {
            return Err(WireError::Truncated {
                offset: self.pos,
                need: n,
                have: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> WireResult<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> WireResult<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> WireResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> WireResult<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// `TPM2B_*` — length-prefixed field, capped.
    pub fn tpm2b(&mut self) -> WireResult<Vec<u8>> {
        let len = self.u16()? as usize;
        if len > TPM2B_CAP {
            return Err(WireError::Oversized {
                len,
                cap: TPM2B_CAP,
            });
        }
        Ok(self.take(len)?.to_vec())
    }

    /// Raw slice of `n` bytes (fixed-size structures).
    pub fn raw(&mut self, n: usize) -> WireResult<&'a [u8]> {
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{TPM_CC_QUOTE, TPM_ST_NO_SESSIONS};

    #[test]
    fn writer_produces_big_endian_header_and_body() {
        let cmd = Writer::new()
            .u16(0xBEEF)
            .u32(0x0102_0304)
            .into_command(TPM_ST_NO_SESSIONS, TPM_CC_QUOTE);
        assert_eq!(&cmd[0..2], &[0x80, 0x01]); // tag BE
        assert_eq!(&cmd[2..6], &16u32.to_be_bytes()); // size = 10 header + 6 body
        assert_eq!(&cmd[6..10], &TPM_CC_QUOTE.to_be_bytes());
        assert_eq!(&cmd[10..], &[0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn reader_round_trips_and_truncation_is_clean() {
        let mut w = Writer::new();
        w.u8(0x7F)
            .u16(0x1234)
            .u32(0xDEAD_BEEF)
            .u64(1)
            .tpm2b(b"nonce");
        let buf = w.as_bytes().to_vec();
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 0x7F);
        assert_eq!(r.u16().unwrap(), 0x1234);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), 1);
        assert_eq!(r.tpm2b().unwrap(), b"nonce".to_vec());
        assert_eq!(r.remaining(), 0);
        assert!(r.u8().is_err(), "read past end must error, not panic");
    }

    #[test]
    fn oversized_tpm2b_is_refused_not_allocated() {
        let mut w = Writer::new();
        w.u16(TPM2B_CAP as u16 + 1);
        w.bytes(&[0u8; 8]);
        let mut r = Reader::new(&w.buf);
        assert!(matches!(r.tpm2b(), Err(WireError::Oversized { .. })));
    }
}
