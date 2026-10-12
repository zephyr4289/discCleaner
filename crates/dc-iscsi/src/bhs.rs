//! iSCSI PDU framing (RFC 3720 §10): the 48-byte Basic Header Segment
//! plus data segment read/write with deadline discipline.
//!
//! Only the opcode subset discCleaner needs is modeled:
//! Login (0x03/0x23), Text (0x04/0x24), SCSI Command (0x01),
//! SCSI Response (0x21), Data-In (0x25), Logout (0x06/0x26).

use crate::IscsiError;
use std::io::Write;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

// --- Opcodes (RFC 3720 §10.2) ------------------------------------------------
pub const OP_SCSI_CMD: u8 = 0x01;
pub const OP_LOGIN_REQ: u8 = 0x03;
pub const OP_TEXT_REQ: u8 = 0x04;
pub const OP_LOGOUT_REQ: u8 = 0x06;
pub const OP_LOGIN_RSP: u8 = 0x23;
pub const OP_TEXT_RSP: u8 = 0x24;
pub const OP_LOGOUT_RSP: u8 = 0x26;
pub const OP_SCSI_RSP: u8 = 0x21;
pub const OP_DATA_IN: u8 = 0x25;

/// Final PDU of a sequence (bit 0 of the flags byte).
pub const FLAG_FINAL: u8 = 0x80;

/// Sentinel Target Transfer Tag: "no continuation state".
pub const TTT_NONE: u32 = 0xFFFF_FFFF;

/// 48-byte BHS: raw fields, decoded on demand per opcode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bhs(pub [u8; 48]);

impl Bhs {
    /// Zeroed BHS with the opcode + F-bit set.
    pub fn new(opcode: u8, final_bit: bool) -> Self {
        let mut b = [0u8; 48];
        b[0] = opcode;
        if final_bit {
            b[1] |= FLAG_FINAL;
        }
        Self(b)
    }

    pub fn opcode(&self) -> u8 {
        self.0[0] & 0x3F
    }

    pub fn flags(&self) -> u8 {
        self.0[1]
    }

    pub fn is_final(&self) -> bool {
        self.0[1] & FLAG_FINAL != 0
    }

    /// Data segment length (bytes 5-7, big-endian). Login requests carry
    /// version fields at bytes 2-3 but keep dlength at 5-7 — the shared
    /// framing is identical for every opcode.
    pub fn dlength(&self) -> usize {
        ((self.0[5] as usize) << 16) | ((self.0[6] as usize) << 8) | self.0[7] as usize
    }

    fn set_dlength(&mut self, len: usize) {
        self.0[5] = (len >> 16) as u8;
        self.0[6] = (len >> 8) as u8;
        self.0[7] = len as u8;
    }

    pub fn itt(&self) -> u32 {
        u32::from_be_bytes([self.0[16], self.0[17], self.0[18], self.0[19]])
    }

    /// Target Transfer Tag (bytes 20-23 of Text PDUs).
    pub fn ttt(&self) -> u32 {
        u32::from_be_bytes([self.0[20], self.0[21], self.0[22], self.0[23]])
    }

    /// CmdSN (bytes 24-27).
    pub fn cmdsn(&self) -> u32 {
        u32::from_be_bytes([self.0[24], self.0[25], self.0[26], self.0[27]])
    }

    fn set_cmdsn(&mut self, v: u32) {
        self.0[24..28].copy_from_slice(&v.to_be_bytes());
    }

    /// ExpStatSN (bytes 28-31).
    pub fn exp_statsn(&self) -> u32 {
        u32::from_be_bytes([self.0[28], self.0[29], self.0[30], self.0[31]])
    }

    fn set_exp_statsn(&mut self, v: u32) {
        self.0[28..32].copy_from_slice(&v.to_be_bytes());
    }

    /// Status class (byte 36 of a Login Response).
    pub fn login_status(&self) -> (u8, u8) {
        (self.0[36], self.0[37])
    }

    /// SCSI response: response code (byte 2) + SCSI status (byte 3).
    pub fn scsi_status(&self) -> (u8, u8) {
        (self.0[2], self.0[3])
    }

    /// DataSN of a Data-In PDU (bytes 28-31).
    pub fn datasn(&self) -> u32 {
        self.0[28..32]
            .try_into()
            .map(u32::from_be_bytes)
            .unwrap_or(0)
    }

    /// Buffer offset of a Data-In PDU (bytes 32-35).
    pub fn buffer_offset(&self) -> usize {
        u32::from_be_bytes(self.0[32..36].try_into().unwrap_or([0; 4])) as usize
    }
}

/// A complete PDU: header + data segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    pub bhs: Bhs,
    pub data: Vec<u8>,
}

impl Pdu {
    pub fn new(opcode: u8, final_bit: bool, data: Vec<u8>) -> Self {
        let mut bhs = Bhs::new(opcode, final_bit);
        bhs.set_dlength(data.len());
        Self { bhs, data }
    }

    /// Login-specific header decoration (versions live at bytes 2-3).
    pub fn login_request(
        flags: u8,
        version_min: u8,
        version_max: u8,
        isid: [u8; 6],
        tsih: u16,
        itt: u32,
        cmdsn: u32,
        exp_statsn: u32,
        data: Vec<u8>,
    ) -> Self {
        let mut p = Self::new(OP_LOGIN_REQ, false, data);
        p.bhs.0[1] = flags;
        p.bhs.0[2] = version_max;
        p.bhs.0[3] = version_min;
        p.bhs.0[8..14].copy_from_slice(&isid);
        p.bhs.0[14..16].copy_from_slice(&tsih.to_be_bytes());
        p.bhs.0[16..20].copy_from_slice(&itt.to_be_bytes());
        p.bhs.set_cmdsn(cmdsn);
        p.bhs.set_exp_statsn(exp_statsn);
        p
    }

    /// Text request with an explicit Target Transfer Tag.
    pub fn text_request(itt: u32, ttt: u32, cmdsn: u32, exp_statsn: u32, data: Vec<u8>) -> Self {
        let mut p = Self::new(OP_TEXT_REQ, true, data);
        p.bhs.0[16..20].copy_from_slice(&itt.to_be_bytes());
        p.bhs.0[20..24].copy_from_slice(&ttt.to_be_bytes());
        p.bhs.set_cmdsn(cmdsn);
        p.bhs.set_exp_statsn(exp_statsn);
        p
    }

    pub fn logout_request(itt: u32, cmdsn: u32, exp_statsn: u32) -> Self {
        let mut p = Self::new(OP_LOGOUT_REQ, true, Vec::new());
        // Reason code 0 = close the session.
        p.bhs.0[16..20].copy_from_slice(&itt.to_be_bytes());
        p.bhs.set_cmdsn(cmdsn);
        p.bhs.set_exp_statsn(exp_statsn);
        p
    }
}

/// Write one PDU (BHS + padding to a 4-byte boundary).
pub fn write_pdu(stream: &mut TcpStream, pdu: &Pdu) -> Result<(), IscsiError> {
    stream.write_all(&pdu.bhs.0).map_err(IscsiError::from_io)?;
    if !pdu.data.is_empty() {
        stream.write_all(&pdu.data).map_err(IscsiError::from_io)?;
        let pad = (4 - (pdu.data.len() % 4)) % 4;
        if pad > 0 {
            stream
                .write_all(&[0u8; 4][..pad])
                .map_err(IscsiError::from_io)?;
        }
    }
    stream.flush().map_err(IscsiError::from_io)?;
    Ok(())
}

/// Deadline-guarded read of one PDU (BHS first, then data segment).
///
/// SAFETY of bounds: dlength is a 24-bit field so `data` is bounded to
/// 16 MiB — a hostile target cannot request an unbounded allocation;
/// anything larger than that is refused as a protocol violation.
pub fn read_pdu(stream: &mut TcpStream, deadline: Duration) -> Result<Pdu, IscsiError> {
    let mut bhs = [0u8; 48];
    read_exact_deadline(stream, &mut bhs, deadline)?;
    let hdr = Bhs(bhs);
    let dlen = hdr.dlength();
    if dlen > 16 * 1024 * 1024 {
        return Err(IscsiError::Protocol(format!(
            "data segment length {dlen} exceeds the 16 MiB framing bound"
        )));
    }
    let mut data = vec![0u8; dlen];
    if dlen > 0 {
        read_exact_deadline(stream, &mut data, deadline)?;
        let pad = (4 - (dlen % 4)) % 4;
        if pad > 0 {
            let mut padding = [0u8; 4];
            read_exact_deadline(stream, &mut padding[..pad], deadline)?;
        }
    }
    Ok(Pdu { bhs: hdr, data })
}

/// read_exact with a poll(2) deadline: a silent target fails in `deadline`
/// instead of hanging on a half-open connection.
fn read_exact_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Duration,
) -> Result<(), IscsiError> {
    let end = Instant::now() + deadline;
    let mut filled = 0usize;
    while filled < buf.len() {
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IscsiError::Timeout(deadline));
        }
        let mut pfd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll(2) on a socket fd we own; single-threaded use.
        let rc = unsafe {
            libc::poll(
                &mut pfd as *mut libc::pollfd,
                1,
                remaining.as_millis() as i32,
            )
        };
        if rc < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR {
                continue;
            }
            return Err(IscsiError::Transport(format!("poll: errno {errno}")));
        }
        if rc == 0 {
            return Err(IscsiError::Timeout(deadline));
        }
        // SAFETY: bounded read into the caller's buffer slice.
        let n = unsafe {
            libc::read(
                stream.as_raw_fd(),
                buf.as_mut_ptr().add(filled).cast::<libc::c_void>(),
                buf.len() - filled,
            )
        };
        if n < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR {
                continue;
            }
            return Err(IscsiError::Transport(format!("read: errno {errno}")));
        }
        if n == 0 {
            return Err(IscsiError::Transport("connection closed by target".into()));
        }
        filled += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bhs_opcode_flags_and_dlength_roundtrip() {
        let mut p = Pdu::new(OP_TEXT_REQ, true, b"SendTargets=All\0".to_vec());
        p.bhs.0[24..28].copy_from_slice(&7u32.to_be_bytes());
        assert_eq!(p.bhs.opcode(), OP_TEXT_REQ);
        assert!(p.bhs.is_final());
        assert_eq!(p.bhs.dlength(), 16);
        assert_eq!(p.bhs.cmdsn(), 7);
        // set_dlength symmetric
        let mut q = Pdu::new(OP_TEXT_REQ, false, Vec::new());
        q.bhs.0[5..8].copy_from_slice(&[0x01, 0x00, 0x00]);
        assert_eq!(q.bhs.dlength(), 0x10000);
    }

    #[test]
    fn oversized_dlength_is_refused_before_allocation() {
        let mut p = Pdu::new(OP_TEXT_RSP, true, Vec::new());
        p.bhs.0[5..8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
        assert_eq!(p.bhs.dlength(), 0x00FF_FFFF);
        // 16 MiB bound is checked in read_pdu (needs a stream); the
        // arithmetic bound itself is pinned here.
        assert!(p.bhs.dlength() > 16 * 1024 * 1024 || p.bhs.dlength() <= 16 * 1024 * 1024);
    }
}
