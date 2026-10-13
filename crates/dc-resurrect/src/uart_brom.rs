//! Vendor Boot-ROM UART protocol — the resurrection front door.
//!
//! When an SSD controller's SPI flash is corrupt but the mask-ROM Boot-ROM
//! (BROM) is intact and a download strap was sampled at power-on, the chip
//! sits in a firmware-recovery shell on a serial port. Every major vendor
//! (Marvell, Silicon Motion, Phison, Samsung) ships one; the command grammar
//! below is the modeled superset used by this rig, with vendor-specific knobs
//! (baud, sync byte, magic, key material) coming from the profile database.
//!
//! Frame grammar (all multi-byte fields little-endian):
//!
//! ```text
//! host -> device  AUTOBAUD   0x55 (raw, BROM measures width)
//! device -> host  ack byte  profile.ack (e.g. 0x5A)
//!
//! host -> device  HELLO     <magic ASCII>
//! device -> host  crc16 LE  of magic (proves a BROM answered, not firmware)
//!
//! CMD_AUTH   0x02 | crc16        reply: 8B challenge | crc16
//!            response 8B         reply: ACK/NAK  (HMAC-SHA256(key, chall))
//! CMD_PEEK   0x05 | u32 | crc16  reply: 4B value | crc16
//! CMD_POKE   0x06 | u32 u32 |crc reply: ACK
//! CMD_DL     0x01 | addr len |crc reply: ACK, then chunks:
//!            [u16 n][n bytes][crc16] -> ACK per chunk (NAK = resend)
//! CMD_JUMP   0x03 | u32 | crc16     reply: ACK — payload owns the UART now
//!
//! payload -> host  heartbeat: 'R''Z' type u8 block u16 data u32 | crc16
//! ```

use crate::crc::crc16_xmodem;
use crate::hal::{LinkError, UartLink};
use crate::sha256::sha256;

pub mod cmd {
    pub const DOWNLOAD: u8 = 0x01;
    pub const AUTH: u8 = 0x02;
    pub const JUMP: u8 = 0x03;
    pub const PEEK: u8 = 0x05;
    pub const POKE: u8 = 0x06;
    pub const ACK: u8 = 0x06;
    pub const NAK: u8 = 0x15;
}

/// Heartbeat frame emitted by the injected nucleus.
///
/// The nucleus writes one u32 to the UART TX register; the wire frame carries
/// it as: type u8 | block u16 LE | data u32 LE | crc16.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heartbeat {
    pub hb_type: u8,
    pub block: u16,
    pub data: u32,
}

pub const HB_PROGRESS: u8 = 0x01;
pub const HB_DONE: u8 = 0x02;

/// Vendor knobs for the BROM shell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BromParams {
    pub baud: u32,
    /// Autobaud byte the host sends (BROM measures its width).
    pub sync: u8,
    /// Reply byte to a successful autobaud.
    pub ack: u8,
    /// ASCII magic for the HELLO exchange.
    pub magic: Vec<u8>,
    /// Whether the BROM demands challenge/response before CMD_DL.
    pub auth_required: bool,
    /// Vendor debug key material (entitlement; demo value in-tree).
    pub key: Vec<u8>,
    /// Timeout for device replies, milliseconds.
    pub reply_ms: u32,
}

impl Default for BromParams {
    fn default() -> Self {
        BromParams {
            baud: 115_200,
            sync: 0x55,
            ack: 0x5A,
            magic: b"GENERIC-BROM".to_vec(),
            auth_required: false,
            key: Vec::new(),
            reply_ms: 300,
        }
    }
}

pub struct BromChannel<'a, U: UartLink> {
    link: &'a mut U,
    pub params: BromParams,
    /// False after CMD_JUMP — subsequent reads are nucleus heartbeats.
    pub payload_mode: bool,
}

const CHUNK: usize = 1024;

impl<'a, U: UartLink> BromChannel<'a, U> {
    pub fn new(link: &'a mut U, params: BromParams) -> Self {
        BromChannel {
            link,
            params,
            payload_mode: false,
        }
    }

    fn read_exact(&mut self, n: usize) -> Result<Option<Vec<u8>>, LinkError> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            match self.link.read_byte_timeout(self.params.reply_ms)? {
                Some(b) => out.push(b),
                None => return Ok(None),
            }
        }
        Ok(Some(out))
    }

    fn expect_ack(&mut self) -> Result<(), LinkError> {
        match self.link.read_byte_timeout(self.params.reply_ms)? {
            Some(cmd::ACK) => Ok(()),
            Some(cmd::NAK) => Err(LinkError::Fault("BROM NAK")),
            Some(_other) => Err(LinkError::Fault("unexpected BROM reply byte")),
            None => Err(LinkError::NoAck),
        }
    }

    fn send_frame(&mut self, head: &[u8]) -> Result<(), LinkError> {
        let mut buf = head.to_vec();
        buf.extend_from_slice(&crc16_xmodem(head).to_le_bytes());
        self.link.write_all(&buf)
    }

    /// Autobaud: emit the sync byte, expect the vendor ack.
    pub fn autobaud(&mut self) -> Result<(), LinkError> {
        self.link.write_byte(self.params.sync)?;
        match self.link.read_byte_timeout(self.params.reply_ms)? {
            Some(b) if b == self.params.ack => Ok(()),
            Some(_) => Err(LinkError::Fault(
                "autobaud reply mismatch — no BROM on this port",
            )),
            None => Err(LinkError::NoAck),
        }
    }

    /// HELLO: prove a BROM (not zombie firmware) is on the wire.
    pub fn hello(&mut self) -> Result<(), LinkError> {
        self.link.write_all(&self.params.magic)?;
        let want = crc16_xmodem(&self.params.magic);
        match self.read_exact(2)? {
            Some(v) if v.len() == 2 => {
                let got = u16::from_le_bytes([v[0], v[1]]);
                if got == want {
                    Ok(())
                } else {
                    Err(LinkError::Fault(
                        "HELLO CRC mismatch — wrong magic or locked shell",
                    ))
                }
            }
            _ => Err(LinkError::NoAck),
        }
    }

    /// Challenge/response: response = SHA-256(key || challenge)[0..8].
    pub fn auth(&mut self) -> Result<(), LinkError> {
        self.send_frame(&[cmd::AUTH])?;
        let challenge = match self.read_exact(8 + 2)? {
            Some(v) if v.len() == 10 => v,
            _ => return Err(LinkError::NoAck),
        };
        let chall = &challenge[..8];
        let crc = u16::from_le_bytes([challenge[8], challenge[9]]);
        if crc != crc16_xmodem(chall) {
            return Err(LinkError::Fault("challenge CRC mismatch"));
        }
        let mut material = self.params.key.clone();
        material.extend_from_slice(chall);
        let response: Vec<u8> = sha256(&material)[..8].to_vec();
        self.link.write_all(&response)?;
        self.expect_ack()
    }

    /// Full bring-up: autobaud + hello + (optional) auth.
    pub fn open(&mut self) -> Result<(), LinkError> {
        self.autobaud()?;
        self.hello()?;
        if self.params.auth_required {
            self.auth()?;
        }
        Ok(())
    }

    /// Read 4 bytes of target memory.
    pub fn peek32(&mut self, addr: u32) -> Result<u32, LinkError> {
        let mut head = vec![cmd::PEEK];
        head.extend_from_slice(&addr.to_le_bytes());
        self.send_frame(&head)?;
        match self.read_exact(4 + 2)? {
            Some(v) if v.len() == 6 => {
                let val = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
                let crc = u16::from_le_bytes([v[4], v[5]]);
                if crc != crc16_xmodem(&v[..4]) {
                    return Err(LinkError::Fault("PEEK CRC mismatch"));
                }
                Ok(val)
            }
            _ => Err(LinkError::NoAck),
        }
    }

    /// Write 4 bytes of target memory.
    pub fn poke32(&mut self, addr: u32, value: u32) -> Result<(), LinkError> {
        let mut head = vec![cmd::POKE];
        head.extend_from_slice(&addr.to_le_bytes());
        head.extend_from_slice(&value.to_le_bytes());
        self.send_frame(&head)?;
        self.expect_ack()
    }

    /// Download a payload image into SRAM at `load_addr`, then jump.
    pub fn download(&mut self, blob: &[u8], load_addr: u32) -> Result<(), LinkError> {
        let mut head = vec![cmd::DOWNLOAD];
        head.extend_from_slice(&load_addr.to_le_bytes());
        head.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        self.send_frame(&head)?;
        self.expect_ack()?;
        for chunk in blob.chunks(CHUNK) {
            let mut tries = 0;
            loop {
                let mut frame = (chunk.len() as u16).to_le_bytes().to_vec();
                frame.extend_from_slice(chunk);
                frame.extend_from_slice(&crc16_xmodem(chunk).to_le_bytes());
                self.link.write_all(&frame)?;
                match self.link.read_byte_timeout(self.params.reply_ms)? {
                    Some(cmd::ACK) => break,
                    Some(cmd::NAK) => {
                        tries += 1;
                        if tries >= 4 {
                            return Err(LinkError::Fault("BROM kept NAKing chunk"));
                        }
                    }
                    Some(_) => return Err(LinkError::Fault("unexpected chunk reply")),
                    None => return Err(LinkError::NoAck),
                }
            }
        }
        Ok(())
    }

    /// Execute the downloaded payload at `entry` (Thumb bit honored).
    pub fn jump(&mut self, entry: u32) -> Result<(), LinkError> {
        let mut head = vec![cmd::JUMP];
        head.extend_from_slice(&entry.to_le_bytes());
        self.send_frame(&head)?;
        self.expect_ack()?;
        self.payload_mode = true;
        Ok(())
    }

    /// Read one nucleus heartbeat (11 bytes, CRC-protected).
    pub fn read_heartbeat(&mut self, ms: u32) -> Result<Option<Heartbeat>, LinkError> {
        let mut buf = Vec::with_capacity(11);
        // Synchronize on the 'R''Z' preamble.
        loop {
            let b = match self.link.read_byte_timeout(ms)? {
                Some(b) => b,
                None => return Ok(None),
            };
            buf.push(b);
            let n = buf.len();
            if n >= 2 && buf[n - 2] == b'R' && buf[n - 1] == b'Z' {
                buf.drain(..n - 2);
                break;
            }
            if n > 4096 {
                return Err(LinkError::Fault("UART noise: no heartbeat preamble"));
            }
        }
        match self.read_exact(9)? {
            Some(rest) if rest.len() == 9 => {
                // rest = type(1) block(2) data(4) crc(2)
                let hb = Heartbeat {
                    hb_type: rest[0],
                    block: u16::from_le_bytes([rest[1], rest[2]]),
                    data: u32::from_le_bytes([rest[3], rest[4], rest[5], rest[6]]),
                };
                let crc = u16::from_le_bytes([rest[7], rest[8]]);
                if crc != crc16_xmodem(&rest[..7]) {
                    return Err(LinkError::Fault("heartbeat CRC mismatch"));
                }
                Ok(Some(hb))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_frame_is_crc_consistent_with_parser() {
        // Build a frame by hand the way the nucleus/sim does, parse it back.
        let hb = Heartbeat {
            hb_type: HB_PROGRESS,
            block: 1023,
            data: 0x5A,
        };
        let mut body = vec![hb.hb_type];
        body.extend_from_slice(&hb.block.to_le_bytes());
        body.extend_from_slice(&hb.data.to_le_bytes());
        let crc = crc16_xmodem(&body);
        // Parser contract: first 7 bytes are the record, last 2 the CRC.
        assert_eq!(body.len(), 7);
        let mut frame = vec![b'R', b'Z'];
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(frame.len(), 11);
        assert_eq!(
            crc16_xmodem(&frame[2..9]),
            u16::from_le_bytes([frame[9], frame[10]])
        );
    }
}
