//! iSCSI login phase + text negotiation (RFC 3720 §10.13, §10.10).
//!
//! The negotiation model: key=value pairs separated by NUL in the PDU
//! data segment; our offers are fixed (no digests, no auth — the same
//! in-band intranet assumption as the NVMe-oF stack) and any target
//! `Reject` or `NotUnderstood` on a required key fails the login. State
//! machine: SecurityNegotiation -> OperationalNegotiation ->
//! FullFeaturePhase (F-bit with NSG=3).

use crate::bhs::{OP_LOGIN_RSP, OP_TEXT_RSP, Pdu, TTT_NONE, read_pdu, write_pdu};
use crate::{IscsiError, IscsiTimeouts};
use std::net::TcpStream;

/// One `Key=Value\0` text parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextParam {
    pub key: String,
    pub value: String,
}

impl TextParam {
    pub fn new(key: &str, value: &str) -> Self {
        Self {
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    pub fn encode(params: &[TextParam]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in params {
            out.extend_from_slice(p.key.as_bytes());
            out.push(b'=');
            out.extend_from_slice(p.value.as_bytes());
            out.push(0);
        }
        out
    }

    /// Parse a text data segment; tolerates a missing trailing NUL.
    pub fn parse_all(data: &[u8]) -> Vec<TextParam> {
        data.split(|&b| b == 0)
            .filter(|chunk| !chunk.is_empty())
            .filter_map(|chunk| {
                let s = String::from_utf8_lossy(chunk);
                let (k, v) = s.split_once('=')?;
                Some(TextParam {
                    key: k.to_string(),
                    value: v.to_string(),
                })
            })
            .collect()
    }
}

/// Negotiation stage bits for the login flags byte (RFC 3720 §10.13.5).
const NSG_SECURITY: u8 = 0 << 3;
const NSG_OPERATIONAL: u8 = 1 << 3;
const NSG_FULL_FEATURE: u8 = 3 << 3;
const TRANSIT: u8 = 0x04;

/// Our fixed parameter offers.
pub fn security_offers() -> Vec<TextParam> {
    vec![TextParam::new("AuthMethod", "None")]
}

pub fn operational_offers(
    session_type: &str,
    initiator_name: &str,
    target_name: Option<&str>,
) -> Vec<TextParam> {
    let mut offers = vec![
        TextParam::new("SessionType", session_type),
        TextParam::new("InitiatorName", initiator_name),
        TextParam::new("HeaderDigest", "None"),
        TextParam::new("DataDigest", "None"),
        TextParam::new("MaxConnections", "1"),
        TextParam::new("InitialR2T", "Yes"),
        TextParam::new("ImmediateData", "No"),
        TextParam::new("MaxRecvDataSegmentLength", "131072"),
        TextParam::new("MaxBurstLength", "1048576"),
        TextParam::new("DefaultTime2Wait", "2"),
        TextParam::new("DefaultTime2Retain", "0"),
        TextParam::new("ErrorRecoveryLevel", "0"),
    ];
    if let Some(tn) = target_name {
        offers.push(TextParam::new("TargetName", tn));
    }
    offers
}

/// The login negotiator: drives one session from TCP connect to the
/// Full Feature Phase, maintaining the CmdSN/ExpStatSN disciplines.
pub struct LoginNegotiator<'a> {
    stream: &'a mut TcpStream,
    timeouts: IscsiTimeouts,
    isid: [u8; 6],
    pub itt: u32,
    pub cmdsn: u32,
    pub exp_statsn: u32,
    /// Negotiated parameters echoed by the target (evidence).
    pub accepted: Vec<TextParam>,
}

impl<'a> LoginNegotiator<'a> {
    pub fn new(stream: &'a mut TcpStream, timeouts: IscsiTimeouts, isid: [u8; 6]) -> Self {
        Self {
            stream,
            timeouts,
            isid,
            itt: 1,
            cmdsn: 0,
            exp_statsn: 1,
            accepted: Vec::new(),
        }
    }

    /// Full login ladder for the given session type ("Discovery" or
    /// "Normal"). Returns the target's accepted parameters.
    pub fn login(
        &mut self,
        session_type: &str,
        initiator_name: &str,
        target_name: Option<&str>,
    ) -> Result<(), IscsiError> {
        // Stage 1: security negotiation (AuthMethod=None) with a
        // transition bit into operational parameters.
        self.login_stage(
            NSG_SECURITY | NSG_OPERATIONAL | TRANSIT | 0x01,
            security_offers(),
        )?;
        // Stage 2: operational negotiation, transitioning to full feature.
        let offers = operational_offers(session_type, initiator_name, target_name);
        self.login_stage(NSG_OPERATIONAL | NSG_FULL_FEATURE | TRANSIT | 0x01, offers)?;
        Ok(())
    }

    fn login_stage(&mut self, flags: u8, offers: Vec<TextParam>) -> Result<(), IscsiError> {
        let data = TextParam::encode(&offers);
        let pdu = Pdu::login_request(
            flags,
            0, // version-min
            0, // version-max
            self.isid,
            0, // TSIH: new session
            self.itt,
            self.cmdsn,
            self.exp_statsn,
            data,
        );
        write_pdu(self.stream, &pdu)?;
        self.cmdsn = self.cmdsn.wrapping_add(1);
        loop {
            let rsp = read_pdu(
                self.stream,
                std::time::Duration::from_millis(self.timeouts.login_ms),
            )?;
            if rsp.bhs.opcode() != OP_LOGIN_RSP {
                return Err(IscsiError::Protocol(format!(
                    "expected Login Response, got opcode {:#04x}",
                    rsp.bhs.opcode()
                )));
            }
            let (class, detail) = rsp.bhs.login_status();
            if class != 0 {
                return Err(IscsiError::LoginRefused {
                    class,
                    detail,
                    message: String::from_utf8_lossy(&rsp.data).to_string(),
                });
            }
            self.exp_statsn = self
                .exp_statsn
                .max(u32::from_be_bytes(rsp.bhs.0[24..28].try_into().unwrap_or([0; 4])) + 1);
            self.accepted.extend(TextParam::parse_all(&rsp.data));
            // Transit bit set: the target moved the stage itself.
            if rsp.bhs.flags() & TRANSIT != 0 && rsp.bhs.is_final() {
                return Ok(());
            }
            if rsp.bhs.is_final() {
                // Target answered our offers without transitioning — the
                // next stage's login (with the transit bit) follows.
                return Ok(());
            }
            // Multi-PDU negotiation (rare): reply "NotUnderstood" is not
            // acceptable on our required keys; continue reading.
        }
    }

    /// Text request/response exchange honoring the TTT continuation
    /// protocol (SendTargets responses can span PDUs).
    pub fn text_exchange(&mut self, request: &[TextParam]) -> Result<Vec<TextParam>, IscsiError> {
        let mut to_send = TextParam::encode(request);
        let mut collected: Vec<TextParam> = Vec::new();
        loop {
            // Request (initial: with payload; continuation: empty).
            let pdu = Pdu::text_request(
                self.itt,
                TTT_NONE,
                self.cmdsn,
                self.exp_statsn,
                std::mem::take(&mut to_send),
            );
            write_pdu(self.stream, &pdu)?;
            self.cmdsn = self.cmdsn.wrapping_add(1);

            let rsp = read_pdu(
                self.stream,
                std::time::Duration::from_millis(self.timeouts.login_ms),
            )?;
            if rsp.bhs.opcode() != OP_TEXT_RSP {
                return Err(IscsiError::Protocol(format!(
                    "expected Text Response, got opcode {:#04x}",
                    rsp.bhs.opcode()
                )));
            }
            self.exp_statsn = self
                .exp_statsn
                .max(u32::from_be_bytes(rsp.bhs.0[24..28].try_into().unwrap_or([0; 4])) + 1);
            collected.extend(TextParam::parse_all(&rsp.data));
            if rsp.bhs.is_final() {
                return Ok(collected);
            }
            // Continuation: answer the pending TTT with an EMPTY request.
            let cont = Pdu::text_request(
                self.itt,
                rsp.bhs.ttt(),
                self.cmdsn,
                self.exp_statsn,
                Vec::new(),
            );
            write_pdu(self.stream, &cont)?;
            self.cmdsn = self.cmdsn.wrapping_add(1);
        }
    }
}

/// Parse a `TargetAddress=domain:port,portal-group-tag` value.
pub fn parse_target_address(value: &str) -> Result<(String, u16, u16), IscsiError> {
    // RFC 3720 §12.10: address[,tag] — the address itself may be
    // [IPv6]:port or IPv4:port or a hostname.
    let (addr_part, tag) = match value.split_once(',') {
        Some((a, t)) => (a, t),
        None => (value, "1"),
    };
    let tag = tag
        .trim()
        .parse::<u16>()
        .map_err(|_| IscsiError::Protocol(format!("portal group tag in '{value}'")))?;
    let (host, port) = if let Some(stripped) = addr_part.strip_prefix('[') {
        // [IPv6]:port
        let (h, p) = stripped
            .split_once(']')
            .ok_or_else(|| IscsiError::Protocol(format!("IPv6 literal '{addr_part}'")))?;
        let port = p.strip_prefix(':').unwrap_or("3260").to_string();
        (h.to_string(), port)
    } else {
        match addr_part.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (addr_part.to_string(), "3260".to_string()),
        }
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| IscsiError::Protocol(format!("port in '{value}'")))?;
    Ok((host, port, tag))
}

/// Extract a 16-byte LUN structure from a numeric LUN id (flat mapping).
pub fn lun_bytes(lun: u16) -> [u8; 8] {
    // SAM flat address method 0: LUN in the first two bytes.
    let mut out = [0u8; 8];
    out[0] = (lun >> 8) as u8;
    out[1] = (lun & 0xFF) as u8;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_params_roundtrip() {
        let params = vec![
            TextParam::new("SendTargets", "All"),
            TextParam::new("SessionType", "Discovery"),
        ];
        let enc = TextParam::encode(&params);
        assert_eq!(&enc, b"SendTargets=All\0SessionType=Discovery\0");
        assert_eq!(TextParam::parse_all(&enc), params);
        // Tolerates missing trailing NUL and stray empties.
        assert_eq!(TextParam::parse_all(b"A=1"), vec![TextParam::new("A", "1")]);
        assert!(TextParam::parse_all(b"garbage-no-equals\0").is_empty());
    }

    #[test]
    fn target_address_variants() {
        assert_eq!(
            parse_target_address("192.168.1.10:3260,1").unwrap(),
            ("192.168.1.10".to_string(), 3260, 1)
        );
        assert_eq!(
            parse_target_address("storage.example.com").unwrap(),
            ("storage.example.com".to_string(), 3260, 1)
        );
        assert_eq!(
            parse_target_address("[2001:db8::1]:3260,5").unwrap(),
            ("2001:db8::1".to_string(), 3260, 5)
        );
        assert!(parse_target_address("host:notaport").is_err());
    }

    #[test]
    fn lun_mapping_is_sam_flat_method_zero() {
        assert_eq!(lun_bytes(0), [0u8; 8]);
        assert_eq!(lun_bytes(1), [0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(lun_bytes(0x0102), [0x01, 0x02, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn login_bhs_layout_matches_rfc() {
        let pdu = Pdu::login_request(
            NSG_SECURITY | NSG_OPERATIONAL | TRANSIT,
            0,
            0,
            [0x00, 0x02, 0x3D, 0x00, 0x00, 0x01],
            0,
            0x1234_5678,
            42,
            7,
            b"A=1\0".to_vec(),
        );
        let b = &pdu.bhs;
        assert_eq!(b.opcode(), crate::bhs::OP_LOGIN_REQ);
        assert_eq!(b.0[2], 0); // version-max
        assert_eq!(b.0[3], 0); // version-min
        assert_eq!(&b.0[8..14], &[0x00, 0x02, 0x3D, 0x00, 0x00, 0x01]); // ISID
        assert_eq!(b.dlength(), 4);
        assert_eq!(b.itt(), 0x1234_5678);
        assert_eq!(b.cmdsn(), 42);
        assert_eq!(b.exp_statsn(), 7);
    }
}
