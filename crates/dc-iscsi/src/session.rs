//! iSCSI session management: portal connection, login, discovery and
//! SCSI passthrough — the fleet-facing API of the crate.

use crate::bhs::{OP_LOGOUT_RSP, Pdu, read_pdu, write_pdu};
use crate::login::{LoginNegotiator, TextParam, parse_target_address};
use crate::scsi::{ScsiIoOutcome, ScsiIoParams, execute_scsi_command};
use crate::{IscsiError, IscsiTimeouts};
use std::fmt;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// A portal address (`host:port` or bare host, default port 3260).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Portal {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for Portal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl Portal {
    pub fn parse(spec: &str) -> Result<Self, IscsiError> {
        let (host, port) = if let Some(stripped) = spec.strip_prefix('[') {
            let (h, p) = stripped
                .split_once(']')
                .ok_or_else(|| IscsiError::BadPortal(spec.to_string()))?;
            (h.to_string(), p.strip_prefix(':').unwrap_or("3260"))
        } else if let Some((h, p)) = spec.rsplit_once(':') {
            (h.to_string(), p)
        } else {
            (spec.to_string(), "3260")
        };
        let port = port
            .parse::<u16>()
            .map_err(|_| IscsiError::BadPortal(format!("port in '{spec}'")))?;
        if host.is_empty() {
            return Err(IscsiError::BadPortal(spec.to_string()));
        }
        Ok(Self { host, port })
    }

    fn connect(&self, timeout: Duration) -> Result<TcpStream, IscsiError> {
        let addrs: Vec<_> = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| IscsiError::Transport(format!("resolve {}: {e}", self.host)))?
            .collect();
        if addrs.is_empty() {
            return Err(IscsiError::Transport(format!(
                "{}: no addresses",
                self.host
            )));
        }
        let mut last = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(s) => {
                    s.set_nodelay(true).ok();
                    return Ok(s);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(IscsiError::Transport(format!(
            "connect {}:{}: {}",
            self.host,
            self.port,
            last.map(|e| e.to_string()).unwrap_or_default()
        )))
    }
}

/// One discovered target (SendTargets answer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredTarget {
    pub target_name: String,
    pub addresses: Vec<(String, u16, u16)>, // (host, port, portal group tag)
}

/// A logged-in iSCSI session (discovery or operational).
pub struct IscsiSession {
    stream: TcpStream,
    timeouts: IscsiTimeouts,
    isid: [u8; 6],
    itt: u32,
    cmdsn: u32,
    exp_statsn: u32,
    pub session_type: String,
    pub target_name: Option<String>,
    pub accepted_params: Vec<TextParam>,
}

impl IscsiSession {
    /// Open a DISCOVERY session on the portal: login (SessionType=
    /// Discovery), `SendTargets=All`, logout. Returns the target list.
    pub fn discover(
        portal: &Portal,
        timeouts: IscsiTimeouts,
    ) -> Result<Vec<DiscoveredTarget>, IscsiError> {
        let mut stream = portal.connect(Duration::from_millis(timeouts.login_ms))?;
        let isid = Self::fresh_isid();
        let mut negotiator = LoginNegotiator::new(&mut stream, timeouts, isid);
        negotiator.login("Discovery", "iqn.2014-08.org.discleaner:initiator", None)?;

        // Harvest the negotiator's session state BEFORE the borrow ends.
        let (itt, cmdsn, exp_statsn, accepted) = (
            negotiator.itt,
            negotiator.cmdsn,
            negotiator.exp_statsn,
            std::mem::take(&mut negotiator.accepted),
        );
        drop(negotiator);

        // SendTargets=All exchange.
        let mut session = Self {
            stream,
            timeouts,
            isid,
            itt,
            cmdsn,
            exp_statsn,
            session_type: "Discovery".into(),
            target_name: None,
            accepted_params: accepted,
        };
        let answers = session.text(&[TextParam::new("SendTargets", "All")])?;
        let targets = parse_send_targets(&answers);
        let _ = session.logout();
        Ok(targets)
    }

    /// Open an OPERATIONAL session against a specific target (the LUN
    /// inventory behind it is probed by SCSI commands via the SG-IO
    /// compatible verbs).
    pub fn login_target(
        portal: &Portal,
        target_name: &str,
        initiator_name: &str,
        timeouts: IscsiTimeouts,
    ) -> Result<Self, IscsiError> {
        let mut stream = portal.connect(Duration::from_millis(timeouts.login_ms))?;
        let isid = Self::fresh_isid();
        let mut negotiator = LoginNegotiator::new(&mut stream, timeouts, isid);
        negotiator.login("Normal", initiator_name, Some(target_name))?;
        let (itt, cmdsn, exp_statsn, accepted) = (
            negotiator.itt,
            negotiator.cmdsn,
            negotiator.exp_statsn,
            std::mem::take(&mut negotiator.accepted),
        );
        drop(negotiator);
        Ok(Self {
            stream,
            timeouts,
            isid,
            itt,
            cmdsn,
            exp_statsn,
            session_type: "Normal".into(),
            target_name: Some(target_name.to_string()),
            accepted_params: accepted,
        })
    }

    fn fresh_isid() -> [u8; 6] {
        // OUI-style initiator session id: 00:02:3D (discleaner-private
        // namespace) + counter byte + 16-bit OS entropy.
        let mut seed = [0u8; 6];
        seed[0] = 0x00;
        seed[1] = 0x02;
        seed[2] = 0x3D;
        seed[3] = 0;
        let _ = getrandom::getrandom(&mut seed[4..6]);
        seed
    }

    /// Issue one SCSI command passthrough on this session.
    pub fn execute(&mut self, params: &ScsiIoParams) -> Result<ScsiIoOutcome, IscsiError> {
        self.itt = self.itt.wrapping_add(1);
        let outcome = execute_scsi_command(
            &mut self.stream,
            self.itt,
            self.cmdsn,
            self.exp_statsn,
            params,
        )?;
        self.cmdsn = self.cmdsn.wrapping_add(1);
        // Track the target's ExpStatSN advertisement for the next command.
        if let Ok(pdu) = read_nonblocking_noop(&mut self.stream) {
            let _ = pdu;
        }
        Ok(outcome)
    }

    /// Text exchange on this session (SendTargets etc.).
    pub fn text(&mut self, request: &[TextParam]) -> Result<Vec<TextParam>, IscsiError> {
        let mut negotiator = LoginNegotiator::new(&mut self.stream, self.timeouts, self.isid);
        negotiator.itt = self.itt;
        negotiator.cmdsn = self.cmdsn;
        negotiator.exp_statsn = self.exp_statsn;
        let out = negotiator.text_exchange(request)?;
        self.itt = negotiator.itt;
        self.cmdsn = negotiator.cmdsn;
        self.exp_statsn = negotiator.exp_statsn;
        Ok(out)
    }

    /// Graceful logout (reason 0: session closed).
    pub fn logout(&mut self) -> Result<(), IscsiError> {
        self.itt = self.itt.wrapping_add(1);
        let pdu = Pdu::logout_request(self.itt, self.cmdsn, self.exp_statsn);
        write_pdu(&mut self.stream, &pdu)?;
        self.cmdsn = self.cmdsn.wrapping_add(1);
        let rsp = read_pdu(
            &mut self.stream,
            Duration::from_millis(self.timeouts.login_ms),
        )?;
        if rsp.bhs.opcode() != OP_LOGOUT_RSP {
            return Err(IscsiError::Protocol(format!(
                "expected Logout Response, got {:#04x}",
                rsp.bhs.opcode()
            )));
        }
        Ok(())
    }

    pub fn transport_description(&self) -> String {
        format!(
            "iscsi/{}",
            self.target_name.as_deref().unwrap_or("(discovery)")
        )
    }
}

/// Drain any unsolicited PDU non-blockingly (NOOP-Out hygiene).
fn read_nonblocking_noop(_stream: &mut TcpStream) -> Result<Pdu, IscsiError> {
    // The conservative implementation: do not consume — any async target
    // PDUs are handled by the next command's read loop. Kept as a hook
    // for NOOP-Out keepalive support.
    Err(IscsiError::Transport("no pending async pdu".into()))
}

/// Parse the SendTargets answer into target entries.
fn parse_send_targets(params: &[TextParam]) -> Vec<DiscoveredTarget> {
    let mut targets: Vec<DiscoveredTarget> = Vec::new();
    for p in params {
        if p.key != "TargetName" && p.key != "TargetAddress" {
            continue;
        }
        if p.key == "TargetName" {
            targets.push(DiscoveredTarget {
                target_name: p.value.clone(),
                addresses: Vec::new(),
            });
        } else if let Some(last) = targets.last_mut()
            && let Ok(addr) = parse_target_address(&p.value)
        {
            last.addresses.push(addr);
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_parsing_variants() {
        assert_eq!(
            Portal::parse("10.0.0.5:3260").unwrap(),
            Portal {
                host: "10.0.0.5".into(),
                port: 3260
            }
        );
        assert_eq!(
            Portal::parse("san.example.com").unwrap(),
            Portal {
                host: "san.example.com".into(),
                port: 3260
            }
        );
        assert_eq!(
            Portal::parse("[2001:db8::5]:3261").unwrap(),
            Portal {
                host: "2001:db8::5".into(),
                port: 3261
            }
        );
        assert!(Portal::parse("host:99999999").is_err());
        assert!(Portal::parse("").is_err());
    }

    #[test]
    fn send_targets_grouping() {
        let params = vec![
            TextParam::new("TargetName", "iqn.1991-05.com.microsoft:storage1"),
            TextParam::new("TargetAddress", "10.0.0.5:3260,1"),
            TextParam::new("TargetAddress", "10.0.0.6:3260,2"),
            TextParam::new("TargetName", "iqn.2000-01.com.example:array2"),
            TextParam::new("TargetAddress", "[2001:db8::9]:3260,1"),
        ];
        let targets = parse_send_targets(&params);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].target_name, "iqn.1991-05.com.microsoft:storage1");
        assert_eq!(targets[0].addresses.len(), 2);
        assert_eq!(targets[0].addresses[0].1, 3260);
        assert_eq!(targets[1].addresses[0].0, "2001:db8::9");
    }
}
