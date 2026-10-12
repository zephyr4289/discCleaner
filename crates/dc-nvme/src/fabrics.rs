//! NVMe-over-Fabrics remote purge transport (v0.8.0, Vector 4).
//!
//! Government datacenters do not just sanitize local drives: they
//! decommission multi-petabyte SANs reachable over NVMe-oF (RDMA / RoCEv2
//! / TCP) and Fibre Channel. The kernel's fabric host stack is driven over
//! generic netlink (family "nvme") — `nvme connect` is `NVME_CMD_CONNECT`
//! with transport attributes, not a device ioctl. This module speaks that
//! protocol directly: no libnvme, no nvme-cli, no dynamic linking.
//!
//! UAPI pinned here (include/uapi/linux/nvme.h, stable since 4.11+):
//! - genl family name "nvme", protocol version 1;
//! - commands: CONNECT=1, DISCONNECT=2 (enum values are frozen);
//! - connect attributes: TRANSPORT=1, TRADDR=2, TRSVCID=3, HOST_TRADDR=4,
//!   NQN=5, DISCOVERY=6, KATO=7 (enum NVMF_ATTR, as consumed by libnvme).
//!
//! Lifecycle (the CLI drives it, everything deadline-guarded):
//! 1. `fabric_uri` parse — `nvme+tcp://10.0.0.5:4420/nqn.2014-08...`
//!    (transports: tcp | rdma | fc | loop).
//! 2. `connect()` — genl CONNECT; the kernel instantiates a controller.
//! 3. `wait_for_controller()` — poll /sys/class/nvme for the new ctrl
//!    matching our address/nqn within `ctrl_appear_ms`.
//! 4. Sanitize via the EXISTING admin-passthrough ladder on the char dev
//!    (dc-nvme purge path — in-band remote sanitize is the same admin
//!    command, the transport below it is what changed).
//! 5. `disconnect()` — genl DISCONNECT, matching the same attributes.
//!
//! Fail-safes: every step is deadline-guarded; connect ACK timeout, ctrl
//! appearance timeout and per-command ioctls each carry their own
//! budget; a fabric target that cannot fully connect-and-disconnect is
//! refused as a purge target (never half-connected certification).

use std::fmt;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Generic netlink wire constants (uapi/linux/genetlink.h semantics)
// ---------------------------------------------------------------------------

/// `NETLINK_GENERIC` socket protocol number.
const NETLINK_GENERIC: i32 = 16;

// nlmsg flags
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;

// nlmsg types
const NLMSG_ERROR: u16 = 0x02;
/// CTRL_CMD_GETFAMILY = 3.
const CTRL_CMD_GETFAMILY: u8 = 3;
/// CTRL_ATTR_FAMILY_NAME = 2, CTRL_ATTR_FAMILY_ID = 1.
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

// genl header: cmd u8, version u8, reserved u16.
const GENL_HDR_LEN: usize = 4;

// NVMe genl (uapi/linux/nvme.h):
const NVME_GENL_FAMILY: &str = "nvme";
const NVME_GENL_VERSION: u8 = 1;
pub const NVME_CMD_CONNECT: u8 = 1;
pub const NVME_CMD_DISCONNECT: u8 = 2;

/// NVMF connect attribute ids (kernel enum, frozen):
pub const NVMF_ATTR_TRANSPORT: u16 = 1;
pub const NVMF_ATTR_TRADDR: u16 = 2;
pub const NVMF_ATTR_TRSVCID: u16 = 3;
pub const NVMF_ATTR_HOST_TRADDR: u16 = 4;
pub const NVMF_ATTR_NQN: u16 = 5;
pub const NVMF_ATTR_DISCOVERY: u16 = 6;
pub const NVMF_ATTR_KATO: u16 = 7;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum FabricError {
    #[error("fabric URI invalid: {0}")]
    Uri(String),
    #[error("generic netlink unavailable: {0}")]
    Netlink(String),
    #[error("connect timeout after {0:?} — fabric controller never answered")]
    ConnectTimeout(Duration),
    #[error("controller never appeared under /sys/class/nvme within {0:?}")]
    CtrlTimeout(Duration),
    #[error("fabric session refused: {0}")]
    Refusal(String),
    #[error("netlink NAK: {0}")]
    Nak(String),
    #[error("sysfs scan: {0}")]
    Sysfs(String),
}

/// Timeout budget for one fabric session.
#[derive(Clone, Copy, Debug)]
pub struct FabricTimeouts {
    /// ACK deadline for the netlink CONNECT/DISCONNECT round trip.
    pub ack_ms: u64,
    /// Deadline for the new controller to appear in /sys/class/nvme.
    pub ctrl_appear_ms: u64,
    /// Poll interval for the sysfs scan.
    pub poll_ms: u64,
}

impl Default for FabricTimeouts {
    fn default() -> Self {
        Self {
            ack_ms: 5_000,
            ctrl_appear_ms: 30_000,
            poll_ms: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Netlink message assembly (pure-Rust, byte-exact, golden-vector tested)
// ---------------------------------------------------------------------------

/// nlmsghdr + genlmsghdr + attributes.
pub fn build_genl_message(family_id: u16, cmd: u8, version: u8, attrs: &[(u16, Attr)]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    // nlmsghdr (16 bytes): nlmsg_len (u32) patched at the end, then type
    // (u16), flags (u16), seq (u32), pid (u32). The nlmsg type carries the
    // genl family id; `transact` re-patches type/flags/seq before sending.
    msg.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_len
    msg.extend_from_slice(&family_id.to_le_bytes()); // nlmsg_type
    msg.extend_from_slice(&0u16.to_le_bytes()); // flags
    msg.extend_from_slice(&0u32.to_le_bytes()); // seq
    msg.extend_from_slice(&0u32.to_le_bytes()); // pid (0 = kernel picks)
                                                // genlmsghdr
    msg.push(cmd);
    msg.push(version);
    msg.extend_from_slice(&0u16.to_le_bytes()); // reserved
    for (ty, val) in attrs {
        let payload = val.encode();
        // nlattr: u16 len (header 4 + payload), u16 type, padded to 4.
        let len = (4 + payload.len()) as u16;
        msg.extend_from_slice(&len.to_le_bytes());
        msg.extend_from_slice(&ty.to_le_bytes());
        msg.extend_from_slice(&payload);
        while msg.len() % 4 != 0 {
            msg.push(0);
        }
    }
    let total = (msg.len() as u32).to_le_bytes();
    msg[0..4].copy_from_slice(&total);
    msg
}

/// Attribute payloads.
pub enum Attr {
    /// NUL-terminated string.
    Str(String),
    /// u32 in native (little-endian) order.
    U32(u32),
    /// Flag (no payload).
    Flag,
}

impl Attr {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Str(s) => {
                let mut v = s.as_bytes().to_vec();
                v.push(0);
                v
            }
            Self::U32(v) => v.to_le_bytes().to_vec(),
            Self::Flag => Vec::new(),
        }
    }
}

/// Resolve the "nvme" genl family id via the nlctrl GETFAMILY dance.
pub fn resolve_nvme_family_id() -> Result<u16, FabricError> {
    let mut sock = GenlSocket::open()?;
    let attrs = [(CTRL_ATTR_FAMILY_NAME, Attr::Str(NVME_GENL_FAMILY.into()))];
    // nlctrl has a fixed family id of 16 (GENL_ID_CTRL), type = 16.
    let msg = build_genl_message(16, CTRL_CMD_GETFAMILY, 1, &attrs);
    let reply = sock.transact(&msg, 0x0010, Duration::from_secs(2))?;
    parse_family_id(&reply).ok_or_else(|| {
        FabricError::Netlink(format!(
            "nlctrl reply carried no CTRL_ATTR_FAMILY_ID for '{NVME_GENL_FAMILY}' — \
             is the nvme-fabrics kernel module loaded?"
        ))
    })
}

/// Parse CTRL_ATTR_FAMILY_ID out of a GETFAMILY reply.
pub fn parse_family_id(reply: &[u8]) -> Option<u16> {
    // Skip nlmsghdr(16) + genlmsghdr(4), walk attributes.
    let mut off = 16 + GENL_HDR_LEN;
    while off + 4 <= reply.len() {
        let len = u16::from_le_bytes([reply[off], reply[off + 1]]) as usize;
        let ty = u16::from_le_bytes([reply[off + 2], reply[off + 3]]);
        if len < 4 || off + len > reply.len() {
            return None;
        }
        if ty == CTRL_ATTR_FAMILY_ID && len >= 6 {
            return Some(u16::from_le_bytes([reply[off + 4], reply[off + 5]]));
        }
        off += (len + 3) & !3; // NLMSG_ALIGN
    }
    None
}

/// The raw netlink socket (libc AF_NETLINK SOCK_RAW, NETLINK_GENERIC).
pub struct GenlSocket {
    fd: i32,
    seq: u32,
}

impl GenlSocket {
    pub fn open() -> Result<Self, FabricError> {
        let fd = unsafe { libc::socket(NETLINK_GENERIC, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(FabricError::Netlink(format!(
                "socket(AF_NETLINK, NETLINK_GENERIC): errno {}",
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            )));
        }
        // Bind with pid 0 (kernel assigns).
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            unsafe { libc::close(fd) };
            return Err(FabricError::Netlink(format!(
                "bind(AF_NETLINK): errno {errno}"
            )));
        }
        Ok(Self { fd, seq: 0 })
    }

    /// Send one message, await its reply (or NAK) with a deadline.
    /// `msg_type` is patched into the nlmsghdr (family id or GENL_ID_CTRL).
    pub fn transact(
        &mut self,
        msg: &[u8],
        msg_type: u16,
        timeout: Duration,
    ) -> Result<Vec<u8>, FabricError> {
        self.seq = self.seq.wrapping_add(1);
        let mut out = msg.to_vec();
        out[4..6].copy_from_slice(&msg_type.to_le_bytes()); // nlmsg_type
        out[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_le_bytes()); // flags
        out[8..12].copy_from_slice(&self.seq.to_le_bytes()); // seq
        out[12..16].copy_from_slice(&0u32.to_le_bytes()); // pid

        let mut dest: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dest.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::sendto(
                self.fd,
                out.as_ptr() as *const libc::c_void,
                out.len(),
                0,
                &dest as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            return Err(FabricError::Netlink(format!(
                "sendto(netlink): errno {}",
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            )));
        }

        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; 8192];
        loop {
            if Instant::now() >= deadline {
                return Err(FabricError::ConnectTimeout(timeout));
            }
            // poll for readability with the remaining budget.
            let remaining_ms = deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as i32;
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, remaining_ms) };
            if prc == 0 {
                return Err(FabricError::ConnectTimeout(timeout));
            }
            if prc < 0 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                if errno == libc::EINTR {
                    continue;
                }
                return Err(FabricError::Netlink(format!(
                    "poll(netlink): errno {errno}"
                )));
            }
            let n =
                unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                continue; // spurious wakeup
            }
            let reply = &buf[..n as usize];
            // NLMSG_ERROR with error != 0 is a NAK; error == 0 is the ACK.
            if reply.len() >= 16 {
                let ty = u16::from_le_bytes([reply[0], reply[1]]);
                if ty == NLMSG_ERROR && reply.len() >= 20 {
                    let err = i32::from_le_bytes([reply[16], reply[17], reply[18], reply[19]]);
                    if err == 0 {
                        return Ok(reply[..n as usize].to_vec());
                    }
                    return Err(FabricError::Nak(format!(
                        "netlink error {err} ({})",
                        errno_label(err)
                    )));
                }
            }
            return Ok(reply.to_vec());
        }
    }
}

impl Drop for GenlSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn errno_label(err: i32) -> &'static str {
    match err {
        libc::ENOENT => "ENOENT (no such controller/attribute)",
        libc::EINVAL => "EINVAL (bad attribute combination)",
        libc::ECONNREFUSED => "ECONNREFUSED (fabric unreachable)",
        libc::ETIMEDOUT => "ETIMEDOUT",
        libc::EBUSY => "EBUSY (already connected)",
        _ => "unmapped errno",
    }
}

// ---------------------------------------------------------------------------
// Fabric URI
// ---------------------------------------------------------------------------

/// Supported NVMe-oF transports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FabricTransport {
    Tcp,
    Rdma,
    Fc,
    Loop,
}

impl FabricTransport {
    pub fn kernel_name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Rdma => "rdma",
            Self::Fc => "fc",
            Self::Loop => "loop",
        }
    }
}

impl fmt::Display for FabricTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kernel_name())
    }
}

/// Parsed fabric target: `nvme+tcp://traddr[:trsvcid]/nqn`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FabricTarget {
    pub transport: FabricTransport,
    pub traddr: String,
    pub trsvcid: String,
    pub nqn: String,
    pub host_traddr: Option<String>,
    pub kato_sec: Option<u32>,
    pub discovery: bool,
}

impl FabricTarget {
    /// Parse `nvme+tcp://10.0.0.5:4420/nqn.2014-08.org.example:sub1`.
    pub fn parse(uri: &str) -> Result<Self, FabricError> {
        let (scheme, rest) = uri
            .split_once("://")
            .ok_or_else(|| FabricError::Uri(format!("'{uri}': expected nvme+<transport>://...")))?;
        let transport = match scheme {
            "nvme+tcp" | "nvmf+tcp" => FabricTransport::Tcp,
            "nvme+rdma" | "nvmf+rdma" => FabricTransport::Rdma,
            "nvme+fc" | "nvmf+fc" => FabricTransport::Fc,
            "nvme+loop" => FabricTransport::Loop,
            other => {
                return Err(FabricError::Uri(format!(
                    "'{other}': unsupported scheme (expected nvme+tcp|rdma|fc|loop)"
                )));
            }
        };
        let (authority, nqn) = rest
            .split_once('/')
            .ok_or_else(|| FabricError::Uri(format!("'{uri}': missing /<nqn> path")))?;
        if !nqn.starts_with("nqn.") && !nqn.starts_with("discovery") {
            return Err(FabricError::Uri(format!(
                "'{nqn}': not an NVMe subsystem NQN"
            )));
        }
        let discovery = nqn == "discovery";
        let default_port = match transport {
            FabricTransport::Tcp => "4420",
            FabricTransport::Rdma => "4420",
            _ => "",
        };
        // Only TCP/RDMA carry a numeric trsvcid; FC addresses are
        // nn-0x...:pn-0x... (the colon is part of the traddr itself).
        let split_port = matches!(transport, FabricTransport::Tcp | FabricTransport::Rdma);
        let (addr, port) = if split_port {
            match authority.rsplit_once(':') {
                Some((a, p)) if !p.is_empty() => {
                    if !p.chars().all(|c| c.is_ascii_digit()) {
                        return Err(FabricError::Uri(format!("'{p}': trsvcid must be numeric")));
                    }
                    (a.to_string(), p.to_string())
                }
                _ => (authority.to_string(), default_port.to_string()),
            }
        } else {
            (authority.to_string(), default_port.to_string())
        };
        if addr.is_empty() && transport != FabricTransport::Loop {
            return Err(FabricError::Uri(format!("'{uri}': empty traddr")));
        }
        Ok(Self {
            transport,
            traddr: addr,
            trsvcid: port,
            nqn: nqn.to_string(),
            host_traddr: None,
            kato_sec: None,
            discovery,
        })
    }

    /// The pinned connect/disconnect attribute set for this target.
    pub fn connect_attrs(&self) -> Vec<(u16, Attr)> {
        let mut attrs = vec![
            (
                NVMF_ATTR_TRANSPORT,
                Attr::Str(self.transport.kernel_name().into()),
            ),
            (NVMF_ATTR_TRADDR, Attr::Str(self.traddr.clone())),
        ];
        if !self.trsvcid.is_empty() {
            attrs.push((NVMF_ATTR_TRSVCID, Attr::Str(self.trsvcid.clone())));
        }
        if let Some(host) = &self.host_traddr {
            attrs.push((NVMF_ATTR_HOST_TRADDR, Attr::Str(host.clone())));
        }
        attrs.push((NVMF_ATTR_NQN, Attr::Str(self.nqn.clone())));
        if self.discovery {
            attrs.push((NVMF_ATTR_DISCOVERY, Attr::Flag));
        }
        if let Some(kato) = self.kato_sec {
            attrs.push((NVMF_ATTR_KATO, Attr::U32(kato)));
        }
        attrs
    }
}

// ---------------------------------------------------------------------------
// Session orchestration
// ---------------------------------------------------------------------------

/// A live fabric session: connected, sanitizer-ready, disconnect on drop
/// semantics are the CALLER's duty (the purge path disconnects explicitly
/// so the certificate can record both timestamps).
pub struct FabricSession {
    pub target: FabricTarget,
    /// e.g. "nvme4" — the sysfs controller name that appeared.
    pub ctrl_name: String,
    /// /dev/nvme4 char device for admin passthrough.
    pub ctrl_char_dev: std::path::PathBuf,
    pub connected_at: Instant,
    /// Genl family id, retained for the disconnect call.
    pub family_id: u16,
}

/// Connect to a fabric target and wait for the controller to appear.
pub fn connect(
    target: &FabricTarget,
    timeouts: &FabricTimeouts,
) -> Result<FabricSession, FabricError> {
    let family_id = resolve_nvme_family_id()?;
    let mut sock = GenlSocket::open()?;
    let msg = build_genl_message(
        family_id,
        NVME_CMD_CONNECT,
        NVME_GENL_VERSION,
        &target.connect_attrs(),
    );
    let started = Instant::now();
    sock.transact(&msg, family_id, Duration::from_millis(timeouts.ack_ms))
        .map_err(|e| match e {
            FabricError::ConnectTimeout(t) => FabricError::Refusal(format!(
                "fabric CONNECT to {}://{} did not ACK within {t:?}",
                target.transport, target.traddr
            )),
            other => other,
        })?;

    // Wait for the controller to appear in sysfs, matching traddr + nqn.
    let deadline = started + Duration::from_millis(timeouts.ctrl_appear_ms);
    loop {
        if let Some(name) = scan_sysfs_for_controller(target)? {
            let ctrl_char_dev = std::path::PathBuf::from("/dev").join(&name);
            return Ok(FabricSession {
                target: target.clone(),
                ctrl_name: name,
                ctrl_char_dev,
                connected_at: started,
                family_id,
            });
        }
        if Instant::now() >= deadline {
            return Err(FabricError::CtrlTimeout(Duration::from_millis(
                timeouts.ctrl_appear_ms,
            )));
        }
        std::thread::sleep(Duration::from_millis(timeouts.poll_ms));
    }
}

/// Disconnect an existing controller (matched by transport/traddr/
/// trsvcid/nqn — the kernel finds the controller from the attributes).
pub fn disconnect(target: &FabricTarget, timeouts: &FabricTimeouts) -> Result<(), FabricError> {
    let family_id = resolve_nvme_family_id()?;
    disconnect_with_family(target, family_id, timeouts)
}

/// Disconnect using a pre-resolved genl family id (avoids a second
/// GETFAMILY round trip on the session teardown path).
pub fn disconnect_with_family(
    target: &FabricTarget,
    family_id: u16,
    timeouts: &FabricTimeouts,
) -> Result<(), FabricError> {
    let mut sock = GenlSocket::open()?;
    let msg = build_genl_message(
        family_id,
        NVME_CMD_DISCONNECT,
        NVME_GENL_VERSION,
        &target.connect_attrs(),
    );
    sock.transact(&msg, family_id, Duration::from_millis(timeouts.ack_ms))?;
    Ok(())
}

/// Scan /sys/class/nvme/nvmeX for a controller matching the target's
/// address and subsystem NQN (sysfs attributes `address` and `subsysnqn`).
pub fn scan_sysfs_for_controller(target: &FabricTarget) -> Result<Option<String>, FabricError> {
    let dir = std::fs::read_dir("/sys/class/nvme")
        .map_err(|e| FabricError::Sysfs(format!("/sys/class/nvme: {e}")))?;
    let mut candidates: Vec<(String, String)> = Vec::new();
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("nvme")
            || name.contains('n') && name.rfind("nvme") == Some(0) && name.len() > 4
        {
            // only controller dirs (nvmeN), not namespaces (nvmeNnM)
            if name[4..].contains('n') {
                continue;
            }
        }
        let sysfs = entry.path();
        let address = std::fs::read_to_string(sysfs.join("address")).unwrap_or_default();
        let subsysnqn = std::fs::read_to_string(sysfs.join("subsysnqn")).unwrap_or_default();
        let address = address.trim().to_string();
        let subsysnqn = subsysnqn.trim().to_string();
        candidates.push((
            name.clone(),
            format!("address={address} subsysnqn={subsysnqn}"),
        ));
        let addr_match = address.contains(&target.traddr)
            || (target.transport == FabricTransport::Loop && address.is_empty());
        if addr_match && subsysnqn == target.nqn {
            return Ok(Some(name));
        }
    }
    let _ = &candidates;
    Ok(None)
}

/// Textual proof for the certificate: everything the evidence needs about
/// the fabric hop.
pub fn session_record(session: &FabricSession, disconnected_at: Instant) -> String {
    let t = &session.target;
    format!(
        "fabric {}://{}:{} nqn={} ctrl={} connect_ms={} session_ms={}",
        t.transport,
        t.traddr,
        t.trsvcid,
        t.nqn,
        session.ctrl_name,
        0, // connect_ms recorded by the caller with its own clock
        disconnected_at
            .duration_since(session.connected_at)
            .as_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_parsing_covers_the_transport_matrix() {
        let t =
            FabricTarget::parse("nvme+tcp://10.0.0.5:4420/nqn.2014-08.org.example:sub1").unwrap();
        assert_eq!(t.transport, FabricTransport::Tcp);
        assert_eq!(t.traddr, "10.0.0.5");
        assert_eq!(t.trsvcid, "4420");
        assert_eq!(t.nqn, "nqn.2014-08.org.example:sub1");
        assert!(!t.discovery);

        // default port
        let t = FabricTarget::parse("nvme+rdma://172.16.0.9/nqn.2014-08.org.example:x").unwrap();
        assert_eq!(t.transport, FabricTransport::Rdma);
        assert_eq!(t.trsvcid, "4420");

        // FC: no port, nn-pn address
        let t = FabricTarget::parse(
            "nvme+fc://nn-0x200000109b57b1f9:pn-0x100000109b57b1f9/nqn.2014-08.org.example:fcsub",
        )
        .unwrap();
        assert_eq!(t.transport, FabricTransport::Fc);
        assert_eq!(t.trsvcid, "");
        assert!(!t.traddr.is_empty());

        // discovery NQN
        let t = FabricTarget::parse("nvme+tcp://10.0.0.5/discovery").unwrap();
        assert!(t.discovery);

        // rejections
        assert!(FabricTarget::parse("http://x/y").is_err());
        assert!(FabricTarget::parse("nvme+tcp://host").is_err());
        assert!(FabricTarget::parse("nvme+ib://host:1/nqn.x").is_err());
        assert!(FabricTarget::parse("nvme+tcp://host:NOTAPORT/nqn.x").is_err());
    }

    #[test]
    fn connect_attrs_are_the_pinned_wire_set() {
        let t = FabricTarget {
            transport: FabricTransport::Tcp,
            traddr: "10.0.0.5".into(),
            trsvcid: "4420".into(),
            nqn: "nqn.2014-08.org.example:sub1".into(),
            host_traddr: Some("10.0.0.1".into()),
            kato_sec: Some(30),
            discovery: false,
        };
        let attrs = t.connect_attrs();
        let names: Vec<u16> = attrs.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            names,
            vec![
                NVMF_ATTR_TRANSPORT,
                NVMF_ATTR_TRADDR,
                NVMF_ATTR_TRSVCID,
                NVMF_ATTR_HOST_TRADDR,
                NVMF_ATTR_NQN,
                NVMF_ATTR_KATO
            ]
        );
        // discovery adds the flag and drops nothing.
        let d = FabricTarget {
            discovery: true,
            ..t
        };
        let names: Vec<u16> = d.connect_attrs().iter().map(|(t, _)| *t).collect();
        assert!(names.contains(&NVMF_ATTR_DISCOVERY));
    }

    #[test]
    fn genl_message_layout_is_byte_pinned() {
        let attrs = [(NVMF_ATTR_TRANSPORT, Attr::Str("tcp".into()))];
        let msg = build_genl_message(0x0023, NVME_CMD_CONNECT, 1, &attrs);
        // nlmsghdr: len = total (u32), type = family, flags = 0 (patched on
        // send), genlmsghdr at offset 16.
        assert_eq!(&msg[0..4], &(msg.len() as u32).to_le_bytes());
        assert_eq!(&msg[4..6], &0x0023u16.to_le_bytes());
        assert_eq!(&msg[6..8], &0u16.to_le_bytes());
        // genlmsghdr at 16: cmd, version, 0 reserved.
        assert_eq!(msg[16], NVME_CMD_CONNECT);
        assert_eq!(msg[17], 1);
        assert_eq!(&msg[18..20], &[0, 0]);
        // first attr at 20: len = 4 + 4 ("tcp\0"), type = 1.
        let len = u16::from_le_bytes([msg[20], msg[21]]);
        assert_eq!(len, 8);
        let ty = u16::from_le_bytes([msg[22], msg[23]]);
        assert_eq!(ty, NVMF_ATTR_TRANSPORT);
        assert_eq!(&msg[24..28], b"tcp\0");
        // total length header must equal the buffer.
        let total = u16::from_le_bytes([msg[0], msg[1]]) as usize;
        assert_eq!(total, msg.len());
        // NLMSG_ALIGN(28) = 28.
        assert_eq!(msg.len(), 28);
    }

    #[test]
    fn family_id_parses_from_a_synthetic_reply() {
        // nlmsghdr(16) + genlmsghdr(4) + attr CTRL_ATTR_FAMILY_ID.
        let mut reply = vec![0u8; 20];
        reply.extend_from_slice(&6u16.to_le_bytes()); // attr len
        reply.extend_from_slice(&CTRL_ATTR_FAMILY_ID.to_le_bytes());
        reply.extend_from_slice(&0x0023u16.to_le_bytes());
        assert_eq!(parse_family_id(&reply), Some(0x23));
        // junk replies are None, not panics.
        assert_eq!(parse_family_id(&[0u8; 3]), None);
        assert_eq!(parse_family_id(&[0xFFu8; 48]), None);
    }

    #[test]
    fn netlink_socket_fails_clean_in_sandboxes() {
        // Opening NETLINK_GENERIC requires privileges in some sandboxes;
        // either way it must be a typed error, not a panic.
        match resolve_nvme_family_id() {
            Ok(_) => {} // host has genl: fine (family may still resolve)
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("netlink") || msg.contains("nlctrl") || msg.contains("errno"),
                    "unexpected error: {msg}"
                );
            }
        }
    }
}
