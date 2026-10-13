//! Pluggable transports: the real Linux raw-Ethernet socket and the
//! deterministic in-memory fabric.
//!
//! Two implementations back every dc-mesh deployment:
//!
//! * [`LinuxRawTransport`] — `AF_PACKET`/`SOCK_RAW` bound to the
//!   sanitization VLAN, filtered to EtherType `0x88B5` by the kernel
//!   (the `protocol` argument of `socket(2)`). Requires `CAP_NET_RAW`
//!   (see docs/SECURITY.md "capability policy"): this is the same
//!   privilege class the wipe engines already run under.
//! * [`VirtualLan`] — a store-and-forward virtual switch with
//!   deterministic delivery, optional frame loss, a full wire log,
//!   and a bandwidth cap for congestion drills. It powers every CI
//!   test, every `dc mesh simulate` drill, and never touches a real
//!   NIC. Frame contents are byte-identical to the wire format, so a
//!   bug found in simulation is a wire bug.

use crate::frame::{BROADCAST_MAC, EthFrame, Mac};
use crate::{ETHERTYPE_DC_MESH, MeshError};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

/// The interface between a mesh node and the fabric.
pub trait MeshTransport {
    /// This node's Ed25519 public key (identity on the wire).
    fn node_id(&self) -> [u8; 32];
    /// Interface MAC (stamped as the Ethernet source address).
    fn mac(&self) -> Mac;
    /// Send one signed L2 payload to a specific peer.
    fn send(&mut self, dst: Mac, payload: &[u8]) -> Result<(), MeshError>;
    /// Fan out to every node on the segment. Returns listener count.
    fn broadcast(&mut self, payload: &[u8]) -> Result<usize, MeshError> {
        self.send(BROADCAST_MAC, payload)?;
        Ok(0)
    }
    /// Receive one raw L2 payload (not yet signature-verified) plus
    /// the source MAC (used for peer routing, never for identity).
    /// Returns `None` on timeout; never blocks past the deadline.
    fn recv(&mut self, timeout_ms: u64) -> Result<Option<(Mac, Vec<u8>)>, MeshError>;
}

// ---------------------------------------------------------------------------
// Linux raw Ethernet transport (production path)
// ---------------------------------------------------------------------------

/// `AF_PACKET` raw-Ethernet transport for one interface.
///
/// # Safety & capability notes
///
/// * The socket is created with the DC-MESH ethertype as its protocol
///   filter, so the kernel hands us ONLY 0x88B5 frames — the node
///   never sees (or can be DoSed by) unrelated segment traffic.
/// * `SOCK_RAW` requires `CAP_NET_RAW`; the standard dc appliance
///   already grants this to the wipe user for the raw device paths.
/// * Frames we send carry our own interface MAC as source; identity
///   and authenticity come from the Ed25519 envelope signature, so
///   MAC spoofing on the segment is cryptographically irrelevant.
#[cfg(target_os = "linux")]
pub struct LinuxRawTransport {
    fd: i32,
    ifindex: u32,
    iface_mac: Mac,
    node: [u8; 32],
    recv_buf: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl LinuxRawTransport {
    /// Bind a raw 0x88B5 socket to `iface` (e.g. "san-vlan7").
    pub fn new(iface: &str, node: [u8; 32]) -> Result<Self, MeshError> {
        let ciface = std::ffi::CString::new(iface)
            .map_err(|e| MeshError::Transport(format!("interface name: {e}")))?;
        // SAFETY: ciface is a valid NUL-terminated string; if_nametoindex
        // does not retain the pointer.
        let ifindex = unsafe { libc::if_nametoindex(ciface.as_ptr()) };
        if ifindex == 0 {
            return Err(MeshError::Transport(format!(
                "interface {iface} does not exist (errno {})",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            )));
        }
        // SAFETY: plain socket() syscall with constant, valid arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (ETHERTYPE_DC_MESH as libc::c_int).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(MeshError::Transport(format!(
                "AF_PACKET socket (needs CAP_NET_RAW): {}",
                std::io::Error::last_os_error()
            )));
        }

        // Bind to the interface so we only see the sanitization segment.
        let sa = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: ETHERTYPE_DC_MESH.to_be(),
            sll_ifindex: ifindex as i32,
            sll_halen: 0,
            sll_pkttype: 0,
            sll_hatype: 0,
            sll_addr: [0; 8],
        };
        // SAFETY: `sa` outlives the call; sockaddr cast is the standard
        // POSIX sockets idiom.
        let rc = unsafe {
            libc::bind(
                fd,
                &sa as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            // SAFETY: fd is a live socket we own.
            unsafe { libc::close(fd) };
            return Err(MeshError::Transport(format!(
                "bind to {iface}: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Non-blocking-ish receive: 50 ms receive timeout slices so a
        // recv() deadline can be honored with a busy loop that also
        // drains cancellation.
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 50_000,
        };
        // SAFETY: fd is a live socket; tv is a valid timeval.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        // Interface MAC from sysfs (read-only, no ioctls).
        let mac_path = format!("/sys/class/net/{iface}/address");
        let mac_str = std::fs::read_to_string(&mac_path)
            .map_err(|e| MeshError::Transport(format!("read {mac_path}: {e}")))?;
        let iface_mac = parse_mac(mac_str.trim())
            .ok_or_else(|| MeshError::Transport(format!("bad MAC in {mac_path}")))?;

        Ok(Self {
            fd,
            ifindex,
            iface_mac,
            node,
            recv_buf: vec![0u8; 1514],
        })
    }

    fn iface_mac(&self) -> Mac {
        self.iface_mac
    }
}

#[cfg(target_os = "linux")]
impl MeshTransport for LinuxRawTransport {
    fn node_id(&self) -> [u8; 32] {
        self.node
    }

    fn mac(&self) -> Mac {
        self.iface_mac()
    }

    fn send(&mut self, dst: Mac, payload: &[u8]) -> Result<(), MeshError> {
        let frame = EthFrame {
            dst,
            payload: payload.to_vec(),
        }
        .to_bytes(self.iface_mac);
        let mut sa = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: ETHERTYPE_DC_MESH.to_be(),
            sll_ifindex: self.ifindex as i32,
            sll_halen: 6,
            sll_pkttype: 0,
            sll_hatype: 0,
            sll_addr: [0; 8],
        };
        sa.sll_addr[..6].copy_from_slice(&dst);
        // SAFETY: frame buffer and sockaddr are valid for the duration
        // of the syscall; sendto does not retain them.
        let rc = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                libc::MSG_NOSIGNAL,
                &sa as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(MeshError::Transport(format!(
                "sendto: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Option<(Mac, Vec<u8>)>, MeshError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            // SAFETY: recv_buf is preallocated at MTU+header size and
            // only written by the kernel; sockaddr is out-param storage.
            let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut salen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    self.fd,
                    self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                    self.recv_buf.len(),
                    0,
                    &mut sa as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                    &mut salen,
                )
            };
            if n >= 0 {
                let n = n as usize;
                if n > 14 {
                    let (src, _dst, payload) = EthFrame::parse(&self.recv_buf[..n])
                        .map_err(|e| MeshError::Transport(format!("wire parse: {e}")))?;
                    // Kernel may deliver our own broadcasts back to us.
                    if src == self.iface_mac {
                        continue;
                    }
                    return Ok(Some((src, payload.to_vec())));
                }
                continue;
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(None);
                    }
                    continue;
                }
                _ => return Err(MeshError::Transport(format!("recvfrom: {err}"))),
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxRawTransport {
    fn drop(&mut self) {
        // SAFETY: fd is a live socket owned by this object, dropped once.
        unsafe { libc::close(self.fd) };
    }
}

/// Parse "aa:bb:cc:dd:ee:ff" into a Mac.
pub fn parse_mac(s: &str) -> Option<Mac> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

// ---------------------------------------------------------------------------
// VirtualLan — deterministic simulation fabric (drills, CI, `dc mesh simulate`)
// ---------------------------------------------------------------------------

/// One node's inbox queue on the virtual fabric.
type Inbox = Rc<RefCell<VecDeque<(Mac, Vec<u8>)>>>;

struct LanInner {
    /// Registered node queues, keyed by virtual MAC.
    queues: Vec<(Mac, Inbox)>,
    /// Pending (src, dst, payload) triples awaiting delivery on tick.
    wire: Vec<(Mac, Mac, Vec<u8>)>,
    /// Every frame ever transmitted, in order (audit log).
    sent_log: Vec<(Mac, Mac, Vec<u8>)>,
    /// Deliveries performed so far (for liveness assertions).
    deliveries: usize,
    /// Deterministic loss: drop every Nth frame (2 = lose half).
    drop_every: Option<u32>,
    /// Seen frame counter for deterministic loss placement.
    frame_seq: u32,
}

/// A deterministic, in-memory L2 fabric.
///
/// Frames sent by a NIC are NOT delivered immediately: they sit on the
/// wire until [`VirtualLan::tick`] is called, which delivers every
/// pending frame in transmission order. A driver that steps nodes in a
/// fixed order and ticks between rounds gets fully reproducible runs —
/// same seed, same rogue behavior, same certificate bytes.
#[derive(Clone)]
pub struct VirtualLan {
    inner: Rc<RefCell<LanInner>>,
}

impl Default for VirtualLan {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualLan {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(LanInner {
                queues: Vec::new(),
                wire: Vec::new(),
                sent_log: Vec::new(),
                deliveries: 0,
                drop_every: None,
                frame_seq: 0,
            })),
        }
    }

    /// Deterministic loss injection: every Nth transmitted frame is
    /// silently dropped by the fabric (N=2 loses half).
    pub fn with_drop_every(self, n: u32) -> Self {
        self.inner.borrow_mut().drop_every = Some(n.max(2));
        self
    }

    /// Attach a fresh NIC (new virtual MAC, inbox queue) to the fabric.
    pub fn join(&self) -> VirtualNic {
        let mac: Mac = {
            let inner = self.inner.borrow_mut();
            let n = inner.queues.len() as u8;
            // Locally administered, unicast range.
            [0x02, 0xDC, 0x13, 0x00, 0x00, n]
        };
        let queue: Inbox = Rc::new(RefCell::new(VecDeque::new()));
        self.inner.borrow_mut().queues.push((mac, queue.clone()));
        VirtualNic {
            mac,
            node: [0u8; 32], // set by owner via `for_node`
            queue,
            lan: self.clone(),
        }
    }

    /// Deliver all pending frames. Broadcast frames reach every queue
    /// except the sender's; unicast only the matching MAC. Deterministic
    /// drop injection happens here, before delivery.
    pub fn tick(&self) {
        let mut inner = self.inner.borrow_mut();
        let pending: Vec<(Mac, Mac, Vec<u8>)> = std::mem::take(&mut inner.wire);
        for (src, dst, payload) in pending {
            inner.deliveries += 1;
            if let Some(n) = inner.drop_every
                && inner.deliveries.is_multiple_of(n as usize)
            {
                continue; // frame lost in the fabric
            }
            let targets: Vec<_> = inner
                .queues
                .iter()
                .filter(|(m, _)| (dst == BROADCAST_MAC && *m != src) || *m == dst)
                .map(|(_, q)| q.clone())
                .collect();
            for q in targets {
                q.borrow_mut().push_back((src, payload.clone()));
            }
        }
    }

    /// Total frames transmitted on the fabric so far.
    pub fn transmitted(&self) -> usize {
        self.inner.borrow().sent_log.len()
    }

    /// Total deliveries completed (post-loss).
    pub fn deliveries(&self) -> usize {
        self.inner.borrow().deliveries
    }
}

/// One attached interface on the [`VirtualLan`].
pub struct VirtualNic {
    mac: Mac,
    node: [u8; 32],
    queue: Inbox,
    lan: VirtualLan,
}

impl VirtualNic {
    /// Bind this NIC to a node identity (for debug output only —
    /// authenticity is enforced by frame signatures).
    pub fn for_node(mut self, node: [u8; 32]) -> Self {
        self.node = node;
        self
    }
}

impl MeshTransport for VirtualNic {
    fn node_id(&self) -> [u8; 32] {
        self.node
    }

    fn mac(&self) -> Mac {
        self.mac
    }

    fn send(&mut self, dst: Mac, payload: &[u8]) -> Result<(), MeshError> {
        let mut inner = self.lan.inner.borrow_mut();
        inner.frame_seq += 1;
        inner.wire.push((self.mac, dst, payload.to_vec()));
        inner.sent_log.push((self.mac, dst, payload.to_vec()));
        Ok(())
    }

    fn broadcast(&mut self, payload: &[u8]) -> Result<usize, MeshError> {
        let listeners = {
            let inner = self.lan.inner.borrow();
            inner.queues.len().saturating_sub(1)
        };
        self.send(BROADCAST_MAC, payload)?;
        Ok(listeners)
    }

    fn recv(&mut self, _timeout_ms: u64) -> Result<Option<(Mac, Vec<u8>)>, MeshError> {
        // Simulation has no wall clock: non-blocking drain.
        Ok(self.queue.borrow_mut().pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_lan_broadcast_and_unicast() {
        let lan = VirtualLan::new();
        let a = lan.join().for_node([1u8; 32]);
        let mut b = lan.join().for_node([2u8; 32]);
        let mut c = lan.join().for_node([3u8; 32]);

        let mut a = a;
        a.send(BROADCAST_MAC, b"hello-all").expect("send");
        lan.tick();

        let (_m1, p1) = b.recv(0).expect("recv").expect("frame");
        assert_eq!(p1, b"hello-all".to_vec());
        let (_m2, p2) = c.recv(0).expect("recv").expect("frame");
        assert_eq!(p2, b"hello-all".to_vec());

        // Unicast only reaches the target.
        b.send(c.mac(), b"secret").expect("send");
        lan.tick();
        let (src, payload) = c.recv(0).expect("recv").expect("frame");
        assert_eq!(payload, b"secret".to_vec());
        assert_eq!(src, b.mac());
        assert_eq!(a.recv(0).expect("recv"), None);
    }

    #[test]
    fn deterministic_loss_injection() {
        let lan = VirtualLan::new().with_drop_every(2);
        let mut a = lan.join();
        let mut b = lan.join();

        for i in 0..4 {
            a.send(b.mac(), format!("f{i}").as_bytes()).expect("send");
            lan.tick();
        }
        // Every 2nd DELIVERY is dropped: deliveries 2 and 4 (frames
        // f1 and f3) never reach the inbox.
        let got: Vec<Vec<u8>> =
            std::iter::from_fn(|| b.recv(0).expect("recv").map(|(_, p)| p)).collect();
        assert_eq!(got, vec![b"f0".to_vec(), b"f2".to_vec()]);
    }

    #[test]
    fn parse_mac_roundtrip() {
        assert_eq!(
            parse_mac("02:dc:13:00:00:07"),
            Some([0x02, 0xDC, 0x13, 0x00, 0x00, 0x07])
        );
        assert_eq!(parse_mac("nope"), None);
        assert_eq!(parse_mac("02:dc:13:00:00"), None);
    }
}
