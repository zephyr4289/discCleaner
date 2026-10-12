//! dc-iscsi — native iSCSI initiator for remote block-target sanitization
//! (v0.9.0, Phase 4 — Storage Protocol Expansion).
//!
//! Completes the remote block storage picture alongside the NVMe-oF stack
//! (`dc-nvme::fabrics`): target discovery, session login and SCSI command
//! passthrough spoken directly over TCP (RFC 3720), with zero dynamic
//! linking and no external initiator stack (no open-iscsi, no kernel
//! iSCSI transport required for the SANITIZE path).
//!
//! What this crate carries:
//! - **Discovery**: a SessionType=Discovery login followed by
//!   `SendTargets=All` — the full target/LUN inventory of a portal,
//!   parsed from RFC 3720 `TargetName=`/`TargetAddress=` text responses.
//! - **Operational login**: parameter negotiation (no digests, no auth —
//!   intranet SAN assumption identical to the NVMe-oF in-band path) up to
//!   the Full Feature Phase.
//! - **SCSI passthrough**: RFC 3720 SCSI Command PDUs wrapping the
//!   dc-hw codec CDBs (SANITIZE / FORMAT UNIT / INQUIRY / REQUEST SENSE),
//!   with Response + Data-IN reassembly and deadline-guarded reads —
//!   a wedged target fails the purge path in seconds, never hangs a
//!   lights-out run.
//!
//! Safety posture: every destructive verb requires the CLI layer's
//! explicit arming flag; the transport itself never issues any CDB it was
//! not handed.

pub mod bhs;
pub mod login;
pub mod scsi;
pub mod session;

pub use bhs::{Bhs, Pdu, read_pdu, write_pdu};
pub use login::{LoginNegotiator, TextParam};
pub use scsi::{ScsiIoOutcome, ScsiIoParams};
pub use session::{DiscoveredTarget, IscsiSession, Portal};

/// Errors of the iSCSI initiator stack.
#[derive(Debug, thiserror::Error)]
pub enum IscsiError {
    #[error("iSCSI TCP transport: {0}")]
    Transport(String),
    #[error("iSCSI read deadline of {0:?} exceeded — target wedged or network partition")]
    Timeout(std::time::Duration),
    #[error("iSCSI wire protocol violation: {0}")]
    Protocol(String),
    #[error("iSCSI login refused (class {class}, detail {detail}): {message}")]
    LoginRefused {
        class: u8,
        detail: u8,
        message: String,
    },
    #[error("iSCSI target refusal: {0}")]
    Refused(String),
    #[error("portal address invalid: {0}")]
    BadPortal(String),
}

impl IscsiError {
    /// Poll(2) deadline guard shared with the TPM transport philosophy.
    pub fn from_io(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
            Self::Timeout(std::time::Duration::from_secs(0))
        } else {
            Self::Transport(e.to_string())
        }
    }
}

/// Default TCP deadlines (mirrors `dc-nvme::fabrics::FabricTimeouts`).
#[derive(Clone, Copy, Debug)]
pub struct IscsiTimeouts {
    /// Per-read deadline for login/text exchanges.
    pub login_ms: u64,
    /// Per-read deadline for SCSI responses (sanitizes are slow to
    /// ACK with IMMED, so only the wire wait is bounded).
    pub scsi_ms: u64,
}

impl Default for IscsiTimeouts {
    fn default() -> Self {
        Self {
            login_ms: 10_000,
            scsi_ms: 30_000,
        }
    }
}
