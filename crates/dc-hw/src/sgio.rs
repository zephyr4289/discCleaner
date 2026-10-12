//! Linux SG_IO ioctl passthrough transport (v0.6.0).
//!
//! The one real door every non-NVMe controller command walks through:
//! `ioctl(fd, SG_IO, &hdr)` against the block device node itself
//! (`/dev/sda`, `/dev/sdb`, ...). SATA drives are addressed through SAT
//! (ATA PASS-THROUGH 12/16 CDBs, `dc_hw::AtaCodec`) and SAS/SCSI drives
//! through native SCSI CDBs (`dc_hw::ScsiCodec`); both ride this transport.
//!
//! Design notes:
//! - The block node is used deliberately; `/dev/sg*` character nodes are
//!   the UNCOVERED DOOR refused by `dc-scsi` (Δ330): opening a second node
//!   for the same LUN bypasses O_EXCL arming. SG_IO on the block node keeps
//!   every controller command observable on the SAME fd the Guardian
//!   locked.
//! - The sense buffer is always captured: SAT bridges return ATA status via
//!   descriptor-format sense data, and SCSI sanitize progress is reported
//!   through sense key 0x02 / ASC 0x04 with the SKS progress field.
//! - Timeouts are explicit and generous: firmware purges legitimately run
//!   for hours; the caller picks the budget, never a hidden default.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;

/// `SG_IO` ioctl request number (linux/scsi/sg.h).
pub const SG_IO_IOCTL: libc::c_ulong = 0x2285;
/// `SG_DXFER_NONE` — no data phase (non-data commands).
pub const SG_DXFER_NONE: i32 = -1;
/// `SG_DXFER_TO_DEV` — data-out (host -> device payload).
pub const SG_DXFER_TO_DEV: i32 = -2;
/// `SG_DXFER_FROM_DEV` — data-in (device -> host payload).
pub const SG_DXFER_FROM_DEV: i32 = -3;

/// Default sense buffer length (52 bytes covers fixed + descriptor forms
/// including the 12-byte SAT ATA return descriptor plus overhead).
pub const SENSE_BUFFER_LEN: usize = 64;

/// Maximum accepted CDB length (SCSI-3 primary commands allow 6/10/12/16).
pub const MAX_CDB_LEN: usize = 16;

/// Repr-C mirror of `struct sg_io_hdr` (linux/scsi/sg.h). Field order and
/// types are ABI; do not reorder.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SgIoHdr {
    pub interface_id: i32,    // 'S' for SCSI generic
    pub dxfer_direction: i32, // SG_DXFER_*
    pub cmd_len: u8,
    pub mx_sb_len: u8,
    pub iovec_count: u16,
    pub dxfer_len: u32,
    pub dxferp: u64,  // void*
    pub cmdp: u64,    // void*
    pub sbp: u64,     // void*
    pub timeout: u32, // milliseconds
    pub flags: u32,
    pub pack_id: i32,
    pub usr_ptr: u64,
    pub status: u8, // SCSI status byte
    pub masked_status: u8,
    pub msg_status: u8,
    pub sb_len_wr: u8,
    pub host_status: u16,
    pub driver_status: u16,
    pub resid: i32,
    pub duration: u32,
    pub info: u32,
}

impl Default for SgIoHdr {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl SgIoHdr {
    /// All-zero header with the interface id set (the only field the kernel
    /// demands pre-initialized).
    pub fn zeroed() -> Self {
        Self {
            interface_id: b'S' as i32,
            dxfer_direction: SG_DXFER_NONE,
            cmd_len: 0,
            mx_sb_len: 0,
            iovec_count: 0,
            dxfer_len: 0,
            dxferp: 0,
            cmdp: 0,
            sbp: 0,
            timeout: 0,
            flags: 0,
            pack_id: 0,
            usr_ptr: 0,
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        }
    }
}

/// Result of one SG_IO execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SgIoResult {
    /// SCSI status byte (0x00 = GOOD, 0x02 = CHECK CONDITION, ...).
    pub status: u8,
    /// Sense bytes actually written (may be empty on GOOD).
    pub sense: Vec<u8>,
    /// Data-in payload (empty unless direction was FROM_DEV).
    pub data_in: Vec<u8>,
    /// Residual transfer bytes (SG resid).
    pub resid: u32,
    /// Kernel-reported duration in milliseconds.
    pub duration_ms: u32,
}

impl SgIoResult {
    /// SCSI GOOD status, no sense.
    pub fn is_good(&self) -> bool {
        self.status == 0x00
    }

    /// CHECK CONDITION with sense data present.
    pub fn is_check_condition(&self) -> bool {
        self.status == 0x02 && !self.sense.is_empty()
    }
}

/// Errors classified the same way operators reason about them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SgIoError {
    /// Device node could not be opened (permissions, missing node).
    Open { path: String, errno: i32 },
    /// The ioctl itself failed.
    Ioctl { errno: i32 },
    /// CDB longer than the transport accepts.
    CdbTooLong { len: usize },
    /// Adapter/device reported a host error.
    HostStatus { code: u16, description: String },
    /// Driver-level error (e.g. DID_ERROR).
    DriverStatus { code: u16, description: String },
}

impl std::fmt::Display for SgIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { path, errno } => write!(
                f,
                "cannot open '{}' for SG_IO passthrough: {} (errno {})",
                path,
                errno_description(*errno),
                errno
            ),
            Self::Ioctl { errno } => {
                write!(
                    f,
                    "SG_IO ioctl failed: {} (errno {})",
                    errno_description(*errno),
                    errno
                )
            }
            Self::CdbTooLong { len } => {
                write!(
                    f,
                    "CDB length {} exceeds the {}-byte SG_IO maximum",
                    len, MAX_CDB_LEN
                )
            }
            Self::HostStatus { code, description } => {
                write!(f, "SCSI host status 0x{:04X}: {}", code, description)
            }
            Self::DriverStatus { code, description } => {
                write!(f, "SCSI driver status 0x{:04X}: {}", code, description)
            }
        }
    }
}

impl std::error::Error for SgIoError {}

fn errno_description(errno: i32) -> &'static str {
    match errno {
        libc::EACCES | libc::EPERM => "permission denied (run as root?)",
        libc::ENOENT => "device node does not exist",
        libc::ENOTTY => "node does not accept SG_IO (not a SCSI/ATA device?)",
        libc::EBUSY => "device is busy (held by another exclusive opener?)",
        libc::EINVAL => "invalid request structure",
        libc::EIO => "I/O error",
        libc::ETIMEDOUT => "command timed out",
        _ => "unclassified error",
    }
}

/// An open block-device node through which controller CDBs are issued.
///
/// One fd, one LUN: the node opened here should be the same path the
/// Guardian locked O_EXCL; the struct deliberately does not implement
/// `Clone` so the fd cannot silently multiply across threads.
pub struct SgIoDevice {
    dev: File,
    path: String,
}

impl SgIoDevice {
    /// Open the block node read/write for SG_IO passthrough. Character
    /// `/dev/sg*` and `/dev/bsg*` nodes are refused — they are the
    /// second-door problem (Δ330 / REG-SCSI-SG-NODE).
    pub fn open_block_node(path: &Path) -> Result<Self, SgIoError> {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.starts_with("sg") || path.to_string_lossy().contains("bsg") {
            return Err(SgIoError::Open {
                path: path.display().to_string(),
                errno: libc::EACCES,
            });
        }
        let dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| SgIoError::Open {
                path: path.display().to_string(),
                errno: e.raw_os_error().unwrap_or(-1),
            })?;
        Ok(Self {
            dev,
            path: path.display().to_string(),
        })
    }

    /// Path this transport is bound to (evidence provenance).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Issue one CDB. `direction` is one of `SG_DXFER_*`; `payload` is the
    /// data-out buffer for TO_DEV (read as-is, its length sets dxfer_len)
    /// and the pre-allocated data-in buffer for FROM_DEV (its length sets
    /// dxfer_len; returned data is truncated to dxfer_len - resid).
    pub fn execute(
        &mut self,
        cdb: &[u8],
        direction: i32,
        payload: &mut [u8],
        timeout_ms: u32,
    ) -> Result<SgIoResult, SgIoError> {
        if cdb.len() > MAX_CDB_LEN || cdb.is_empty() {
            return Err(SgIoError::CdbTooLong { len: cdb.len() });
        }

        let mut cmd_buf = [0u8; MAX_CDB_LEN];
        cmd_buf[..cdb.len()].copy_from_slice(cdb);
        let mut sense_buf = [0u8; SENSE_BUFFER_LEN];

        let mut hdr = SgIoHdr::zeroed();
        hdr.dxfer_direction = if payload.is_empty() && direction != SG_DXFER_NONE {
            // A FROM/TO request with a zero-length buffer is a non-data
            // phase; normalize so the kernel never sees a mismatch.
            SG_DXFER_NONE
        } else {
            direction
        };
        hdr.cmd_len = cdb.len() as u8;
        hdr.mx_sb_len = SENSE_BUFFER_LEN as u8;
        hdr.dxfer_len = payload.len() as u32;
        hdr.cmdp = cmd_buf.as_mut_ptr() as u64;
        hdr.sbp = sense_buf.as_mut_ptr() as u64;
        hdr.dxferp = if payload.is_empty() {
            0
        } else {
            payload.as_mut_ptr() as u64
        };
        hdr.timeout = timeout_ms;

        let rc =
            unsafe { libc::ioctl(self.dev.as_raw_fd(), SG_IO_IOCTL, &mut hdr as *mut SgIoHdr) };
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            // A CHECK CONDITION is reported via sense data, not a failed
            // ioctl; a real ioctl failure is a transport fault.
            return Err(SgIoError::Ioctl { errno });
        }

        // Host/driver level failures are hard errors even when status
        // looks GOOD (a bridged SAT layer that lies still cannot fake
        // DID_OK with a hung command).
        const DID_OK: u16 = 0x00;
        const DID_NO_CONNECT: u16 = 0x01;
        const DID_BUS_BUSY: u16 = 0x04;
        const DID_TIME_OUT: u16 = 0x06;
        const DID_ERROR: u16 = 0x07;
        const DRIVER_OK: u16 = 0x00;
        const DRIVER_SENSE: u16 = 0x08; // sense valid — NOT an error
        if hdr.host_status != DID_OK && hdr.host_status != DID_NO_CONNECT
        // transient link reset, surface as-is
        {
            let description = match hdr.host_status {
                DID_BUS_BUSY => "adapter busy".to_string(),
                DID_TIME_OUT => "command timed out at the adapter".to_string(),
                DID_ERROR => "adapter reported an error".to_string(),
                code => format!("unclassified host status 0x{:04X}", code),
            };
            return Err(SgIoError::HostStatus {
                code: hdr.host_status,
                description,
            });
        }
        if (hdr.driver_status & !DRIVER_SENSE) != DRIVER_OK {
            return Err(SgIoError::DriverStatus {
                code: hdr.driver_status,
                description: format!("driver status 0x{:04X}", hdr.driver_status),
            });
        }

        let sense = sense_buf[..hdr.sb_len_wr as usize].to_vec();
        let data_in = if direction == SG_DXFER_FROM_DEV && !payload.is_empty() {
            let delivered = (hdr.dxfer_len as i64 - hdr.resid as i64).max(0) as usize;
            payload[..delivered.min(payload.len())].to_vec()
        } else {
            Vec::new()
        };

        Ok(SgIoResult {
            status: hdr.status,
            sense,
            data_in,
            resid: hdr.resid.max(0) as u32,
            duration_ms: hdr.duration,
        })
    }

    /// Convenience: issue a non-data CDB.
    pub fn execute_non_data(
        &mut self,
        cdb: &[u8],
        timeout_ms: u32,
    ) -> Result<SgIoResult, SgIoError> {
        self.execute(cdb, SG_DXFER_NONE, &mut [], timeout_ms)
    }

    /// Convenience: issue a data-in CDB with an exact-size receive buffer.
    pub fn execute_data_in(
        &mut self,
        cdb: &[u8],
        expected_len: usize,
        timeout_ms: u32,
    ) -> Result<SgIoResult, SgIoError> {
        let mut buf = vec![0u8; expected_len];
        self.execute(cdb, SG_DXFER_FROM_DEV, &mut buf, timeout_ms)
    }

    /// Convenience: issue a data-out CDB carrying `payload`.
    pub fn execute_data_out(
        &mut self,
        cdb: &[u8],
        payload: &[u8],
        timeout_ms: u32,
    ) -> Result<SgIoResult, SgIoError> {
        let mut buf = payload.to_vec();
        self.execute(cdb, SG_DXFER_TO_DEV, &mut buf, timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_matches_kernel_abi() {
        // 88 bytes on 64-bit Linux: the sg_io_hdr struct size is ABI.
        // If this fires, the repr/field order drifted — do not "fix" the
        // test, fix the struct.
        assert_eq!(std::mem::size_of::<SgIoHdr>(), 88);
        assert_eq!(std::mem::align_of::<SgIoHdr>(), 8);
        assert_eq!(SgIoHdr::zeroed().interface_id, b'S' as i32);
    }

    #[test]
    fn character_nodes_are_refused_at_open() {
        // REG-SCSI-SG-NODE discipline applies to the raw transport too.
        assert!(SgIoDevice::open_block_node(Path::new("/dev/sg0")).is_err());
        assert!(SgIoDevice::open_block_node(Path::new("/dev/bsg/1:0:0:0")).is_err());
        // A missing block node fails with an Open error, not a panic.
        match SgIoDevice::open_block_node(Path::new("/dev/nonexistent-sdz")) {
            Err(SgIoError::Open { .. }) => {}
            other => panic!("expected Open error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn cdb_length_is_enforced() {
        // /dev/null opens fine but is not a SCSI device; length validation
        // happens before the ioctl, so it must trip first regardless.
        if let Ok(mut d) = SgIoDevice::open_block_node(Path::new("/dev/null")) {
            let long_cdb = [0u8; 17];
            assert!(matches!(
                d.execute(&long_cdb, SG_DXFER_NONE, &mut [], 1000),
                Err(SgIoError::CdbTooLong { len: 17 })
            ));
            let empty: [u8; 0] = [];
            assert!(matches!(
                d.execute(&empty, SG_DXFER_NONE, &mut [], 1000),
                Err(SgIoError::CdbTooLong { len: 0 })
            ));
        }
    }
}
