//! USB CCID card transport over Linux usbfs — the physical door to the
//! secure element (v0.7.0, Vector 1).
//!
//! No PKCS#11 shared library is ever loaded (that is the supply-chain door
//! the design refuses to open): the CCID bulk protocol (USB ICC rev 1.1)
//! and the PIV applet (SP 800-73-4) are spoken directly over ioctls on
//! `/dev/bus/usb/<bus>/<dev>`, in the same bounded-unsafe style as the
//! SG_IO and NVMe admin passthrough transports.
//!
//! Kernel interface (linux/usbdevice_fs.h, frozen UAPI):
//! - `USBDEVFS_CLAIMINTERFACE` 0x8004550F — exclusive interface claim.
//! - `USBDEVFS_RELEASEINTERFACE` 0x80045510 — release on drop.
//! - `USBDEVFS_BULK` 0xC0185502 — synchronous bulk transfer.
//!
//! CCID framing (USB-IF CCID rev 1.1):
//! - Host -> reader: `PC_to_RDR_IccPowerOn` (0x62), `PC_to_RDR_XfrBlock`
//!   (0x6F) carrying one ISO 7816 APDU.
//! - Reader -> host: `RDR_to_PC_DataBlock` (0x80) carrying the response,
//!   `RDR_to_PC_SlotStatus` (0x81), `RDR_to_PC_Parameters` (0x82).

use crate::iso7816::{CommandApdu, Iso7816Transport, ResponseApdu};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// `USBDEVFS_CLAIMINTERFACE` — `_IOR('U', 15, unsigned int)`.
const USBDEVFS_CLAIMINTERFACE: libc::c_ulong = 0x8004550F;
/// `USBDEVFS_RELEASEINTERFACE` — `_IOR('U', 16, unsigned int)`.
const USBDEVFS_RELEASEINTERFACE: libc::c_ulong = 0x80045510;
/// `USBDEVFS_BULK` — `_IOWR('U', 2, struct usbdevfs_bulktransfer)` where
/// the struct is `{ u32 ep; u32 len; u32 timeout; void* data; }` = 24 bytes
/// on LP64 (4-byte tail padding before the pointer).
const USBDEVFS_BULK: libc::c_ulong = 0xC0185502;

/// CCID message types we exchange (host -> reader).
const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
/// CCID message types (reader -> host).
const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;

/// Bulk endpoint directions (interface-relative).
const EP_DIR_IN: u8 = 0x80;

/// A CCID interface discovered on the USB bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CcidEndpoint {
    /// Char-device node: `/dev/bus/usb/<bus>/<dev>`.
    pub device_node: PathBuf,
    /// `bInterfaceNumber` of the CCID interface.
    pub interface: u32,
    /// Bulk OUT endpoint address (host -> reader).
    pub bulk_out_ep: u8,
    /// Bulk IN endpoint address (reader -> host).
    pub bulk_in_ep: u8,
    /// Sysfs identity: idVendor.
    pub id_vendor: u16,
    /// Sysfs identity: idProduct.
    pub id_product: u16,
    /// USB iSerial (reader serial), when published.
    pub serial: Option<String>,
}

/// Errors of the usbfs layer, errno-first like the other transports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CcidError {
    Open {
        path: String,
        errno: i32,
    },
    Claim {
        interface: u32,
        errno: i32,
    },
    Bulk {
        direction: &'static str,
        errno: i32,
        ep: u8,
    },
    /// Reader returned a CCID error status byte (bError != 0).
    ReaderStatus {
        message_type: u8,
        slot: u8,
        error: u8,
    },
    /// Reader response shorter than the 10-byte CCID header.
    Truncated {
        got: usize,
    },
    /// Reader answered a different message type than the request.
    UnexpectedResponse {
        expected: u8,
        got: u8,
    },
    /// ICC absent from the slot.
    IccAbsent,
}

impl std::fmt::Display for CcidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { path, errno } => {
                write!(f, "cannot open usb node '{}': errno {}", path, errno)
            }
            Self::Claim { interface, errno } => {
                write!(
                    f,
                    "cannot claim CCID interface {}: errno {}",
                    interface, errno
                )
            }
            Self::Bulk {
                direction,
                errno,
                ep,
            } => write!(
                f,
                "bulk {} transfer failed on endpoint 0x{:02X}: errno {}",
                direction, ep, errno
            ),
            Self::ReaderStatus {
                message_type,
                slot,
                error,
            } => write!(
                f,
                "reader status error (message 0x{:02X}, slot {}, bError 0x{:02X})",
                message_type, slot, error
            ),
            Self::Truncated { got } => write!(f, "CCID response shorter than header: {}", got),
            Self::UnexpectedResponse { expected, got } => write!(
                f,
                "reader answered message 0x{:02X}, expected 0x{:02X}",
                got, expected
            ),
            Self::IccAbsent => write!(f, "no ICC (smart card) present in the reader slot"),
        }
    }
}

/// Repr-C mirror of `struct usbdevfs_bulktransfer` (field order is UAPI).
#[repr(C)]
#[derive(Clone, Copy)]
struct UsbBulkTransfer {
    ep: u32,
    len: u32,
    timeout: u32,
    data: *mut u8,
}

/// Encode a PC_to_RDR message: 10-byte header + payload.
fn encode_rdr(message_type: u8, slot: u8, seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.push(message_type);
    out.push(0x00); // dwLength (4 bytes, LE) — filled next
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    out.push(slot);
    out.push(seq);
    out.push(0x00); // bBWI
    out.extend_from_slice(&[0, 0]); // wLevelParameter
    let len = payload.len() as u32;
    out[1..5].copy_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// ICC status (RDR_to_PC bStatus bits 1:0): 0b10 = no ICC.
const ICC_NOT_PRESENT: u8 = 0x02;

/// Decode a RDR_to_PC message: header + payload, carrying the ICC status.
struct RdrMessage {
    message_type: u8,
    slot: u8,
    /// bStatus (byte 7): command status in bits 7:6, ICC status in 1:0.
    status: u8,
    /// bError (byte 8): valid when the command status is failed.
    error: u8,
    payload: Vec<u8>,
}

impl RdrMessage {
    fn icc_not_present(&self) -> bool {
        self.status & 0x03 == ICC_NOT_PRESENT
    }

    fn command_failed(&self) -> bool {
        // Command status (bits 7:6): 01 = failed, 10 = time extension.
        (self.status >> 6) & 0x01 != 0
    }
}

fn decode_rdr(raw: &[u8]) -> Result<RdrMessage, CcidError> {
    if raw.len() < 10 {
        return Err(CcidError::Truncated { got: raw.len() });
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&raw[1..5]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    Ok(RdrMessage {
        message_type: raw[0],
        slot: raw[5],
        status: raw[7],
        error: raw[8],
        payload: raw[10.min(raw.len())..(10 + len).min(raw.len())].to_vec(),
    })
}

/// An open CCID interface: usb node claimed, APDUs tunneled through
/// `PC_to_RDR_XfrBlock`.
pub struct CcidCardTransport {
    dev: File,
    path: PathBuf,
    interface: u32,
    bulk_out_ep: u8,
    bulk_in_ep: u8,
    seq: u8,
}

impl CcidCardTransport {
    /// Open and claim the CCID interface of a discovered endpoint.
    pub fn open(endpoint: &CcidEndpoint) -> Result<Self, CcidError> {
        let dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&endpoint.device_node)
            .map_err(|e| CcidError::Open {
                path: endpoint.device_node.display().to_string(),
                errno: e.raw_os_error().unwrap_or(-1),
            })?;
        let mut transport = Self {
            dev,
            path: endpoint.device_node.clone(),
            interface: endpoint.interface,
            bulk_out_ep: endpoint.bulk_out_ep,
            bulk_in_ep: endpoint.bulk_in_ep,
            seq: 0,
        };
        transport.claim()?;
        transport.power_on_icc()?;
        Ok(transport)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn claim(&self) -> Result<(), CcidError> {
        let iface = self.interface;
        let rc = unsafe {
            libc::ioctl(
                self.dev.as_raw_fd(),
                USBDEVFS_CLAIMINTERFACE,
                &iface as *const u32,
            )
        };
        if rc != 0 {
            return Err(CcidError::Claim {
                interface: self.interface,
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            });
        }
        Ok(())
    }

    /// `PC_to_RDR_IccPowerOn`: bring the ICC up before the first exchange.
    fn power_on_icc(&mut self) -> Result<(), CcidError> {
        let msg = encode_rdr(PC_TO_RDR_ICC_POWER_ON, 0x00, self.next_seq(), &[]);
        let raw = self.bulk_roundtrip(&msg)?;
        let reply = decode_rdr(&raw)?;
        if reply.message_type != RDR_TO_PC_SLOT_STATUS && reply.message_type != RDR_TO_PC_DATA_BLOCK
        {
            return Err(CcidError::UnexpectedResponse {
                expected: RDR_TO_PC_SLOT_STATUS,
                got: reply.message_type,
            });
        }
        if reply.icc_not_present() {
            return Err(CcidError::IccAbsent);
        }
        Ok(())
    }

    fn next_seq(&mut self) -> u8 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    fn bulk_transfer(&self, ep: u8, data: &mut [u8], timeout_ms: u32) -> Result<usize, CcidError> {
        let mut xfer = UsbBulkTransfer {
            ep: ep as u32,
            len: data.len() as u32,
            timeout: timeout_ms,
            data: data.as_mut_ptr(),
        };
        let rc = unsafe {
            libc::ioctl(
                self.dev.as_raw_fd(),
                USBDEVFS_BULK,
                &mut xfer as *mut UsbBulkTransfer,
            )
        };
        if rc < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return Err(CcidError::Bulk {
                direction: if ep & EP_DIR_IN != 0 { "IN" } else { "OUT" },
                errno,
                ep,
            });
        }
        Ok(rc as usize)
    }

    fn bulk_roundtrip(&self, out_msg: &[u8]) -> Result<Vec<u8>, CcidError> {
        self.bulk_transfer(self.bulk_out_ep, &mut out_msg.to_vec(), 10_000)?;
        // Response buffer: header + generous payload room.
        let mut in_buf = vec![0u8; 10 + 4096];
        let n = self.bulk_transfer(self.bulk_in_ep | EP_DIR_IN, &mut in_buf, 30_000)?;
        in_buf.truncate(n);
        Ok(in_buf)
    }
}

impl Iso7816Transport for CcidCardTransport {
    fn exchange(&mut self, command: &CommandApdu) -> Result<ResponseApdu, String> {
        let apdu_bytes = command.encode();
        let msg = encode_rdr(PC_TO_RDR_XFR_BLOCK, 0x00, self.next_seq(), &apdu_bytes);
        let raw = self.bulk_roundtrip(&msg).map_err(|e| e.to_string())?;
        let reply = decode_rdr(&raw).map_err(|e| e.to_string())?;
        if reply.message_type != RDR_TO_PC_DATA_BLOCK {
            return Err(CcidError::UnexpectedResponse {
                expected: RDR_TO_PC_DATA_BLOCK,
                got: reply.message_type,
            }
            .to_string());
        }
        if reply.icc_not_present() {
            return Err(CcidError::IccAbsent.to_string());
        }
        if reply.command_failed() {
            return Err(CcidError::ReaderStatus {
                message_type: reply.message_type,
                slot: reply.slot,
                error: reply.error,
            }
            .to_string());
        }
        ResponseApdu::decode(&reply.payload)
    }
}

impl Drop for CcidCardTransport {
    fn drop(&mut self) {
        let iface = self.interface;
        let _ = unsafe {
            libc::ioctl(
                self.dev.as_raw_fd(),
                USBDEVFS_RELEASEINTERFACE,
                &iface as *const u32,
            )
        };
    }
}

/// Discover CCID (bInterfaceClass 0x0B) interfaces on the USB bus by
/// walking sysfs — no udev/hal dependency, no daemon trust.
///
/// Each interface directory is
/// `/sys/bus/usb/devices/<addr>:<config>.<iface>` with:
/// `bInterfaceClass` (0x0b selects CCID), `bEndpointAddress` (per endpoint
/// subdirectory), `busnum`/`devnum` (the /dev node), `idVendor`,
/// `idProduct`, and optionally `serial`.
pub fn discover_ccid_interfaces() -> Vec<CcidEndpoint> {
    let mut found = Vec::new();
    let dir = match std::fs::read_dir("/sys/bus/usb/devices") {
        Ok(d) => d,
        Err(_) => return found,
    };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // Interface entries contain a ':' (device entries do not).
        if !name.contains(':') {
            continue;
        }
        let iface_dir = entry.path();
        let class = read_sys_u16(&iface_dir.join("bInterfaceClass"));
        if class != Some(0x0B) {
            continue;
        }
        let interface = match read_sys_u16(&iface_dir.join("bInterfaceNumber")) {
            Some(i) => i as u32,
            None => continue,
        };
        let (bulk_out_ep, bulk_in_ep) = match discover_bulk_endpoints(&iface_dir) {
            Some(pair) => pair,
            None => continue,
        };
        let device_dir = match device_sysdir_of_interface(&iface_dir) {
            Some(d) => d,
            None => continue,
        };
        let busnum = match read_sys_u16(&device_dir.join("busnum")) {
            Some(b) => b,
            None => continue,
        };
        let devnum = match read_sys_u16(&device_dir.join("devnum")) {
            Some(d) => d,
            None => continue,
        };
        found.push(CcidEndpoint {
            device_node: PathBuf::from(format!("/dev/bus/usb/{:03}/{:03}", busnum, devnum)),
            interface,
            bulk_out_ep,
            bulk_in_ep,
            id_vendor: read_sys_u16(&device_dir.join("idVendor")).unwrap_or(0),
            id_product: read_sys_u16(&device_dir.join("idProduct")).unwrap_or(0),
            serial: std::fs::read_to_string(device_dir.join("serial"))
                .ok()
                .map(|s| s.trim().to_string()),
        });
    }
    found
}

/// Find the (bulk-out, bulk-in) endpoint pair of an interface directory.
fn discover_bulk_endpoints(iface_dir: &Path) -> Option<(u8, u8)> {
    let mut out_ep = None;
    let mut in_ep = None;
    for ep_dir in std::fs::read_dir(iface_dir).ok()?.flatten() {
        let addr = read_sys_u16_hex(&ep_dir.path().join("bEndpointAddress"))? as u8;
        let xfer_type = read_sys_u16(&ep_dir.path().join("bTransferType"))? as u8;
        const USB_ENDPOINT_XFER_BULK: u16 = 2;
        if xfer_type as u16 == USB_ENDPOINT_XFER_BULK {
            if addr & EP_DIR_IN != 0 {
                in_ep = Some(addr);
            } else {
                out_ep = Some(addr);
            }
        }
    }
    Some((out_ep?, in_ep?))
}

/// Walk from an interface sysdir (`.../1-2:1.0`) to its parent device
/// sysdir (`.../1-2`). In the flat `/sys/bus/usb/devices` directory both
/// are sibling entries, so the device entry is
/// `<iface_dir.parent()>/<device-name>`; under the real
/// `/sys/devices/...` tree the interface dir also sits one level below
/// the device dir, which the same construction resolves.
fn device_sysdir_of_interface(iface_dir: &Path) -> Option<PathBuf> {
    let name = iface_dir.file_name()?.to_string_lossy().to_string();
    let device_name = name.split(':').next()?.to_string();
    iface_dir.parent().map(|p| p.join(device_name))
}

fn read_sys_u16(path: &Path) -> Option<u16> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
}

fn read_sys_u16_hex(path: &Path) -> Option<u16> {
    // sysfs endpoint addresses print as hex with 0x prefix ("81"/"01" are
    // both accepted; bEndpointAddress publishes 0xNN).
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| u16::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usbfs_ioctl_numbers_match_kernel_uapi() {
        // _IOR('U', 15, u32): (2<<30)|(4<<16)|(0x55<<8)|15
        assert_eq!(USBDEVFS_CLAIMINTERFACE, 0x8004550F);
        // _IOR('U', 16, u32)
        assert_eq!(USBDEVFS_RELEASEINTERFACE, 0x80045510);
        // _IOWR('U', 2, 24-byte struct)
        assert_eq!(USBDEVFS_BULK, 0xC0185502);
        // The repr-C transfer struct must match the kernel layout.
        assert_eq!(std::mem::size_of::<UsbBulkTransfer>(), 24);
        assert_eq!(std::mem::align_of::<UsbBulkTransfer>(), 8);
    }

    #[test]
    fn pc_to_rdr_framing_carries_length_and_seq() {
        let msg = encode_rdr(
            PC_TO_RDR_XFR_BLOCK,
            0x00,
            0x07,
            &[0x00, 0xA4, 0x04, 0x00, 0x00],
        );
        assert_eq!(msg[0], 0x6F);
        assert_eq!(u32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]), 5);
        assert_eq!(msg[6], 0x07); // sequence
        assert_eq!(msg.len(), 10 + 5);
    }

    #[test]
    fn truncated_reader_replies_are_refused() {
        assert!(matches!(
            decode_rdr(&[0x80, 0x01, 0x02]),
            Err(CcidError::Truncated { got: 3 })
        ));
    }

    #[test]
    fn decode_rdr_splits_header_from_payload() {
        let mut raw = vec![RDR_TO_PC_DATA_BLOCK, 2, 0, 0, 0, 0, 0x11, 0, 0, 0];
        raw.extend_from_slice(&[0x90, 0x00]);
        let msg = decode_rdr(&raw).unwrap();
        assert_eq!(msg.message_type, RDR_TO_PC_DATA_BLOCK);
        assert_eq!(msg.slot, 0x00);
        assert_eq!(msg.status, 0x00);
        assert_eq!(msg.payload, vec![0x90, 0x00]);
        assert!(!msg.icc_not_present());
        assert!(!msg.command_failed());
        // bStatus bits 1:0 == 0b10: ICC absent.
        let absent = vec![RDR_TO_PC_SLOT_STATUS, 0, 0, 0, 0, 0, 0x05, 0x02, 0x00, 0x00];
        let msg = decode_rdr(&absent).unwrap();
        assert!(msg.icc_not_present());
    }

    #[test]
    fn interface_sysdir_resolution_strips_interface_suffix() {
        let iface = PathBuf::from("/sys/bus/usb/devices/2-1.3:1.0");
        let dev = device_sysdir_of_interface(&iface).unwrap();
        assert_eq!(dev, PathBuf::from("/sys/bus/usb/devices/2-1.3"));
    }
}
