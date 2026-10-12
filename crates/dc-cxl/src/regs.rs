//! CXL 2.0/3.0 Type 3 Memory Device register layout constants.
//!
//! Sources: CXL Base Specification 2.0/3.1 ( Compute Express Link
//! Base Specification Revision 3.1, Chapter 8 "Memory Device")
//! — capability structure offsets within the **device register block**
//! located via the PCIe DVSEC for CXL Devices (Register Block Locator)
//! or the kernel's `/sys/bus/cxl` component map.
//!
//! ⚠️ Layout governance: every magic number in this file is a named
//! constant with its spec citation. If a future CXL revision moves a
//! register, this file is the single place to correct — the protocol
//! engine ([`crate::mailbox`]) is layout-agnostic and mock-tested against
//! these definitions.

/// Offset of the Memory Device Mailbox within the device register block
/// (CXL 2.0 §8.2.8.5 — fixed by the specification so software written for
/// one Type 3 device finds the mailbox at a stable offset).
pub const MBOX_OFFSET: u64 = 0x8880;

/// Mailbox Capability register (+0x00): payload size in bits [4:0]
/// (`2^n` bytes; 8 = the standard 256-byte mailbox).
pub const MBOX_CAPS: u64 = 0x00;
/// Mailbox Control register (+0x08): bit 0 = interrupt enable.
pub const MBOX_CONTROL: u64 = 0x08;
/// Command register (+0x10): opcode in bits [15:0], payload length in
/// bits [40:32].
pub const MBOX_COMMAND: u64 = 0x10;
/// Status register (+0x18): bit 0 = mailbox busy; return code in bits
/// [15:0] (valid when not busy).
pub const MBOX_STATUS: u64 = 0x18;
/// Background Command Status register (+0x20): opcode in bits [15:0],
/// percent complete in bits [23:16], background return code in [31:16].
pub const MBOX_BG_STATUS: u64 = 0x20;
/// Mailbox payload region (+0x80, 256 bytes).
pub const MBOX_PAYLOAD: u64 = 0x80;
/// Maximum mailbox payload (spec minimum for Type 3 devices).
pub const MBOX_PAYLOAD_SIZE: usize = 256;

// -- Memory Device Mailbox opcodes (CXL 2.0 §8.2.9.5 command set) --------

/// Identify Memory Device.
pub const OP_IDENTIFY: u16 = 0x4000;
/// Get Security State.
pub const OP_GET_SECURITY_STATE: u16 = 0x4500;
/// Sanitize (background operation — overwrites ALL media contents).
pub const OP_SANITIZE: u16 = 0x4400;
/// Secure Erase (foreground — cryptographically erases user data).
pub const OP_SECURE_ERASE: u16 = 0x4401;

// -- Return codes (CXL 2.0 §8.2.9.2 Table 8-43) ---------------------------

pub const RC_SUCCESS: u16 = 0x00;
pub const RC_BACKGROUND_STARTED: u16 = 0x01;
pub const RC_MAILBOX_BUSY: u16 = 0x03;
pub const RC_INVALID_PAYLOAD_LENGTH: u16 = 0x09;
pub const RC_UNSUPPORTED: u16 = 0x0b;
pub const RC_INTERNAL_ERROR: u16 = 0x0c;
pub const RC_RETRY: u16 = 0x0d;
pub const RC_BUSY: u16 = 0x0e;
pub const RC_MEDIA_DISABLED: u16 = 0x0f;
pub const RC_SANITIZE_IN_PROGRESS: u16 = 0x44;
pub const RC_SECURITY_FAILURE: u16 = 0x50;

/// Human-readable return code names for evidence and CLI output.
pub fn return_code_name(rc: u16) -> &'static str {
    match rc {
        RC_SUCCESS => "Success",
        RC_BACKGROUND_STARTED => "Background operation started",
        0x02 => "Background operation not started",
        RC_MAILBOX_BUSY => "Mailbox busy",
        0x04 => "Command issued while background busy",
        0x05 => "Command data area overflow",
        0x06 => "Command data area underflow",
        0x07 => "Command data area exhausted",
        0x08 => "Invalid epoch",
        RC_INVALID_PAYLOAD_LENGTH => "Invalid payload length",
        0x0a => "Invalid command",
        RC_UNSUPPORTED => "Unsupported command",
        RC_INTERNAL_ERROR => "Internal device error",
        RC_RETRY => "Retry suggested",
        RC_BUSY => "Device busy",
        RC_MEDIA_DISABLED => "Media disabled",
        0x10 => "Firmware transfer needed",
        0x11 => "Firmware transfer out of order",
        0x12 => "Firmware transfer cancelled",
        0x13 => "Firmware transfer aborted",
        0x20 => "Continue",
        0x21 => "Continue with return data",
        RC_SANITIZE_IN_PROGRESS => "Sanitize in progress",
        0x45 => "Password not acceptable",
        RC_SECURITY_FAILURE => "Security failure",
        _ => "Unknown return code",
    }
}

// -- PCIe DVSEC (Designated Vendor-Specific Extended Capability) ---------

/// PCIe Extended Capability ID for DVSEC.
pub const PCIE_EXT_CAP_DVSEC: u16 = 0x23;
/// CXL LLC (PCIe SIG-assigned) vendor ID used by CXL DVSEC structures.
pub const CXL_DVSEC_VENDOR_ID: u16 = 0x1e98;
/// DVSEC ID 0: PCIe DVSEC for CXL Device (contains the Register Block
/// Locator pointing at the device register block).
pub const DVSEC_ID_CXL_DEVICE: u16 = 0x0000;
/// DVSEC ID 2: PCIe DVSEC for CXL Extensions (device lock etc.).
pub const DVSEC_ID_CXL_EXTENSIONS: u16 = 0x0002;
/// Offset of the DVSEC header fields within the extended capability.
pub const DVSEC_HDR_LEN: u64 = 0x0C;

// -- Identify Memory Device payload fields (§8.2.9.5.1) ------------------

pub const IDENTIFY_PAYLOAD_LEN: usize = 64;
/// Byte offset of the 16-byte serial number inside the identify payload.
pub const IDENTIFY_SERIAL_OFF: usize = 0;
/// Byte offset of the 16-byte host-managed device memory (HDM) label.
pub const IDENTIFY_HDM_OFF: usize = 16;
/// Total volatile + persistent capacity fields (u64 LE pairs at offset 32).
pub const IDENTIFY_CAPACITY_OFF: usize = 32;
/// Alignment requirement for capacity fields.
pub const IDENTIFY_ALIGNMENT_OFF: usize = 48;
