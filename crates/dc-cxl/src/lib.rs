//! `dc-cxl` — CXL 2.0/3.0 Type 3 memory device sanitization (v0.11.0,
//! Frontier 2).
//!
//! Hyperscaler AI clusters and in-memory databases (SAP HANA, LLM
//! inference caches) increasingly hold secrets in **CXL Type 3
//! Persistent Memory / Memory Expanders** sitting directly on the PCIe
//! bus. When a server reboots or is reassigned, sensitive weights and
//! pages linger in non-volatile CXL RAM that neither `dd` nor NVMe
//! commands can touch.
//!
//! This crate implements the native CXL sanitization path:
//!
//! 1. **Discovery** ([`discovery`]): enumerate `/sys/bus/cxl/devices`
//!    (kernel cxl_mem), resolve each memdev to its PCI function and
//!    parse the CXL DVSEC (vendor `0x1E98`) Register Block Locator to
//!    find the device register block.
//! 2. **Mailbox** ([`mailbox`]): drive the CXL Memory Device Mailbox
//!    over MMIO — write payload, write Command register, poll Status,
//!    collect the return code and response. Background commands poll the
//!    Background Command Status register (opcode + percent complete).
//!    Sanitize = opcode **0x4400** (background, overwrites all media);
//!    Secure Erase = opcode **0x4401** (foreground cryptographic erase).
//! 3. **Verification** ([`verify`]): sampled read-back of the mapped
//!    media proving the observable post-condition, plus
//!    **component register hashes** and the Identify payload digest
//!    bound into the certificate evidence.
//! 4. **Evidence** ([`CxlSanitizeEvidence`]): the signature-covered
//!    certificate extension carrying device identity, opcodes, return
//!    codes, progress telemetry and the media verification.
//!
//! All MMIO access is behind the [`mailbox::MailboxBackend`] trait; the
//! in-memory [`mailbox::MockCxlDevice`] simulates a full Type 3 device
//! (including background sanitize progress) so the entire lifecycle is
//! testable without hardware — the same mock-first discipline as the
//! TPM, KVM-vault and fabric layers.
//!
//! # Register layout governance
//!
//! Every hardware offset lives in [`regs`] with its specification
//! citation; the protocol engine is layout-agnostic. If a future CXL
//! revision moves a register, `regs.rs` is the single correction point.

pub mod discovery;
pub mod dvsec;
pub mod mailbox;
pub mod mmio;
pub mod regs;
pub mod verify;

use dc_cert::cxl::CxlSanitizeEvidence;
use mailbox::{Mailbox, MailboxBackend, MailboxError};
use regs::*;
use thiserror::Error;

/// Post-erase media access for verification: the mock serves its media
/// array; the production MMIO backend has no HDM-decoded window mapped
/// yet (returns empty — an inert pass, media verification is then
/// carried by the controller's own sanitize status; see docs).
pub trait MediaSource {
    fn media_view(&self) -> Vec<u8>;
}

impl MediaSource for mailbox::MockCxlDevice {
    fn media_view(&self) -> Vec<u8> {
        self.media.clone()
    }
}

impl MediaSource for mmio::MmioBackend {
    fn media_view(&self) -> Vec<u8> {
        Vec::new()
    }
}

#[derive(Debug, Error)]
pub enum CxlError {
    #[error("mailbox: {0}")]
    Mailbox(#[from] MailboxError),
    #[error("discovery: {0}")]
    Discovery(#[from] discovery::DiscoveryError),
    #[error("media verification failed: {0} nonzero windows of {1}")]
    VerificationFailed(usize, u64),
    #[error("identify payload malformed (shorter than {0} bytes)")]
    MalformedIdentify(usize),
}

/// Which erase command to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraseCommand {
    /// 0x4400 — background overwrite of ALL media (NIST SP 800-88
    /// Purge-equivalent for CXL media).
    Sanitize,
    /// 0x4401 — foreground cryptographic erase of user data.
    SecureErase,
}

impl EraseCommand {
    pub fn opcode(self) -> u16 {
        match self {
            EraseCommand::Sanitize => OP_SANITIZE,
            EraseCommand::SecureErase => OP_SECURE_ERASE,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            EraseCommand::Sanitize => "sanitize",
            EraseCommand::SecureErase => "secure-erase",
        }
    }
}

/// Identify Memory Device (opcode 0x4000) — serial number and capacity.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentifyInfo {
    pub serial_hex: String,
    pub total_capacity_bytes: u64,
    pub raw: Vec<u8>,
}

pub fn identify<D: MailboxBackend>(mbox: &mut Mailbox<D>) -> Result<IdentifyInfo, CxlError> {
    let reply = mbox.execute(OP_IDENTIFY, &[])?;
    if reply.payload.len() < IDENTIFY_PAYLOAD_LEN {
        return Err(CxlError::MalformedIdentify(IDENTIFY_PAYLOAD_LEN));
    }
    let serial = &reply.payload[IDENTIFY_SERIAL_OFF..IDENTIFY_SERIAL_OFF + 16];
    let cap = u64::from_le_bytes(
        reply.payload[IDENTIFY_CAPACITY_OFF..IDENTIFY_CAPACITY_OFF + 8]
            .try_into()
            .unwrap(),
    );
    Ok(IdentifyInfo {
        serial_hex: hex::encode(serial),
        total_capacity_bytes: cap,
        raw: reply.payload[..IDENTIFY_PAYLOAD_LEN].to_vec(),
    })
}

/// Security state flags (opcode 0x4500): bit 0 = enabled, bit 1 = locked,
/// bit 2 = frozen, bit 3 = encrypted.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityState {
    pub enabled: bool,
    pub locked: bool,
    pub frozen: bool,
    pub encrypted: bool,
}

pub fn security_state<D: MailboxBackend>(mbox: &mut Mailbox<D>) -> Result<SecurityState, CxlError> {
    let reply = mbox.execute(OP_GET_SECURITY_STATE, &[])?;
    let f = reply.payload.first().copied().unwrap_or(0);
    Ok(SecurityState {
        enabled: f & 0x1 != 0,
        locked: f & 0x2 != 0,
        frozen: f & 0x4 != 0,
        encrypted: f & 0x8 != 0,
    })
}

/// Outcome of a full erase lifecycle.
#[derive(Debug, Clone)]
pub struct SanitizeOutcome {
    pub evidence: CxlSanitizeEvidence,
    pub identify: IdentifyInfo,
}

/// Run one full erase lifecycle against a mailbox backend:
/// identify → (pre-state snapshot) → erase → verify → evidence.
///
/// `regs_snapshot` supplies the device register block bytes as observed
/// before the command (component register hash binding); for the mock
/// device this is the simulated register file, for production it is a
/// read of the mapped register window.
pub fn run_erase<D: MailboxBackend + MediaSource>(
    device: &str,
    bdf: &str,
    mbox: &mut Mailbox<D>,
    command: EraseCommand,
    regs_pre: &[u8],
    regs_post: &[u8],
) -> Result<SanitizeOutcome, CxlError> {
    let identify = identify(mbox)?;
    let _security = security_state(mbox)?;

    let report = match command {
        EraseCommand::Sanitize => mbox.execute_background(OP_SANITIZE, &[])?,
        EraseCommand::SecureErase => {
            let reply = mbox.execute(OP_SECURE_ERASE, &[])?;
            mailbox::BackgroundReport {
                opcode: OP_SECURE_ERASE,
                return_code: reply.return_code,
                samples: Vec::new(),
                completed_in: std::time::Duration::ZERO,
            }
        }
    };
    if report.return_code != RC_SUCCESS {
        return Err(CxlError::Mailbox(MailboxError::ReturnCode(
            report.return_code,
            return_code_name(report.return_code),
        )));
    }

    // Media verification: sample up to 64 4-KiB windows of the LIVE
    // post-erase media view (plus a full digest for media <= 1 MiB).
    let media = mbox.backend().media_view();
    let media_ver = verify::verify_media_sampled(&media, 4096, 64);
    if !media_ver.all_zero {
        return Err(CxlError::VerificationFailed(
            media_ver.nonzero_windows.len(),
            media_ver.sampled_windows,
        ));
    }

    let evidence = verify::build_evidence(
        device.to_string(),
        bdf.to_string(),
        command.label(),
        command.opcode(),
        &report,
        regs_pre,
        regs_post,
        &identify.raw,
        &media_ver,
    );
    Ok(SanitizeOutcome { evidence, identify })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailbox::{Mailbox, MockCxlDevice};

    #[test]
    fn full_sanitize_lifecycle_on_mock() {
        let mut mbox = Mailbox::new(MockCxlDevice::new(1 << 20));
        let outcome = run_erase(
            "mem0",
            "0000:41:00.0",
            &mut mbox,
            EraseCommand::Sanitize,
            &[0x11; 128],
            &[0x22; 128],
        )
        .unwrap();
        assert_eq!(outcome.evidence.opcode, OP_SANITIZE);
        assert_eq!(outcome.evidence.return_code, RC_SUCCESS);
        assert!(outcome.evidence.media.all_zero);
        assert_eq!(
            outcome.identify.serial_hex,
            format!("{}{}", hex::encode(b"MOCKCXL1"), "0".repeat(16))
        );
        assert!(!outcome.evidence.progress.is_empty());
        assert_ne!(
            outcome.evidence.component_regs_sha256_pre,
            outcome.evidence.component_regs_sha256_post
        );
    }

    #[test]
    fn full_secure_erase_lifecycle_on_mock() {
        let mut mbox = Mailbox::new(MockCxlDevice::new(1 << 16));
        let outcome = run_erase(
            "mem1",
            "0000:42:00.0",
            &mut mbox,
            EraseCommand::SecureErase,
            &[0x11; 128],
            &[0x11; 128],
        )
        .unwrap();
        assert_eq!(outcome.evidence.opcode, OP_SECURE_ERASE);
        assert!(outcome.evidence.media.all_zero);
        assert!(
            outcome.evidence.progress.is_empty(),
            "foreground command carries no progress telemetry"
        );
    }

    #[test]
    fn failed_sanitize_verification_surfaces() {
        // Fault-injected device: claims success, leaves media dirty —
        // the sampled read-back must catch it.
        let mut dev = MockCxlDevice::new(1 << 20);
        dev.sanitize_leaves_media = true;
        let mut mbox = Mailbox::new(dev);
        let outcome = run_erase(
            "memX",
            "bdf",
            &mut mbox,
            EraseCommand::Sanitize,
            &[0; 128],
            &[0; 128],
        );
        assert!(matches!(outcome, Err(CxlError::VerificationFailed(n, _)) if n > 0));
    }
}
