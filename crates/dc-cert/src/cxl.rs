//! CXL Type 3 memory-device sanitize evidence (v0.11.0, Frontier 2).
//!
//! Embedded into `SanitizationCertificate.cxl` by `dc cxl sanitize` /
//! `dc cxl erase`. Signature-covered like every other certificate field.
//! Mirrors the structure produced by the `dc-cxl` engine — see that
//! crate for the field semantics (opcode 0x4400 sanitize / 0x4401 secure
//! erase, component register hashes, background progress telemetry,
//! sampled media verification).

use serde::{Deserialize, Serialize};

/// Post-sanitize media read-back verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CxlMediaVerification {
    pub sampled_windows: u64,
    pub window_size: u64,
    pub nonzero_windows: Vec<u64>,
    pub media_sha256: Option<String>,
    pub all_zero: bool,
}

/// Full evidence bundle for one CXL erase lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CxlSanitizeEvidence {
    /// sysfs memdev name (e.g. `mem0`) and PCI BDF.
    pub device: String,
    pub bdf: String,
    /// Which command ran: "sanitize" (0x4400) or "secure-erase" (0x4401).
    pub command: String,
    pub opcode: u16,
    /// Final mailbox return code (0 = success).
    pub return_code: u16,
    /// SHA-256 of the device register block as observed before the
    /// command (component register hash — binds the executing hardware).
    pub component_regs_sha256_pre: String,
    /// SHA-256 of the device register block after completion.
    pub component_regs_sha256_post: String,
    /// SHA-256 of the Identify Memory Device payload.
    pub identify_sha256: String,
    /// Identify serial number field (hex).
    pub identify_serial_hex: String,
    /// Background progress telemetry (elapsed_ms, percent).
    pub progress: Vec<(u64, u8)>,
    /// Wall-clock completion time in nanoseconds.
    pub completed_in_ns: u128,
    /// Media verification (sampled read-back).
    pub media: CxlMediaVerification,
    /// Fingerprint of the audit evidence version.
    pub evidence_version: u8,
}
