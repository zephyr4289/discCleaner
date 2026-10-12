//! Post-sanitize verification and certificate evidence binding.
//!
//! Two evidence legs are collected for the SanitizationCertificate:
//!
//! 1. **Controller attestation**: the component register block hash
//!    (SHA-256 over the device register window as observed pre/post
//!    command), the Identify payload digest and the full background
//!    progress telemetry — binding WHAT executed the erase.
//! 2. **Media verification**: a deterministic sampled read-back of the
//!    mapped media window (via the HDM-decoded region or the mock's
//!    media array) proving the observable post-condition — all sampled
//!    windows read zero after `Sanitize` / `Secure Erase`.

use crate::mailbox::BackgroundReport;
use crate::regs;
pub use dc_cert::cxl::{CxlMediaVerification as MediaVerification, CxlSanitizeEvidence};
use sha2::{Digest, Sha256};

/// Sample `n_windows` evenly-spaced windows of `window_size` bytes from
/// `media`, plus (for small media) a full digest. Returns the finding.
pub fn verify_media_sampled(
    media: &[u8],
    window_size: usize,
    n_windows: usize,
) -> MediaVerification {
    let n_windows = n_windows.max(1);
    let window_size = window_size.max(1);
    if media.is_empty() {
        return MediaVerification {
            sampled_windows: 0,
            window_size: window_size as u64,
            nonzero_windows: Vec::new(),
            media_sha256: Some(hex_sha256(&[])),
            all_zero: true,
        };
    }
    let usable = media.len() / window_size;
    let mut nonzero: Vec<u64> = Vec::new();
    let sampled: u64;
    if usable == 0 {
        // whole media is one partial window
        sampled = 1;
        if media.iter().any(|&b| b != 0) {
            nonzero.push(0);
        }
    } else {
        sampled = n_windows as u64;
        for k in 0..n_windows {
            let idx = if n_windows == 1 {
                0
            } else {
                (k * (usable - 1)) / (n_windows - 1)
            };
            let start = idx * window_size;
            if media[start..start + window_size].iter().any(|&b| b != 0) {
                nonzero.push(idx as u64);
            }
        }
    }
    let digest = if media.len() <= 1 << 20 {
        Some(hex_sha256(media))
    } else {
        None
    };
    let all_zero = nonzero.is_empty();
    MediaVerification {
        sampled_windows: sampled,
        window_size: window_size as u64,
        nonzero_windows: nonzero,
        media_sha256: digest,
        all_zero,
    }
}

pub fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Build the certificate evidence bundle from a completed lifecycle.
pub fn build_evidence(
    device: String,
    bdf: String,
    command: &'static str,
    opcode: u16,
    report: &BackgroundReport,
    regs_pre: &[u8],
    regs_post: &[u8],
    identify: &[u8],
    media: &MediaVerification,
) -> CxlSanitizeEvidence {
    let serial = identify
        .get(regs::IDENTIFY_SERIAL_OFF..regs::IDENTIFY_SERIAL_OFF + 8)
        .map(hex::encode)
        .unwrap_or_default();
    CxlSanitizeEvidence {
        device,
        bdf,
        command: command.to_string(),
        opcode,
        return_code: report.return_code,
        component_regs_sha256_pre: hex_sha256(regs_pre),
        component_regs_sha256_post: hex_sha256(regs_post),
        identify_sha256: hex_sha256(identify),
        identify_serial_hex: serial,
        progress: report.samples.clone(),
        completed_in_ns: report.completed_in.as_nanos(),
        media: media.clone(),
        evidence_version: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_media_passes() {
        let media = vec![0u8; 1 << 20];
        let v = verify_media_sampled(&media, 4096, 16);
        assert!(v.all_zero);
        assert_eq!(v.sampled_windows, 16);
        assert!(v.nonzero_windows.is_empty());
        assert!(v.media_sha256.is_some());
    }

    #[test]
    fn dirty_media_fails_with_window_index() {
        let mut media = vec![0u8; 1 << 20];
        // corrupt the last window
        let ws = 4096;
        let last = media.len() - ws;
        media[last] = 0xff;
        let v = verify_media_sampled(&media, ws, 16);
        assert!(!v.all_zero);
        assert!(
            !v.nonzero_windows.is_empty(),
            "corrupted window must be found"
        );
    }

    #[test]
    fn tiny_media_partial_window() {
        let v = verify_media_sampled(&[0u8; 100], 4096, 4);
        assert!(v.all_zero);
        assert_eq!(v.sampled_windows, 1);
    }

    #[test]
    fn empty_media_is_inert_zero() {
        let v = verify_media_sampled(&[], 4096, 4);
        assert!(v.all_zero);
        assert_eq!(v.sampled_windows, 0);
    }

    #[test]
    fn evidence_serializes() {
        let media = MediaVerification {
            sampled_windows: 4,
            window_size: 4096,
            nonzero_windows: vec![],
            media_sha256: Some("ab".repeat(32)),
            all_zero: true,
        };
        let report = BackgroundReport {
            opcode: regs::OP_SANITIZE,
            return_code: 0,
            samples: vec![(0, 0), (10, 50), (20, 100)],
            completed_in: std::time::Duration::from_millis(20),
        };
        let ev = build_evidence(
            "mem0".into(),
            "0000:41:00.0".into(),
            "sanitize",
            regs::OP_SANITIZE,
            &report,
            &[1u8; 64],
            &[2u8; 64],
            &{
                let mut id = vec![0u8; 64];
                id[..8].copy_from_slice(b"MOCKCXL1");
                id
            },
            &media,
        );
        assert_eq!(ev.identify_serial_hex, hex::encode(b"MOCKCXL1"));
        let s = serde_json::to_string(&ev).unwrap();
        let back: CxlSanitizeEvidence = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
        assert!(s.contains("component_regs_sha256_pre"));
    }
}
