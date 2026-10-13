//! Challenge-driven I/O probe scores (v0.12.0, Miracle 2 — "The Pulse").
//!
//! A probe is a deterministic sequence of reads designed to excite the
//! drive's mechanical resonances in a challenge-specific way:
//!
//! * **HDD seek micro-stepping**: alternating short reads between
//!   pseudo-random LBA islands, each followed by a settle delay. The
//!   arm's servo transients ring the chassis at its natural
//!   frequencies; each drive's actuator assembly rings slightly
//!   differently (mass, bearing wear, head-stack alignment).
//! * **SSD read bursts**: clustered reads with inter-burst gaps excite
//!   controller/PCB piezoelectric and power-delivery resonances
//!   observable on board-level voltage/temperature channels.
//!
//! The score is derived from `H(challenge || domain || step)` — an
//! auditor can regenerate the exact LBA script from the challenge and
//! the geometry recorded in the enrollment.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::FileExt;

/// Errors from the probe layer.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("I/O on target device: {0}")]
    Io(#[from] std::io::Error),
    #[error("device geometry unusable: {0}")]
    Geometry(String),
    #[error("probe interrupted")]
    Interrupted,
}

/// One step of a probe score.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProbeStep {
    /// LBA to touch (in 512-byte sectors for portability).
    pub lba: u64,
    /// Bytes to read at this step.
    pub read_bytes: u32,
    /// Settle delay in microseconds AFTER the read — the mechanical
    /// ring the telemetry listens into.
    pub settle_us: u32,
}

/// A full probe score (the "musical" excitation program).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SeekScore {
    /// Challenge nonce this score was derived from (hex).
    pub challenge_hex: String,
    /// Number of 512-byte sectors on the target (recorded for
    /// regeneration; probes never touch the last 1 MiB).
    pub total_lbas: u64,
    pub steps: Vec<ProbeStep>,
    /// Media class the score was tuned for ("hdd" | "ssd").
    pub media_class: String,
}

/// Deterministic challenge → LBA stream (domain-separated counter
/// mode over SHA-256; no PRNG dependency).
fn lba_stream(challenge: &[u8; 32], counter: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(b"dc-sonar/lba/v1");
    h.update(challenge);
    h.update(counter.to_be_bytes());
    let d = h.finalize();
    u64::from_be_bytes(d[..8].try_into().expect("8 bytes"))
}

fn delay_stream(challenge: &[u8; 32], counter: u64) -> u32 {
    let mut h = Sha256::new();
    h.update(b"dc-sonar/delay/v1");
    h.update(challenge);
    h.update(counter.to_be_bytes());
    let d = h.finalize();
    // settle delay 200 µs .. 3 ms — audible-in-band excitation
    200 + (u32::from_be_bytes(d[..4].try_into().expect("4 bytes")) % 2800)
}

impl SeekScore {
    /// Compose a probe score for a device.
    ///
    /// `total_lbas` is the device size in 512-byte sectors;
    /// `media_class` in {"hdd", "ssd"} selects the excitation style.
    pub fn compose(
        challenge: &[u8; 32],
        total_lbas: u64,
        media_class: &str,
        steps: usize,
    ) -> Result<Self, ProbeError> {
        if total_lbas < 4096 {
            return Err(ProbeError::Geometry(format!(
                "device too small for probing ({total_lbas} sectors)"
            )));
        }
        // Keep 1 MiB away from both edges: never disturb GPT/EBR areas.
        let margin = 2048u64; // 1 MiB in 512-byte sectors
        let lo = margin;
        let hi = total_lbas.saturating_sub(margin).max(lo + 1);
        let mut out = Vec::with_capacity(steps);
        for i in 0..steps as u64 {
            let raw = lba_stream(challenge, i);
            let lba = lo + (raw % (hi - lo));
            let read_bytes: u32 = match media_class {
                // SSD bursts: bigger reads, tighter rhythm
                "ssd" => 4096 + ((raw >> 32) as u32 % (128 * 1024 - 4096)),
                // HDD micro-stepping: small reads so the arm movement
                // (not the media stream) dominates
                _ => 512 + ((raw >> 40) as u32 % 3584),
            };
            let settle_us = match media_class {
                "ssd" => delay_stream(challenge, i) / 4,
                _ => delay_stream(challenge, i),
            };
            out.push(ProbeStep {
                lba,
                read_bytes,
                settle_us,
            });
        }
        Ok(Self {
            challenge_hex: hex::encode(challenge),
            total_lbas,
            steps: out,
            media_class: media_class.to_string(),
        })
    }
}

/// The physical read backend a probe runs against.
pub trait DriveIo {
    /// Read `len` bytes at `lba` (512-byte sectors). Implementations
    /// return the bytes (content irrelevant — the TIMING and the
    /// telemetry response is the signal).
    fn read_at(&mut self, lba: u64, len: u32) -> Result<Vec<u8>, ProbeError>;

    /// Human-readable identity of the backend (for evidence records).
    fn describe(&self) -> String;
}

/// Real block-device backend (pread on an opened file).
pub struct FileIo {
    pub file: File,
    pub path: String,
}

impl FileIo {
    pub fn open(path: &std::path::Path) -> Result<Self, ProbeError> {
        let file = File::open(path)?;
        Ok(Self {
            file,
            path: path.display().to_string(),
        })
    }
}

impl DriveIo for FileIo {
    fn read_at(&mut self, lba: u64, len: u32) -> Result<Vec<u8>, ProbeError> {
        let mut buf = vec![0u8; len as usize];
        self.file
            .read_exact_at(&mut buf, lba * 512)
            .map_err(ProbeError::Io)?;
        Ok(buf)
    }

    fn describe(&self) -> String {
        format!("file:{}", self.path)
    }
}

/// Replay backend for tests and forensic re-analysis: serves
/// deterministic pseudo-content.
pub struct ReplayIo {
    pub label: String,
    pub seed: u64,
}

impl DriveIo for ReplayIo {
    fn read_at(&mut self, lba: u64, len: u32) -> Result<Vec<u8>, ProbeError> {
        // Content is irrelevant to the PUF — deterministic filler.
        let mut v = Vec::with_capacity(len as usize);
        let mut state = self.seed ^ lba ^ (len as u64) << 32;
        for _ in 0..len {
            // xorshift64*
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            v.push((state.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8);
        }
        Ok(v)
    }

    fn describe(&self) -> String {
        format!("replay:{}", self.label)
    }
}

/// Execute a probe score against a drive: performs the reads with
/// their settle delays. The `progress` callback fires per step
/// (return `false` to cancel).
pub fn run_score(
    io: &mut dyn DriveIo,
    score: &SeekScore,
    mut progress: impl FnMut(usize) -> bool,
) -> Result<(), ProbeError> {
    for (i, step) in score.steps.iter().enumerate() {
        if !progress(i) {
            return Err(ProbeError::Interrupted);
        }
        let _ = io.read_at(step.lba, step.read_bytes)?;
        std::thread::sleep(std::time::Duration::from_micros(step.settle_us as u64));
    }
    Ok(())
}

/// Convenience used by tests/forensics: read a whole file's worth of
/// LBA content without the probe pacing (not used on the PUF path).
pub fn read_span(io: &mut dyn DriveIo, lba: u64, len: u32) -> Result<Vec<u8>, ProbeError> {
    io.read_at(lba, len)
}

// Keep the unused-import lint quiet for Seek used on some platforms.
#[allow(unused)]
fn _seek_helper(f: &mut File, pos: SeekFrom) -> std::io::Result<u64> {
    f.seek(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_deterministic_per_challenge() {
        let c1: [u8; 32] = [0x11; 32];
        let c2: [u8; 32] = [0x22; 32];
        let s1 = SeekScore::compose(&c1, 100_000_000, "hdd", 32).unwrap();
        let s1b = SeekScore::compose(&c1, 100_000_000, "hdd", 32).unwrap();
        let s2 = SeekScore::compose(&c2, 100_000_000, "hdd", 32).unwrap();
        assert_eq!(s1, s1b, "same challenge → same score");
        assert_ne!(s1.steps, s2.steps, "different challenge → different score");

        // All LBAs inside the safe band.
        for st in &s1.steps {
            assert!(st.lba >= 2048);
            assert!(st.lba < 100_000_000 - 2048);
            assert!(st.settle_us >= 200 && st.settle_us < 3000);
        }
    }

    #[test]
    fn replay_backend_serves_deterministic_content() {
        let mut io = ReplayIo {
            label: "test".into(),
            seed: 7,
        };
        let a = io.read_at(1000, 512).unwrap();
        let b = io.read_at(1000, 512).unwrap();
        let c = io.read_at(1001, 512).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
