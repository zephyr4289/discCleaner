//! # dc-sonar — Acoustic & Ultrasonic Hardware Fingerprinting
//! (v0.12.0, Miracle 2)
//!
//! Counterfeit SSDs and refurbished HDDs in global supply chains
//! routinely carry **flashed serial numbers and spoofed firmware
//! WWNs**. You think you wiped "Drive Serial #12345" — but a rogue
//! swap took place, and the real classified drive was smuggled out the
//! back door while a decoy took its place.
//!
//! Every mechanical drive arm, spindle motor and even the piezoelectric
//! capacitors on an SSD circuit board carry **unique microscopic
//! physical imperfections** that resonate at distinct acoustic and
//! vibrational harmonics. dc-sonar turns the drive itself into a
//! challenge–response Physical Unclonable Function:
//!
//! 1. **The Pulse** — a deterministic, challenge-derived I/O score
//!    ([`probe`]): sub-millisecond seek micro-stepping on HDDs, burst
//!    read throttling on SSDs. The score acts like a musical probe
//!    exciting the drive's mechanical resonances.
//! 2. **The Pickup** — high-rate telemetry sampling ([`telemetry`]):
//!    motherboard accelerometers (Linux IIO), thermal/voltage/fan
//!    resistance channels (hwmon), each observing the drive's
//!    microscopic response from a different physical angle.
//! 3. **The Fingerprint** — [`signal`] extracts harmonic features
//!    (a hand-written radix-2 FFT — zero dependencies); [`puf`]
//!    quantizes the most stable features into a
//!    challenge–response fingerprint with public helper data, and
//!    scores verification candidates by Hamming distance.
//!
//! Even an attacker who clones the drive's firmware and spoofs its
//! serial **cannot clone the physical resonance of the chassis**. The
//! wipe certificate binds the cryptographic evidence to the physical
//! silicon body of the drive ([`evidence`]).
//!
//! Operations:
//! * `dc sonar enroll` — capture K probe responses, build a robust
//!   enrollment with helper data.
//! * `dc sonar verify` — fresh challenge–response against an
//!   enrollment; match/mismatch verdict with per-feature scores.
//! * `dc execute --puf-guard <enrollment>` — the wipe ABORTS
//!   (fail-closed) if the drive under the write head stops matching
//!   its enrolled acoustic fingerprint mid-run — the rogue-swap
//!   detector.

pub mod evidence;
pub mod probe;
pub mod puf;
pub mod signal;
pub mod telemetry;

pub use evidence::{SonarPufEvidence, VerificationRecord};
pub use probe::{DriveIo, FileIo, ProbeStep, ReplayIo, SeekScore, run_score};
pub use puf::{Enrollment, PufError, VerifyOutcome};
pub use signal::{HarmonicPeak, SpectrumFeatures, extract_features};
pub use telemetry::{Capture, TelemetryKind, TelemetrySource, iio_accel, replay, sysfs_hwmon};

/// Length of a PUF challenge nonce (domain-separated everywhere).
pub const CHALLENGE_LEN: usize = 32;

/// Fresh random challenge (OS entropy).
pub fn fresh_challenge() -> Result<[u8; CHALLENGE_LEN], PufError> {
    let mut c = [0u8; CHALLENGE_LEN];
    getrandom::getrandom(&mut c).map_err(|e| PufError::Entropy(e.to_string()))?;
    Ok(c)
}
