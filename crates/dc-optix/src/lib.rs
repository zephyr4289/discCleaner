//! # dc-optix — Sub-Surface Optical Disk Laser Photobleaching &
//! Phase-Change Destruction (v0.14.0, Breakthrough 3)
//!
//! **The myth this crate kills:** *"WORM media (Archival Blu-Ray,
//! M-DISC, CD-R, DVD-R) can only be destroyed by shredders or
//! incinerators."* The physical recording layer — organic dye,
//! inorganic phase-change alloy or glassy carbon — is chemically
//! unmodifiable through standard OS write commands. But it is
//! nothing but a thin film sitting a few hundred microns from a
//! precision-stabilized 100 mW-class laser: the drive's OWN
//! optical pickup.
//!
//! dc-optix weaponizes the drive firmware:
//!
//! * [`mmc`] — the MMC/ATAPI raw-passthrough abstraction: vendor
//!   diagnostic commands that disable run-time laser power
//!   calibration (OPC), overdrive the laser diode PWM duty and
//!   drive current, and park the CLV servo at minimum linear
//!   velocity. Real backends wrap `dc-scsi`/SG_IO or `dc-ata`
//!   passthrough; the simulation records the command stream for
//!   the certificate.
//! * [`opu`] — the optical pickup unit model: laser diode power
//!   (read / write / overdriven CW), PWM duty, focus servo, and
//!   the CLV law `v = ω(r)·r` — energy per unit track length
//!   `E/L = P/v` is maximized at LOW linear velocity with HIGH
//!   power, the exact opposite of the drive's write strategy.
//! * [`layer`] — the recording layer physics: per-cell
//!   reflectivity state, media-type-specific destruction thresholds
//!   (photobleach for organic dye, melt-and-quench-to-amorphous
//!   for phase-change, ablation for glassy carbon), and the dose
//!   response `R(D)`.
//! * [`anneal`] — the annihilation engine: walk the full spiral
//!   lead-in → lead-out, depositing overdriven-CW dose at parked
//!   velocity with along-track thermal spreading, tracking
//!   per-cell coverage.
//! * [`rfeeye`] — the readback verification: the HF RF eye
//!   pattern (eye height ∝ reflectivity modulation ΔR/R), the
//!   quadrature-photodiode push-pull tracking signal (groove
//!   thermal flattening), and jitter — the forensics-lab
//!   read-recovery model.
//! * [`proof`] — the **Photobleach Destruction Certificate**:
//!   100% spiral coverage, per-zone ΔR/R collapse below the read
//!   threshold, RF eye closed to the noise floor, read-recovery
//!   at chance — BLAKE3-digest bound.
//!
//! ## Threat model
//!
//! 1. **Forensic readback** — a lab re-reads the disc on a
//!    calibrated drive: post-treatment reflectivity modulation is
//!    flat, every channel bit reads as noise (recovery at chance).
//! 2. **Microscopy recovery** — polished cross-sections scanned
//!    for surviving mark trains: the dose model requires EVERY
//!    spiral cell to receive annihilating energy; coverage is
//!    proven per-cell, not per-zone.
//! 3. **Certificate forgery / replay** — BLAKE3 digest over the
//!    canonical body (signable via dc-cert hybrid Ed25519+ML-DSA
//!    at the CLI layer); verdicts recomputed from raw
//!    statistics.

pub mod anneal;
pub mod layer;
pub mod mmc;
pub mod opu;
pub mod proof;
pub mod rfeeye;

/// Optical destruction errors.
#[derive(Debug, thiserror::Error)]
pub enum OptixError {
    #[error("drive transport refused: {0}")]
    Transport(String),
    #[error("media physics violation: {0}")]
    Physics(String),
    #[error("annihilation run failed: {0}")]
    Annihilation(String),
    #[error("certificate verification failed: {0}")]
    Certificate(String),
}

/// Splitmix64 stream PRNG (house pattern; deterministic campaigns).
pub struct SimRng {
    state: u64,
}

impl SimRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform [0, 1).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Standard normal via Box-Muller.
    pub fn next_normal(&mut self) -> f64 {
        let u1 = self.next_f64().max(f64::MIN_POSITIVE);
        let u2 = self.next_f64();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    /// Uniform integer in [0, bound).
    pub fn below(&mut self, bound: u64) -> u64 {
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let x = self.next_u64();
            let m = (x as u128) * (bound as u128);
            let lo = m as u64;
            if lo >= threshold {
                return (m >> 64) as u64;
            }
        }
    }
}
