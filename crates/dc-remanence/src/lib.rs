//! # dc-remanence — MFM Anti-Forensics & Remanence Annihilation
//! (v0.14.0, Breakthrough 1)
//!
//! **The myth this crate kills:** *"overwriting a sector with zeros
//! destroys the data."* In magnetic physics it does not. When a
//! write head records a bit, its fringing field leaks past the
//! nominal track edge into the guard bands, leaving sub-track
//! magnetization remnants a few nanometres wide (the "track-edge
//! shoulder"). A state-grade forensics lab with a Magnetic Force
//! Microscope (MFM) or a spin-polarized SEM scans those guard bands
//! and reads the hysteresis ghosts of the *previous* recording —
//! the data survives at the track edges even after a NIST-grade
//! overwrite of the track core.
//!
//! dc-remanence is the annihilation engine for that residual layer:
//!
//! * [`track`] — the thin-film track geometry model: track pitch,
//!   write-element width, guard bands, and the exponential
//!   fringing-field falloff with write-current-dependent write
//!   bubble width.
//! * [`microstep`] — the off-track micro-stepping planner and the
//!   vendor-diagnostic transport abstraction: the head is stepped
//!   in sub-track increments (+15%, −15%, +30%, −30% off the track
//!   centerline) with write-current bias, so the write bubble sweeps
//!   the guard bands on BOTH sides of every track.
//! * [`curie`] — the Curie-dither: a high-spatial-frequency
//!   alternating-flux write pattern (elevated current, polarity
//!   inverted every few cells, random phase) that scrambles
//!   transition boundaries and unpins domain walls. Each dither
//!   pass gives guard-band grains a Néel-Brown thermal switch
//!   attempt toward the *current* (alternating) polarity — the old
//!   domain orientation decays geometrically and ends up
//!   re-randomized, decoupled from the previous recording.
//! * [`remanence`] — the platter physics simulation: per-column
//!   grain magnetization with distributed coercivity, the original
//!   (old-data) fringe write, the overwrite scenarios (baseline
//!   single zero-write vs. the full dc-remanence treatment), and
//!   the residual-correlation measurement an MFM adversary would
//!   perform.
//! * [`prml`] — the PRML read channel: the Johnson-Nyquist thermal
//!   noise floor (4k<sub>B</sub>TRB) of the read path, the PR4
//!   partial-response trellis with a max-log soft-decision LLR
//!   extraction, and the matched-filter LLR statistics of the
//!   guard-band adversary read.
//! * [`proof`] — the **Remanence Annihilation Certificate**:
//!   per-track guard-band coverage from the micro-step ladder, the
//!   99%-confidence upper bound on residual old-bit SNR proven
//!   below −20 dB, the MFM distinguisher's detection horizon
//!   (cells required at P<sub>FA</sub> = 10⁻⁶, P<sub>D</sub> = 99%),
//!   all BLAKE3-digest bound.
//!
//! ## Threat model
//!
//! 1. **Track-edge ghost (the MFM read)** — the adversary knows the
//!    plaintext candidate (known-plaintext attack) and scans the
//!    guard bands with a sharp-tip magnetometer. Defense: the
//!    micro-step ladder must cover 100% of the guard band with
//!    hard-switch fields, and the Curie-dither must randomize what
//!    the ladder's soft edges left behind; the certificate bounds
//!    the adversary's per-cell amplitude SNR below −20 dB.
//! 2. **Transition-boundary forensics** — the adversary skips bit
//!    values and instead reads the *positions* of old NRZ
//!    transition edges (density-modulation signatures). Defense:
//!    the dither writes a maximum-density random transition comb,
//!    and the certificate bounds the old-period autocorrelation of
//!    the post-treatment guard-band signal.
//! 3. **Certificate forgery / replay** — every field is bound by a
//!    BLAKE3 digest over the canonical body (signable by the
//!    dc-cert hybrid Ed25519+ML-DSA machinery at the CLI layer);
//!    verdicts are recomputed from raw statistics, not trusted
//!    from stored booleans.
//!
//! ## What the certificate proves
//!
//! That, for every track of the target device, (a) the executed
//! off-track plan delivered hard-switch or repeated-thermal
//! coverage to 100% of the guard band columns, and (b) the
//! residual correlation between the post-treatment magnetization
//! and the previous recording is bounded (99% one-sided
//! confidence) below an amplitude SNR of −20 dB relative to the
//! read path's Johnson-Nyquist noise floor — the regime where an
//! MFM distinguisher needs more guard-band cells than the platter
//! physically contains to separate "wiped" from "never written".

pub mod curie;
pub mod microstep;
pub mod prml;
pub mod proof;
pub mod remanence;
pub mod track;

/// Remanence annihilation errors.
#[derive(Debug, thiserror::Error)]
pub enum RemanenceError {
    #[error("track geometry impossible: {0}")]
    Geometry(String),
    #[error("micro-step transport refused: {0}")]
    Transport(String),
    #[error("physics model violation: {0}")]
    Physics(String),
    #[error("certificate verification failed: {0}")]
    Certificate(String),
    #[error("platter simulation failure: {0}")]
    Simulation(String),
}

/// Splitmix64: deterministic, well-mixed stream PRNG for the platter
/// simulations (same house pattern as the photon fountain / swarm rigs).
/// Carries no secrecy — its only job is mapping a `u64` seed to a
/// reproducible physics tape.
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
        // 53 bits of mantissa, fully determined.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Standard normal via Box-Muller (deterministic pairing).
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
