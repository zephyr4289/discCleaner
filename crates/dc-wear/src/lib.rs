//! # dc-wear — Silicon-Level Analog Flash Degradation Analysis &
//! Charge Bleed (v0.13.0, Frontier 2)
//!
//! **The doubt this crate kills:** after a 3-pass NIST 800-88 Clear,
//! an auditor asks *"did the flash controller ACTUALLY erase the
//! cells — or did it silently remap bad blocks, keep the original
//! charge states, and tell the software what it wanted to hear?"*
//! Software-visible readback cannot answer that question: the FTL
//! owns the mapping, and a lie at the firmware layer is invisible to
//! a lie detector that runs on top of the same firmware.
//!
//! dc-wear measures the **physics** instead of the firmware:
//!
//! * [`latency`] — sub-microsecond program/erase latency capture.
//!   Worn floating gates trap charge; trapped charge raises the
//!   cell's threshold voltage tail, which forces the controller's
//!   ISPP (incremental step-pulse program) loops to run longer and
//!   erase-verify retries to multiply. Latency variance across
//!   channels is a wear signature the FTL cannot fake without
//!   also faking the timing the host observes.
//! * [`vth`] — threshold-voltage (Vth) distribution modeling: the
//!   per-level Gaussian cell populations, their mean shift ΔVth and
//!   σ-widening after P/E stress, and the estimation of ΔVth from
//!   observable read-retry behavior (the controller's own
//!   compensation is the witness against its own silence).
//! * [`tunnel`] — Fowler-Nordheim tunneling proof: erase pulses at
//!   oxide fields around 10 MV/cm strip electrons off the floating
//!   gate THROUGH the dielectric. Every pulse injects charge
//!   through the tunnel oxide; the cumulative injected charge
//!   density (Q_inj) is the physical, unfakeable quantity that
//!   both wears the oxide and proves erasure pulses actually ran.
//! * [`ber`] — raw bit error rate distributions per channel vs P/E
//!   cycles (the classic power-law endurance curve), distinguishing
//!   fresh media from cycled media far below the ECC wall.
//! * [`stress`] — the P/E cycle stress campaign driver: erase/write
//!   pulse trains with instrumentation hooks over the [`stress::
//!   NandProbe`] trait (a simulated physics backend for CI and
//!   `dc wear simulate`; real device backends land on top of
//!   dc-nvme/dc-ata timing paths).
//! * [`certificate`] — the **Silicon Wear Certificate**: the
//!   statistical, per-channel physical proof that high-voltage
//!   erase pulses stressed the floating-gate dielectric across
//!   100% of active channels — evidence the hardware physically
//!   underwent erasure rather than an FTL shortcut.
//!
//! ## Threat model
//!
//! 1. **Controller remap lie** — bad blocks quietly retired,
//!    original data intact elsewhere: no P/E pulse train hits the
//!    retired die → its latency/Vth/BER statistics stay FRESH → the
//!    channel coverage check fails the certificate.
//! 2. **FTL bookkeeping lie** — erase recorded without pulses: F-N
//!    charge accounting is pulse-derived; zero injected charge over
//!    a "wiped" channel is physically impossible after a real
//!    erase.
//! 3. **Replay of a genuine certificate** — every certificate binds
//!    the device identity, the campaign seed, the pulse count and
//!    the observed statistics under a BLAKE3 digest (signable by
//!    the dc-cert hybrid Ed25519+ML-DSA machinery at the CLI
//!    layer).
//!
//!    ## What the certificate proves
//!
//!    That every active physical channel of the target device shows
//!    statistically significant P/E stress evidence — ΔVth shift above
//!    the fresh-media confidence band, elevated program-latency
//!    variance, and RBER consistent with the cycled population — with
//!    the Fowler-Nordheim charge integral that only real high-voltage
//!    erase pulses can produce.

pub mod ber;
pub mod certificate;
pub mod latency;
pub mod stress;
pub mod tunnel;
pub mod vth;

/// Silicon wear measurement errors.
#[derive(Debug, thiserror::Error)]
pub enum WearError {
    #[error("channel {channel} measurement incomplete: {reason}")]
    IncompleteChannel { channel: u32, reason: String },
    #[error("coverage failure: {covered}/{active} channels show stress evidence")]
    Coverage { covered: usize, active: usize },
    #[error("physics model violation: {0}")]
    Physics(String),
    #[error("certificate verification failed: {0}")]
    Certificate(String),
    #[error("probe I/O error: {0}")]
    Probe(String),
}

/// A NAND flash channel coordinate: (channel, chip-enable, LUN).
///
/// One "channel" in the certificate sense is a physical flash data
/// bus; the CEs and LUNs behind it share the wear budget because
/// they share the erase-pulse driver.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct ChannelCoord {
    pub channel: u32,
    pub ce: u32,
    pub lun: u32,
}

impl ChannelCoord {
    pub const fn new(channel: u32, ce: u32, lun: u32) -> Self {
        Self { channel, ce, lun }
    }
}

/// The die topology of one target device (from dc-probe inventory).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Topology {
    /// Active physical channels (the coverage denominator).
    pub channels: u32,
    /// Chip-enables per channel.
    pub ces_per_channel: u32,
    /// LUNs per CE.
    pub luns_per_ce: u32,
}

impl Topology {
    /// Enumerate every (channel, ce, lun) die coordinate, row-major.
    pub fn dies(&self) -> Vec<ChannelCoord> {
        let mut v =
            Vec::with_capacity((self.channels * self.ces_per_channel * self.luns_per_ce) as usize);
        for c in 0..self.channels {
            for e in 0..self.ces_per_channel {
                for l in 0..self.luns_per_ce {
                    v.push(ChannelCoord::new(c, e, l));
                }
            }
        }
        v
    }

    /// Distinct channel indices (the 100%-coverage set).
    pub fn channel_ids(&self) -> Vec<u32> {
        (0..self.channels).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_enumerates_all_dies_row_major() {
        let t = Topology {
            channels: 4,
            ces_per_channel: 2,
            luns_per_ce: 2,
        };
        let dies = t.dies();
        assert_eq!(dies.len(), 16);
        // Sorted, unique, starts at origin.
        assert_eq!(dies[0], ChannelCoord::new(0, 0, 0));
        assert_eq!(dies[15], ChannelCoord::new(3, 1, 1));
        let mut sorted = dies.clone();
        sorted.sort();
        let mut dedup: Vec<ChannelCoord> = Vec::new();
        for d in sorted {
            if dedup.last() != Some(&d) {
                dedup.push(d);
            }
        }
        assert_eq!(dedup.len(), dies.len(), "coordinates are unique");
        assert_eq!(t.channel_ids(), vec![0, 1, 2, 3]);
    }
}
