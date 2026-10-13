//! The P/E cycle stress campaign driver.
//!
//! A **campaign** is a scripted, instrumented sequence of erase and
//! write pulses applied to every die of a target device, with the
//! measurement hooks that turn physics into evidence:
//!
//! * per-operation latency capture (sub-µs, the ISPP/erase-retry
//!   signature),
//! * per-channel read-retry and RBER tallies on verify reads,
//! * Fowler-Nordheim charge accounting per channel.
//!
//! The device side is the [`NandProbe`] trait — deliberately narrow
//! so a real backend (NVMe/ATA passthrough timing, vendor log pages)
//! and the deterministic [`SimNand`] physics model implement the
//! exact same contract. A campaign that passes in simulation
//! exercises identical arithmetic to one on real silicon.

use crate::ber::BerTally;
use crate::latency::{LatencyStats, ShiftEvidence};
use crate::tunnel::{ErasePulse, TunnelAccountant};
use crate::vth::{EstimatedVthShift, VthEstimator};
use crate::{ChannelCoord, Topology, WearError};
use serde::{Deserialize, Serialize};

/// One die's observed response to a pulse (the probe's report).
#[derive(Debug, Clone, Copy)]
pub struct PulseObservation {
    /// Wall-clock time the operation took, ns.
    pub latency_ns: u64,
    /// Bit errors observed in the follow-up verify read.
    pub verify_errors: u64,
    /// Bits covered by the verify read.
    pub verify_bits: u64,
    /// Read-retry events during the verify read.
    pub read_retries: u64,
}

/// The device-side contract: apply pulses, report measurements.
///
/// Real backends implement this over passthrough I/O with
/// high-resolution timestamps; [`SimNand`] implements it with the
/// deterministic wear physics model.
pub trait NandProbe {
    /// Apply one erase pulse to the die at `coord`; report what the
    /// operation looked like from the host.
    fn erase_pulse(&mut self, coord: ChannelCoord) -> Result<PulseObservation, WearError>;
    /// Apply one program pulse to the die at `coord`.
    fn program_pulse(&mut self, coord: ChannelCoord) -> Result<PulseObservation, WearError>;
    /// Baseline (fresh-media) latency profile for this die, if the
    /// probe captured one before the campaign started.
    fn baseline_latency(&self, coord: ChannelCoord) -> Option<Vec<u64>>;
}

/// Erase pulse shape the campaign applies (operator-configurable).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PulseShape {
    pub field_mv_cm: f64,
    pub duration_us: f64,
}

impl Default for PulseShape {
    fn default() -> Self {
        // A standard erase regime: ~10.5 MV/cm across the tunnel
        // oxide, 1 ms pulses.
        Self {
            field_mv_cm: 10.5,
            duration_us: 1000.0,
        }
    }
}

/// Campaign configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    pub topology: Topology,
    /// Full erase+verify cycles per die.
    pub cycles: u32,
    /// Verify reads per cycle (BER / retry statistics sample size).
    pub verify_reads_per_cycle: u32,
    pub pulse: PulseShape,
    /// Floating-gate capacitance per cell, fF (charge-bleed check).
    pub c_fg_ff: f64,
    /// Cells per channel (ledger scale).
    pub cells_per_channel: u64,
    /// Deterministic physics seed (SimNand).
    pub seed: u64,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            topology: Topology {
                channels: 8,
                ces_per_channel: 2,
                luns_per_ce: 2,
            },
            cycles: 2000,
            verify_reads_per_cycle: 2,
            pulse: PulseShape::default(),
            c_fg_ff: 1.0,
            cells_per_channel: 1_000_000_000,
            seed: 42,
        }
    }
}

/// Per-channel accumulated evidence from one campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelEvidence {
    pub coord: ChannelCoord,
    /// Erase pulses applied to this die.
    pub erase_pulses: u64,
    /// Program pulses applied to this die.
    pub program_pulses: u64,
    /// Fowler-Nordheim charge ledger (the unfakeable quantity).
    pub tunnel: TunnelAccountant,
    /// Latency statistics over the pulse train.
    pub erase_latency: LatencyStats,
    pub program_latency: LatencyStats,
    /// Fresh-baseline comparison for program ops.
    pub program_shift: ShiftEvidence,
    /// BER / retry tallies.
    pub ber: BerTally,
    /// Vth shift estimated from retry behavior.
    pub vth_shift: EstimatedVthShift,
}

impl ChannelEvidence {
    /// The channel this row attests for (rollup key).
    pub fn channel(&self) -> u32 {
        self.coord.channel
    }
}

/// Run one full stress campaign over `probe`.
///
/// Every die of every channel receives the same scripted pulse
/// train; the evidence rows come back per-die (the certificate
/// rolls them up per-channel). Baseline latency, when the probe
/// provides one, anchors the statistical shift evidence.
pub fn run_campaign(
    probe: &mut dyn NandProbe,
    config: &CampaignConfig,
) -> Result<Vec<ChannelEvidence>, WearError> {
    if config.cycles == 0 {
        return Err(WearError::Physics(
            "a wear campaign with zero cycles produces no evidence".into(),
        ));
    }
    let estimator = VthEstimator::new(
        crate::vth::VthDistribution::new(-1.0, 0.12),
        crate::vth::VthDistribution::new(2.0, 0.20),
    );
    let mut rows = Vec::new();

    for coord in config.topology.dies() {
        // -- baseline latency (if the probe has one) --
        let baseline = probe
            .baseline_latency(coord)
            .map(|b| LatencyStats::compute(&b));

        // -- pulse train with instrumentation --
        let mut tunnel = TunnelAccountant::new(config.c_fg_ff, config.cells_per_channel);
        let pulse = ErasePulse {
            field_mv_cm: config.pulse.field_mv_cm,
            duration_us: config.pulse.duration_us,
        };
        let mut erase_lat: Vec<u64> = Vec::new();
        let mut prog_lat: Vec<u64> = Vec::new();
        let mut ber = BerTally::new();

        for cycle in 0..config.cycles {
            let obs = probe.erase_pulse(coord)?;
            erase_lat.push(obs.latency_ns);
            tunnel.apply(&pulse);
            ber.observe(obs.verify_bits, obs.verify_errors, obs.read_retries);

            let obs = probe.program_pulse(coord)?;
            prog_lat.push(obs.latency_ns);
            ber.observe(obs.verify_bits, obs.verify_errors, obs.read_retries);

            // Extra verify reads widen the BER sample.
            for _ in 1..config.verify_reads_per_cycle {
                // Reuse the last observation's verify fields for the
                // additional sampling window (probes with dedicated
                // read ops fold them in here).
                ber.observe(obs.verify_bits, obs.verify_errors, obs.read_retries);
            }
            let _ = cycle;
        }

        let erase_stats = LatencyStats::compute(&erase_lat);
        let prog_stats = LatencyStats::compute(&prog_lat);
        let program_shift = match &baseline {
            Some(b) => ShiftEvidence::compare(b, &prog_stats),
            None => ShiftEvidence {
                t: 0.0,
                delta_mean_ns: 0.0,
                var_ratio: 1.0,
            },
        };
        // Vth estimate from the retry behavior the probe observed
        // (per-1k-read rate over the campaign's verify reads).
        let reads = config.cycles as u64 * (config.verify_reads_per_cycle as u64 + 1) * 2;
        let retry_rate = ber.retry_rate_per_1k(reads);
        let vth_shift = estimator.estimate(retry_rate);

        rows.push(ChannelEvidence {
            coord,
            erase_pulses: tunnel.pulses,
            program_pulses: config.cycles as u64,
            tunnel,
            erase_latency: erase_stats,
            program_latency: prog_stats,
            program_shift,
            ber,
            vth_shift,
        });
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// SimNand — deterministic physics model (CI, drills, `dc wear simulate`)
// ---------------------------------------------------------------------------

/// Deterministic NAND physics backend.
///
/// Models the measurable behavior of a wearing die:
///
/// * **Erase latency** grows with accumulated cycles (erase-verify
///   retries multiply as the Vth tail drifts): L = L0·(1 + k·N^γ)
///   plus log-normal per-op jitter.
/// * **Program latency** (ISPP steps) grows similarly.
/// * **Verify errors** follow the RBER power law with per-op noise.
/// * **Read retries** grow with the Vth-distribution overlap.
///
/// The PRNG is xorshift64* seeded per die — fully reproducible.
pub struct SimNand {
    config: CampaignConfig,
    /// Cycles accumulated per die.
    cycles: std::collections::HashMap<(u32, u32, u32), u64>,
    rng: u64,
    baseline: bool,
}

impl SimNand {
    pub fn new(config: &CampaignConfig) -> Self {
        Self {
            config: config.clone(),
            cycles: std::collections::HashMap::new(),
            rng: config.seed ^ 0x5DEECE66D,
            baseline: true,
        }
    }

    fn next_f64(&mut self) -> f64 {
        // xorshift64* → uniform [0,1)
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Log-normal-ish positive jitter: exp(N(0, s)).
    fn jitter(&mut self, s: f64) -> f64 {
        // Box-Muller with the uniforms we have.
        let u1 = self.next_f64().max(1e-12);
        let u2 = self.next_f64();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        (z * s).exp()
    }
}

impl NandProbe for SimNand {
    fn erase_pulse(&mut self, coord: ChannelCoord) -> Result<PulseObservation, WearError> {
        let key = (coord.channel, coord.ce, coord.lun);
        let n = *self.cycles.entry(key).or_insert(0);
        // Erase latency: verify retries grow with wear.
        let wear = 1.0 + 0.9 * (n as f64 / 2000.0).min(6.0);
        let lat = (85_000.0 * wear * self.jitter(0.3)) as u64;
        // Verify errors: RBER power law over a 4 KiB window.
        let law = crate::ber::BerModel::default();
        let rber = law.rber(n.min(100_000));
        let bits = 4096 * 8;
        let expected = rber * bits as f64;
        let errors = (expected * self.jitter(0.4).max(0.05)).round() as u64;
        // Retries fire on margin erosion — Vth-distribution overlap
        // growth — which begins orders of magnitude before hard
        // errors. Model: retry probability per read grows as
        // (N/N_end)^1.5 toward ~35% at the endurance budget.
        let x = (n as f64 / 100_000.0).min(1.0);
        let retry_prob = 0.35 * x.powf(1.5);
        let retries = if self.next_f64() < retry_prob { 1 } else { 0 };
        self.cycles.insert(key, n + 1);
        Ok(PulseObservation {
            latency_ns: lat,
            verify_errors: errors,
            verify_bits: bits,
            read_retries: retries,
        })
    }

    fn program_pulse(&mut self, coord: ChannelCoord) -> Result<PulseObservation, WearError> {
        let key = (coord.channel, coord.ce, coord.lun);
        let n = *self.cycles.entry(key).or_insert(0);
        // ISPP steps grow with wear.
        let wear = 1.0 + 1.4 * (n as f64 / 2000.0).min(6.0);
        let lat = (450_000.0 * wear * self.jitter(0.45)) as u64;
        let law = crate::ber::BerModel::default();
        let rber = law.rber(n.min(100_000));
        let bits = 4096 * 8;
        let expected = rber * bits as f64;
        let errors = (expected * self.jitter(0.4).max(0.05)).round() as u64;
        // Same margin-erosion retry model as the erase path.
        let x = (n as f64 / 100_000.0).min(1.0);
        let retry_prob = 0.35 * x.powf(1.5);
        let retries = if self.next_f64() < retry_prob { 1 } else { 0 };
        Ok(PulseObservation {
            latency_ns: lat,
            verify_errors: errors,
            verify_bits: bits,
            read_retries: retries,
        })
    }

    fn baseline_latency(&self, coord: ChannelCoord) -> Option<Vec<u64>> {
        if !self.baseline {
            return None;
        }
        // Deterministic fresh-media baseline (same PRNG discipline,
        // computed with a local stream to avoid perturbing the run).
        let mut v = Vec::with_capacity(64);
        let mut s = self.config.seed
            ^ 0xB05E1
            ^ (coord.channel as u64)
            ^ ((coord.ce as u64) << 8)
            ^ ((coord.lun as u64) << 16);
        for _ in 0..64 {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            let u = ((s.wrapping_mul(0x2545F4914F6CDD1D) >> 11) as f64) / (1u64 << 53) as f64;
            // Fresh: ~450 µs program, ±25% log-normal-ish.
            v.push((450_000.0 * (0.75 + 0.5 * u)) as u64);
        }
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_covers_every_die_with_evidence() {
        let cfg = CampaignConfig {
            cycles: 500,
            verify_reads_per_cycle: 1,
            ..CampaignConfig::default()
        };
        let mut sim = SimNand::new(&cfg);
        let rows = run_campaign(&mut sim, &cfg).expect("campaign");
        // 8 × 2 × 2 = 32 dies.
        assert_eq!(rows.len(), 32);
        for row in &rows {
            assert_eq!(row.erase_pulses, 500);
            assert_eq!(row.program_pulses, 500);
            assert!(row.tunnel.q_inj_c_cm2 > 0.0);
            assert!(row.erase_latency.n == 500);
            assert!(row.program_latency.n == 500);
            assert!(row.ber.bits_read > 0);
        }
        // Every channel present (8 distinct).
        let channels: std::collections::HashSet<u32> =
            rows.iter().map(|r| r.coord.channel).collect();
        assert_eq!(channels.len(), 8);
    }

    #[test]
    fn worn_channels_show_latency_shift_and_vth_evidence() {
        let cfg = CampaignConfig {
            cycles: 3000,
            verify_reads_per_cycle: 2,
            ..CampaignConfig::default()
        };
        let mut sim = SimNand::new(&cfg);
        let rows = run_campaign(&mut sim, &cfg).expect("campaign");
        let row = &rows[0];
        // Program latency mean grew vs the 450 µs fresh baseline.
        assert!(
            row.program_latency.mean_ns > 600_000.0,
            "mean={}",
            row.program_latency.mean_ns
        );
        // Statistical separation from the baseline sample.
        assert!(row.program_shift.t > 3.0, "t={}", row.program_shift.t);
        assert!(row.program_shift.var_ratio > 1.0);
        // Retry-driven Vth estimate says the die was cycled hard.
        assert!(
            row.vth_shift.implied_cycles > 100,
            "cycles={}",
            row.vth_shift.implied_cycles
        );
        // And the F-N ledger covers the observed shift.
        assert!(
            row.tunnel.consistency(row.vth_shift.shift_v) >= 1.0,
            "consistency={}",
            row.tunnel.consistency(row.vth_shift.shift_v)
        );
    }

    #[test]
    fn zero_pulse_channel_is_not_cycled() {
        // A fresh probe (no pulses) has no evidence — the accounting
        // must show it.
        let cfg = CampaignConfig {
            cycles: 0,
            ..CampaignConfig::default()
        };
        let mut sim = SimNand::new(&cfg);
        // run_campaign with 0 cycles still builds rows (empty stats
        // are guarded per-die).
        let rows = run_campaign(&mut sim, &cfg);
        // Zero-cycle campaigns are rejected: LatencyStats::compute
        // asserts on empty samples — the campaign driver must refuse
        // before that.
        assert!(rows.is_err());
    }

    #[test]
    fn deterministic_replay_produces_identical_rows() {
        let cfg = CampaignConfig {
            cycles: 400,
            topology: Topology {
                channels: 2,
                ces_per_channel: 1,
                luns_per_ce: 1,
            },
            ..CampaignConfig::default()
        };
        let mut a = SimNand::new(&cfg);
        let mut b = SimNand::new(&cfg);
        let ra = run_campaign(&mut a, &cfg).expect("a");
        let rb = run_campaign(&mut b, &cfg).expect("b");
        for (x, y) in ra.iter().zip(rb.iter()) {
            assert_eq!(x.coord, y.coord);
            assert_eq!(x.erase_pulses, y.erase_pulses);
            assert_eq!(
                x.erase_latency.mean_ns as u64,
                y.erase_latency.mean_ns as u64
            );
            assert_eq!(x.ber.bit_errors, y.ber.bit_errors);
        }
    }

    #[test]
    fn sim_erasure_latencies_stay_in_physical_range() {
        let cfg = CampaignConfig {
            cycles: 100,
            topology: Topology {
                channels: 1,
                ces_per_channel: 1,
                luns_per_ce: 1,
            },
            ..CampaignConfig::default()
        };
        let mut sim = SimNand::new(&cfg);
        let rows = run_campaign(&mut sim, &cfg).expect("campaign");
        let r = &rows[0];
        // Erase block: 20 µs – 5 ms.
        assert!(r.erase_latency.min_ns > 20_000);
        assert!(r.erase_latency.max_ns < 5_000_000);
        // Program page: 100 µs – 10 ms.
        assert!(r.program_latency.min_ns > 100_000);
        assert!(r.program_latency.max_ns < 10_000_000);
    }
}
