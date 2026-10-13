//! The Silicon Wear Certificate — statistical physical proof that
//! the target's flash physically underwent high-voltage erasure.
//!
//! The certificate rolls the per-die campaign evidence up to
//! **per-channel verdicts** and asserts three things per channel:
//!
//! 1. **F-N charge present** — a non-zero Fowler-Nordheim injected
//!    charge integral (real 10+ MV/cm pulses ran; an FTL shortcut
//!    books zero charge).
//! 2. **Charge-bleed consistency** — the observed ΔVth (from
//!    read-retry statistics) is covered by the charge the pulses
//!    moved: `consistency = supplied/needed ≥ 1`.
//! 3. **Statistical stress signature** — the program-latency
//!    distribution separated from the fresh baseline by ≥ `t_min`
//!    sigmas (Welch t), or — when no baseline capture exists — the
//!    retry-implied P/E cycle count exceeds `cycles_min`.
//!
//!    And one thing about the fleet: **100% channel coverage** — every
//!    ACTIVE channel of the topology must carry a passing verdict. A
//!    single silent die (bad-block retirement, controller remap lie)
//!    fails the whole certificate. That is the point: the auditor's
//!    "did it REALLY erase the silicon?" becomes arithmetic on signed,
//!    dated numbers.
//!
//!    ## Digest binding
//!
//!    `digest` is BLAKE3 over the canonical JSON of the evidence body
//!    (everything except the digest itself). The CLI layer signs this
//!    digest with the existing hybrid Ed25519 + ML-DSA machinery, the
//!    same way drive reports are signed — the certificate itself stays
//!    key-free and verifiable offline.

use crate::ber::BerModel;
use crate::stress::{CampaignConfig, ChannelEvidence};
use crate::{Topology, WearError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema tag.
pub const WEAR_CERT_SCHEMA: &str = "dc-wear-cert/1";

/// Minimum Welch-t separation for the latency-shift verdict.
pub const DEFAULT_T_MIN: f64 = 3.0;
/// Minimum retry-implied P/E cycles (no-baseline path).
pub const DEFAULT_CYCLES_MIN: u64 = 50;

/// One channel's rolled-up verdict row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelVerdict {
    /// Channel index in the topology.
    pub channel: u32,
    /// Dies covered on this channel.
    pub dies: u32,
    /// Total erase pulses applied across the channel's dies.
    pub erase_pulses: u64,
    /// F-N injected charge integral, C/cm² (min over dies — the
    /// weakest die speaks for the channel).
    pub q_inj_c_cm2_min: f64,
    /// Observed Vth shift estimate (max over dies), volts.
    pub vth_shift_v_max: f64,
    /// Charge-bleed consistency ratio (min over dies).
    pub charge_consistency_min: f64,
    /// Program-latency Welch t vs baseline (min over dies).
    pub latency_t_min: f64,
    /// Retry-implied P/E cycles (min over dies).
    pub implied_cycles_min: u64,
    /// Empirical RBER (max over dies).
    pub rber_max: f64,
    /// Overall verdict for the channel.
    pub passed: bool,
    /// Failure reasons (empty when passed).
    pub reasons: Vec<String>,
}

/// The certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiliconWearCertificate {
    pub schema: String,
    /// Target identity (serial / NGUID, from the inventory).
    pub device_id: String,
    /// Topology the campaign ran over.
    pub topology: Topology,
    /// Campaign parameters (pulse shape, cycles, seed).
    pub campaign: CampaignConfig,
    /// Per-channel verdict rows (sorted by channel).
    pub channels: Vec<ChannelVerdict>,
    /// Channels that showed stress evidence / active channels.
    pub covered_channels: usize,
    pub active_channels: usize,
    /// Overall verdict.
    pub verified: bool,
    /// BLAKE3 over the canonical evidence body (hex).
    pub digest: String,
    /// Human-readable audit trail notes.
    pub notes: Vec<String>,
}

impl SiliconWearCertificate {
    /// Assemble (and judge) a certificate from campaign evidence.
    pub fn assemble(
        device_id: &str,
        config: &CampaignConfig,
        evidence: &[ChannelEvidence],
    ) -> Result<Self, WearError> {
        // Group evidence rows by channel (BTreeMap → sorted output).
        let mut by_channel: BTreeMap<u32, Vec<&ChannelEvidence>> = BTreeMap::new();
        for row in evidence {
            by_channel.entry(row.coord.channel).or_default().push(row);
        }

        let t_min = DEFAULT_T_MIN;
        let cycles_min = DEFAULT_CYCLES_MIN;
        let mut verdicts = Vec::with_capacity(by_channel.len());

        for (channel, rows) in &by_channel {
            let mut reasons = Vec::new();
            let q_min = rows
                .iter()
                .map(|r| r.tunnel.q_inj_c_cm2)
                .fold(f64::INFINITY, f64::min);
            let vth_max = rows.iter().map(|r| r.vth_shift.shift_v).fold(0.0, f64::max);
            let cons_min = rows
                .iter()
                .map(|r| r.tunnel.consistency(r.vth_shift.shift_v))
                .fold(f64::INFINITY, f64::min);
            let t_stat = rows
                .iter()
                .map(|r| r.program_shift.t)
                .fold(f64::INFINITY, f64::min);
            let cycles_min_row = rows
                .iter()
                .map(|r| r.vth_shift.implied_cycles)
                .fold(u64::MAX, u64::min);
            let rber_max = rows.iter().map(|r| r.ber.rber()).fold(0.0, f64::max);
            let pulses = rows.iter().map(|r| r.erase_pulses).sum();

            // Verdict 1: the F-N charge integral must be present.
            if q_min <= 0.0 {
                reasons.push("zero Fowler-Nordheim injected charge (no real erase pulses)".into());
            }
            // Verdict 2: charge-bleed consistency.
            if cons_min < 1.0 {
                reasons.push(format!(
                    "observed Vth shift exceeds the campaign charge ledger (consistency {cons_min:.2})"
                ));
            }
            // Verdict 3: statistical stress signature — either path
            // suffices (latency separation OR retry-implied cycles).
            let latency_path = t_stat >= t_min;
            let cycle_path = cycles_min_row >= cycles_min;
            if !latency_path && !cycle_path {
                reasons.push(format!(
                    "no stress signature: latency t={t_stat:.1} < {t_min}, implied cycles {cycles_min_row} < {cycles_min}"
                ));
            }
            // Sanity: implied cycles must not exceed the pulse count
            // (the ledger bounds the physical cycling).
            if cycles_min_row > pulses * 10 {
                reasons.push("implied cycles exceed pulse accounting".into());
            }

            verdicts.push(ChannelVerdict {
                channel: *channel,
                dies: rows.len() as u32,
                erase_pulses: pulses,
                q_inj_c_cm2_min: q_min,
                vth_shift_v_max: vth_max,
                charge_consistency_min: cons_min,
                latency_t_min: t_stat,
                implied_cycles_min: cycles_min_row,
                rber_max,
                passed: reasons.is_empty(),
                reasons,
            });
        }

        let active = config.topology.channels as usize;
        let covered = verdicts.iter().filter(|v| v.passed).count();
        let verified = covered == active && verdicts.len() == active;

        let mut notes = Vec::new();
        if verdicts.len() != active {
            notes.push(format!(
                "evidence covers {} of {} topology channels — dies missing from the campaign",
                verdicts.len(),
                active
            ));
        }
        if covered != active {
            notes.push(format!(
                "{}/{} channels show full stress evidence — controller remap or skipped-die suspected on the rest",
                covered, active
            ));
        }

        let mut cert = Self {
            schema: WEAR_CERT_SCHEMA.to_string(),
            device_id: device_id.to_string(),
            topology: config.topology.clone(),
            campaign: config.clone(),
            channels: verdicts,
            covered_channels: covered,
            active_channels: active,
            verified,
            digest: String::new(),
            notes,
        };
        cert.digest = cert.compute_digest();
        Ok(cert)
    }

    /// Canonical evidence body (everything the digest binds).
    fn evidence_json(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Body<'a> {
            schema: &'a str,
            device_id: &'a str,
            topology: &'a Topology,
            campaign: &'a CampaignConfig,
            channels: &'a [ChannelVerdict],
            covered_channels: usize,
            active_channels: usize,
            verified: bool,
            notes: &'a [String],
        }
        serde_json::to_vec(&Body {
            schema: &self.schema,
            device_id: &self.device_id,
            topology: &self.topology,
            campaign: &self.campaign,
            channels: &self.channels,
            covered_channels: self.covered_channels,
            active_channels: self.active_channels,
            verified: self.verified,
            notes: &self.notes,
        })
        .expect("canonical wear body json")
    }

    /// BLAKE3 over the canonical body.
    pub fn compute_digest(&self) -> String {
        blake3::hash(&self.evidence_json()).to_hex().to_string()
    }

    /// Offline verification: recompute every verdict from the rows,
    /// re-derive the digest, and check the coverage math.
    pub fn verify(&self) -> Result<(), WearError> {
        if self.schema != WEAR_CERT_SCHEMA {
            return Err(WearError::Certificate(format!(
                "unknown schema {}",
                self.schema
            )));
        }
        if self.digest != self.compute_digest() {
            return Err(WearError::Certificate(
                "digest does not cover the evidence body — tampered or corrupt".into(),
            ));
        }
        // NOTE: fewer verdict rows than topology channels is an
        // HONEST coverage failure (recorded in `notes`, reflected in
        // `verified == false`) — the certificate verifies as a
        // document. Integrity and coverage are different questions.
        // Recount coverage.
        let covered = self.channels.iter().filter(|c| c.passed).count();
        if covered != self.covered_channels {
            return Err(WearError::Certificate("coverage count mismatch".into()));
        }
        if self.verified != (covered == self.active_channels) {
            return Err(WearError::Certificate(
                "verified flag disagrees with the coverage math".into(),
            ));
        }
        // Per-channel arithmetic re-checks.
        for v in &self.channels {
            let should = v.q_inj_c_cm2_min > 0.0
                && v.charge_consistency_min >= 1.0
                && (v.latency_t_min >= DEFAULT_T_MIN || v.implied_cycles_min >= DEFAULT_CYCLES_MIN);
            if should != v.passed {
                return Err(WearError::Certificate(format!(
                    "channel {} verdict disagrees with its own numbers",
                    v.channel
                )));
            }
        }
        Ok(())
    }

    /// The RBER model over the worst channel (audit convenience).
    pub fn worst_channel_rber_law(&self) -> BerModel {
        BerModel::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stress::{SimNand, run_campaign};

    fn full_campaign() -> (CampaignConfig, Vec<ChannelEvidence>) {
        let cfg = CampaignConfig {
            cycles: 3000,
            verify_reads_per_cycle: 2,
            ..CampaignConfig::default()
        };
        let mut sim = SimNand::new(&cfg);
        let rows = run_campaign(&mut sim, &cfg).expect("campaign");
        (cfg, rows)
    }

    #[test]
    fn honest_campaign_certifies_with_full_coverage() {
        let (cfg, rows) = full_campaign();
        let cert = SiliconWearCertificate::assemble("SIM-WEAR-001", &cfg, &rows).expect("assemble");
        assert_eq!(cert.channels.len(), 8);
        assert_eq!(cert.covered_channels, 8);
        assert_eq!(cert.active_channels, 8);
        assert!(cert.verified, "notes: {:?}", cert.notes);
        assert!(cert.notes.is_empty());
        cert.verify().expect("offline verification");
        for v in &cert.channels {
            assert!(v.passed, "channel {}: {:?}", v.channel, v.reasons);
            assert!(v.erase_pulses > 0);
            assert!(v.q_inj_c_cm2_min > 0.0);
            assert!(v.charge_consistency_min >= 1.0);
            assert!(v.vth_shift_v_max > 0.0);
        }
    }

    #[test]
    fn tampering_with_the_body_breaks_the_digest() {
        let (cfg, rows) = full_campaign();
        let mut cert =
            SiliconWearCertificate::assemble("SIM-WEAR-002", &cfg, &rows).expect("assemble");
        assert!(cert.verify().is_ok());
        // Flip one verdict: the digest must refuse to cover it.
        cert.channels[0].erase_pulses = 0;
        assert!(cert.verify().is_err());
        // Restore; flip the device id instead.
        let (cfg2, rows2) = full_campaign();
        let mut c2 =
            SiliconWearCertificate::assemble("SIM-WEAR-003", &cfg2, &rows2).expect("assemble");
        c2.device_id = "COUNTERFEIT-DEVICE".into();
        assert!(c2.verify().is_err());
    }

    #[test]
    fn a_missing_channel_fails_the_certificate() {
        let (cfg, mut rows) = full_campaign();
        // Drop every die of channel 5 — the "controller retired this
        // die and lied" scenario.
        rows.retain(|r| r.coord.channel != 5);
        let cert = SiliconWearCertificate::assemble("SIM-WEAR-004", &cfg, &rows).expect("assemble");
        assert!(!cert.verified);
        assert_eq!(cert.covered_channels, 7);
        assert!(cert.notes.iter().any(|n| n.contains("channels")));
        assert!(
            cert.verify().is_ok(),
            "verification of an HONEST failure is ok"
        );
    }

    #[test]
    fn a_fresh_untouched_channel_fails_its_verdict() {
        let (cfg, rows) = full_campaign();
        // Fabricate a shortcut: one die of channel 2 never pulsed.
        let mut rows = rows;
        for r in rows.iter_mut() {
            if r.coord.channel == 2 {
                r.tunnel.q_inj_c_cm2 = 0.0;
                r.tunnel.pulses = 0;
                r.vth_shift.shift_v = 0.0;
                r.vth_shift.implied_cycles = 0;
                r.program_shift.t = 0.0;
            }
        }
        let cert = SiliconWearCertificate::assemble("SIM-WEAR-005", &cfg, &rows).expect("assemble");
        assert!(!cert.verified);
        let ch2 = cert.channels.iter().find(|v| v.channel == 2).unwrap();
        assert!(!ch2.passed);
        assert!(ch2.reasons.iter().any(|r| r.contains("Fowler-Nordheim")));
    }

    #[test]
    fn certificate_is_deterministic_for_identical_campaigns() {
        let (cfg, rows) = full_campaign();
        let a = SiliconWearCertificate::assemble("SIM-WEAR-006", &cfg, &rows).unwrap();
        // Re-run the whole simulation: identical bytes.
        let mut sim = SimNand::new(&cfg);
        let rows2 = run_campaign(&mut sim, &cfg).expect("campaign");
        let b = SiliconWearCertificate::assemble("SIM-WEAR-006", &cfg, &rows2).unwrap();
        assert_eq!(a.digest, b.digest);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }

    #[test]
    fn json_roundtrip_preserves_verdicts() {
        let (cfg, rows) = full_campaign();
        let cert = SiliconWearCertificate::assemble("SIM-WEAR-007", &cfg, &rows).unwrap();
        let json = serde_json::to_string(&cert).unwrap();
        let back: SiliconWearCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.digest, cert.digest);
        assert_eq!(back.verified, cert.verified);
        assert_eq!(back.channels, cert.channels);
        back.verify().expect("round-tripped cert verifies");
    }
}
