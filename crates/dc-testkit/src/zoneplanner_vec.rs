use crate::zonereport_oracle::{ZoneCondition, ZoneDesc, ZoneReport, ZoneType};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneOp {
    Reset { zone_id: u64 },
    Open { zone_id: u64 },
    Write { zone_id: u64, target_lba: u64, window_idx: u64 },
    Finish { zone_id: u64 },
}

pub struct ZoneDisciplinePlanner;

impl ZoneDisciplinePlanner {
    /// Plan deterministic per-zone operations enforcing sequential write pointer progression (Δ496, Δ497).
    pub fn plan_zone_pass(
        report: &ZoneReport,
        _pass_num: u8,
        window_size_lbas: u64,
    ) -> Vec<ZoneOp> {
        let mut ops = Vec::new();

        for zone in &report.zones {
            match zone.zone_type {
                ZoneType::SequentialWriteRequired | ZoneType::SequentialWritePreferred => {
                    // Reset zone first to enable fresh pass
                    ops.push(ZoneOp::Reset { zone_id: zone.zone_id });
                    ops.push(ZoneOp::Open { zone_id: zone.zone_id });

                    let num_windows = (zone.capacity_lbas + window_size_lbas - 1) / window_size_lbas;
                    for k in 0..num_windows {
                        let target_lba = zone.start_lba + k * window_size_lbas;
                        ops.push(ZoneOp::Write {
                            zone_id: zone.zone_id,
                            target_lba,
                            window_idx: k,
                        });
                    }

                    ops.push(ZoneOp::Finish { zone_id: zone.zone_id });
                }
                ZoneType::Conventional => {
                    let num_windows = (zone.capacity_lbas + window_size_lbas - 1) / window_size_lbas;
                    for k in 0..num_windows {
                        let target_lba = zone.start_lba + k * window_size_lbas;
                        ops.push(ZoneOp::Write {
                            zone_id: zone.zone_id,
                            target_lba,
                            window_idx: k,
                        });
                    }
                }
            }
        }

        ops
    }

    /// Permanent ban on ZONE APPEND commands to protect recipe bijection (Δ497).
    pub fn evaluate_write_command_safety(is_append_command: bool) -> Result<(), &'static str> {
        if is_append_command {
            Err("ZONE_APPEND_BANNED_TO_PRESERVE_RECIPE_BIJECTION")
        } else {
            Ok(())
        }
    }

    /// Disambiguate FULL zone pass strictly from journal transactions (Δ498).
    pub fn resolve_full_zone_ambiguity(
        zone_desc: &ZoneDesc,
        journal_recorded_pass: u8,
    ) -> Result<u8, &'static str> {
        if zone_desc.condition != ZoneCondition::Full {
            return Err("ZONE_NOT_FULL");
        }
        // Device report alone cannot distinguish Pass 1 from Pass 2; journal is sole authority!
        Ok(journal_recorded_pass)
    }

    /// Evaluate timing collapse indicating Drive-Managed SMR (Δ501).
    pub fn evaluate_smr_timing_anomaly(
        first_sweep_kib_s: u64,
        rewrite_sweep_kib_s: u64,
    ) -> Option<&'static str> {
        // If rewrite speed collapses to < 20% of first sweep baseline
        if first_sweep_kib_s > 0 && rewrite_sweep_kib_s < first_sweep_kib_s / 5 {
            Some("suspected-managed-smr: rewrite throughput collapse observed")
        } else {
            None
        }
    }
}
