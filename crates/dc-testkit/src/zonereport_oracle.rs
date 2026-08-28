use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneType {
    Conventional,
    SequentialWriteRequired,
    SequentialWritePreferred,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneCondition {
    Empty,
    ImplicitlyOpen,
    ExplicitlyOpen,
    Closed,
    Full,
    ReadOnly,
    Offline,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneDesc {
    pub zone_id: u64,
    pub start_lba: u64,
    pub capacity_lbas: u64,
    pub write_pointer_lba: u64,
    pub zone_type: ZoneType,
    pub condition: ZoneCondition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneReport {
    pub nr_zones: usize,
    pub max_open_zones: u32,
    pub zones: Vec<ZoneDesc>,
}

pub struct ZoneReportOracle;

impl ZoneReportOracle {
    /// Evaluate if every sequential zone reports FULL at capacity (Δ500).
    pub fn evaluate_full_coverage(report: &ZoneReport) -> Result<&'static str, &'static str> {
        for zone in &report.zones {
            match zone.zone_type {
                ZoneType::SequentialWriteRequired | ZoneType::SequentialWritePreferred => {
                    if zone.condition != ZoneCondition::Full
                        || zone.write_pointer_lba < zone.start_lba + zone.capacity_lbas
                    {
                        return Err("ZONE_COVERAGE_INCOMPLETE");
                    }
                }
                ZoneType::Conventional => {}
            }
        }
        Ok("ZONE_ATTESTED_FULL_COVERAGE")
    }
}
