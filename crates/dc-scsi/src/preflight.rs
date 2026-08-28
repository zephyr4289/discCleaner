use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyReport {
    pub is_consistent: bool,
    pub ceiling_disclosed: bool,
    pub detail: String,
}

pub struct PreflightBattery;

impl PreflightBattery {
    /// Single-path internal consistency cross-check (Δ328).
    /// Cross-examines drive self-description across IDENTIFY words and READ CAPACITY (16).
    pub fn check_single_path_consistency(
        identify_lba: u64,
        read_capacity_16_lba: u64,
    ) -> ConsistencyReport {
        if identify_lba != read_capacity_16_lba {
            ConsistencyReport {
                is_consistent: false,
                ceiling_disclosed: true,
                detail: format!(
                    "CAPACITY_MASK detected: IDENTIFY reports {} LBAs, but READ CAPACITY (16) reports {} LBAs. Bridge masks capacity!",
                    identify_lba, read_capacity_16_lba
                ),
            }
        } else {
            ConsistencyReport {
                is_consistent: true,
                ceiling_disclosed: false,
                detail: "Single-path self-descriptions are internally consistent".to_string(),
            }
        }
    }
}
