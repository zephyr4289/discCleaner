use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScsiSenseVerdict {
    Progress { permille: u16 },
    CompletedExpectUA,
    UnitAttention { asc: u8, ascq: u8 },
    Failed { key: u8, asc: u8, ascq: u8 },
    NoSenseConsumed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScsiMechanismGrade {
    SanitizePurgeGrade,
    FormatUnitGrade, // Capped below Purge per SBC-3
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScsiLunDesignator {
    pub naa_wwn: String,
    pub paths: Vec<String>,
}

pub struct ScsiDevMock {
    pub is_in_progress: bool,
    pub progress_permille: u16,
    pub unit_attention_pending: bool,
    pub sense_consumed: bool,
    pub designator: ScsiLunDesignator,
}

impl ScsiDevMock {
    pub fn new(naa_wwn: &str, paths: Vec<String>) -> Self {
        Self {
            is_in_progress: false,
            progress_permille: 0,
            unit_attention_pending: false,
            sense_consumed: false,
            designator: ScsiLunDesignator {
                naa_wwn: naa_wwn.to_string(),
                paths,
            },
        }
    }

    /// Issue SCSI SANITIZE command (requires IMMED=1 per Δ288).
    pub fn issue_sanitize(&mut self, immed: bool) -> Result<(), &'static str> {
        if !immed {
            return Err("BLOCKING_IMMED_0_FORBIDDEN");
        }
        self.is_in_progress = true;
        self.progress_permille = 0;
        self.sense_consumed = false;
        self.unit_attention_pending = false;
        Ok(())
    }

    /// Advance simulated sanitize progress.
    pub fn advance_progress(&mut self, permille: u16) {
        self.progress_permille = permille;
        self.sense_consumed = false;
        if permille >= 1000 {
            self.is_in_progress = false;
            self.unit_attention_pending = true;
        }
    }

    /// Execute REQUEST SENSE polling with channel consumption semantics (Δ286, Δ287).
    pub fn request_sense(&mut self) -> ScsiSenseVerdict {
        if self.unit_attention_pending {
            self.unit_attention_pending = false; // Consumed!
            return ScsiSenseVerdict::UnitAttention {
                asc: 0x29,  // POWER ON, RESET, OR BUS DEVICE RESET OCCURRED / SANITIZE COMPLETED
                ascq: 0x00,
            };
        }

        if self.is_in_progress {
            if self.sense_consumed {
                // Sense was already read and cleared by the previous request
                return ScsiSenseVerdict::NoSenseConsumed;
            }
            self.sense_consumed = true; // Consumed upon reading!
            return ScsiSenseVerdict::Progress {
                permille: self.progress_permille,
            };
        }

        ScsiSenseVerdict::CompletedExpectUA
    }
}
