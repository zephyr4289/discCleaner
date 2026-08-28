use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestDrive {
    pub serial: String,
    pub model: String,
    pub size_bytes: u64,
    pub tbw_rated_tb: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareManifest {
    pub drives: Vec<ManifestDrive>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnduranceLedger {
    pub serial: String,
    pub cumulative_bytes_written: u64,
    pub total_runs: u64,
}

impl HardwareManifest {
    /// Verify that target drive serial exists in hardware manifest (Δ78 Guardian).
    pub fn verify_manifest_pinning(&self, target_serial: &str) -> Result<&ManifestDrive, String> {
        self.drives
            .iter()
            .find(|d| d.serial == target_serial)
            .ok_or_else(|| {
                format!(
                    "MANIFEST_REFUSAL: Target drive serial '{}' is not registered in hardware manifest! Refusing run to protect host disks.",
                    target_serial
                )
            })
    }
}

impl EnduranceLedger {
    /// Load or initialize ledger from persistent path.
    pub fn load_or_init(path: &Path, serial: &str) -> Self {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(ledger) = serde_json::from_str::<EnduranceLedger>(&content) {
                if ledger.serial == serial {
                    return ledger;
                }
            }
        }
        Self {
            serial: serial.to_string(),
            cumulative_bytes_written: 0,
            total_runs: 0,
        }
    }

    /// Check if endurance budget has at least 20% remaining (Δ76).
    pub fn check_budget(&self, drive: &ManifestDrive) -> Result<(), String> {
        let max_bytes = drive.tbw_rated_tb * 1_000_000_000_000;
        let used_fraction = self.cumulative_bytes_written as f64 / max_bytes as f64;

        if used_fraction >= 0.80 {
            return Err(format!(
                "ENDURANCE_GATE_REFUSAL: Drive '{}' has consumed {:.1}% of rated TBW! Refusing to wear sacrificial drive further.",
                self.serial, used_fraction * 100.0
            ));
        }

        Ok(())
    }

    /// Record a completed wipe run and save ledger.
    pub fn record_run(&mut self, path: &Path, bytes_written: u64) -> Result<(), String> {
        self.cumulative_bytes_written += bytes_written;
        self.total_runs += 1;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| e.to_string())
    }
}
