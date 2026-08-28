use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FleetJobOutcome {
    Clean = 0,
    Interrupted = 1,
    GuardianRefused = 2,
    IoFailed = 3,
    VerificationFailed = 4,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetJobRecord {
    pub slot_id: usize,
    pub serial: String,
    pub outcome: FleetJobOutcome,
    pub exit_code: i32,
    pub cert_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetReport {
    pub batch_id: String,
    pub manifest_hash: String,
    pub merkle_fingerprint: String,
    pub records: Vec<FleetJobRecord>,
}

impl FleetReport {
    /// Derive aggregate fleet exit code according to strict severity hierarchy (Δ384):
    /// VerificationFailed (4) > IoFailed (3) > GuardianRefused (2) > Interrupted (1) > Clean (0)
    pub fn derive_aggregate_exit_code(&self) -> i32 {
        let max_outcome = self
            .records
            .iter()
            .map(|r| r.outcome)
            .max()
            .unwrap_or(FleetJobOutcome::Clean);

        match max_outcome {
            FleetJobOutcome::VerificationFailed => 4,
            FleetJobOutcome::IoFailed => 3,
            FleetJobOutcome::GuardianRefused => 2,
            FleetJobOutcome::Interrupted => 1,
            FleetJobOutcome::Clean => 0,
        }
    }

    /// Compute Merkle batch fingerprint across sorted child certificates/outcomes (Δ383).
    pub fn compute_merkle_fingerprint(records: &[FleetJobRecord]) -> String {
        let mut hasher = blake3::Hasher::new();
        for r in records {
            hasher.update(r.serial.as_bytes());
            hasher.update(format!("{:?}", r.outcome).as_bytes());
            if let Some(ref h) = r.cert_hash {
                hasher.update(h.as_bytes());
            }
        }
        hasher.finalize().to_hex().to_string()
    }
}
