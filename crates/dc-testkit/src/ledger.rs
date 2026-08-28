use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssertionStatus {
    Passed,
    Failed,
    Waived,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssertionRecord {
    pub cell: String,
    pub id: String,
    pub expected: String,
    pub observed: String,
    pub artifact_path: Option<String>,
    pub status: AssertionStatus,
}

pub struct RigLedger {
    records: Mutex<Vec<AssertionRecord>>,
}

impl RigLedger {
    pub fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }

    /// Record and format assertion (CELL | ID | expected | observed | artifact-path) (Δ96).
    pub fn assert(
        &self,
        cell: &str,
        id: &str,
        expected: impl Display,
        observed: impl Display,
        artifact_path: Option<&str>,
    ) -> bool {
        let expected_str = expected.to_string();
        let observed_str = observed.to_string();
        let passed = expected_str == observed_str;

        let status = if passed {
            AssertionStatus::Passed
        } else {
            AssertionStatus::Failed
        };

        let formatted = format!(
            "{} | {} | {} | {} | {}",
            cell,
            id,
            expected_str,
            observed_str,
            artifact_path.unwrap_or("-")
        );

        if passed {
            println!("  [✓] {}", formatted);
        } else {
            eprintln!("  [✗] FAIL: {}", formatted);
        }

        let record = AssertionRecord {
            cell: cell.to_string(),
            id: id.to_string(),
            expected: expected_str,
            observed: observed_str,
            artifact_path: artifact_path.map(|s| s.to_string()),
            status,
        };

        self.records.lock().unwrap().push(record);
        passed
    }

    /// Record a structured waiver with reason (Δ104).
    pub fn waive(&self, cell: &str, id: &str, reason: &str) {
        println!("  [~] WAIVED: {} | {} | Reason: {}", cell, id, reason);
        let record = AssertionRecord {
            cell: cell.to_string(),
            id: id.to_string(),
            expected: "Waived".to_string(),
            observed: reason.to_string(),
            artifact_path: None,
            status: AssertionStatus::Waived,
        };
        self.records.lock().unwrap().push(record);
    }

    /// Check if all recorded assertions passed or were waived.
    pub fn is_all_green(&self) -> bool {
        self.records
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.status != AssertionStatus::Failed)
    }

    /// Extract all records.
    pub fn records(&self) -> Vec<AssertionRecord> {
        self.records.lock().unwrap().clone()
    }
}
