use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignmentRow {
    pub slot_id: usize,
    pub expected_serial: String,
    pub plan_profile: String,
    pub scan_attestation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchManifest {
    pub batch_id: String,
    pub rows: Vec<AssignmentRow>,
}

impl BatchManifest {
    pub fn new(batch_id: &str, rows: Vec<AssignmentRow>) -> Self {
        Self {
            batch_id: batch_id.to_string(),
            rows,
        }
    }

    /// Compute cryptographic BLAKE3 manifest hash (Δ379).
    pub fn compute_manifest_hash(&self) -> String {
        let serialized = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&serialized).to_hex().to_string()
    }

    /// Validate manifest integrity and refuse ambiguous or duplicate assignments (Δ379).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.rows.is_empty() {
            return Err("EMPTY_BATCH_MANIFEST");
        }

        let mut seen_slots = HashSet::new();
        let mut seen_serials = HashSet::new();

        for row in &self.rows {
            if !seen_slots.insert(row.slot_id) {
                return Err("DUPLICATE_SLOT_IN_MANIFEST");
            }
            if !seen_serials.insert(&row.expected_serial) {
                return Err("AMBIGUOUS_ASSIGNMENT_CLONED_SERIAL");
            }
        }

        Ok(())
    }
}
