use crate::fleet::assignment::BatchManifest;
use crate::fleet::report::{FleetJobOutcome, FleetJobRecord, FleetReport};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildJournalState {
    pub slot_id: usize,
    pub serial: String,
    pub terminal_state: Option<String>, // "CLEAN_COMPLETED", "INTERRUPTED", "FAILED"
    pub cert_hash: Option<String>,
}

pub struct BatchReconstructor;

impl BatchReconstructor {
    /// Reconstruct batch report purely from manifest and child journal evidence (Δ381).
    pub fn reconstruct_from_evidence(
        manifest: &BatchManifest,
        child_journals: &[ChildJournalState],
    ) -> FleetReport {
        let mut records = Vec::new();

        for row in &manifest.rows {
            let matching_journal = child_journals.iter().find(|j| j.slot_id == row.slot_id);

            let (outcome, exit_code, cert_hash) = match matching_journal {
                Some(j) => match j.terminal_state.as_deref() {
                    Some("CLEAN_COMPLETED") => (FleetJobOutcome::Clean, 0, j.cert_hash.clone()),
                    Some("INTERRUPTED") => (FleetJobOutcome::Interrupted, 1, None),
                    Some("VERIFICATION_FAILED") => (FleetJobOutcome::VerificationFailed, 4, None),
                    Some("GUARDIAN_REFUSED") => (FleetJobOutcome::GuardianRefused, 2, None),
                    _ => (FleetJobOutcome::IoFailed, 3, None),
                },
                None => (FleetJobOutcome::IoFailed, 3, None),
            };

            records.push(FleetJobRecord {
                slot_id: row.slot_id,
                serial: row.expected_serial.clone(),
                outcome,
                exit_code,
                cert_hash,
            });
        }

        let merkle = FleetReport::compute_merkle_fingerprint(&records);
        let manifest_hash = manifest.compute_manifest_hash();

        FleetReport {
            batch_id: manifest.batch_id.clone(),
            manifest_hash,
            merkle_fingerprint: merkle,
            records,
        }
    }
}
