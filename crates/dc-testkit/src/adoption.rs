use dc_hw::NvmeSanitizeStatus;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdoptionDecision {
    AdoptInFlight { sprog: u16, progress_permille: u16 },
    AdoptCompleted,
    RefuseForeign,
    RefuseContradiction { reason: String },
}

pub struct AdoptionArbiter;

impl AdoptionArbiter {
    /// Pure adoption arbiter implementing the 4-case matrix (Δ236, INV15).
    pub fn arbitrate(
        has_issuance_record: bool,
        journal_failed_or_aborted: bool,
        drive_status: &NvmeSanitizeStatus,
    ) -> AdoptionDecision {
        // Case 3: Foreign in flight (no issuance anchor in our journal)
        if !has_issuance_record {
            if drive_status.is_in_progress {
                return AdoptionDecision::RefuseForeign;
            } else {
                return AdoptionDecision::RefuseContradiction {
                    reason: "Drive is not in an active sanitize state and no journal issuance exists".to_string(),
                };
            }
        }

        // Case 4: Contradiction (journal says failed/aborted, but drive says in-progress)
        if journal_failed_or_aborted && drive_status.is_in_progress {
            return AdoptionDecision::RefuseContradiction {
                reason: "Journal recorded operation failure, but drive is currently in-progress".to_string(),
            };
        }

        // Case 1: Ours in flight (adopt progress without re-issuing)
        if drive_status.is_in_progress {
            return AdoptionDecision::AdoptInFlight {
                sprog: drive_status.raw_sprog,
                progress_permille: drive_status.progress_permille,
            };
        }

        // Case 2: Ours completed while process was dead (adopt completed attestation)
        if drive_status.is_completed {
            return AdoptionDecision::AdoptCompleted;
        }

        AdoptionDecision::RefuseContradiction {
            reason: format!("Unexpected controller status SSTAT={}", drive_status.raw_sstat),
        }
    }
}
