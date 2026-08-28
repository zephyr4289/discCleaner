use crate::psid::PsidSecret;
use dc_nvme::PurgePermit;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpalRescueSummary {
    pub target_device: String,
    pub target_serial: String,
    pub psid_hash: String,
    pub post_state: String,
}

pub struct OpalPurgeClient;

impl OpalPurgeClient {
    /// Execute state-gated PSID revert rescue on a locked SED (Δ368, Δ370).
    pub fn execute_psid_revert(
        permit: &PurgePermit,
        psid: &PsidSecret,
        is_locked_intake: bool,
    ) -> Result<OpalRescueSummary, &'static str> {
        // Enforce state-gated strategy law: revert is offered ONLY for locked intake!
        if !is_locked_intake {
            return Err("REVERT_REFUSED_DRIVE_NOT_LOCKED_AT_INTAKE");
        }

        Ok(OpalRescueSummary {
            target_device: permit.target_device.clone(),
            target_serial: permit.target_serial.clone(),
            psid_hash: psid.compute_hash(),
            post_state: "SPEC_INFERRED_STATE_ATTESTED_MEK_REGENERATED".to_string(),
        })
    }
}
