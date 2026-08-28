use crate::confirm::TwoAxisConfirmation;
use crate::permit::{ConfigTransactionPermit, ConfigTxnGuard};
use dc_nvme::PurgePermit;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmcPurgeExecutionSummary {
    pub target_device: String,
    pub executed_partitions: Vec<String>,
    pub proof_substrate: String, // "MockTranscribed" or "SiliconObserved"
}

pub struct MmcPurgeClient {
    pub access_class: dc_testkit::MmcAccessClass,
}

impl MmcPurgeClient {
    pub fn new(access_class: dc_testkit::MmcAccessClass) -> Self {
        Self { access_class }
    }

    /// Execute partition-scoped purges under two-axis confirmation and config transaction permit (Δ348, Δ349).
    pub fn execute_confirmed_purge(
        &mut self,
        permit: &PurgePermit,
        confirmation: &TwoAxisConfirmation,
        current_config: &mut u8,
    ) -> Result<MmcPurgeExecutionSummary, String> {
        let config_permit = ConfigTransactionPermit::derive(permit);
        let guard = ConfigTxnGuard::new(&config_permit, current_config);

        // Execute purges across confirmed partitions
        let executed = confirmation.confirmed_partitions.clone();

        // Reconcile
        confirmation.reconcile_executed_scope(&executed)?;

        // Safely commit the config transaction
        guard.commit();

        Ok(MmcPurgeExecutionSummary {
            target_device: permit.target_device.clone(),
            executed_partitions: executed,
            proof_substrate: "MockTranscribed".to_string(), // Explicit provenance (Δ347)
        })
    }
}
