use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoAxisConfirmation {
    pub device_cid_token: String,
    pub confirmed_partitions: Vec<String>,
}

impl TwoAxisConfirmation {
    pub fn new(cid_token: &str, partitions: Vec<String>) -> Self {
        Self {
            device_cid_token: cid_token.to_string(),
            confirmed_partitions: partitions,
        }
    }

    /// Reconcile executed partition outcomes against confirmed partition scope (Δ348).
    pub fn reconcile_executed_scope(&self, executed_partitions: &[String]) -> Result<(), String> {
        for confirmed in &self.confirmed_partitions {
            if !executed_partitions.contains(confirmed) {
                return Err(format!(
                    "SCOPE_RECONCILIATION_ERROR: Confirmed partition '{}' was not executed!",
                    confirmed
                ));
            }
        }

        for executed in executed_partitions {
            if !self.confirmed_partitions.contains(executed) {
                return Err(format!(
                    "SCOPE_RECONCILIATION_ERROR: Unconfirmed partition '{}' was executed!",
                    executed
                ));
            }
        }

        Ok(())
    }
}
