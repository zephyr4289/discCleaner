use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetLifecycleRecord {
    pub serial: String,
    pub model: String,
    pub sacrificial: bool,
    pub tbw_budget_gb: u64,
    pub tbw_consumed_gb: u64,
    pub retired: bool,
}

pub struct EstateLedger {
    pub assets: HashMap<String, AssetLifecycleRecord>,
}

impl EstateLedger {
    pub fn new() -> Self {
        Self {
            assets: HashMap::new(),
        }
    }

    pub fn register_asset(&mut self, record: AssetLifecycleRecord) {
        self.assets.insert(record.serial.clone(), record);
    }

    /// Authorize a characterization campaign against the asset endurance budget (Δ302).
    pub fn authorize_campaign(&mut self, serial: &str, tbw_cost_gb: u64) -> Result<(), &'static str> {
        if let Some(asset) = self.assets.get_mut(serial) {
            if asset.retired {
                return Err("ASSET_RETIRED");
            }
            if asset.tbw_consumed_gb + tbw_cost_gb > asset.tbw_budget_gb {
                return Err("ESTATE_BUDGET_EXCEEDED_UNAFFORDABLE");
            }
            asset.tbw_consumed_gb += tbw_cost_gb;
            Ok(())
        } else {
            Err("ASSET_NOT_FOUND")
        }
    }
}
