use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeFinding {
    pub is_frozen: bool,
    pub disclosure_text: String,
    pub override_active: bool,
}

pub struct FreezeEvaluator;

impl FreezeEvaluator {
    /// Evaluate ATA security freeze status according to the product contract (Δ280).
    pub fn evaluate(is_frozen: bool, allow_override: bool) -> Result<(), FreezeFinding> {
        if is_frozen && !allow_override {
            Err(FreezeFinding {
                is_frozen: true,
                disclosure_text: "Drive is frozen by host firmware/BIOS. Destructive security commands refused unless --assume-unfrozen is set in boot environments.".to_string(),
                override_active: false,
            })
        } else if is_frozen && allow_override {
            Ok(())
        } else {
            Ok(())
        }
    }
}
