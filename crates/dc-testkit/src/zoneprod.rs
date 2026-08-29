use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriteModel {
    RandomCapable,
    ZonedSequential,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposedStrategy {
    pub class_ladder: Vec<String>,
    pub write_model: WriteModel,
    pub requires_post_sanitize_zone_reread: bool,
}

pub struct ZoneProductionDriver;

impl ZoneProductionDriver {
    /// Strategy compiler with orthogonal write-model axis (Δ507, Δ508).
    pub fn compile_zoned_strategy(
        is_zoned: bool,
        has_crypto_erase: bool,
    ) -> ComposedStrategy {
        let mut ladder = Vec::new();
        if has_crypto_erase {
            ladder.push("CryptoErase".to_string());
        }
        ladder.push("LogicalOverwriteSweep".to_string());

        let write_model = if is_zoned {
            WriteModel::ZonedSequential
        } else {
            WriteModel::RandomCapable
        };

        // Post-mechanism zone re-derivation law (Δ508):
        // Hardware sanitization invalidates zone pointers; must re-read report and reset-sweep!
        let requires_post_sanitize_zone_reread = is_zoned && has_crypto_erase;

        ComposedStrategy {
            class_ladder: ladder,
            write_model,
            requires_post_sanitize_zone_reread,
        }
    }
}
