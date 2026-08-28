use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolBuild {
    pub name: String,
    pub version: String,
    pub build_hash: String,
    pub target_triple: String,
}

impl ToolBuild {
    pub fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_hash: option_env!("DC_BUILD_HASH")
                .unwrap_or("development-build-0000000000000000")
                .to_string(),
            target_triple: option_env!("TARGET")
                .unwrap_or(std::env::consts::ARCH)
                .to_string(),
        }
    }
}
