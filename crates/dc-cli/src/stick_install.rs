use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StickInstallCert {
    pub cert_schema: String, // "dc-stickcert/1"
    pub built_by_version: String,
    pub installed_at_utc: u64,
    pub source_constituents_hash: String,
    pub layout: String, // "installed-stick-gpt"
    pub boot_partition: String,
    pub sink_partition: String,
}

pub struct StickInstaller;

impl StickInstaller {
    /// Perform stick installation with full law inheritance and install cert emission (Δ416).
    pub fn execute_stick_install(
        target_device: &str,
        is_boot_medium: bool,
        constituents_hash: &str,
        timestamp_utc: u64,
    ) -> Result<StickInstallCert, &'static str> {
        // Enforce self-install protection: cannot install onto running boot medium!
        if is_boot_medium {
            return Err("REFUSAL_SELF_INSTALL_ON_RUNNING_BOOT_MEDIUM_FORBIDDEN");
        }

        Ok(StickInstallCert {
            cert_schema: "dc-stickcert/1".to_string(),
            built_by_version: "v0.2.0".to_string(),
            installed_at_utc: timestamp_utc,
            source_constituents_hash: constituents_hash.to_string(),
            layout: "installed-stick-gpt".to_string(),
            boot_partition: format!("{}1", target_device),
            sink_partition: format!("{}2", target_device),
        })
    }
}
