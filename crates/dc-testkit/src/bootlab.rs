use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSinkMode {
    PersistentDisk { path: String, verified: bool },
    VolatileRam { copy_out_rendered: bool },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentProvenance {
    pub kernel_version: String,
    pub initramfs_build_hash: String,
    pub boot_medium_serial: String,
    pub owns_the_box: bool,
    pub entropy_source: String,
}

pub struct BootLabMock {
    pub boot_medium_serial: String,
    pub boot_medium_path: String,
    pub evidence_sink_path: String,
    pub owns_the_box: bool,
    pub sink_mode: EvidenceSinkMode,
}

impl BootLabMock {
    pub fn new(boot_serial: &str, boot_path: &str, sink_path: &str, owns_the_box: bool) -> Self {
        Self {
            boot_medium_serial: boot_serial.to_string(),
            boot_medium_path: boot_path.to_string(),
            evidence_sink_path: sink_path.to_string(),
            owns_the_box,
            sink_mode: EvidenceSinkMode::PersistentDisk {
                path: sink_path.to_string(),
                verified: false,
            },
        }
    }

    /// Pre-wipe evidence sink probe: write -> re-read -> verify hash before destruction begins (Δ400).
    pub fn probe_evidence_sink(&mut self) -> Result<&'static str, &'static str> {
        match &mut self.sink_mode {
            EvidenceSinkMode::PersistentDisk { verified, .. } => {
                *verified = true;
                Ok("EVIDENCE_SINK_PROBED_AND_VERIFIED")
            }
            EvidenceSinkMode::VolatileRam { copy_out_rendered } => {
                *copy_out_rendered = true;
                Ok("VOLATILE_RAM_SINK_DISCLOSED")
            }
        }
    }

    /// Check target against never-overridable BOOT_MEDIUM and EVIDENCE_SINK guardian rows (Δ401).
    pub fn validate_target_safety(
        &self,
        target_serial: &str,
        target_path: &str,
    ) -> Result<(), &'static str> {
        if target_serial == self.boot_medium_serial || target_path == self.boot_medium_path {
            return Err("REFUSAL_BOOT_MEDIUM_TARGET_NEVER_OVERRIDABLE");
        }
        if target_path == self.evidence_sink_path {
            return Err("REFUSAL_EVIDENCE_SINK_TARGET_NEVER_OVERRIDABLE");
        }
        Ok(())
    }

    /// Execute S3 suspend/resume unfreeze dance gated by owns_the_box detection (Δ402).
    pub fn execute_s3_unfreeze_dance(&self) -> Result<&'static str, &'static str> {
        if self.owns_the_box {
            Ok("S3_UNFREEZE_DANCE_COMPLETED_UNFROZEN_ASSERTED")
        } else {
            Err("S3_UNFREEZE_DANCE_REFUSED_INSTALLED_HOST_OS_PROTECTED")
        }
    }

    /// Generate environment provenance block for certificate / fleet report (Δ406).
    pub fn generate_environment_provenance(&self) -> EnvironmentProvenance {
        EnvironmentProvenance {
            kernel_version: "Linux 6.6.21-dc-rt".to_string(),
            initramfs_build_hash: "a4f8e1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab".to_string(),
            boot_medium_serial: self.boot_medium_serial.clone(),
            owns_the_box: self.owns_the_box,
            entropy_source: "getrandom/virtio-rng".to_string(),
        }
    }
}
