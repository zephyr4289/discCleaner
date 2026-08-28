use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BusType {
    Nvme,
    Sata,
    Sas,
    Usb,
    Mmc,
    Ufs,
    Virtio,
    Loop,
    DeviceMapper,
    File,
    Unknown,
}

impl std::fmt::Display for BusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nvme => write!(f, "NVMe"),
            Self::Sata => write!(f, "SATA"),
            Self::Sas => write!(f, "SAS"),
            Self::Usb => write!(f, "USB"),
            Self::Mmc => write!(f, "eMMC/SD"),
            Self::Ufs => write!(f, "UFS"),
            Self::Virtio => write!(f, "VirtIO"),
            Self::Loop => write!(f, "Loopback"),
            Self::DeviceMapper => write!(f, "DeviceMapper"),
            Self::File => write!(f, "File"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Stable identity: survives USB re-enumeration and device node re-enumeration.
/// Compared at plan time, arm time, and every checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StableIdentity {
    pub model: Option<String>,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub size_bytes: u64,
    pub bus: BusType,
    #[serde(default)]
    pub dm_name: Option<String>,
    #[serde(default)]
    pub dm_uuid: Option<String>,
}

impl StableIdentity {
    /// Normative Identity Comparator (§5.3 / Δ46):
    /// Returns `Ok(warnings)` on compatibility (including one-sided field absence).
    /// Returns `Err(contradiction_reason)` on hard contradiction.
    pub fn check_compatibility(&self, other: &StableIdentity) -> Result<Vec<String>, String> {
        let mut warnings = Vec::new();

        // 1. Capacity must match exactly
        if self.size_bytes != other.size_bytes {
            return Err(format!(
                "Size contradiction! Expected: {} bytes, Observed: {} bytes",
                self.size_bytes, other.size_bytes
            ));
        }

        // 2. DM UUID check
        match (&self.dm_uuid, &other.dm_uuid) {
            (Some(a), Some(b)) if a != b => {
                return Err(format!(
                    "Device-Mapper UUID contradiction! Expected: '{}', Observed: '{}'",
                    a, b
                ));
            }
            (Some(_), None) => {
                warnings.push("DM UUID missing in observed target".to_string());
            }
            (None, Some(_)) => {
                warnings.push("DM UUID present in observed target but absent in expected".to_string());
            }
            _ => {}
        }

        // 3. Serial check
        match (&self.serial, &other.serial) {
            (Some(a), Some(b)) if a != b => {
                return Err(format!(
                    "Serial number contradiction! Expected: '{}', Observed: '{}'",
                    a, b
                ));
            }
            (Some(_), None) => {
                warnings.push("Drive serial missing in observed target (possible bridge difference)".to_string());
            }
            (None, Some(_)) => {
                warnings.push("Drive serial observed but absent in expected baseline".to_string());
            }
            _ => {}
        }

        // 4. WWN check
        match (&self.wwn, &other.wwn) {
            (Some(a), Some(b)) if a != b => {
                return Err(format!(
                    "WWN contradiction! Expected: '{}', Observed: '{}'",
                    a, b
                ));
            }
            (Some(_), None) => {
                warnings.push("WWN missing in observed target".to_string());
            }
            (None, Some(_)) => {
                warnings.push("WWN observed but absent in expected baseline".to_string());
            }
            _ => {}
        }

        // 5. Model check
        match (&self.model, &other.model) {
            (Some(a), Some(b)) if a != b => {
                return Err(format!(
                    "Model name contradiction! Expected: '{}', Observed: '{}'",
                    a, b
                ));
            }
            _ => {}
        }

        Ok(warnings)
    }
}

/// Kernel identity: what the open fd actually is (fstat st_rdev major:minor).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelIdentity {
    pub major: u32,
    pub minor: u32,
}

impl std::fmt::Display for KernelIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub stable: StableIdentity,
    pub kernel: KernelIdentity,
    pub kernel_name: String,      // "sdb", "nvme0n1", "dm-0"
    pub dev_path: String,         // resolved path at open time (informational only)
    pub logical_block_size: u32,  // BLKSSZGET
    pub physical_block_size: u32, // BLKPBSZGET
}
