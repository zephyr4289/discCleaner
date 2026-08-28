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
            Self::File => write!(f, "File"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Stable identity: survives USB re-enumeration (device unplugged/replugged).
/// Compared at plan time, arm time, and every checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StableIdentity {
    pub model: Option<String>,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub size_bytes: u64,
    pub bus: BusType,
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
    pub kernel_name: String,      // "sdb", "nvme0n1"
    pub dev_path: String,         // resolved path at open time (informational only)
    pub logical_block_size: u32,  // BLKSSZGET
    pub physical_block_size: u32, // BLKPBSZGET
}
