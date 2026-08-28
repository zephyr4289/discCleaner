use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IoctlTaxonomy {
    Success,
    TransportFault { errno: i32, description: String },
    ControllerRejected { errno: i32, description: String },
    TimeoutAmbiguous { errno: i32 },
    OurBug { errno: i32, description: String },
    UnmappedLoud { errno: i32 },
}

pub struct ErrnoClassifier;

impl ErrnoClassifier {
    /// Strict kernel errno to client taxonomy mapping (Δ268).
    pub fn classify(errno: i32) -> IoctlTaxonomy {
        match errno {
            0 => IoctlTaxonomy::Success,
            libc::EIO => IoctlTaxonomy::ControllerRejected {
                errno,
                description: "Controller rejected admin command or I/O error".to_string(),
            },
            libc::EPERM | libc::EACCES => IoctlTaxonomy::TransportFault {
                errno,
                description: "Permission denied for raw NVMe passthrough ioctl".to_string(),
            },
            libc::ENODEV | libc::ENXIO => IoctlTaxonomy::TransportFault {
                errno,
                description: "NVMe device node disappeared from transport".to_string(),
            },
            libc::ETIMEDOUT => IoctlTaxonomy::TimeoutAmbiguous { errno },
            libc::EFAULT => IoctlTaxonomy::OurBug {
                errno,
                description: "EFAULT: Invalid memory layout in passthrough buffer (internal bug)".to_string(),
            },
            libc::EINVAL => IoctlTaxonomy::OurBug {
                errno,
                description: "EINVAL: Invalid parameter in admin CDW construction (internal bug)".to_string(),
            },
            _ => IoctlTaxonomy::UnmappedLoud { errno },
        }
    }
}

pub trait NvmeAdminTransport: Send {
    fn admin_passthrough(&mut self, cmd: &[u8; 64]) -> Result<Vec<u8>, IoctlTaxonomy>;
}
