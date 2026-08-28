pub const SPEC_NVME_BASE: &str = "NVM Express Base Specification, Revision 2.0d, §5.24 (Sanitize) & §5.15 (Get Log Page)";
pub const SPEC_ATA8_ACS: &str = "ATA/ATAPI Command Set - 8 (ATA8-ACS), Revision 6a, §7.16 (IDENTIFY DEVICE) & §7.43 (SECURITY ERASE)";
pub const SPEC_SPC4: &str = "SCSI Primary Commands - 4 (SPC-4), Revision 37, §6.34 (SANITIZE) & §7.2 (Sense Data)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecCitation {
    pub standard: &'static str,
    pub revision: &'static str,
    pub clause: &'static str,
}

pub const CITATION_NVME_SANITIZE: SpecCitation = SpecCitation {
    standard: "NVM Express Base",
    revision: "2.0d",
    clause: "§5.24",
};

pub const CITATION_NVME_LOG_81: SpecCitation = SpecCitation {
    standard: "NVM Express Base",
    revision: "2.0d",
    clause: "§5.15.1.18",
};

pub const CITATION_ATA_IDENTIFY_W128: SpecCitation = SpecCitation {
    standard: "ATA8-ACS",
    revision: "6a",
    clause: "§7.16.7.47",
};

pub const CITATION_SCSI_SANITIZE: SpecCitation = SpecCitation {
    standard: "SPC-4",
    revision: "37",
    clause: "§6.34",
};

/// SSTAT (Sanitize Status) decoding table per NVMe Base §5.15.1.18.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeSstatStatus {
    NeverSanitized = 0,
    SanitizeCompletedSuccessfully = 1,
    SanitizeInProgress = 2,
    SanitizeFailed = 3,
    SanitizeCompletedWithGlobalDeallocate = 4,
}

impl NvmeSstatStatus {
    pub fn from_raw(sstat: u16) -> Self {
        match sstat & 0x07 {
            1 => NvmeSstatStatus::SanitizeCompletedSuccessfully,
            2 => NvmeSstatStatus::SanitizeInProgress,
            3 => NvmeSstatStatus::SanitizeFailed,
            4 => NvmeSstatStatus::SanitizeCompletedWithGlobalDeallocate,
            _ => NvmeSstatStatus::NeverSanitized,
        }
    }
}
