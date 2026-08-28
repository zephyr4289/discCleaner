pub mod ata_codec;
pub mod nvme_codec;
pub mod scsi_codec;

pub use ata_codec::{AtaCodec, AtaIdentifyData, AtaSecurityStatus};
pub use nvme_codec::{
    NvmeCodec, NvmeSanitizeAction, NvmeSanitizeStatus, NvmeSecureEraseSetting,
};
pub use scsi_codec::{ScsiCodec, ScsiSanitizeServiceAction, ScsiSenseData};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvme_sanitize_encoding() {
        let cmd = NvmeCodec::encode_sanitize(NvmeSanitizeAction::CryptoErase, true);
        assert_eq!(cmd[0], 0x84, "Opcode must be 0x84 for NVMe Sanitize");
        let cdw10 = u32::from_le_bytes([cmd[40], cmd[41], cmd[42], cmd[43]]);
        assert_eq!(cdw10 & 0x07, 4, "Action must be 4 (Crypto Erase)");
        assert_eq!((cdw10 >> 9) & 1, 1, "No-Deallocate bit must be set");
    }

    #[test]
    fn test_scsi_sanitize_encoding() {
        let cdb = ScsiCodec::encode_sanitize(ScsiSanitizeServiceAction::BlockErase, true);
        assert_eq!(cdb[0], 0x48, "Opcode must be 0x48 for SCSI SANITIZE");
        assert_eq!(cdb[1] & 0x1F, 2, "Service action must be 2 (Block Erase)");
        assert_eq!((cdb[1] >> 7) & 1, 1, "IMMED bit must be set");
    }
}
