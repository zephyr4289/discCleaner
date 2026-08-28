use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NvmeSecureEraseSetting {
    None = 0,
    UserDataErase = 1,
    CryptoErase = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NvmeSanitizeAction {
    ExitFailureMode = 1,
    BlockErase = 2,
    Overwrite = 3,
    CryptoErase = 4,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeSanitizeStatus {
    pub progress_permille: u16, // Progress in permille (0 to 1000)
    pub is_in_progress: bool,
    pub is_completed: bool,
    pub is_failed: bool,
    pub raw_sstat: u16,
    pub raw_sprog: u16,
}

pub struct NvmeCodec;

impl NvmeCodec {
    /// Encode a 64-byte NVMe Format NVM Admin Command (Opcode 0x80).
    pub fn encode_format_nvm(nsid: u32, ses: NvmeSecureEraseSetting, lbaf: u8) -> [u8; 64] {
        let mut cmd = [0u8; 64];
        cmd[0] = 0x80; // Opcode: Format NVM
        cmd[4..8].copy_from_slice(&nsid.to_le_bytes()); // NSID

        let cdw10 = ((ses as u32) << 9) | ((lbaf as u32) & 0x0F);
        cmd[40..44].copy_from_slice(&cdw10.to_le_bytes()); // CDW10

        cmd
    }

    /// Encode a 64-byte NVMe Sanitize Admin Command (Opcode 0x84).
    pub fn encode_sanitize(action: NvmeSanitizeAction, no_deallocate: bool) -> [u8; 64] {
        let mut cmd = [0u8; 64];
        cmd[0] = 0x84; // Opcode: Sanitize
        cmd[4..8].copy_from_slice(&0x00000000u32.to_le_bytes()); // NSID is 0 for Sanitize (Controller-scoped)

        let mut cdw10 = (action as u32) & 0x07;
        if no_deallocate {
            cdw10 |= 1 << 9;
        }
        cmd[40..44].copy_from_slice(&cdw10.to_le_bytes()); // CDW10

        cmd
    }

    /// Encode a 64-byte NVMe Get Log Page Admin Command for Sanitize Status Log 0x81 (Opcode 0x02).
    pub fn encode_get_sanitize_status_log() -> [u8; 64] {
        let mut cmd = [0u8; 64];
        cmd[0] = 0x02; // Opcode: Get Log Page
        cmd[4..8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // NSID: 0xFFFFFFFF (Global)

        // CDW10: Log ID 0x81, NUMDL = (512 / 4) - 1 = 127 = 0x7F in upper 16 bits
        let cdw10 = 0x81 | (0x007F << 16);
        cmd[40..44].copy_from_slice(&cdw10.to_le_bytes());

        cmd
    }

    /// Decode NVMe Sanitize Status Log 0x81 (512-byte payload).
    pub fn decode_sanitize_status_log(payload: &[u8]) -> Result<NvmeSanitizeStatus, String> {
        if payload.len() < 8 {
            return Err("Payload too short for NVMe Sanitize Status Log".to_string());
        }

        let sprog = u16::from_le_bytes([payload[0], payload[1]]);
        let sstat = u16::from_le_bytes([payload[2], payload[3]]);

        let status_code = sstat & 0x07;
        let is_completed = status_code == 1;
        let is_in_progress = status_code == 2;
        let is_failed = status_code == 3;

        // sprog is fraction of 65536
        let progress_permille = ((sprog as u64 * 1000) / 65536) as u16;

        Ok(NvmeSanitizeStatus {
            progress_permille,
            is_in_progress,
            is_completed,
            is_failed,
            raw_sstat: sstat,
            raw_sprog: sprog,
        })
    }
}
