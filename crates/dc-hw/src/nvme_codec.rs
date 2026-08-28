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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeIdentifyController {
    pub vid: u16,
    pub ssvid: u16,
    pub sn: String,
    pub mn: String,
    pub fr: String,
    pub ieee: [u8; 3],
    pub nn: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeIdentifyNamespace {
    pub nsze: u64,
    pub ncap: u64,
    pub nuse: u64,
    pub flbas: u8,
    pub eui64: Option<String>,
    pub nguid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeHealthLog {
    pub critical_warning: u8,
    pub temperature_kelvin: u16,
    pub available_spare_percent: u8,
    pub percentage_used: u8,
    pub data_units_read: u128,    // in units of 1,000 × 512-byte blocks
    pub data_units_written: u128, // in units of 1,000 × 512-byte blocks
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    pub media_errors: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
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

    /// Decode NVMe Identify Controller 4096-byte payload (NVMe Base §5.17.2.1).
    pub fn decode_identify_controller(payload: &[u8]) -> Result<NvmeIdentifyController, String> {
        if payload.len() < 4096 {
            return Err("Identify Controller buffer must be 4096 bytes".to_string());
        }

        let vid = u16::from_le_bytes([payload[0], payload[1]]);
        let ssvid = u16::from_le_bytes([payload[2], payload[3]]);
        let sn = String::from_utf8_lossy(&payload[4..24]).trim().to_string();
        let mn = String::from_utf8_lossy(&payload[24..64]).trim().to_string();
        let fr = String::from_utf8_lossy(&payload[64..72]).trim().to_string();
        let ieee = [payload[73], payload[74], payload[75]];
        let nn = u32::from_le_bytes([payload[516], payload[517], payload[518], payload[519]]);

        Ok(NvmeIdentifyController {
            vid,
            ssvid,
            sn,
            mn,
            fr,
            ieee,
            nn,
        })
    }

    /// Decode NVMe Identify Namespace 4096-byte payload (NVMe Base §5.17.2.5).
    pub fn decode_identify_namespace(payload: &[u8]) -> Result<NvmeIdentifyNamespace, String> {
        if payload.len() < 4096 {
            return Err("Identify Namespace buffer must be 4096 bytes".to_string());
        }

        let nsze = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let ncap = u64::from_le_bytes(payload[8..16].try_into().unwrap());
        let nuse = u64::from_le_bytes(payload[16..24].try_into().unwrap());
        let flbas = payload[26];

        let eui64_bytes = &payload[120..128];
        let eui64 = if eui64_bytes.iter().any(|&b| b != 0) {
            Some(hex::encode(eui64_bytes))
        } else {
            None
        };

        let nguid_bytes = &payload[104..120];
        let nguid = if nguid_bytes.iter().any(|&b| b != 0) {
            Some(hex::encode(nguid_bytes))
        } else {
            None
        };

        Ok(NvmeIdentifyNamespace {
            nsze,
            ncap,
            nuse,
            flbas,
            eui64,
            nguid,
        })
    }

    /// Decode NVMe SMART / Health Log Page 0x02 512-byte payload (NVMe Base §5.15.1.2).
    pub fn decode_health_log(payload: &[u8]) -> Result<NvmeHealthLog, String> {
        if payload.len() < 512 {
            return Err("Health Log buffer must be 512 bytes".to_string());
        }

        let critical_warning = payload[0];
        let temperature_kelvin = u16::from_le_bytes([payload[1], payload[2]]);
        let available_spare_percent = payload[3];
        let percentage_used = payload[5];

        let data_units_read = u128::from_le_bytes(payload[32..48].try_into().unwrap());
        let data_units_written = u128::from_le_bytes(payload[48..64].try_into().unwrap());
        let host_read_commands = u128::from_le_bytes(payload[64..80].try_into().unwrap());
        let host_write_commands = u128::from_le_bytes(payload[80..96].try_into().unwrap());
        let power_cycles = u128::from_le_bytes(payload[112..128].try_into().unwrap());
        let power_on_hours = u128::from_le_bytes(payload[128..144].try_into().unwrap());
        let media_errors = u128::from_le_bytes(payload[160..176].try_into().unwrap());

        Ok(NvmeHealthLog {
            critical_warning,
            temperature_kelvin,
            available_spare_percent,
            percentage_used,
            data_units_read,
            data_units_written,
            host_read_commands,
            host_write_commands,
            media_errors,
            power_cycles,
            power_on_hours,
        })
    }
}
