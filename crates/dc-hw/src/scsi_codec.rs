use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScsiSanitizeServiceAction {
    Overwrite = 0x01,
    BlockErase = 0x02,
    CryptoErase = 0x03,
    ExitFailureMode = 0x1F,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScsiSenseData {
    pub sense_key: u8,
    pub asc: u8,
    pub ascq: u8,
    pub progress_permille: Option<u16>,
}

pub struct ScsiCodec;

impl ScsiCodec {
    /// Encode a 16-byte SCSI SANITIZE CDB (Opcode 0x48 - SPC-4 §6.34).
    pub fn encode_sanitize(service_action: ScsiSanitizeServiceAction, immed: bool) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = 0x48; // Opcode: SANITIZE
        cdb[1] = (service_action as u8) & 0x1F;
        if immed {
            cdb[1] |= 0x80; // IMMED bit
        }
        cdb
    }

    /// Encode a 6-byte SCSI FORMAT UNIT CDB (Opcode 0x04 - SBC-3 §5.2).
    pub fn encode_format_unit(immed: bool) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = 0x04; // Opcode: FORMAT UNIT
        cdb[1] = 0x10; // FmtData = 0, CmpList = 0, Defect List Format = 0
        if immed {
            cdb[1] |= 0x80; // IMMED bit
        }
        cdb
    }

    /// Encode a 6-byte SCSI REQUEST SENSE CDB (Opcode 0x03).
    pub fn encode_request_sense(alloc_len: u8) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = 0x03; // Opcode: REQUEST SENSE
        cdb[4] = alloc_len;
        cdb
    }

    /// Decode SCSI Sense Data (Fixed and Descriptor formats).
    pub fn decode_sense_data(raw: &[u8]) -> Result<ScsiSenseData, String> {
        if raw.len() < 8 {
            return Err("Sense data too short".to_string());
        }

        let response_code = raw[0] & 0x7F;
        if response_code == 0x70 || response_code == 0x71 {
            // Fixed format sense data
            let sense_key = raw[2] & 0x0F;
            let asc = if raw.len() > 12 { raw[12] } else { 0 };
            let ascq = if raw.len() > 13 { raw[13] } else { 0 };

            // Sense-key specific progress (SKSV bit 7 of byte 15)
            let progress_permille = if raw.len() >= 18 && (raw[15] & 0x80) != 0 {
                let progress_raw = u16::from_be_bytes([raw[16], raw[17]]);
                Some(((progress_raw as u64 * 1000) / 65536) as u16)
            } else {
                None
            };

            Ok(ScsiSenseData {
                sense_key,
                asc,
                ascq,
                progress_permille,
            })
        } else {
            // Descriptor format or generic
            let sense_key = raw[1] & 0x0F;
            let asc = if raw.len() > 2 { raw[2] } else { 0 };
            let ascq = if raw.len() > 3 { raw[3] } else { 0 };

            Ok(ScsiSenseData {
                sense_key,
                asc,
                ascq,
                progress_permille: None,
            })
        }
    }
}
