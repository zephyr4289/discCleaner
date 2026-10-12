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
    ///
    /// Byte 1: bit 7 IMMED, bit 4 FMTDATA, bit 3 CMPLIST, bits 2:0 Defect
    /// List Format. FMTDATA=0 means NO parameter list follows; setting it
    /// (as the old `0x10` constant did) obligates the initiator to transfer
    /// a defect-list header the CDB never supplies, hanging the target.
    pub fn encode_format_unit(immed: bool) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = 0x04; // Opcode: FORMAT UNIT
        cdb[1] = 0x00; // FmtData = 0, CmpList = 0, Defect List Format = 0
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

    /// Encode a 10-byte READ DEFECT DATA CDB (Opcode 0x37 — SBC-3 §5.13).
    /// `grown_only = true` requests the grown defect list (G-List — the
    /// reallocated/retired sector list the defense disclosure reads);
    /// otherwise the primary (P-List) is requested. The allocation length
    /// covers the 4-byte header, so a single round-trip yields the total
    /// defect count without fetching every descriptor.
    pub fn encode_read_defect_data(grown_only: bool, alloc_len: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = 0x37; // Opcode: READ DEFECT DATA (10)
                       // Byte 1 list selection: bit 3 (0x08) = grown list, bit 4 (0x10) =
                       // primary list. Requesting neither returns the combined count.
        cdb[1] = if grown_only { 0x08 } else { 0x10 };
        // Byte 2 defect list format: 0 = vendor; the returned header's
        // length field is what we consume.
        cdb[7] = (alloc_len >> 8) as u8;
        cdb[8] = alloc_len as u8;
        cdb
    }

    /// Parse the defect count from a READ DEFECT DATA header (first 4
    /// bytes: byte 0 echoes the format bits, bytes 2-3 = defect list
    /// length in bytes). Standard physical-sector descriptors are 8
    /// bytes each, so count = length / 8.
    pub fn decode_defect_list_count(header: &[u8]) -> Result<u64, String> {
        if header.len() < 4 {
            return Err("READ DEFECT DATA header must be 4 bytes".to_string());
        }
        let list_len = u16::from_be_bytes([header[2], header[3]]) as u64;
        Ok(list_len / 8)
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

            // Sense-key specific progress (SKSV bit 7 of byte 15);
            // round half-up so 0xFFFF/0x65536 reports 1000 permille.
            let progress_permille = if raw.len() >= 18 && (raw[15] & 0x80) != 0 {
                let progress_raw = u16::from_be_bytes([raw[16], raw[17]]);
                Some(((progress_raw as u64 * 1000 + 32768) / 65536) as u16)
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
