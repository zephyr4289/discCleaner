use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaSecurityStatus {
    pub supported: bool,
    pub enabled: bool,
    pub locked: bool,
    pub frozen: bool,
    pub enhanced_erase_supported: bool,
    pub erase_time_minutes: Option<u16>,
    pub enhanced_erase_time_minutes: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaIdentifyData {
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub lba48_sectors: u64,
    pub security: AtaSecurityStatus,
}

pub struct AtaCodec;

impl AtaCodec {
    /// Parse 512-byte ATA IDENTIFY DEVICE response.
    pub fn decode_identify_device(raw: &[u8]) -> Result<AtaIdentifyData, String> {
        if raw.len() < 512 {
            return Err("Identify buffer must be at least 512 bytes".to_string());
        }

        let mut words = [0u16; 256];
        for i in 0..256 {
            words[i] = u16::from_le_bytes([raw[i * 2], raw[i * 2 + 1]]);
        }

        let serial = Self::decode_ata_string(&raw[20..40]);
        let firmware = Self::decode_ata_string(&raw[46..54]);
        let model = Self::decode_ata_string(&raw[54..94]);

        // Word 100-103: 48-bit LBA user capacity
        let lba48_sectors = (words[100] as u64)
            | ((words[101] as u64) << 16)
            | ((words[102] as u64) << 32)
            | ((words[103] as u64) << 48);

        // Word 128: Security Status
        let w128 = words[128];
        let security = AtaSecurityStatus {
            supported: (w128 & 0x0001) != 0,
            enabled: (w128 & 0x0002) != 0,
            locked: (w128 & 0x0004) != 0,
            frozen: (w128 & 0x0008) != 0,
            enhanced_erase_supported: (w128 & 0x0020) != 0,
            erase_time_minutes: if words[89] > 0 { Some(words[89]) } else { None },
            enhanced_erase_time_minutes: if words[90] > 0 { Some(words[90]) } else { None },
        };

        Ok(AtaIdentifyData {
            model,
            serial,
            firmware,
            lba48_sectors,
            security,
        })
    }

    /// Decode byte-swapped ATA ASCII string.
    fn decode_ata_string(bytes: &[u8]) -> String {
        let mut swapped = Vec::with_capacity(bytes.len());
        for chunk in bytes.chunks_exact(2) {
            swapped.push(chunk[1]);
            swapped.push(chunk[0]);
        }
        String::from_utf8_lossy(&swapped).trim().to_string()
    }

    /// Encode SAT (SCSI-to-ATA Translation) ATA PASS-THROUGH (16) 16-byte SCSI CDB (Opcode 0x85).
    pub fn encode_sat_passthrough_16(
        command: u8,
        features: u16,
        lba: u64,
        count: u16,
        protocol: u8,
    ) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = 0x85; // ATA PASS-THROUGH (16)
        cdb[1] = (protocol << 1) | 0x01; // Protocol + extend bit
        cdb[2] = 0x2E; // OFF_LINE=0, CK_COND=1, T_DIR=1 (read), BYTE_BLOCK=1, T_LENGTH=2

        // Features (16-bit)
        cdb[3] = (features >> 8) as u8;
        cdb[4] = features as u8;

        // Sector Count (16-bit)
        cdb[5] = (count >> 8) as u8;
        cdb[6] = count as u8;

        // 48-bit LBA
        cdb[7] = (lba >> 24) as u8;
        cdb[8] = lba as u8;
        cdb[9] = (lba >> 32) as u8;
        cdb[10] = (lba >> 8) as u8;
        cdb[11] = (lba >> 40) as u8;
        cdb[12] = (lba >> 16) as u8;

        cdb[13] = 0x40; // Device (LBA mode)
        cdb[14] = command; // ATA Command code (e.g. 0xEC for IDENTIFY, 0xB4 for SANITIZE)
        cdb[15] = 0x00; // Control

        cdb
    }
}
