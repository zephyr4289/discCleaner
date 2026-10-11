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

/// SAT (SCSI-to-ATA Translation) transfer framing class for ATA PASS-THROUGH
/// commands. Encoding the wrong class is not cosmetic: the SAT layer sizes its
/// data buffer from these bits, so a non-data command framed as `DataIn`
/// makes the OS wait for a device data-in phase that never comes (hang) or
/// corrupts the transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SatTransferClass {
    /// Non-data command (e.g. SECURITY ERASE UNIT): T_LENGTH=0, BYTE_BLOCK=0,
    /// T_DIR=0. Protocol 3 (Non-Data).
    None,
    /// PIO data-in (e.g. IDENTIFY DEVICE): T_DIR=1, BYTE_BLOCK=1, T_LENGTH=2.
    /// Protocol 4 (PIO Data-In).
    DataIn,
    /// PIO data-out (e.g. SECURITY SET PASSWORD): T_DIR=0, BYTE_BLOCK=1,
    /// T_LENGTH=2. Protocol 5.
    DataOut,
}

impl SatTransferClass {
    /// SAT protocol code (SAT-5 `PROTOCOL` field, CDB byte 1 bits 4:1).
    pub fn protocol(self) -> u8 {
        match self {
            SatTransferClass::None => 3,
            SatTransferClass::DataIn => 4,
            SatTransferClass::DataOut => 5,
        }
    }

    /// CDB byte 2 transfer framing bits: bits 1:0 T_LENGTH, bit 2 BYTE_BLOCK,
    /// bit 3 T_DIR, bit 5 CK_COND.
    fn framing(self) -> u8 {
        match self {
            SatTransferClass::None => 0x00,
            SatTransferClass::DataIn => 0x2E, // CK_COND=1, T_DIR=1, BYTE_BLOCK=1, T_LENGTH=2
            SatTransferClass::DataOut => 0x06, // BYTE_BLOCK=1, T_LENGTH=2, T_DIR=0
        }
    }
}

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
    /// Real drives pad with spaces AND NUL bytes (both are stripped).
    fn decode_ata_string(bytes: &[u8]) -> String {
        let mut swapped = Vec::with_capacity(bytes.len());
        for chunk in bytes.chunks_exact(2) {
            swapped.push(chunk[1]);
            swapped.push(chunk[0]);
        }
        String::from_utf8_lossy(&swapped)
            .trim_matches(|c: char| c == '\0' || c == ' ')
            .to_string()
    }

    /// Encode SAT ATA PASS-THROUGH (16) 16-byte SCSI CDB (Opcode 0x85) with an
    /// explicit transfer class. The caller must pick the class that matches
    /// the ATA command's data direction (see `SatTransferClass`).
    pub fn encode_sat_passthrough_16_framed(
        command: u8,
        features: u16,
        lba: u64,
        count: u16,
        xfer: SatTransferClass,
    ) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = 0x85; // ATA PASS-THROUGH (16)
        cdb[1] = (xfer.protocol() << 1) | 0x01; // Protocol + extend bit
        cdb[2] = xfer.framing();

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
        cdb[14] = command; // ATA Command code
        cdb[15] = 0x00; // Control

        cdb
    }

    /// Encode SAT ATA PASS-THROUGH (16) for a PIO data-IN command (the
    /// historical framing; retained for IDENTIFY DEVICE-style reads).
    /// SECURITY ERASE-class commands MUST use `encode_sat_passthrough_16_framed`
    /// with `SatTransferClass::None` — never this function.
    pub fn encode_sat_passthrough_16(
        command: u8,
        features: u16,
        lba: u64,
        count: u16,
        _protocol: u8,
    ) -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(
            command,
            features,
            lba,
            count,
            SatTransferClass::DataIn,
        )
    }

    /// SECURITY ERASE PREPARE (ATA-ACS: opcode 0xF3, non-data).
    /// Mandatory prelude before SECURITY ERASE UNIT on locked/frozen stacks.
    pub fn encode_sat_security_erase_prepare() -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(
            0xF3,
            0x0000,
            0,
            1,
            SatTransferClass::None,
        )
    }

    /// SECURITY ERASE UNIT (ATA-ACS: opcode 0xF4, non-data).
    /// `enhanced = true` requests the enhanced (cryptographic) erase variant
    /// via the FEATURES register.
    pub fn encode_sat_security_erase_unit(enhanced: bool) -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(
            0xF4,
            if enhanced { 0x0001 } else { 0x0000 },
            0,
            1,
            SatTransferClass::None,
        )
    }

    /// SECURITY FREEZE LOCK (ATA-ACS: opcode 0xF5, non-data). Idempotent.
    pub fn encode_sat_security_freeze_lock() -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(
            0xF5,
            0x0000,
            0,
            1,
            SatTransferClass::None,
        )
    }
}
