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

/// SANITIZE DEVICE feature support decoded from IDENTIFY DEVICE word 169
/// (guarded by the word 206 VALID coverage bits). Drives without sanitize
/// fall back to the ATA SECURITY ERASE ladder.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaSanitizeSupport {
    pub supported: bool,
    pub crypto_scramble_supported: bool,
    pub block_erase_supported: bool,
    pub overwrite_supported: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaIdentifyData {
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub lba48_sectors: u64,
    pub security: AtaSecurityStatus,
    /// SANITIZE DEVICE feature support (word 169).
    pub sanitize: AtaSanitizeSupport,
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

        // Word 169: SANITIZE DEVICE support. Valid only when word 206
        // bits 14:12 report the VALID coverage (0b001/0b010); bit 0 =
        // sanitize supported, bit 1 = crypto scramble, bit 2 = block erase,
        // bit 3 = overwrite.
        let w169 = words[169];
        let w206 = words[206];
        let sanitize_valid = (w206 >> 12) & 0x7;
        let sanitize = AtaSanitizeSupport {
            supported: sanitize_valid != 0 && (w169 & 0x0001) != 0,
            crypto_scramble_supported: sanitize_valid != 0 && (w169 & 0x0002) != 0,
            block_erase_supported: sanitize_valid != 0 && (w169 & 0x0004) != 0,
            overwrite_supported: sanitize_valid != 0 && (w169 & 0x0008) != 0,
        };

        Ok(AtaIdentifyData {
            model,
            serial,
            firmware,
            lba48_sectors,
            security,
            sanitize,
        })
    }

    /// Parse the DCO (Device Configuration Overlay) 512-byte sector from
    /// DEVICE CONFIGURATION IDENTIFY: the maximum accessible sectors live
    /// in words 100-103 (same layout as IDENTIFY DEVICE). When the DCO
    /// reports zero, the drive has no factory reserve beyond the reported
    /// native capacity (nothing to unmask).
    pub fn decode_device_config_overlay(raw: &[u8]) -> Result<u64, String> {
        if raw.len() < 208 {
            return Err("DCO sector must be at least 208 bytes".to_string());
        }
        let w100 = u16::from_le_bytes([raw[200], raw[201]]);
        let w101 = u16::from_le_bytes([raw[202], raw[203]]);
        let w102 = u16::from_le_bytes([raw[204], raw[205]]);
        let w103 = u16::from_le_bytes([raw[206], raw[207]]);
        Ok((w100 as u64) | ((w101 as u64) << 16) | ((w102 as u64) << 32) | ((w103 as u64) << 48))
    }

    /// Decode byte-swapped ATA ASCII string.
    /// Real drives pad with spaces AND NUL bytes (both are stripped).
    fn decode_ata_string(bytes: &[u8]) -> String {
        let mut swapped = Vec::with_capacity(bytes.len());
        for chunk in bytes.as_chunks::<2>().0 {
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
        Self::encode_sat_passthrough_16_framed(0xF3, 0x0000, 0, 1, SatTransferClass::None)
    }

    /// SECURITY ERASE UNIT (ATA-ACS: opcode 0xF4). `enhanced = true` requests
    /// the enhanced (cryptographic) erase variant via the FEATURES register.
    ///
    /// FEATURES encoding (ATA8-ACS §7.43): bit 0 = Master Password
    /// Capability, bit 1 = Enhanced Security Erase. NOTE (v0.6.0): the
    /// pre-0.6.0 codec selected enhanced with bit 0, which names the
    /// master-password authority and leaves the erase NORMAL — fixed here
    /// and pinned by REG-ATA-PURGE-SGIO-FRAMING. The real pipeline uses
    /// [`encode_sat_security_erase_unit_auth`], which also frames the
    /// command as PIO data-out with its 512-byte password payload
    /// (SECURITY ERASE UNIT is a PIO Data-Out command; a non-data framing
    /// never transfers the password and can never authenticate).
    pub fn encode_sat_security_erase_unit(enhanced: bool) -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(
            0xF4,
            if enhanced { 0x0002 } else { 0x0000 },
            0,
            1,
            SatTransferClass::None,
        )
    }

    /// SECURITY FREEZE LOCK (ATA-ACS: opcode 0xF5, non-data). Idempotent.
    pub fn encode_sat_security_freeze_lock() -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(0xF5, 0x0000, 0, 1, SatTransferClass::None)
    }

    // -------------------------------------------------------------------
    // v0.6.0 — Universal ATA hardware purge ladder (SAT framing)
    // -------------------------------------------------------------------

    /// IDENTIFY DEVICE (ATA8-ACS §7.16: opcode 0xEC, PIO data-in, 512-byte
    /// response). Sector count 0 = the conventional full 256-word page.
    pub fn encode_sat_identify_device() -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(0xEC, 0x0000, 0, 0, SatTransferClass::DataIn)
    }

    /// SECURITY SET PASSWORD (ATA-ACS: opcode 0xF1, PIO data-out, 512-byte
    /// payload). `master = true` sets the master password, else the user
    /// password. The payload carries the password at bytes 2..33.
    pub fn encode_sat_security_set_password(
        master: bool,
        password: &[u8; 32],
    ) -> ([u8; 16], [u8; 512]) {
        let cdb =
            Self::encode_sat_passthrough_16_framed(0xF1, 0x0000, 0, 1, SatTransferClass::DataOut);
        (cdb, Self::security_password_payload(master, password))
    }

    /// SECURITY ERASE UNIT with its 512-byte password payload (opcode
    /// 0xF4, PIO data-out). FEATURES: bit 0 = master password authority,
    /// bit 1 = enhanced security erase (ATA8-ACS §7.43).
    pub fn encode_sat_security_erase_unit_auth(
        master: bool,
        enhanced: bool,
        password: &[u8; 32],
    ) -> ([u8; 16], [u8; 512]) {
        let features: u16 = (master as u16) | ((enhanced as u16) << 1);
        let cdb =
            Self::encode_sat_passthrough_16_framed(0xF4, features, 0, 1, SatTransferClass::DataOut);
        (cdb, Self::security_password_payload(master, password))
    }

    /// SECURITY DISABLE PASSWORD (ATA-ACS: opcode 0xF6, PIO data-out) —
    /// the no-harm repair path when an erase fails mid-flight.
    pub fn encode_sat_security_disable_password(
        master: bool,
        password: &[u8; 32],
    ) -> ([u8; 16], [u8; 512]) {
        let cdb =
            Self::encode_sat_passthrough_16_framed(0xF6, 0x0000, 0, 1, SatTransferClass::DataOut);
        (cdb, Self::security_password_payload(master, password))
    }

    /// SECURITY UNLOCK (ATA-ACS: opcode 0xF2, PIO data-out).
    pub fn encode_sat_security_unlock(master: bool, password: &[u8; 32]) -> ([u8; 16], [u8; 512]) {
        let cdb =
            Self::encode_sat_passthrough_16_framed(0xF2, 0x0000, 0, 1, SatTransferClass::DataOut);
        (cdb, Self::security_password_payload(master, password))
    }

    /// ATA SECURITY password payload sector (ATA8-ACS §7.44):
    /// byte 0 bit 7 = master password capability (0 = user, 1 = master),
    /// bytes 2..34 = the password, bytes 34.. = master password revision
    /// (master only). Reserved bytes are zero.
    fn security_password_payload(master: bool, password: &[u8; 32]) -> [u8; 512] {
        let mut payload = [0u8; 512];
        if master {
            payload[0] = 0x80;
        }
        payload[2..34].copy_from_slice(password);
        payload
    }

    /// SANITIZE DEVICE (ATA8-ACS §7.47: opcode 0xB4, non-data). The
    /// FEATURES register selects the sanitize operation.
    pub fn encode_sat_sanitize_device(feature: AtaSanitizeFeature) -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(0xB4, feature as u16, 0, 1, SatTransferClass::None)
    }

    /// SMART READ DATA (ATA8-ACS: opcode 0xB0, features 0xD0, PIO data-in,
    /// 512-byte attribute table). The 0x4F/0xC2 key bytes in the LBA field
    /// are the SMART command signature the device demands.
    pub fn encode_sat_smart_read_data() -> [u8; 16] {
        // LBA low = 0x4F, LBA mid = 0xC2 (SMART key), count = 1 sector.
        Self::encode_sat_passthrough_16_framed(0xB0, 0xD0, 0xC24F, 1, SatTransferClass::DataIn)
    }

    /// READ LOG EXT (ATA8-ACS: opcode 0x2F, PIO data-in, 48-bit). Reads
    /// multi-page general purpose logs where the page number rides the
    /// LBA field: bits 7:0 = log address, bits 31:8 = page number. This
    /// is how the Device Statistics log (0x04) pages beyond page 0 are
    /// fetched (v0.7.0, Vector 4).
    pub fn encode_sat_read_log_ext(log_address: u8, page: u16, sector_count: u16) -> [u8; 16] {
        let lba = (log_address as u64) | ((page as u64) << 8);
        Self::encode_sat_passthrough_16_framed(
            0x2F,
            0x0000,
            lba,
            sector_count,
            SatTransferClass::DataIn,
        )
    }

    /// SMART READ LOG (ATA8-ACS: opcode 0xB0, features 0xD5, PIO data-in,
    /// 512-byte log page). `log_address` 0x30 selects the Sanitize Status
    /// log.
    pub fn encode_sat_smart_read_log(log_address: u8) -> [u8; 16] {
        // LBA low carries the log address, LBA mid = 0xC2 SMART key.
        Self::encode_sat_passthrough_16_framed(
            0xB0,
            0xD5,
            0xC200 | (log_address as u64),
            1,
            SatTransferClass::DataIn,
        )
    }

    /// DEVICE CONFIGURATION IDENTIFY (opcode 0xB1, feature 0xC2, PIO
    /// data-in, 512 bytes): the DCO sector, whose maximum-sector words
    /// (100-103, same layout as IDENTIFY DEVICE) disclose the factory
    /// capacity ceiling.
    pub fn encode_sat_device_config_identify() -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(0xB1, 0xC2, 0, 1, SatTransferClass::DataIn)
    }

    /// DEVICE CONFIGURATION RESTORE (opcode 0xB1, feature 0xC0, non-data).
    /// Restores the DCO to factory defaults; a power-on reset applies it.
    pub fn encode_sat_device_config_restore() -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(0xB1, 0xC0, 0, 1, SatTransferClass::None)
    }

    /// READ NATIVE MAX ADDRESS EXT (opcode 0x27, non-data with CK_COND=1):
    /// the 48-bit native maximum LBA returns in the ATA task file, which
    /// SAT delivers as the 0x09 (ATA return) sense descriptor.
    pub fn encode_sat_read_native_max_ext() -> [u8; 16] {
        let mut cdb =
            Self::encode_sat_passthrough_16_framed(0x27, 0x0000, 0, 1, SatTransferClass::None);
        // CK_COND=1 (bit 5 of byte 2): request the return task file in
        // sense data so the native max LBA is observable.
        cdb[2] |= 0x20;
        cdb
    }

    /// SET MAX ADDRESS EXT (opcode 0x37, features 0x0000, non-data):
    /// re-addresses the device up to `native_max_lba`, exposing HPA-hidden
    /// capacity to subsequent commands (including purges).
    pub fn encode_sat_set_max_ext(native_max_lba: u64) -> [u8; 16] {
        Self::encode_sat_passthrough_16_framed(
            0x37,
            0x0000,
            native_max_lba,
            1,
            SatTransferClass::None,
        )
    }

    /// Extract the 48-bit LBA from a SAT sense buffer carrying the 0x09
    /// ATA return descriptor (returned by READ NATIVE MAX ADDRESS EXT
    /// when CK_COND=1). Descriptor layout (SAT-5 §11.1): descriptor bytes
    /// 6..12 carry LBA 47:40, 31:24, 39:32, 23:16, 15:8, 7:0.
    pub fn decode_ata_return_descriptor_lba(sense: &[u8]) -> Result<u64, String> {
        // Walk descriptor-format sense data: response code 0x72/0x73,
        // descriptors start at byte 8, each [type, len, payload...].
        if sense.len() < 10 {
            return Err("sense buffer too short for descriptor walk".to_string());
        }
        let response_code = sense[0] & 0x7F;
        if response_code != 0x72 && response_code != 0x73 {
            return Err(format!(
                "expected descriptor-format sense (0x72/0x73), got 0x{:02X}",
                response_code
            ));
        }
        let sense_len = sense.len();
        let mut off = 8usize;
        while off + 2 <= sense_len {
            let desc_type = sense[off];
            let desc_len = sense[off + 1] as usize;
            if desc_type == 0x09 && desc_len >= 12 && off + 2 + 12 <= sense_len {
                // d[0] is descriptor byte 2 (flags); descriptor byte N is
                // d[N - 2]. LBA fields are descriptor bytes 6..12.
                let d = &sense[off + 2..off + 2 + 12];
                let lba = ((d[4] as u64) << 40)
                    | ((d[5] as u64) << 24)
                    | ((d[6] as u64) << 32)
                    | ((d[7] as u64) << 16)
                    | ((d[8] as u64) << 8)
                    | (d[9] as u64);
                return Ok(lba);
            }
            off += 2 + desc_len;
        }
        Err("no 0x09 ATA return descriptor in sense data".to_string())
    }

    /// Parse SMART attribute 0x05 (Reallocated_Sector_Ct) raw value from a
    /// 512-byte SMART READ DATA table. Attribute entries are 12 bytes
    /// (id, flags 2, current/worst/reserved 3, raw 6, reserved 1); the
    /// table ends at the first 0x00 id. The raw value is the grown defect
    /// (G-List) count the defense disclosure is built from.
    pub fn decode_smart_reallocated_sectors(raw: &[u8]) -> Result<u64, String> {
        if raw.len() < 512 {
            return Err("SMART READ DATA buffer must be 512 bytes".to_string());
        }
        for entry_idx in 0..30 {
            let base = 2 + entry_idx * 12; // table starts at byte 2
            if base + 12 > 512 {
                break;
            }
            let id = raw[base];
            if id == 0x00 {
                break; // end of attribute table
            }
            if id == 0x05 {
                // Raw value: 6 bytes little-endian at offset +5.
                let mut value: u64 = 0;
                for (i, b) in raw[base + 5..base + 11].iter().enumerate() {
                    value |= (*b as u64) << (8 * i);
                }
                return Ok(value);
            }
        }
        // Attribute absent: the drive does not report reallocations.
        Ok(0)
    }
}

/// ATA Device Statistics log (GP Log 0x04) — decoded wear evidence
/// (v0.7.0, Vector 4).
///
/// Layout per ATA8-ACS §7.22: each 512-byte page begins with a 8-byte
/// header (page number u16, rsvd, entry count u32 at offset 4), followed
/// by entries of `2-byte code | 1-byte flags | 1-byte rsvd | value`.
/// The value length is code-determined (the standard publishes the size
/// table; the D bit in the flags marks data valid).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaDeviceStatisticsPage {
    /// Page number (0x00 General, 0x01 Rotating Media, 0x04 Solid State
    /// Device Statistics, ...).
    pub page_number: u16,
    /// Entries in page order, decoded generically.
    pub entries: Vec<AtaDeviceStatisticsEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaDeviceStatisticsEntry {
    /// 2-byte entry code (e.g. 0x0004 Logical Sectors Written).
    pub code: u16,
    /// The D bit (bit 4 of the flags byte): the value is valid data.
    pub data_valid: bool,
    /// Decoded value (length per the code's spec table).
    pub value: u64,
}

impl AtaDeviceStatisticsEntry {
    /// Canonical name for the codes the evidence stack cites, in the
    /// context of the page they were decoded from.
    pub fn name_in_page(&self, page_number: u16) -> Option<&'static str> {
        match (page_number, self.code) {
            (0x00, 0x0001) => Some("Lifetime Power-on Resets"),
            (0x00, 0x0002) => Some("Power-on Hours"),
            (0x00, 0x0004) => Some("Logical Sectors Written"),
            (0x00, 0x0005) => Some("Number of Write Commands"),
            (0x00, 0x0006) => Some("Logical Sectors Read"),
            (0x00, 0x0007) => Some("Number of Read Commands"),
            (0x00, 0x0008) => Some("Date and Time of Reset"),
            (0x04, 0x0001) => Some("Percentage Used Endurance Indicator"),
            (0x04, 0x0002) => Some("Logical Sectors Read (SSD)"),
            (0x04, 0x0004) => Some("Logical Sectors Written (SSD)"),
            _ => None,
        }
    }
}

impl AtaDeviceStatisticsPage {
    /// Decode one 512-byte Device Statistics page. The page number is read
    /// from the page header itself (word 0); the hint parameter only
    /// documents what the caller requested.
    pub fn decode(raw: &[u8], _page_number_hint: u16) -> Result<Self, String> {
        if raw.len() < 512 {
            return Err("Device Statistics page must be 512 bytes".to_string());
        }
        let page_number = u16::from_le_bytes([raw[0], raw[1]]);
        let entry_count = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
        let mut entries = Vec::with_capacity(entry_count);
        let mut off = 8usize;
        for _ in 0..entry_count {
            if off + 4 > 512 {
                break; // vendor tail: decode what the header promised
            }
            let code = u16::from_le_bytes([raw[off], raw[off + 1]]);
            let flags = raw[off + 2];
            let data_valid = flags & 0x10 != 0;
            let len = stat_value_len(page_number, code);
            if off + 4 + len > 512 {
                break;
            }
            let mut value: u64 = 0;
            for (i, b) in raw[off + 4..off + 4 + len].iter().enumerate() {
                value |= (*b as u64) << (8 * i);
            }
            entries.push(AtaDeviceStatisticsEntry {
                code,
                data_valid,
                value,
            });
            off += 4 + len;
        }
        Ok(Self {
            page_number,
            entries,
        })
    }

    /// Fetch a decoded entry by code.
    pub fn entry(&self, code: u16) -> Option<&AtaDeviceStatisticsEntry> {
        self.entries.iter().find(|e| e.code == code)
    }

    /// The SSD Percentage Used Endurance Indicator (page 0x04, code 0x0001,
    /// 1-byte value).
    pub fn percentage_used_endurance(&self) -> Option<u8> {
        if self.page_number == 0x04 {
            self.entry(0x0001).map(|e| e.value as u8)
        } else {
            None
        }
    }
}

/// Value length per (page, code) — the standard's published size table.
/// Default is 4 bytes. The 6-byte values are the sector counters and the
/// date/time of reset; page 0x04's endurance indicator is 1 byte. NOTE the
/// code spaces are PER-PAGE: 0x0002 is Power-on Hours (4B) in the General
/// page but Logical Sectors Read (6B) in the Solid State page.
fn stat_value_len(page: u16, code: u16) -> usize {
    if page == 0x04 {
        return match code {
            0x0001 => 1, // Percentage Used Endurance Indicator
            0x0002 => 6, // Logical Sectors Read (SSD page)
            0x0004 => 6, // Logical Sectors Written (SSD page)
            _ => 4,
        };
    }
    match code {
        0x0004 | 0x0006 => 6, // Logical Sectors Written / Read
        0x0008 => 6,          // Date and Time of Reset
        _ => 4,
    }
}

/// Sanitize operations selectable through the SANITIZE DEVICE command's
/// FEATURES register (ATA8-ACS §7.47.2).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtaSanitizeFeature {
    /// Block Erase: electrical erase of all user data blocks.
    BlockErase = 0x10,
    /// Crypto Scramble: destroy the internal data encryption key.
    CryptoScramble = 0x20,
    /// Overwrite: single-pattern overwrite of all user data blocks.
    Overwrite = 0x40,
}

/// ATA Sanitize Status log (log address 0x30) decode — the ATA mirror of
/// `NvmeSanitizeStatus`. Field offsets follow the ATA8-ACS Sanitize Status
/// log page layout as implemented: 16-bit SSTAT at word 5 (offset 10) with
/// bit 0 = in progress, bit 1 = completed successfully, bit 2 = failed;
/// 16-bit progress fraction at word 2 (offset 4), 0x10000-scaled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaSanitizeStatus {
    pub progress_permille: u16,
    pub is_in_progress: bool,
    pub is_completed: bool,
    pub is_failed: bool,
    pub raw_sstat: u16,
    pub raw_sprog: u16,
}

impl AtaSanitizeStatus {
    /// Decode the 512-byte Sanitize Status log page.
    pub fn decode_log(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 12 {
            return Err("Sanitize Status log page must be at least 12 bytes".to_string());
        }
        let raw_sprog = u16::from_le_bytes([raw[4], raw[5]]);
        let raw_sstat = u16::from_le_bytes([raw[10], raw[11]]);
        let progress_permille = ((raw_sprog as u32 * 1000 + 32767) / 65536).min(1000) as u16;
        Ok(Self {
            progress_permille,
            is_in_progress: raw_sstat & 0x0001 != 0,
            is_completed: raw_sstat & 0x0002 != 0,
            is_failed: raw_sstat & 0x0004 != 0,
            raw_sstat,
            raw_sprog,
        })
    }
}
