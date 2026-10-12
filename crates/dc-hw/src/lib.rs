pub mod ata_codec;
pub mod nvme_codec;
pub mod raw;
pub mod scsi_codec;
pub mod sgio;
pub mod tables;

pub use ata_codec::{
    AtaCodec, AtaIdentifyData, AtaSanitizeFeature, AtaSanitizeStatus, AtaSanitizeSupport,
    AtaSecurityStatus,
};
pub use nvme_codec::{
    NvmeCodec, NvmeHealthLog, NvmeIdentifyController, NvmeIdentifyNamespace, NvmeSanitizeAction,
    NvmeSanitizeStatus, NvmeSecureEraseSetting,
};
pub use raw::RawBlob;
pub use scsi_codec::{ScsiCodec, ScsiSanitizeServiceAction, ScsiSenseData};
pub use sgio::{
    SgIoDevice, SgIoError, SgIoHdr, SgIoResult, MAX_CDB_LEN, SENSE_BUFFER_LEN, SG_DXFER_FROM_DEV,
    SG_DXFER_NONE, SG_DXFER_TO_DEV, SG_IO_IOCTL,
};
pub use tables::{
    NvmeSstatStatus, CITATION_ATA_IDENTIFY_W128, CITATION_ATA_SANITIZE, CITATION_NVME_LOG_81,
    CITATION_NVME_SANITIZE, CITATION_SCSI_SANITIZE, SPEC_ATA8_ACS, SPEC_NVME_BASE, SPEC_SAT5,
    SPEC_SBC3, SPEC_SPC4,
};

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

// ---------------------------------------------------------------------------
// Unit test layer (LLVM-style: focused, descriptive, per-codec)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod unit_tests {
    use super::*;

    // ---------------- ATA / SAT ----------------

    #[test]
    fn sat_transfer_classes_have_distinct_protocol_framing() {
        let none = AtaCodec::encode_sat_passthrough_16_framed(
            0xF4,
            0x0001,
            0,
            1,
            crate::ata_codec::SatTransferClass::None,
        );
        let din = AtaCodec::encode_sat_passthrough_16_framed(
            0xEC,
            0x0000,
            0,
            1,
            crate::ata_codec::SatTransferClass::DataIn,
        );
        let dout = AtaCodec::encode_sat_passthrough_16_framed(
            0xF1,
            0x0000,
            0,
            1,
            crate::ata_codec::SatTransferClass::DataOut,
        );

        // SAT protocol field lives at CDB byte 1 bits 4:1.
        assert_eq!((none[1] >> 1) & 0x0F, 3, "Non-Data = protocol 3");
        assert_eq!((din[1] >> 1) & 0x0F, 4, "PIO Data-In = protocol 4");
        assert_eq!((dout[1] >> 1) & 0x0F, 5, "PIO Data-Out = protocol 5");

        // T_LENGTH / BYTE_BLOCK / T_DIR framing in byte 2.
        assert_eq!(
            none[2] & 0x0F,
            0b0000,
            "non-data: no transfer length, no byte-block"
        );
        assert_eq!(
            din[2] & 0x0F,
            0b1110,
            "data-in: T_DIR|BYTE_BLOCK|T_LENGTH=2"
        );
        assert_eq!(
            dout[2] & 0x0F,
            0b0110,
            "data-out: BYTE_BLOCK|T_LENGTH=2, T_DIR=0"
        );
    }

    #[test]
    fn security_erase_encoders_are_non_data_and_opcode_correct() {
        // REG-SAT-NONDATA: SECURITY ERASE-family commands must NEVER claim a
        // data-in transfer (the historical single-framing encoder did).
        let prep = AtaCodec::encode_sat_security_erase_prepare();
        let unit = AtaCodec::encode_sat_security_erase_unit(false);
        let enhanced = AtaCodec::encode_sat_security_erase_unit(true);
        let freeze = AtaCodec::encode_sat_security_freeze_lock();

        let cases: [(&str, &[u8; 16]); 4] = [
            ("prepare", &prep),
            ("unit", &unit),
            ("enhanced", &enhanced),
            ("freeze", &freeze),
        ];
        for (name, cdb) in cases {
            assert_eq!(cdb[14] & 0xF0, 0xF0, "{} opcode high nibble", name);
            assert_eq!(cdb[2], 0x00, "{} must be framed Non-Data", name);
            assert_eq!((cdb[1] >> 1) & 0x0F, 3, "{} SAT protocol 3", name);
        }
        assert_eq!(prep[14], 0xF3);
        assert_eq!(unit[14], 0xF4);
        // Enhanced erase is requested via the FEATURES register bit 1
        // (ATA8-ACS §7.43: bit 0 = Master Password Capability, bit 1 =
        // Enhanced Security Erase). v0.6.0 correction: the pre-0.6.0 codec
        // set bit 0 for enhanced, which names the master-password
        // authority and silently leaves the erase NORMAL.
        assert_eq!(unit[4], 0x00);
        assert_eq!(enhanced[4], 0x02, "enhanced = FEATURES bit 1 (0x02)");
        assert_eq!(freeze[14], 0xF5);
    }

    #[test]
    fn security_erase_unit_auth_carries_password_payload() {
        // REG-ATA-PURGE-SGIO-FRAMING: the real pipeline frames SECURITY
        // ERASE UNIT as PIO Data-Out with its 512-byte password sector
        // (a non-data framing never transfers the password and cannot
        // authenticate the erase).
        let password = [0xABu8; 32];
        let (cdb, payload) = AtaCodec::encode_sat_security_erase_unit_auth(false, true, &password);
        assert_eq!(cdb[14], 0xF4, "SECURITY ERASE UNIT opcode");
        assert_eq!(cdb[4], 0x02, "master=0 | enhanced<<1");
        // PIO Data-Out framing: protocol 5, BYTE_BLOCK|T_LENGTH=2, T_DIR=0.
        assert_eq!((cdb[1] >> 1) & 0x0F, 5, "SAT protocol 5 (PIO Data-Out)");
        assert_eq!(cdb[2] & 0x0F, 0b0110, "data-out transfer framing");
        assert_eq!(payload.len(), 512);
        assert_eq!(&payload[2..34], &password, "password at bytes 2..34");
        assert_eq!(payload[0] & 0x80, 0, "user password authority");

        let (cdb_m, payload_m) =
            AtaCodec::encode_sat_security_erase_unit_auth(true, true, &password);
        assert_eq!(cdb_m[4], 0x03, "master bit 0 | enhanced bit 1");
        assert_eq!(payload_m[0] & 0x80, 0x80, "master password authority");
    }

    #[test]
    fn sanitize_device_cdb_selects_feature_via_features_register() {
        // REG-ATA-PURGE-SGIO-FRAMING: SANITIZE DEVICE (0xB4) with the
        // FEATURES register selecting the operation; non-data framing.
        for (feature, expected) in [
            (AtaSanitizeFeature::BlockErase, 0x10),
            (AtaSanitizeFeature::CryptoScramble, 0x20),
            (AtaSanitizeFeature::Overwrite, 0x40),
        ] {
            let cdb = AtaCodec::encode_sat_sanitize_device(feature);
            assert_eq!(cdb[0], 0x85, "ATA PASS-THROUGH (16)");
            assert_eq!(cdb[14], 0xB4, "SANITIZE DEVICE opcode");
            assert_eq!(cdb[4], expected, "FEATURES selects the operation");
            assert_eq!((cdb[1] >> 1) & 0x0F, 3, "non-data protocol 3");
            assert_eq!(cdb[2] & 0x0F, 0x00, "non-data framing");
        }
    }

    #[test]
    fn smart_and_defect_probes_decode_glist_counts() {
        // REG-SMART-GLIST-DISCLOSURE (codec half): SMART attribute 0x05
        // raw value and SCSI grown-defect headers both decode.
        let mut smart = vec![0u8; 512];
        smart[2] = 0x05; // first attribute id
        smart[7..13].copy_from_slice(&1234u64.to_le_bytes()[..6]);
        assert_eq!(
            AtaCodec::decode_smart_reallocated_sectors(&smart).unwrap(),
            1234
        );
        // SCSI READ DEFECT DATA header: 5 descriptors of 8 bytes.
        assert_eq!(
            ScsiCodec::decode_defect_list_count(&[0x00, 0x00, 0x00, 40]).unwrap(),
            5
        );
        // Sanitize Status log: SSTAT completed, SPROG full scale.
        let mut log = vec![0u8; 512];
        log[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
        log[10..12].copy_from_slice(&0x0002u16.to_le_bytes());
        let status = AtaSanitizeStatus::decode_log(&log).unwrap();
        assert!(status.is_completed && !status.is_in_progress);
        assert_eq!(status.progress_permille, 1000);
    }

    #[test]
    fn identify_device_decodes_nul_and_space_padded_strings() {
        // REG-ATA-NUL-PAD: real drives NUL-pad as well as space-pad.
        let mut raw = vec![0u8; 512];
        // ATA strings are 16-bit-word byte-swapped; pre-swap the desired
        // decoded values so the codec's swap yields them back.
        let mut put_swapped = |slot: usize, want: &str| {
            let padded: Vec<u8> = want.bytes().collect();
            let mut i = 0;
            for chunk in padded.chunks(2) {
                if chunk.len() == 2 {
                    raw[slot + i] = chunk[1];
                    raw[slot + i + 1] = chunk[0];
                } else {
                    raw[slot + i] = 0;
                    raw[slot + i + 1] = chunk[0];
                }
                i += 2;
            }
        };
        put_swapped(20, "SN-NUL-PAD-99\0\0"); // serial (bytes 20..40)
        put_swapped(54, "  MODEL-X 9000  "); // model (bytes 54..94)

        let data = AtaCodec::decode_identify_device(&raw).unwrap();
        assert_eq!(data.serial, "SN-NUL-PAD-99", "NUL padding must be trimmed");
        assert_eq!(data.model, "MODEL-X 9000", "space padding must be trimmed");
    }

    // ---------------- NVMe ----------------

    #[test]
    fn format_nvm_ses_occupies_bits_10_9() {
        // Verified against QEMU's NVMe emulation + Linux kernel: SES is
        // CDW10 bits 10:09, LBAF bits 03:00, MSET bit 4.
        let cmd =
            NvmeCodec::encode_format_nvm(0x1234_5678, NvmeSecureEraseSetting::CryptoErase, 0x5);
        assert_eq!(cmd[0], 0x80);
        assert_eq!(&cmd[4..8], &0x1234_5678u32.to_le_bytes());
        let cdw10 = u32::from_le_bytes([cmd[40], cmd[41], cmd[42], cmd[43]]);
        assert_eq!((cdw10 >> 9) & 0x3, 2, "Crypto Erase SES = 0b10");
        assert_eq!(cdw10 & 0x0F, 5, "LBAF in low bits");
    }

    #[test]
    fn sanitize_status_rounding_full_scale_is_1000_permille() {
        // REG-SANITIZE-ROUNDING: SPROG=0xFFFF is a COMPLETED sanitize and
        // must report 1000 permille, not 999.
        let mut log = [0u8; 512];
        log[0..2].copy_from_slice(&65535u16.to_le_bytes()); // SPROG
        log[2..4].copy_from_slice(&1u16.to_le_bytes()); // SSTAT: completed
        let status = NvmeCodec::decode_sanitize_status_log(&log).unwrap();
        assert_eq!(status.progress_permille, 1000);
        assert!(status.is_completed);

        let mut half = [0u8; 512];
        half[0..2].copy_from_slice(&32768u16.to_le_bytes());
        half[2..4].copy_from_slice(&2u16.to_le_bytes()); // in progress
        let s = NvmeCodec::decode_sanitize_status_log(&half).unwrap();
        assert_eq!(s.progress_permille, 500);
        assert!(s.is_in_progress);

        let mut zero = [0u8; 512];
        zero[2..4].copy_from_slice(&3u16.to_le_bytes()); // failed
        let f = NvmeCodec::decode_sanitize_status_log(&zero).unwrap();
        assert!(f.is_failed);
        assert_eq!(f.progress_permille, 0);
    }

    // ---------------- SCSI ----------------

    #[test]
    fn format_unit_never_sets_fmtdata_without_parameter_list() {
        // REG-SCSI-FMTDATA: FMTDATA=1 obligates a defect-list transfer the
        // CDB never supplies; the historical 0x10 constant hung targets.
        let cdb = ScsiCodec::encode_format_unit(false);
        assert_eq!(cdb[0], 0x04);
        assert_eq!(cdb[1] & 0x10, 0, "FMTDATA must be clear");

        let imm = ScsiCodec::encode_format_unit(true);
        assert_eq!(imm[1] & 0x80, 0x80, "IMMED bit set when requested");
        assert_eq!(imm[1] & 0x10, 0, "IMMED variant must still clear FMTDATA");
    }

    #[test]
    fn sense_data_progress_uses_round_half_up_permille() {
        let mut sense = [0u8; 32];
        sense[0] = 0x70; // fixed format
        sense[2] = 0x06; // UNIT ATTENTION
        sense[15] = 0x80; // SKSV present
        sense[16] = 0xFF;
        sense[17] = 0xFF;
        let decoded = ScsiCodec::decode_sense_data(&sense).unwrap();
        assert_eq!(decoded.sense_key, 6);
        assert_eq!(decoded.progress_permille, Some(1000));
    }

    #[test]
    fn raw_blob_hashes_payload() {
        let blob = super::raw::RawBlob::new(42u32, b"payload");
        assert_eq!(blob.blake3, blake3::hash(b"payload").to_hex().to_string());
        assert_eq!(blob.decoded, 42);
    }
}
