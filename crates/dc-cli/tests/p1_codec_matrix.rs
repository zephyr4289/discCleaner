use dc_hw::{
    AtaCodec, NvmeCodec, NvmeSanitizeAction, NvmeSecureEraseSetting, ScsiCodec,
    ScsiSanitizeServiceAction,
};
use dc_testkit::RigLedger;

#[test]
fn test_p1_codec_matrix() {
    let ledger = RigLedger::new();

    // 1. HW-NVME: NVMe Admin Command Encoding & Log 0x81 Decoding (Δ209, Δ214)
    run_nvme_codec_tests(&ledger);

    // 2. HW-ATA: ATA IDENTIFY Word 128 Parsing & SAT 16 Framing (Δ209)
    run_ata_codec_tests(&ledger);

    // 3. HW-SCSI: SCSI SANITIZE CDB Encoding & Sense Decoding (Δ209)
    run_scsi_codec_tests(&ledger);

    assert!(ledger.is_all_green(), "[P1-FAIL] Hardware Codec matrix contains failing assertions!");
    println!("\n[=== PHASE 1 HARDWARE CODEC MATRIX PASSED ALL CELLS ===]\n");
}

fn run_nvme_codec_tests(ledger: &RigLedger) {
    println!("\n[>>> HW-NVME: Testing NVMe Command Encodings & Log 0x81 (Δ209, Δ214) <<<]");

    // 1. Sanitize Crypto Erase
    let sanitize_cmd = NvmeCodec::encode_sanitize(NvmeSanitizeAction::CryptoErase, true);
    assert_eq!(sanitize_cmd[0], 0x84, "Opcode must be 0x84 (Sanitize)");
    let cdw10 = u32::from_le_bytes([sanitize_cmd[40], sanitize_cmd[41], sanitize_cmd[42], sanitize_cmd[43]]);
    assert_eq!(cdw10 & 0x07, 4, "SANACT must be 4 (Crypto Erase)");
    assert_eq!((cdw10 >> 9) & 1, 1, "NODAS bit must be 1");
    ledger.assert("P1-NVME", "HW-NVME-SANITIZE-ENCODE", "true", "true", None);

    // 2. Format NVM (SES=2 Crypto Erase)
    let format_cmd = NvmeCodec::encode_format_nvm(1, NvmeSecureEraseSetting::CryptoErase, 0);
    assert_eq!(format_cmd[0], 0x80, "Opcode must be 0x80 (Format NVM)");
    let f_cdw10 = u32::from_le_bytes([format_cmd[40], format_cmd[41], format_cmd[42], format_cmd[43]]);
    assert_eq!((f_cdw10 >> 9) & 0x07, 2, "SES must be 2 (Crypto Erase)");
    ledger.assert("P1-NVME", "HW-NVME-FORMAT-ENCODE", "true", "true", None);

    // 3. Decode Log 0x81 (SPROG=32768 => 50% = 500 permille, SSTAT=2 In Progress)
    let mut raw_log = vec![0u8; 512];
    raw_log[0..2].copy_from_slice(&32768u16.to_le_bytes()); // SPROG
    raw_log[2..4].copy_from_slice(&2u16.to_le_bytes());     // SSTAT (In progress)
    let status = NvmeCodec::decode_sanitize_status_log(&raw_log).unwrap();
    assert_eq!(status.progress_permille, 500);
    assert!(status.is_in_progress);
    assert!(!status.is_completed);
    ledger.assert("P1-NVME", "HW-NVME-LOG-DECODE", "500", status.progress_permille.to_string(), None);
}

fn run_ata_codec_tests(ledger: &RigLedger) {
    println!("\n[>>> HW-ATA: Testing ATA IDENTIFY & SAT 16 Framing (Δ209) <<<]");

    // 1. Synthetic 512-byte IDENTIFY payload
    let mut raw_id = vec![0u8; 512];

    // Model: "Crucial_CT1000MX" (ASCII byte-swapped in pairs)
    let model_str = b"rCucai_lTC001MX0";
    raw_id[54..54 + model_str.len()].copy_from_slice(model_str);

    // Word 100-103: 48-bit LBA (e.g. 1,953,525,168 sectors = ~1 TB)
    let lba: u64 = 1_953_525_168;
    raw_id[200..208].copy_from_slice(&lba.to_le_bytes());

    // Word 128: Security Status (bit 0=supported, bit 1=enabled, bit 3=frozen, bit 5=enhanced erase supported)
    let w128: u16 = 0x0001 | 0x0002 | 0x0008 | 0x0020;
    raw_id[256..258].copy_from_slice(&w128.to_le_bytes());

    let ident = AtaCodec::decode_identify_device(&raw_id).unwrap();
    assert_eq!(ident.lba48_sectors, lba);
    assert!(ident.security.supported);
    assert!(ident.security.enabled);
    assert!(ident.security.frozen);
    assert!(ident.security.enhanced_erase_supported);
    ledger.assert("P1-ATA", "HW-ATA-IDENTIFY-WORD128", "true", ident.security.frozen.to_string(), None);

    // 2. SAT ATA PASS-THROUGH (16) encoding (Opcode 0x85)
    let sat_cdb = AtaCodec::encode_sat_passthrough_16(0xEC, 0x0000, 0, 1, 4); // IDENTIFY DEVICE
    assert_eq!(sat_cdb[0], 0x85);
    assert_eq!(sat_cdb[14], 0xEC);
    ledger.assert("P1-ATA", "HW-ATA-SAT-ENCODE", "true", "true", None);
}

fn run_scsi_codec_tests(ledger: &RigLedger) {
    println!("\n[>>> HW-SCSI: Testing SCSI SANITIZE CDB & Sense Decoding (Δ209) <<<]");

    // 1. SCSI SANITIZE (Block Erase = 0x02, IMMED=1)
    let cdb = ScsiCodec::encode_sanitize(ScsiSanitizeServiceAction::BlockErase, true);
    assert_eq!(cdb[0], 0x48, "Opcode 0x48 for SCSI SANITIZE");
    assert_eq!(cdb[1], 0x82, "IMMED (0x80) | ServiceAction (0x02)");
    ledger.assert("P1-SCSI", "HW-SCSI-SANITIZE-ENCODE", "true", "true", None);

    // 2. Sense data with progress (SKSV set, progress = 32768 => 500 permille)
    let mut raw_sense = vec![0u8; 32];
    raw_sense[0] = 0x70; // Fixed format
    raw_sense[2] = 0x02; // Sense key: NOT READY
    raw_sense[12] = 0x04; // ASC: LOGICAL UNIT NOT READY
    raw_sense[13] = 0x1B; // ASCQ: SANITIZE IN PROGRESS
    raw_sense[15] = 0x80; // SKSV bit set
    raw_sense[16..18].copy_from_slice(&32768u16.to_be_bytes()); // Progress raw

    let sense = ScsiCodec::decode_sense_data(&raw_sense).unwrap();
    assert_eq!(sense.sense_key, 2);
    assert_eq!(sense.progress_permille, Some(500));
    ledger.assert("P1-SCSI", "HW-SCSI-SENSE-DECODE", "500", sense.progress_permille.unwrap().to_string(), None);
}
