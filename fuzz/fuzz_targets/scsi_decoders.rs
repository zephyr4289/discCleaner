//! cargo-fuzz target: SCSI + ATA binary decoders (host-side untrusted input).
//!
//! Drives and SAT translators return attacker-shaped sense data, inquiry
//! pages, defect lists, log pages and ATA return descriptors. Every
//! decoder in `dc-hw` must bound-check before it trusts: a malicious
//! drive answering a purge preflight must never crash the fleet agent.

#![no_main]

use dc_hw::ata_codec::AtaCodec;
use dc_hw::scsi_codec::ScsiCodec;
use dc_hw::thermal::{decode_log_sense_temperature, decode_smart_temperature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // SCSI: sense data, inquiry identity, defect list, log-sense temperature.
    let _ = ScsiCodec::decode_sense_data(data);
    let _ = ScsiCodec::decode_inquiry_identity(data);
    let _ = ScsiCodec::decode_defect_list_count(data);
    let _ = decode_log_sense_temperature(data);
    // ATA: SMART attribute temperature + return-descriptor LBA.
    let _ = decode_smart_temperature(data);
    let _ = AtaCodec::decode_ata_return_descriptor_lba(data);
    // The 512-byte identify block is length-gated internally; arbitrary
    // input must be rejected, never trusted.
    let _ = AtaCodec::decode_identify_device(data);
});
