/// Independent second-lineage hardware codec oracle (Δ224).
/// Hand-transcribed from NVM Express Base 2.0d, ATA8-ACS 6a, and SPC-4 37 without importing dc-hw.

pub struct HwOracle;

impl HwOracle {
    /// Independent NVMe Sanitize command encoder.
    pub fn encode_nvme_sanitize(action: u8, no_deallocate: bool) -> [u8; 64] {
        let mut cmd = [0u8; 64];
        cmd[0] = 0x84; // NVMe Sanitize Opcode
        let mut cdw10 = (action as u32) & 0x07;
        if no_deallocate {
            cdw10 |= 1 << 9;
        }
        cmd[40..44].copy_from_slice(&cdw10.to_le_bytes());
        cmd
    }

    /// Independent SCSI SANITIZE 16-byte CDB encoder.
    pub fn encode_scsi_sanitize(service_action: u8, immed: bool) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = 0x48; // SCSI SANITIZE Opcode
        cdb[1] = service_action & 0x1F;
        if immed {
            cdb[1] |= 0x80;
        }
        cdb
    }

    /// Independent SAT ATA PASS-THROUGH (16) encoder.
    pub fn encode_sat_16(command: u8, features: u16, lba: u64, count: u16) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = 0x85;
        cdb[1] = 0x09; // Protocol: DMA or PIO with extend
        cdb[2] = 0x2E;
        cdb[3] = (features >> 8) as u8;
        cdb[4] = features as u8;
        cdb[5] = (count >> 8) as u8;
        cdb[6] = count as u8;
        cdb[7] = (lba >> 24) as u8;
        cdb[8] = lba as u8;
        cdb[9] = (lba >> 32) as u8;
        cdb[10] = (lba >> 8) as u8;
        cdb[11] = (lba >> 40) as u8;
        cdb[12] = (lba >> 16) as u8;
        cdb[13] = 0x40;
        cdb[14] = command;
        cdb[15] = 0x00;
        cdb
    }
}
