//! SCSI command encapsulation over the iSCSI session (RFC 3720 §10.3):
//! SCSI Command PDU -> Data-In reassembly -> SCSI Response with sense.

use crate::IscsiError;
use crate::bhs::{OP_DATA_IN, OP_SCSI_CMD, OP_SCSI_RSP, Pdu, read_pdu, write_pdu};
use dc_hw::ScsiSenseData;
use std::net::TcpStream;
use std::time::Duration;

/// Parameters for one SCSI passthrough command.
#[derive(Clone, Debug)]
pub struct ScsiIoParams {
    /// 8-byte LUN structure (SAM flat addressing).
    pub lun: [u8; 8],
    /// The CDB (1-16 bytes).
    pub cdb: [u8; 16],
    /// CDB length in bytes (the 16-byte array is zero-padded).
    pub cdb_len: usize,
    /// Expected read-back length (0 = no data expected).
    pub expected_read_len: u32,
    /// Per-PDU deadline.
    pub timeout: Duration,
}

impl ScsiIoParams {
    pub fn read(lun: u16, cdb: [u8; 16], cdb_len: usize, expected: u32, timeout: Duration) -> Self {
        Self {
            lun: crate::login::lun_bytes(lun),
            cdb,
            cdb_len,
            expected_read_len: expected,
            timeout,
        }
    }

    pub fn write(lun: u16, cdb: [u8; 16], cdb_len: usize, timeout: Duration) -> Self {
        Self::read(lun, cdb, cdb_len, 0, timeout)
    }
}

/// Result of one SCSI command exchange.
#[derive(Clone, Debug)]
pub struct ScsiIoOutcome {
    /// iSCSI response code (0 = command completed at target level).
    pub response: u8,
    /// SCSI status byte (0 = GOOD, 2 = CHECK CONDITION, ...).
    pub status: u8,
    /// Reassembled Data-In payload.
    pub data_in: Vec<u8>,
    /// Sense data when the target reported CHECK CONDITION.
    pub sense: Option<ScsiSenseData>,
    /// Hex digest of the exchange transcript (evidence hook).
    pub itt_hex: String,
}

impl ScsiIoOutcome {
    /// Command completed with SCSI status GOOD (0x00)?
    pub fn is_good(&self) -> bool {
        self.response == 0 && self.status == 0
    }

    /// SANITIZE "in progress" sense: 2/04/1B (NOT READY / LOGICAL UNIT NOT
    /// READY / SANITIZE IN PROGRESS).
    pub fn is_sanitize_in_progress(&self) -> bool {
        self.sense
            .as_ref()
            .map(|s| s.sense_key == 0x02 && s.asc == 0x04 && s.ascq == 0x1B)
            .unwrap_or(false)
    }
}

/// Issue one SCSI command on the logged-in session.
///
/// Frames the CDB exactly as the local SG_IO path would, then collects
/// Data-In PDUs until the final SCSI Response. Read and write data are
/// both bounded by `expected_read_len` (write payloads beyond the CDB
/// are not needed by the sanitize/format/inquiry verb set).
pub fn execute_scsi_command(
    stream: &mut TcpStream,
    itt: u32,
    cmdsn: u32,
    exp_statsn: u32,
    params: &ScsiIoParams,
) -> Result<ScsiIoOutcome, IscsiError> {
    // Build the SCSI Command PDU.
    let mut pdu = Pdu::new(OP_SCSI_CMD, true, Vec::new());
    {
        let b = &mut pdu.bhs.0;
        b[8..16].copy_from_slice(&params.lun); // LUN
        b[16..20].copy_from_slice(&itt.to_be_bytes()); // ITT
        b[20..24].copy_from_slice(&params.expected_read_len.to_be_bytes()); // EDTL
        b[24..28].copy_from_slice(&cmdsn.to_be_bytes()); // CmdSN
        b[28..32].copy_from_slice(&exp_statsn.to_be_bytes()); // ExpStatSN
        b[4] = 0; // TotalAHSLength
        // Expected bidirectional... (R/W bits): reads are implied by EDTL.
        // The CDB lives at bytes 32..48, right-padded.
        let padded = pad_cdb(&params.cdb, params.cdb_len);
        b[32..48].copy_from_slice(&padded);
    }
    write_pdu(stream, &pdu)?;

    // Collect Data-In PDUs until the SCSI Response.
    let mut data_in: Vec<u8> = Vec::new();
    let mut placed = 0usize;
    loop {
        let rsp = read_pdu(stream, params.timeout)?;
        match rsp.bhs.opcode() {
            OP_DATA_IN => {
                let offset = rsp.bhs.buffer_offset();
                if offset > 16 * 1024 * 1024 {
                    return Err(IscsiError::Protocol(format!(
                        "Data-In buffer offset {offset} outside the framing bound"
                    )));
                }
                if offset != placed {
                    return Err(IscsiError::Protocol(format!(
                        "Data-In offset {offset} != expected {placed} (unordered target)"
                    )));
                }
                if placed + rsp.data.len() > 16 * 1024 * 1024 {
                    return Err(IscsiError::Protocol(
                        "Data-In stream exceeds the 16 MiB bound".into(),
                    ));
                }
                data_in.extend_from_slice(&rsp.data);
                placed += rsp.data.len();
            }
            OP_SCSI_RSP => {
                let (response, status) = rsp.bhs.scsi_status();
                let sense = if status == 0x02 && !rsp.data.is_empty() {
                    decode_sense(&rsp.data)
                } else {
                    None
                };
                return Ok(ScsiIoOutcome {
                    response,
                    status,
                    data_in,
                    sense,
                    itt_hex: hex::encode(itt.to_be_bytes()),
                });
            }
            other => {
                return Err(IscsiError::Protocol(format!(
                    "unexpected opcode {other:#04x} during SCSI exchange"
                )));
            }
        }
    }
}

fn pad_cdb(cdb: &[u8; 16], len: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = len.min(16);
    out[..n].copy_from_slice(&cdb[..n]);
    out
}

/// Decode fixed-format sense data (SCSI SPC-4 §4.5): the descriptor
/// format and the legacy fixed format share the first 8 bytes for our
/// purposes (key at byte 2 low nibble, ASC byte 12, ASCQ byte 13 of
/// fixed format).
pub fn decode_sense(raw: &[u8]) -> Option<ScsiSenseData> {
    if raw.len() < 14 {
        return None;
    }
    let sense_key = raw[2] & 0x0F;
    let asc = raw[12];
    let ascq = raw[13];
    // Sense progress indicator: sense specific bytes 16..18, permille.
    let progress_permille = if raw.len() >= 18 && raw[15] & 0x80 != 0 {
        let raw16 = u16::from_be_bytes([raw[16], raw[17]]);
        // Progress is a 16-bit fraction of 65536 scaled to permille.
        Some((raw16 as u32 * 1000 / 65536) as u16)
    } else {
        None
    };
    Some(ScsiSenseData {
        sense_key,
        asc,
        ascq,
        progress_permille,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sense_decoding_maps_keys_asc_ascq() {
        let mut raw = [0u8; 18];
        raw[0] = 0x70; // fixed format, current
        raw[2] = 0x02; // NOT READY
        raw[12] = 0x04; // ASC
        raw[13] = 0x1B; // ASCQ: SANITIZE IN PROGRESS
        let s = decode_sense(&raw).unwrap();
        assert_eq!(s.sense_key, 2);
        assert_eq!(s.asc, 0x04);
        assert_eq!(s.ascq, 0x1B);
        let outcome = ScsiIoOutcome {
            response: 0,
            status: 2,
            data_in: Vec::new(),
            sense: Some(s),
            itt_hex: "00000001".into(),
        };
        assert!(outcome.is_sanitize_in_progress());
        assert!(!outcome.is_good());
    }

    #[test]
    fn short_sense_is_rejected_cleanly() {
        assert!(decode_sense(&[0u8; 8]).is_none());
        assert!(decode_sense(&[]).is_none());
    }

    #[test]
    fn progress_permille_scales_correctly() {
        let mut raw = [0u8; 18];
        raw[15] = 0x80; // valid sense-specific bytes
        raw[16] = 0x80; // 0x8000 = 50% -> 500 permille
        raw[17] = 0x00;
        let s = decode_sense(&raw).unwrap();
        assert_eq!(s.progress_permille, Some(500));
    }
}
