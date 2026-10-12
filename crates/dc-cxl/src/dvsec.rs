//! PCIe DVSEC discovery: parse extended capabilities from config space,
//! find the CXL DVSEC structures (vendor 0x1E98) and extract the device
//! register block locator.

use crate::regs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DvsecError {
    #[error("config space too short ({0} bytes, need at least 256)")]
    TooShort(usize),
    #[error("malformed extended capability chain at offset {0:#x}")]
    MalformedChain(u16),
    #[error("no CXL DVSEC (vendor {:#06x}) found", regs::CXL_DVSEC_VENDOR_ID)]
    NoCxlDvsec,
    #[error("register block locator has no component register block")]
    NoRegisterBlock,
}

/// One parsed DVSEC structure.
#[derive(Debug, Clone, PartialEq)]
pub struct Dvsec {
    /// Offset of the DVSEC header within config space.
    pub offset: u16,
    /// DVSEC revision.
    pub revision: u8,
    /// DVSEC length in bytes (including header).
    pub length: u16,
    /// DVSEC ID (0 = CXL Device, 2 = CXL Extensions, ...).
    pub id: u16,
    /// Body bytes (after the 8-byte DVSEC header).
    pub body: Vec<u8>,
}

/// Walk the PCIe extended capability chain and return all DVSEC
/// structures with the CXL vendor ID.
pub fn find_cxl_dvsecs(config: &[u8]) -> Result<Vec<Dvsec>, DvsecError> {
    if config.len() < 256 {
        return Err(DvsecError::TooShort(config.len()));
    }
    let mut out = Vec::new();
    // The extended capability chain begins at 0x100 (if the space is
    // extended at all); the first entry's cap id of 0 means "none".
    let first_id = u16::from_le_bytes([config[0x100], config[0x101]]);
    let mut next: u16 = if first_id == 0 { 0 } else { 0x100 };
    let mut guard = 0;
    while next != 0 && next >= 0x40 && (next as usize) + 12 <= config.len() {
        guard += 1;
        if guard > 256 {
            return Err(DvsecError::MalformedChain(next));
        }
        let base = next as usize;
        let cap_id = u16::from_le_bytes([config[base], config[base + 1]]);
        let cap_next = u16::from_le_bytes([config[base + 2], config[base + 3]]) & 0xfffc;
        if cap_id == regs::PCIE_EXT_CAP_DVSEC {
            // DVSEC Header 1 (+4): vendor [15:0], revision [19:16],
            // length [31:20] (length includes the full DVSEC from 00h).
            let hdr1 = u32::from_le_bytes(config[base + 4..base + 8].try_into().unwrap());
            let vendor = (hdr1 & 0xffff) as u16;
            let revision = ((hdr1 >> 16) & 0xf) as u8;
            let length = ((hdr1 >> 20) & 0xfff) as u16;
            // DVSEC Header 2 (+8): DVSEC ID [15:0].
            let id = u16::from_le_bytes([config[base + 8], config[base + 9]]);
            let body_end = base as u32 + u32::from(length.max(12));
            let body = config
                .get(base + 12..body_end as usize)
                .map(|s| s.to_vec())
                .unwrap_or_default();
            if vendor == regs::CXL_DVSEC_VENDOR_ID {
                out.push(Dvsec {
                    offset: next,
                    revision,
                    length,
                    id,
                    body,
                });
            }
        }
        next = cap_next;
    }
    if out.is_empty() {
        return Err(DvsecError::NoCxlDvsec);
    }
    Ok(out)
}

/// Extract the offset of the CXL device register block (BAR + offset)
/// from the PCIe DVSEC for CXL Device (ID 0) Register Block Locator
/// (§8.1.3.7: DVSEC body offset 0x00 = register block identifier: BAR
/// index in bits [1:0], offset in bits [31:16]).
#[derive(Debug, Clone, PartialEq)]
pub struct RegisterBlockLocator {
    pub bar_index: u8,
    /// 32-bit offset within the BAR.
    pub bar_offset: u64,
}

pub fn register_block_locator(dvsec: &Dvsec) -> Result<RegisterBlockLocator, DvsecError> {
    if dvsec.id != regs::DVSEC_ID_CXL_DEVICE || dvsec.body.len() < 4 {
        return Err(DvsecError::NoRegisterBlock);
    }
    let rbl = u32::from_le_bytes([dvsec.body[0], dvsec.body[1], dvsec.body[2], dvsec.body[3]]);
    let bar_index = (rbl & 0x3) as u8;
    if rbl & 0x4 == 0 {
        // Register block not identified — no component registers.
        return Err(DvsecError::NoRegisterBlock);
    }
    // Bits [31:16]: offset within the BAR.
    let bar_offset = u64::from(rbl >> 16);
    Ok(RegisterBlockLocator {
        bar_index,
        bar_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a config space with one DVSEC at 0x100: CXL vendor, given
    /// ID, and a Register Block Identifier in the DVSEC data.
    fn synth_config(dvsec_vendor: u16, dvsec_id: u16, rbl: Option<u32>) -> Vec<u8> {
        let mut c = vec![0u8; 512];
        let base = 0x100;
        // ext cap header: id 0x23, next 0
        c[base..base + 2].copy_from_slice(&regs::PCIE_EXT_CAP_DVSEC.to_le_bytes());
        c[base + 2..base + 4].copy_from_slice(&0x0000u16.to_le_bytes());
        // DVSEC header 1: vendor + revision 1 + length 0x18 (24 bytes)
        let hdr1 = u32::from(dvsec_vendor) | (1u32 << 16) | (0x18u32 << 20);
        c[base + 4..base + 8].copy_from_slice(&hdr1.to_le_bytes());
        // DVSEC header 2: ID
        c[base + 8..base + 10].copy_from_slice(&dvsec_id.to_le_bytes());
        // DVSEC data at +0x0C: register block identifier
        if let Some(rbl) = rbl {
            c[base + 12..base + 16].copy_from_slice(&rbl.to_le_bytes());
        }
        c
    }

    #[test]
    fn finds_cxl_dvsec_and_locator() {
        // BAR index 1, component registers mapped (bit 2).
        let rbl = 1u32 | 0x4;
        let c = synth_config(regs::CXL_DVSEC_VENDOR_ID, 0, Some(rbl));
        let dvsecs = find_cxl_dvsecs(&c).unwrap();
        assert_eq!(dvsecs.len(), 1);
        assert_eq!(dvsecs[0].id, 0);
        assert_eq!(dvsecs[0].length, 0x18);
        let loc = register_block_locator(&dvsecs[0]).unwrap();
        assert_eq!(loc.bar_index, 1);
        assert_eq!(loc.bar_offset, 0);
    }

    #[test]
    fn locator_bar_offset_decodes() {
        // BAR 2, offset 0x10000 in bits [31:16].
        let rbl = 2u32 | 0x4 | (0x10000u32 >> 16 << 16);
        let rbl = (rbl & 0x0000ffff) | (0x0001u32 << 16);
        let c = synth_config(regs::CXL_DVSEC_VENDOR_ID, 0, Some(rbl));
        let dvsecs = find_cxl_dvsecs(&c).unwrap();
        let loc = register_block_locator(&dvsecs[0]).unwrap();
        assert_eq!(loc.bar_index, 2);
        assert_eq!(loc.bar_offset, 1);
    }

    #[test]
    fn ignores_foreign_dvsec_vendors() {
        let c = synth_config(0x1234, 0, Some(0x5));
        assert!(matches!(find_cxl_dvsecs(&c), Err(DvsecError::NoCxlDvsec)));
    }

    #[test]
    fn rejects_short_config() {
        assert!(matches!(
            find_cxl_dvsecs(&[0u8; 128]),
            Err(DvsecError::TooShort(_))
        ));
    }

    #[test]
    fn unmarked_register_block_rejected() {
        // bit 2 clear: no component register block identified
        let c = synth_config(regs::CXL_DVSEC_VENDOR_ID, 0, Some(0x1));
        let dvsecs = find_cxl_dvsecs(&c).unwrap();
        assert!(matches!(
            register_block_locator(&dvsecs[0]),
            Err(DvsecError::NoRegisterBlock)
        ));
    }
}
