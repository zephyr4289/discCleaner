//! Raw NAND flash layer — the thing the kernel owns once silicon is revived.
//!
//! Command set is the classic asynchronous interface every ONFI-style die
//! speaks (identical opcodes across vendors):
//!
//! ```text
//! 0xFF RESET            0x90 READ ID (addr 0x00, 5 bytes; addr 0x20 = ONFI)
//! 0xEC READ PARAM PAGE  0x70 READ STATUS
//! 0x60 ERASE SETUP      0xD0 ERASE CONFIRM   (row address between them)
//! 0x00/0x30 PAGE READ   0xEF/0xEE SET/GET FEATURES
//! ```
//!
//! Geometry discovery is real, not hard-coded: stage-1 of the injected
//! nucleus issues READ PARAM (0xEC) and the host parses the ONFI parameter
//! page (signature "ONFI", bytes/page @ 32, spare @ 36, pages/block @ 38,
//! blocks/LUN @ 42, LUNs @ 46). Stage-2 is then *assembled for that exact
//! geometry* — the self in self-assembling.
//!
//! The device-side [`NandDie`] models: erased pages read 0xFF, bad-block
//! markers in the first spare byte, per-block erase counters, and marginal
//! blocks that fail erase N times before succeeding (the wear-out pattern
//! you meet on decade-old drives in decommissioning bins).

/// NAND command bytes.
pub mod nand_cmd {
    pub const RESET: u8 = 0xFF;
    pub const READ_ID: u8 = 0x90;
    pub const READ_PARAM: u8 = 0xEC;
    pub const READ_STATUS: u8 = 0x70;
    pub const ERASE_SETUP: u8 = 0x60;
    pub const ERASE_CONFIRM: u8 = 0xD0;
    pub const READ_SETUP: u8 = 0x00;
    pub const READ_CONFIRM: u8 = 0x30;
}

/// Status register bits (modeled, Micron-datasheet flavored).
pub mod nand_status {
    /// Status is valid (last operation complete).
    pub const READY: u8 = 0x80;
    /// Last erase/program failed.
    pub const FAIL: u8 = 0x01;
}

/// Geometry of the attached raw NAND.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NandGeometry {
    pub bytes_per_page: u32,
    pub spare_bytes: u32,
    pub pages_per_block: u32,
    pub blocks_per_lun: u32,
    pub luns: u32,
}

impl NandGeometry {
    pub fn new(
        bytes_per_page: u32,
        spare_bytes: u32,
        pages_per_block: u32,
        blocks_per_lun: u32,
        luns: u32,
    ) -> Self {
        NandGeometry {
            bytes_per_page,
            spare_bytes,
            pages_per_block,
            blocks_per_lun,
            luns,
        }
    }

    /// User-visible capacity in bytes.
    pub fn capacity(&self) -> u64 {
        self.total_blocks() as u64 * self.pages_per_block as u64 * self.bytes_per_page as u64
    }

    pub fn total_blocks(&self) -> u32 {
        self.blocks_per_lun * self.luns
    }

    pub fn page_stride(&self) -> u32 {
        self.bytes_per_page + self.spare_bytes
    }

    /// Row address cycles: 3 for these part sizes (24-bit block<<ppb).
    pub fn row_cycles(&self) -> u32 {
        3
    }

    /// Column address cycles: 2 (16-bit offset within page).
    pub fn col_cycles(&self) -> u32 {
        2
    }

    /// log2 for shift-based addressing (geometry is power-of-two here).
    pub fn log2_pages_per_block(&self) -> u32 {
        self.pages_per_block.trailing_zeros()
    }

    pub fn log2_blocks_per_lun(&self) -> u32 {
        self.blocks_per_lun.trailing_zeros()
    }

    /// Build a 256-byte ONFI parameter page for this geometry.
    pub fn to_onfi_param_page(&self) -> [u8; 256] {
        let mut p = [0xFFu8; 256];
        p[0..4].copy_from_slice(b"ONFI");
        p[4] = 0x01; // revision 1.0
        p[5] = 0x00;
        p[6..8].copy_from_slice(&[0x00, 0x00]); // features
        p[8..10].copy_from_slice(&[0x00, 0x00]); // optional commands
        p[10..12].copy_from_slice(&[0x00, 0x00]); // reserved
        p[32..36].copy_from_slice(&self.bytes_per_page.to_le_bytes());
        p[36..38].copy_from_slice(&(self.spare_bytes as u16).to_le_bytes());
        p[38..42].copy_from_slice(&self.pages_per_block.to_le_bytes());
        p[42..46].copy_from_slice(&self.blocks_per_lun.to_le_bytes());
        p[46] = self.luns as u8;
        p[47] = ((self.col_cycles() << 4) | self.row_cycles()) as u8;
        p[48] = 1; // 1 bit per cell (SLC-mode model)
        p[49..51].copy_from_slice(&16u16.to_le_bytes()); // bad blocks per LUN max (LE u16)
        p[52] = 1; // block endurance, dummy model
        // guaranteed valid block start... (offsets beyond our parse scope)
        p
    }

    /// Parse the fields the rig needs out of an ONFI parameter page.
    pub fn from_onfi_param_page(page: &[u8]) -> Option<NandGeometry> {
        if page.len() < 48 || &page[0..4] != b"ONFI" {
            return None;
        }
        let bytes_per_page = u32::from_le_bytes([page[32], page[33], page[34], page[35]]);
        let spare_bytes = u16::from_le_bytes([page[36], page[37]]) as u32;
        let pages_per_block = u32::from_le_bytes([page[38], page[39], page[40], page[41]]);
        let blocks_per_lun = u32::from_le_bytes([page[42], page[43], page[44], page[45]]);
        let luns = page[46] as u32;
        if bytes_per_page == 0 || pages_per_block == 0 || blocks_per_lun == 0 || luns == 0 {
            return None;
        }
        Some(NandGeometry {
            bytes_per_page,
            spare_bytes,
            pages_per_block,
            blocks_per_lun,
            luns,
        })
    }
}

/// Result of one erase attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EraseOutcome {
    Ok,
    FailedThisAttempt,
}

/// One physical erase block.
pub struct NandBlock {
    /// pages_per_block * (main + spare) bytes, page-major.
    data: Vec<u8>,
    erase_count: u32,
    bad: bool,
}

/// One LUN / chip-enable worth of blocks (the "die" the kernel erases).
pub struct NandDie {
    pub geometry: NandGeometry,
    blocks: Vec<NandBlock>,
    read_id: [u8; 5],
    /// Marginal blocks: number of erase attempts that still fail.
    marginal: std::collections::HashMap<u32, u32>,
    /// Blocks that never erase (injected permanent faults).
    stuck: std::collections::HashSet<u32>,
    status: u8,
}

impl NandDie {
    /// Build a die pre-loaded with seeded forensic-looking data.
    pub fn new(
        geometry: NandGeometry,
        read_id: [u8; 5],
        rng: &mut crate::rng::XorShift,
    ) -> NandDie {
        let stride = geometry.page_stride() as usize;
        let ppb = geometry.pages_per_block as usize;
        let main = geometry.bytes_per_page as usize;
        let blocks = (0..geometry.blocks_per_lun)
            .map(|_| {
                let mut v = vec![0xFFu8; stride * ppb];
                // Every page carries old data except spare bad markers.
                for page in v.chunks_mut(stride) {
                    rng.fill_forensic(&mut page[..main]);
                }
                NandBlock {
                    data: v,
                    erase_count: 0,
                    bad: false,
                }
            })
            .collect();
        let mut die = NandDie {
            geometry,
            blocks,
            read_id,
            marginal: Default::default(),
            stuck: Default::default(),
            status: nand_status::READY,
        };
        die.finish_init(rng);
        die
    }

    /// Mark a handful of factory bad blocks (spare byte 0 of page 0 = 0x00),
    /// plus two marginal blocks that fail erase once or twice before
    /// succeeding (the decade-old-drive wear pattern).
    fn finish_init(&mut self, rng: &mut crate::rng::XorShift) {
        let len = self.blocks.len() as u32;
        let m0 = 37 % len;
        let m1 = 200 % len;
        self.marginal.insert(m0, 1);
        self.marginal.insert(m1, 2);
        let nbad = (len / 256).max(2);
        let mut marked = 0;
        while marked < nbad {
            let b = rng.below(len as u64) as u32;
            // Never bury a marginal block under a bad marker — the demo
            // needs the retry path to be reachable.
            if self.marginal.contains_key(&b) || b == 0 {
                continue;
            }
            self.mark_bad(b);
            marked += 1;
        }
    }

    fn mark_bad(&mut self, block: u32) {
        let main = self.geometry.bytes_per_page as usize;
        if let Some(b) = self.blocks.get_mut(block as usize) {
            b.bad = true;
            // Classic factory bad marker: spare byte 0 of page 0 = 0x00.
            b.data[main] = 0x00;
        }
    }

    pub fn read_id(&self) -> [u8; 5] {
        self.read_id
    }

    /// ONFI parameter page bytes.
    pub fn param_page(&self) -> [u8; 256] {
        self.geometry.to_onfi_param_page()
    }

    pub fn status(&self) -> u8 {
        self.status
    }

    pub fn set_status(&mut self, s: u8) {
        self.status = s;
    }

    pub fn block_count(&self) -> u32 {
        self.blocks.len() as u32
    }

    pub fn is_bad(&self, block: u32) -> bool {
        self.blocks
            .get(block as usize)
            .map(|b| b.bad)
            .unwrap_or(true)
    }

    pub fn erase_count(&self, block: u32) -> u32 {
        self.blocks
            .get(block as usize)
            .map(|b| b.erase_count)
            .unwrap_or(0)
    }

    /// Erase one block. Marginal blocks fail a bounded number of attempts;
    /// injected stuck blocks never succeed.
    pub fn erase_block(&mut self, block: u32) -> EraseOutcome {
        if let Some(n) = self.marginal.get_mut(&block)
            && *n > 0
        {
            *n -= 1;
            return EraseOutcome::FailedThisAttempt;
        }
        if self.stuck.contains(&block) {
            return EraseOutcome::FailedThisAttempt;
        }
        if let Some(b) = self.blocks.get_mut(block as usize) {
            b.data.fill(0xFF);
            b.erase_count += 1;
            EraseOutcome::Ok
        } else {
            EraseOutcome::FailedThisAttempt
        }
    }

    /// Inject a permanently stuck block (test / fault-injection path).
    pub fn inject_stuck(&mut self, block: u32) {
        self.stuck.insert(block);
    }

    /// Read one page (main + spare, contiguous slice).
    pub fn read_page(&self, block: u32, page: u32) -> Option<&[u8]> {
        let b = self.blocks.get(block as usize)?;
        let stride = self.geometry.page_stride() as usize;
        let ppb = self.geometry.pages_per_block as usize;
        let idx = page as usize;
        if idx >= ppb {
            return None;
        }
        Some(&b.data[idx * stride..(idx + 1) * stride])
    }

    /// Count non-erased bytes in a page (host-side verify helper).
    pub fn count_non_ff(page: &[u8]) -> u32 {
        page.iter().filter(|&&b| b != 0xFF).count() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geo() -> NandGeometry {
        NandGeometry::new(2048, 64, 64, 512, 2)
    }

    #[test]
    fn onfi_round_trip() {
        let g = geo();
        let page = g.to_onfi_param_page();
        assert_eq!(&page[0..4], b"ONFI");
        let parsed = NandGeometry::from_onfi_param_page(&page).unwrap();
        assert_eq!(parsed, g);
        assert_eq!(parsed.capacity(), 512 * 2 * 64 * 2048);
    }

    #[test]
    fn onfi_rejects_garbage() {
        assert!(NandGeometry::from_onfi_param_page(&[0u8; 256]).is_none());
        let mut p = geo().to_onfi_param_page();
        p[38] = 0; // pages_per_block = 0
        assert!(NandGeometry::from_onfi_param_page(&p).is_none());
    }

    #[test]
    fn erase_and_bad_markers() {
        let mut rng = crate::rng::XorShift::new(7);
        let g = geo();
        let mut die = NandDie::new(g, [0x98, 0xDE, 0x94, 0x32, 0x76], &mut rng);
        assert!(die.block_count() == 512);
        // data present before erase
        assert!(die.read_page(10, 3).map(NandDie::count_non_ff).unwrap_or(0) > 0);
        assert_eq!(die.erase_block(10), EraseOutcome::Ok);
        assert_eq!(NandDie::count_non_ff(die.read_page(10, 3).unwrap()), 0);
        assert_eq!(die.erase_count(10), 1);
        // marginal block 37 fails first, succeeds second
        assert_eq!(die.erase_block(37), EraseOutcome::FailedThisAttempt);
        assert!(die.read_page(37, 0).map(NandDie::count_non_ff).unwrap_or(0) > 0);
        assert_eq!(die.erase_block(37), EraseOutcome::Ok);
        // stuck blocks never erase
        die.inject_stuck(400);
        for _ in 0..5 {
            assert_eq!(die.erase_block(400), EraseOutcome::FailedThisAttempt);
        }
        // factory bad blocks exist and are flagged
        let bads = (0..die.block_count()).filter(|&b| die.is_bad(b)).count();
        assert!(bads >= 2, "expected factory bad blocks, got {bads}");
    }
}
