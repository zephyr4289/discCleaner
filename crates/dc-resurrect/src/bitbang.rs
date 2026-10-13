//! Boundary-scan NAND bit-bang — the corpse endgame.
//!
//! When the vendor debug bridges are locked (SWD AP faults, JTAG-DP feeds
//! junk) but the TAP still scans, the last route into the silicon is
//! IEEE 1149.1 EXTEST: drive the controller's NAND bus pins — CLE, ALE,
//! nCE, nWE, nRE, DQ[7:0] — directly through the boundary-scan register.
//! Every command byte costs two BSR shifts; every data byte three; no
//! CPU, no firmware, no cooperation required from anything on the board.
//!
//! This is why the payload-injection routes exist: at 1 MHz TCK the
//! pin-level path moves bytes at roughly two per BSR shift-set. The
//! in-silicon nucleus does the same work four orders of magnitude faster.
//! But when the alternative is a shredder quote, slow works.
//!
//! BSR cell map (24-bit default, matching the profile database):
//!
//! ```text
//! bits 0-7   DQ[7:0]   bidirectional data bus
//! bit  8     CLE       command latch enable
//! bit  9     ALE       address latch enable
//! bit  10    nCE       chip enable (active low)
//! bit  11    nWE       write enable (active low; latch on rising edge)
//! bit  12    nRE       read enable (active low; DQ driven while low)
//! bit  13    R/nB      ready/busy (input from the die)
//! bit  14    DIE_SEL   modeled die-select line for multi-LUN packages
//! ```

use crate::attest::BlockRecord;
use crate::crc::crc32_byte;
use crate::hal::JtagLink;
use crate::jtag::{JtagEngine, tap_ir};
use crate::nand::NandGeometry;
use crate::nand::nand_cmd::{
    ERASE_CONFIRM, ERASE_SETUP, READ_CONFIRM, READ_SETUP, READ_STATUS, RESET,
};
use crate::payload::VerifyMode;

pub struct BitBangNand<'a, L: JtagLink> {
    eng: &'a mut JtagEngine<L>,
    bsr_len: u32,
    /// Total BSR shift operations performed (for the cost model).
    pub shifts: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
    die_sel: bool,
}

fn pins_word(
    dq: u8,
    cle: bool,
    ale: bool,
    ce_n: bool,
    we_n: bool,
    re_n: bool,
    die_sel: bool,
    len: usize,
) -> Vec<bool> {
    let mut v = vec![false; len];
    for k in 0..8 {
        if v.len() > k {
            v[k] = (dq >> k) & 1 == 1;
        }
    }
    let set = |v: &mut Vec<bool>, i: usize, b: bool| {
        if v.len() > i {
            v[i] = b;
        }
    };
    set(&mut v, 8, cle);
    set(&mut v, 9, ale);
    set(&mut v, 10, ce_n);
    set(&mut v, 11, we_n);
    set(&mut v, 12, re_n);
    set(&mut v, 14, die_sel);
    v
}

impl<'a, L: JtagLink> BitBangNand<'a, L> {
    pub fn new(eng: &'a mut JtagEngine<L>, irlen: u32, bsr_len: u32) -> BitBangNand<'a, L> {
        eng.shift_ir(tap_ir::EXTEST, irlen);
        BitBangNand {
            eng,
            bsr_len,
            shifts: 0,
            bytes_written: 0,
            bytes_read: 0,
            die_sel: false,
        }
    }

    /// One BSR update: shift `tdi` through DR, apply on Update-DR,
    /// return the captured input cells.
    fn apply(&mut self, tdi: Vec<bool>) -> Vec<bool> {
        self.shifts += 1;
        self.eng.shift_dr(&tdi)
    }

    fn idle_pins(&self) -> Vec<bool> {
        pins_word(
            0,
            false,
            false,
            false,
            true,
            true,
            self.die_sel,
            self.bsr_len as usize,
        )
    }

    fn select_die(&mut self, die: u32) {
        self.die_sel = die & 1 == 1;
    }

    /// Strobe one command byte (CLE qualified, latch on rising nWE).
    pub fn cmd(&mut self, byte: u8) {
        self.apply(pins_word(
            byte,
            true,
            false,
            false,
            false,
            true,
            self.die_sel,
            self.bsr_len as usize,
        ));
        self.apply(pins_word(
            byte,
            true,
            false,
            false,
            true,
            true,
            self.die_sel,
            self.bsr_len as usize,
        ));
        self.bytes_written += 1;
    }

    /// Strobe one address byte (ALE qualified).
    pub fn addr(&mut self, byte: u8) {
        self.apply(pins_word(
            byte,
            false,
            true,
            false,
            false,
            true,
            self.die_sel,
            self.bsr_len as usize,
        ));
        self.apply(pins_word(
            byte,
            false,
            true,
            false,
            true,
            true,
            self.die_sel,
            self.bsr_len as usize,
        ));
        self.bytes_written += 1;
    }

    /// Read one byte: assert nRE (controller drives DQ), capture, release.
    pub fn read_byte(&mut self) -> u8 {
        self.apply(pins_word(
            0,
            false,
            false,
            false,
            true,
            false,
            self.die_sel,
            self.bsr_len as usize,
        ));
        let cap = self.apply(pins_word(
            0,
            false,
            false,
            false,
            true,
            false,
            self.die_sel,
            self.bsr_len as usize,
        ));
        self.apply(pins_word(
            0,
            false,
            false,
            false,
            true,
            true,
            self.die_sel,
            self.bsr_len as usize,
        ));
        self.bytes_read += 1;
        let mut b = 0u8;
        for k in 0..8 {
            if cap.get(k).copied().unwrap_or(false) {
                b |= 1 << k;
            }
        }
        b
    }

    /// Poll the R/nB cell (BSR bit 13).
    pub fn wait_ready(&mut self) -> bool {
        for _ in 0..2000 {
            let cap = self.apply(self.idle_pins());
            if cap.get(13).copied().unwrap_or(true) {
                return true;
            }
        }
        false
    }

    /// Issue READ STATUS and return the status byte.
    pub fn status(&mut self) -> u8 {
        self.cmd(READ_STATUS);
        self.read_byte()
    }

    pub fn is_ready(st: u8) -> bool {
        st & 0x80 != 0
    }

    pub fn is_fail(st: u8) -> bool {
        st & 0x01 != 0
    }

    /// Full erase pass over every die, at pin level.
    ///
    /// Records mirror what the in-silicon kernel would have written:
    /// status 0 = erased (with CRC of verified pages), 1 = factory bad
    /// skipped, 2 = failed after retries.
    pub fn run_erase(
        &mut self,
        geo: &NandGeometry,
        verify: VerifyMode,
        irlen: u32,
        mut progress: impl FnMut(u32, u32),
    ) -> Vec<BlockRecord> {
        let mut records = Vec::new();
        for die in 0..geo.luns {
            self.select_die(die);
            self.cmd(RESET);
            let _ = self.wait_ready();
            let mut block: u32 = 0;
            while block < geo.blocks_per_lun {
                progress(die, block);
                // factory bad marker: spare byte 0 of page 0
                let bad = self.read_bad_marker(geo, die, block);
                if bad != 0xFF {
                    records.push(BlockRecord::skipped_bad(die as u8, block));
                    block += 1;
                    continue;
                }
                // erase with up to 3 attempts
                let mut erased = false;
                for _ in 0..3 {
                    self.cmd(ERASE_SETUP);
                    let row = (die * geo.blocks_per_lun + block) << geo.log2_pages_per_block();
                    for k in 0..3 {
                        self.addr(((row >> (8 * k)) & 0xFF) as u8);
                    }
                    self.cmd(ERASE_CONFIRM);
                    if !self.wait_ready() {
                        continue;
                    }
                    let st = self.status();
                    if Self::is_ready(st) && !Self::is_fail(st) {
                        erased = true;
                        break;
                    }
                }
                if !erased {
                    records.push(BlockRecord::failed_erase(die as u8, block));
                    block += 1;
                    continue;
                }
                // verify pass
                let stride = match verify {
                    VerifyMode::Off => 0,
                    VerifyMode::Sampled => (geo.pages_per_block / 2).max(1),
                    VerifyMode::Full => 1,
                };
                let mut nonzero: u32 = 0;
                let mut crc: u32 = 0xFFFF_FFFF;
                if stride > 0 {
                    let mut page: u32 = 0;
                    while page < geo.pages_per_block {
                        nonzero += self.read_page_crc(geo, die, block, page, &mut crc);
                        page += stride;
                    }
                }
                records.push(BlockRecord::erased(die as u8, block, nonzero, !crc));
                block += 1;
            }
        }
        let _ = irlen;
        records
    }

    /// Read the bad marker: spare byte 0 of page 0 of (die, block).
    fn read_bad_marker(&mut self, geo: &NandGeometry, die: u32, block: u32) -> u8 {
        self.cmd(READ_SETUP);
        let col = geo.bytes_per_page;
        self.addr((col & 0xFF) as u8);
        self.addr(((col >> 8) & 0xFF) as u8);
        let row = (die * geo.blocks_per_lun + block) << geo.log2_pages_per_block();
        for k in 0..3 {
            self.addr(((row >> (8 * k)) & 0xFF) as u8);
        }
        self.cmd(READ_CONFIRM);
        if !self.wait_ready() {
            return 0x00;
        }
        self.read_byte()
    }

    /// Read one page (main area only) at pin level; updates the running
    /// CRC-32 state, returns the page's non-FF byte count.
    fn read_page_crc(
        &mut self,
        geo: &NandGeometry,
        die: u32,
        block: u32,
        page: u32,
        crc: &mut u32,
    ) -> u32 {
        self.cmd(READ_SETUP);
        self.addr(0);
        self.addr(0);
        let row = ((die * geo.blocks_per_lun + block) << geo.log2_pages_per_block()) + page;
        for k in 0..3 {
            self.addr(((row >> (8 * k)) & 0xFF) as u8);
        }
        self.cmd(READ_CONFIRM);
        if !self.wait_ready() {
            return u32::MAX;
        }
        let mut nonzero = 0u32;
        for _ in 0..geo.bytes_per_page {
            let b = self.read_byte();
            if b != 0xFF {
                nonzero += 1;
            }
            *crc = crc32_byte(*crc, b);
        }
        nonzero
    }
}

/// Estimated wall time for the pin-level path at a given TCK frequency.
pub fn estimate_seconds(shifts: u64, bsr_len: u32, tck_hz: u64) -> f64 {
    // Each shift = IR/DR walk overhead (~12 clocks) + bsr_len data clocks.
    let clocks = shifts * (bsr_len as u64 + 12);
    clocks as f64 / tck_hz as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_model_scales() {
        let s = estimate_seconds(1_000_000, 24, 1_000_000);
        assert!((s - 36.0).abs() < 0.01, "{s}");
    }

    #[test]
    fn pin_word_layout() {
        let w = pins_word(0xA5, true, false, false, false, true, false, 24);
        assert!(w[0]);
        assert!(!w[1]);
        assert!(w[5]);
        assert!(w[7]); // 0xA5 = 1010_0101
        assert!(w[8]); // CLE
        assert!(!w[9]); // ALE
        assert!(!w[10]); // nCE
        assert!(!w[11]); // nWE
        assert!(w[12]); // nRE
    }
}
