//! Simulated NAND controller — the block the kernel takes over.
//!
//! Two frontends drive one backend state machine, exactly like a real SoC:
//!
//! * **MMIO** (the in-silicon nucleus): command/addr/data/status/CE
//!   registers at the profile's `nand_mmio` block.
//! * **Pins** (the boundary-scan fallback for locked or corpse silicon):
//!   CLE/ALE/nCE/nWE/nRE edges on the DQ bus, plus R/nB and status read
//!   through 0x70 — what an EXTEST bit-bang rig wiggles.
//!
//! Command semantics (ONFI async interface, address cycles LSB first):
//!
//! ```text
//! 0x60 <row x3> 0xD0            erase block (row = block * pages_per_block)
//! 0x00 <col x2> <row x3> 0x30   page read, DATA auto-advances from col
//! 0x90 0x00                     read ID (5 bytes on DATA)
//! 0xEC 0x00                     read ONFI parameter page (256 bytes on DATA)
//! 0x70                          status latch: 0x80 ready, bit0 = fail
//! 0xFF                          reset
//! ```
//!
//! After an erase or read, `busy_polls` models the R/nB line: the first
//! status read(s) report busy, then the latched result appears.

use crate::nand::{EraseOutcome, NandDie, NandGeometry, nand_cmd, nand_status};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Idle,
    /// Column cycles expected: 2 for page read, 1 for ID/param.
    AddrCol {
        kind: u8,
    },
    /// Row cycles expected: 3 for erase / page read.
    AddrRow,
    ReadData,
}

/// Pin-level view of the NAND bus (driven by EXTEST bit-bang).
#[derive(Clone, Copy, Debug, Default)]
pub struct NandPins {
    pub cle: bool,
    pub ale: bool,
    pub ce_n: bool,
    pub we_n: bool,
    pub re_n: bool,
    pub dq: u8,
    /// R/nB line (controller -> rig), true = ready.
    pub rb_n: bool,
    /// Modeled die-select line for multi-LUN packages (pin-level CE mux).
    pub die_sel: u8,
}

pub struct NandCtrl {
    pub base: u32,
    pub dies: Vec<NandDie>,
    pub selected: usize,
    mode: Mode,
    addr_col: Vec<u8>,
    addr_row: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
    busy_polls: u8,
    fail_bit: bool,
    // pin edge tracking
    prev_we_n: bool,
    prev_re_n: bool,
    pub pins: NandPins,
    /// Status reads reporting busy after an operation (R/nB model).
    pub busy_latency: u8,
}

impl NandCtrl {
    pub fn new(base: u32, dies: Vec<NandDie>) -> NandCtrl {
        NandCtrl {
            base,
            dies,
            selected: 0,
            mode: Mode::Idle,
            addr_col: Vec::new(),
            addr_row: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            busy_polls: 0,
            fail_bit: false,
            prev_we_n: true,
            prev_re_n: true,
            pins: NandPins {
                ce_n: false,
                we_n: true,
                re_n: true,
                rb_n: true,
                die_sel: 0,
                ..Default::default()
            },
            busy_latency: 2,
        }
    }

    pub fn geometry(&self) -> NandGeometry {
        self.dies
            .first()
            .map(|d| d.geometry)
            .unwrap_or(NandGeometry::new(2048, 64, 64, 512, 1))
    }

    fn selected_die(&mut self) -> &mut NandDie {
        let idx = self.selected.min(self.dies.len().saturating_sub(1));
        &mut self.dies[idx]
    }

    fn status_byte(&mut self) -> u8 {
        if self.busy_polls > 0 {
            self.busy_polls -= 1;
            self.pins.rb_n = self.busy_polls == 0;
            return 0x00; // busy: ready bit clear
        }
        self.pins.rb_n = true;
        nand_status::READY | if self.fail_bit { nand_status::FAIL } else { 0 }
    }

    // ---- backend: one command byte -------------------------------------

    fn cmd_byte(&mut self, b: u8) {
        match b {
            nand_cmd::RESET => {
                self.mode = Mode::Idle;
                self.busy_polls = self.busy_latency;
                self.fail_bit = false;
                self.selected_die().set_status(nand_status::READY);
            }
            nand_cmd::READ_STATUS => {
                let st = self.status_byte();
                self.read_buf = vec![st];
                self.read_pos = 0;
                self.mode = Mode::ReadData;
            }
            nand_cmd::READ_ID => {
                self.addr_col.clear();
                self.addr_row.clear();
                self.mode = Mode::AddrCol { kind: 1 };
            }
            nand_cmd::READ_PARAM => {
                self.addr_col.clear();
                self.addr_row.clear();
                self.mode = Mode::AddrCol { kind: 2 };
            }
            nand_cmd::ERASE_SETUP => {
                self.addr_row.clear();
                self.mode = Mode::AddrRow;
            }
            nand_cmd::ERASE_CONFIRM => {
                let row = Self::le24(&self.addr_row);
                let l2ppb = self.geometry().log2_pages_per_block();
                // Rows are package-global (die base included); the selected
                // CE addresses a die-local block.
                let die_base = self.selected as u32 * self.geometry().blocks_per_lun;
                let block = (row >> l2ppb).wrapping_sub(die_base);
                let outcome = self.selected_die().erase_block(block);
                self.fail_bit = outcome == EraseOutcome::FailedThisAttempt;
                self.busy_polls = self.busy_latency;
                self.mode = Mode::Idle;
            }
            nand_cmd::READ_SETUP => {
                self.addr_col.clear();
                self.addr_row.clear();
                self.mode = Mode::AddrCol { kind: 0 };
            }
            nand_cmd::READ_CONFIRM => {
                let col = Self::le16(&self.addr_col) as usize;
                let row = Self::le24(&self.addr_row);
                let g = self.geometry();
                let l2ppb = g.log2_pages_per_block();
                let die_base = self.selected as u32 * g.blocks_per_lun;
                let block = (row >> l2ppb).wrapping_sub(die_base);
                let page = row & (g.pages_per_block - 1);
                if let Some(slice) = self.selected_die().read_page(block, page) {
                    self.read_buf = slice.to_vec();
                    self.read_pos = col.min(self.read_buf.len());
                } else {
                    self.read_buf = Vec::new();
                    self.read_pos = 0;
                }
                self.busy_polls = self.busy_latency;
                self.mode = Mode::ReadData;
            }
            _ => {
                // Unknown command: bus hang, modeled as eternal busy.
                self.busy_polls = 200;
                self.mode = Mode::Idle;
            }
        }
    }

    fn addr_byte(&mut self, b: u8) {
        match self.mode {
            Mode::AddrCol { kind } => {
                self.addr_col.push(b);
                let want = if kind == 0 { 2 } else { 1 };
                if self.addr_col.len() == want {
                    match kind {
                        0 => self.mode = Mode::AddrRow,
                        1 => {
                            let id = self.selected_die().read_id();
                            self.read_buf = id.to_vec();
                            self.read_pos = 0;
                            self.mode = Mode::ReadData;
                        }
                        _ => {
                            let page = self.selected_die().param_page();
                            self.read_buf = page.to_vec();
                            self.read_pos = 0;
                            self.mode = Mode::ReadData;
                        }
                    }
                }
            }
            Mode::AddrRow => {
                self.addr_row.push(b);
                if self.addr_row.len() == 3 {
                    self.mode = Mode::Idle;
                }
            }
            _ => {}
        }
    }

    fn data_next(&mut self) -> u8 {
        if self.read_pos < self.read_buf.len() {
            let b = self.read_buf[self.read_pos];
            self.read_pos += 1;
            b
        } else {
            0xFF
        }
    }

    fn data_peek(&self) -> u8 {
        if self.read_pos < self.read_buf.len() {
            self.read_buf[self.read_pos]
        } else {
            0xFF
        }
    }

    // ---- MMIO frontend ---------------------------------------------------

    /// `off` is relative to `base`; `value` for 0x10 selects the die.
    pub fn mmio_write(&mut self, off: u32, value: u32) {
        match off {
            0x00 => self.cmd_byte(value as u8),
            0x04 => self.addr_byte(value as u8),
            0x10 => self.selected = value as usize,
            _ => {}
        }
    }

    pub fn mmio_read(&mut self, off: u32) -> u32 {
        match off {
            0x08 => self.data_next() as u32,
            0x0C => self.status_byte() as u32,
            _ => 0xDEAD_DEAD,
        }
    }

    // ---- pin frontend (EXTEST bit-bang) -----------------------------------

    /// Apply a new pin state (called on every BSR Update-Dr).
    /// Latches on rising nWE (CLE/ALE qualify), drives DQ on falling nRE and
    /// HOLDS it while nRE stays low (the bus is controller-driven during a
    /// read strobe). R/nB tracks the busy model; every boundary update is
    /// simulated time, so busy counters drain here too.
    pub fn pins_update(&mut self, new_pins: NandPins) {
        let we_rising = !self.prev_we_n && new_pins.we_n;
        let re_falling = self.prev_re_n && !new_pins.re_n;
        let re_rising = !self.prev_re_n && new_pins.re_n;
        let re_held_low = !self.prev_re_n && !new_pins.re_n;
        let dq_prev = self.pins.dq;
        self.prev_we_n = new_pins.we_n;
        self.prev_re_n = new_pins.re_n;
        self.selected = new_pins.die_sel as usize;
        self.pins = new_pins;
        if re_held_low {
            // Bus still turned around: keep driving the byte.
            self.pins.dq = dq_prev;
        }
        if self.busy_polls > 0 {
            self.busy_polls -= 1;
        }
        self.pins.rb_n = self.busy_polls == 0;
        if we_rising && !new_pins.ce_n {
            if new_pins.cle {
                self.cmd_byte(new_pins.dq);
            } else if new_pins.ale {
                self.addr_byte(new_pins.dq);
            }
        }
        if re_falling && !new_pins.ce_n && !new_pins.cle && !new_pins.ale {
            // Controller drives DQ with the next data byte.
            self.pins.dq = self.data_peek();
        }
        if re_rising {
            // Rig consumed the byte; advance.
            if self.read_pos < self.read_buf.len() {
                self.read_pos += 1;
            }
        }
    }

    fn le24(b: &[u8]) -> u32 {
        (b.first().copied().unwrap_or(0) as u32)
            | ((b.get(1).copied().unwrap_or(0) as u32) << 8)
            | ((b.get(2).copied().unwrap_or(0) as u32) << 16)
    }

    fn le16(b: &[u8]) -> u32 {
        (b.first().copied().unwrap_or(0) as u32) | ((b.get(1).copied().unwrap_or(0) as u32) << 8)
    }
}
