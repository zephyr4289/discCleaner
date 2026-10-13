//! Hardware abstraction: MMIO traits + the `SimBoard` virtual
//! softcore for CI.
//!
//! The payload never touches memory-mapped registers directly —
//! every access flows through [`Mmio`], so the identical state
//! machine code drives a real NEORV32/VexRiscv SoC (via
//! [`RealMmio`], constructed with the board's peripheral base) and
//! the deterministic [`SimBoard`] in unit tests.

use crate::efuse::EfuseBank;

/// Read/write access to one 32-bit register bank.
pub trait Mmio {
    /// Read the 32-bit register at `offset` (bytes) from the bank base.
    fn read32(&self, offset: usize) -> u32;
    /// Write the 32-bit register at `offset`.
    fn write32(&mut self, offset: usize, value: u32);
}

/// The real payload's bank: thin volatile pointer wrappers.
///
/// # Safety contract
/// `base` must point at a 32-bit-aligned, 32-bit-readable device
/// region of at least `len` bytes for the lifetime of this object.
/// Constructed only by the `silicon` payload entry with
/// link-time-fixed addresses.
pub struct RealMmio {
    #[allow(dead_code)] // used by the silicon feature build
    base: *mut u32,
}

#[cfg(feature = "silicon")]
impl RealMmio {
    /// # Safety
    /// Caller guarantees the region is a live MMIO bank (see the
    /// struct's safety contract). Used by `bin/ghost_silicon.rs`.
    pub const unsafe fn new(base: *mut u32) -> Self {
        Self { base }
    }
}

#[cfg(feature = "silicon")]
impl Mmio for RealMmio {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: constructor contract — aligned live device region.
        unsafe { core::ptr::read_volatile((self.base as usize + offset) as *const u32) }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        // SAFETY: constructor contract — aligned live device region.
        unsafe { core::ptr::write_volatile((self.base as usize + offset) as *mut u32, value) }
    }
}

/// Console output the payload uses (a byte sink).
pub trait Console {
    fn put_byte(&mut self, b: u8);
    fn put_str(&mut self, s: &str) {
        for b in s.bytes() {
            self.put_byte(b);
        }
    }
    fn put_u32(&mut self, v: u32) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.put_str("0x");
        for shift in [28, 24, 20, 16, 12, 8, 4, 0] {
            self.put_byte(HEX[((v >> shift) & 0xF) as usize]);
        }
    }
}

/// A console that records bytes for host-side assertions.
#[derive(Default, Clone)]
pub struct SinkConsole {
    pub bytes: alloc_dummy::Vec,
}

/// Tiny no_std-friendly byte buffer stand-in for tests (no alloc).
pub mod alloc_dummy {
    /// Fixed-capacity recorded console buffer (tests + sim only).
    #[derive(Clone)]
    pub struct Vec {
        pub data: [u8; 1024],
        pub len: usize,
    }
    impl Default for Vec {
        fn default() -> Self {
            Self {
                data: [0; 1024],
                len: 0,
            }
        }
    }
    impl Vec {
        pub fn push(&mut self, b: u8) -> bool {
            if self.len < self.data.len() {
                self.data[self.len] = b;
                self.len += 1;
                true
            } else {
                false
            }
        }
        pub fn as_str(&self) -> &str {
            core::str::from_utf8(&self.data[..self.len]).unwrap_or("")
        }
    }
}

impl Console for SinkConsole {
    fn put_byte(&mut self, b: u8) {
        let _ = self.bytes.push(b);
    }
}

// ---------------------------------------------------------------------------
// SimBoard — the virtual softcore
// ---------------------------------------------------------------------------

/// Register map of the interceptor core (byte offsets).
pub mod regs {
    /// Interceptor global control/status.
    pub const CSR_STATUS: usize = 0x00;
    pub const CSR_CTRL: usize = 0x04;
    /// Lane gate control: one bit per lane (0 = bypass, 1 = gated).
    pub const LANE_GATE: usize = 0x10;
    /// Lane gate latch (write 1 = permanent; reads back).
    pub const LANE_LATCH: usize = 0x14;
    /// Target-present bitmap (read-only, one bit per lane).
    pub const LANE_PRESENT: usize = 0x18;
    /// Per-lane command/data window (lane index selects via
    /// LANE_SELECT).
    pub const LANE_SELECT: usize = 0x1C;
    pub const LANE_CMD: usize = 0x20;
    pub const LANE_ADDR: usize = 0x24;
    pub const LANE_DATA: usize = 0x28;
    pub const LANE_STAT: usize = 0x2C;
    /// Simulated target backing switch (sim only; real silicon has
    /// the actual flash behind the lane).
    pub const SIM_TARGET_CFG: usize = 0xF0;
    /// eFuse bank (see efuse module for bit semantics).
    pub const EFUSE: usize = 0x80;
}

/// Lane commands (LANE_CMD values).
pub mod lane_cmd {
    /// Identify the target behind the selected lane.
    pub const IDENTIFY: u32 = 0x01;
    /// Block-erase the addressed window.
    pub const ERASE: u32 = 0x02;
    /// Write the data register to the addressed window.
    pub const WRITE: u32 = 0x03;
    /// Read the addressed window into the data register.
    pub const READ: u32 = 0x04;
    /// Read the target's wear/status counters.
    pub const WEAR: u32 = 0x05;
}

/// Lane status bits (LANE_STAT).
pub mod lane_stat {
    pub const BUSY: u32 = 1 << 0;
    pub const OK: u32 = 1 << 1;
    pub const TARGET_ERR: u32 = 1 << 2;
}

/// The deterministic virtual softcore board: one interceptor core
/// with 4 storage lanes, each optionally holding a simulated target
/// with a small backing window array, plus an eFuse bank.
///
/// Every unit test in this crate drives THIS board through the same
/// [`Mmio`] trait the real payload uses.
pub struct SimBoard {
    regs: [u32; 64],
    /// Backing media per lane (256 words each; None = no target).
    pub media: [Option<[u32; 256]>; 4],
    /// Wear counters per lane (erase pulse count).
    pub wear: [u32; 4],
    pub fuse: EfuseBank,
    /// Write-transaction counter seen by the lane gate while
    /// LATCHED (attempts after completion — must all be refused).
    pub latched_write_attempts: u32,
    latch_engaged: bool,
}

impl Default for SimBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl SimBoard {
    /// A board with no targets behind any lane.
    pub fn new() -> Self {
        Self {
            regs: [0; 64],
            media: [None, None, None, None],
            wear: [0; 4],
            fuse: EfuseBank::new(),
            latched_write_attempts: 0,
            latch_engaged: false,
        }
    }

    /// Attach a target to lane `i` with a recognizable (non-erased)
    /// backing pattern.
    pub fn attach_target(&mut self, lane: usize) {
        assert!(lane < 4);
        let mut media = [0u32; 256];
        // Leftover classified data: recognizable, non-zero.
        for (i, w) in media.iter_mut().enumerate() {
            *w = 0xDEAD_BEEFu32 ^ (i as u32).wrapping_mul(0x0101_0101);
        }
        self.media[lane] = Some(media);
        self.regs[regs::LANE_PRESENT / 4] |= 1 << lane;
    }

    fn selected_lane(&self) -> usize {
        (self.regs[regs::LANE_SELECT / 4] & 0xF) as usize
    }

    fn execute_lane_op(&mut self, lane: usize, cmd: u32) {
        let addr = self.regs[regs::LANE_ADDR / 4] as usize;
        let data = self.regs[regs::LANE_DATA / 4];
        let stat_slot = regs::LANE_STAT / 4;
        self.regs[stat_slot] = 0;
        let Some(media) = self.media[lane].as_mut() else {
            self.regs[stat_slot] = lane_stat::TARGET_ERR;
            return;
        };
        // Gate policy: commands other than IDENTIFY require the
        // lane to be gated; writes additionally require NOT latched.
        let gated = (self.regs[regs::LANE_GATE / 4] >> lane) & 1 == 1;
        let is_write = matches!(cmd, lane_cmd::WRITE | lane_cmd::ERASE);
        if !gated && cmd != lane_cmd::IDENTIFY {
            self.regs[stat_slot] = lane_stat::TARGET_ERR;
            return;
        }
        if is_write {
            if self.latch_engaged {
                self.latched_write_attempts += 1;
                self.regs[stat_slot] = lane_stat::TARGET_ERR;
                return;
            }
            match cmd {
                lane_cmd::ERASE => {
                    if addr < media.len() {
                        media[addr] = 0;
                        self.wear[lane] = self.wear[lane].saturating_add(1);
                        self.regs[stat_slot] = lane_stat::OK;
                    } else {
                        self.regs[stat_slot] = lane_stat::TARGET_ERR;
                    }
                }
                lane_cmd::WRITE => {
                    if addr < media.len() {
                        media[addr] = data;
                        self.regs[stat_slot] = lane_stat::OK;
                    } else {
                        self.regs[stat_slot] = lane_stat::TARGET_ERR;
                    }
                }
                _ => unreachable!(),
            }
            return;
        }
        match cmd {
            lane_cmd::IDENTIFY => {
                self.regs[stat_slot] = lane_stat::OK;
                self.regs[regs::LANE_DATA / 4] =
                    0x0447_4554 /* "TGET"-ish, top nibble = lane */ | ((lane as u32) << 28);
            }
            lane_cmd::READ => {
                self.regs[regs::LANE_DATA / 4] = media.get(addr).copied().unwrap_or(0xFFFF_FFFF);
                self.regs[stat_slot] = lane_stat::OK;
            }
            lane_cmd::WEAR => {
                self.regs[regs::LANE_DATA / 4] = self.wear[lane];
                self.regs[stat_slot] = lane_stat::OK;
            }
            _ => {
                self.regs[stat_slot] = lane_stat::TARGET_ERR;
            }
        }
    }
}

impl Mmio for SimBoard {
    fn read32(&self, offset: usize) -> u32 {
        if offset == regs::EFUSE {
            return self.fuse.word();
        }
        self.regs.get(offset / 4).copied().unwrap_or(0)
    }

    fn write32(&mut self, offset: usize, value: u32) {
        let slot = offset / 4;
        match offset {
            regs::LANE_LATCH => {
                // One-way: once latched, never unlatched.
                if value != 0 {
                    self.latch_engaged = true;
                }
                self.regs[slot] = 1;
            }
            regs::LANE_CMD => {
                let lane = self.selected_lane();
                self.execute_lane_op(lane, value);
            }
            regs::EFUSE => {
                // Fuse writes go through the bank (one-way bits).
                self.fuse.burn_mask(value);
            }
            _ => {
                if slot < self.regs.len() {
                    self.regs[slot] = value;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_sink_records() {
        let mut c = SinkConsole::default();
        c.put_str("ghost ");
        c.put_u32(0xA5);
        let s = c.bytes.as_str();
        assert!(s.starts_with("ghost 0x"), "{s}");
        assert!(s.ends_with("000000a5"), "{s}");
    }

    #[test]
    fn ungated_commands_are_refused() {
        let mut board = SimBoard::new();
        board.attach_target(0);
        // Lane not gated: ERASE must be refused (bypass = host path).
        board.write32(regs::LANE_SELECT, 0);
        board.write32(regs::LANE_ADDR, 5);
        board.write32(regs::LANE_CMD, lane_cmd::ERASE);
        assert_eq!(
            board.read32(regs::LANE_STAT) & lane_stat::TARGET_ERR,
            lane_stat::TARGET_ERR
        );
        // IDENTIFY is allowed ungated (discovery).
        board.write32(regs::LANE_CMD, lane_cmd::IDENTIFY);
        assert_eq!(board.read32(regs::LANE_STAT) & lane_stat::OK, lane_stat::OK);
    }

    #[test]
    fn erase_and_readback_through_the_gate() {
        let mut board = SimBoard::new();
        board.attach_target(1);
        board.write32(regs::LANE_GATE, 1 << 1); // gate lane 1
        board.write32(regs::LANE_SELECT, 1);
        board.write32(regs::LANE_ADDR, 7);
        board.write32(regs::LANE_CMD, lane_cmd::ERASE);
        assert_eq!(board.read32(regs::LANE_STAT) & lane_stat::OK, lane_stat::OK);
        board.write32(regs::LANE_CMD, lane_cmd::READ);
        assert_eq!(board.read32(regs::LANE_DATA), 0);
        assert_eq!(board.wear[1], 1);
        // Write a word, read it back.
        board.write32(regs::LANE_ADDR, 7);
        board.write32(regs::LANE_DATA, 0x1234_5678);
        board.write32(regs::LANE_CMD, lane_cmd::WRITE);
        board.write32(regs::LANE_CMD, lane_cmd::READ);
        assert_eq!(board.read32(regs::LANE_DATA), 0x1234_5678);
    }

    #[test]
    fn latch_refuses_all_later_writes() {
        let mut board = SimBoard::new();
        board.attach_target(2);
        board.write32(regs::LANE_GATE, 1 << 2);
        board.write32(regs::LANE_SELECT, 2);
        board.write32(regs::LANE_LATCH, 1);
        board.write32(regs::LANE_ADDR, 0);
        board.write32(regs::LANE_CMD, lane_cmd::ERASE);
        assert_eq!(
            board.read32(regs::LANE_STAT) & lane_stat::TARGET_ERR,
            lane_stat::TARGET_ERR
        );
        assert_eq!(board.latched_write_attempts, 1);
        // Un-latch attempts are ignored (one-way).
        board.write32(regs::LANE_LATCH, 0);
        board.write32(regs::LANE_CMD, lane_cmd::ERASE);
        assert_eq!(board.latched_write_attempts, 2);
        // Reads still work (audit path).
        board.write32(regs::LANE_CMD, lane_cmd::READ);
        assert_eq!(board.read32(regs::LANE_STAT) & lane_stat::OK, lane_stat::OK);
    }

    #[test]
    fn fuse_bank_is_one_way() {
        let mut board = SimBoard::new();
        board.write32(regs::EFUSE, 0b1010);
        assert_eq!(board.read32(regs::EFUSE), 0b1010);
        // Blowing more bits only adds.
        board.write32(regs::EFUSE, 0b0110);
        assert_eq!(board.read32(regs::EFUSE), 0b1110);
    }

    #[test]
    fn absent_target_reports_error() {
        let mut board = SimBoard::new();
        board.write32(regs::LANE_SELECT, 3);
        board.write32(regs::LANE_GATE, 1 << 3);
        board.write32(regs::LANE_CMD, lane_cmd::READ);
        assert_eq!(
            board.read32(regs::LANE_STAT) & lane_stat::TARGET_ERR,
            lane_stat::TARGET_ERR
        );
    }
}
