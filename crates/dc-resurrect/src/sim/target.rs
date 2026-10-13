//! SimTarget — one dead drive on the bench, seen from the wire.
//!
//! Everything the rig talks to lives here at the granularity the hardware
//! sees it:
//!
//! * [`JtagTap`] — a real 16-state TAP: IDCODE/BYPASS/EXTEST/SAMPLE-PRELOAD/
//!   DPACC/APACC instructions, boundary cells fed from the NAND pins, TLR
//!   semantics including the SWD -> JTAG return.
//! * [`SwdDevice`] — an ADIv5 wire-level SWD decoder: request capture with
//!   parity check, OK/WAIT/FAULT acks, posted reads, turnarounds,
//!   line-reset detection, and the JTAG-to-SWD switch magic.
//! * The BROM shell — an inline UART state machine (autobaud, magic HELLO,
//!   challenge/response, PEEK/POKE, CRC-checked chunk download, JUMP).
//! * A DP/AP register file shared by the SWD and JTAG-DP paths, whose
//!   MEM-AP TAR/DRW land on the real memory bus.
//! * The reference [`Core`], executing the injected nucleus out of SRAM
//!   through the MMIO map a live controller would present.

use std::collections::VecDeque;

use super::core::{BusError, Core, CoreBus, RunOutcome, Width};
use super::nand_ctrl::{NandCtrl, NandPins};
use crate::crc::crc16_xmodem;
use crate::dp::{ap_reg, ctrl_stat, dp_reg};
use crate::jtag::{TapState, tap_ir, tap_next};
use crate::nand::NandDie;
use crate::rng::XorShift;
use crate::sha256::sha256;
use crate::uart_brom::{BromParams, cmd as brom_cmd};
use crate::vendors::ControllerProfile;

/// How the drive died — drives the triage report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScenarioKind {
    /// SPI flash corrupted during a brownout; BROM strap held at POR.
    FirmwareCorrupt,
    /// Cortex-R4 stuck in a HardFault loop; BROM UART not strapped in.
    HardFaultLockup,
    /// Blown TVS diode — board unpowered until the rig applies bench power.
    PowerPathTvn,
    /// Vendor debug lock: SWD AP faults, JTAG-DP junk, EXTEST still works.
    DebugLockdown,
}

impl ScenarioKind {
    pub fn parse(s: &str) -> Option<ScenarioKind> {
        let k = s.to_ascii_lowercase().replace(['-', '_'], "");
        match k.as_str() {
            "firmwarecorrupt" | "firmware" => Some(ScenarioKind::FirmwareCorrupt),
            "hardfaultlockup" | "hardfault" => Some(ScenarioKind::HardFaultLockup),
            "powerpathtvn" | "tvn" | "power" => Some(ScenarioKind::PowerPathTvn),
            "debuglockdown" | "lockdown" => Some(ScenarioKind::DebugLockdown),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ScenarioKind::FirmwareCorrupt => "firmware-corrupt",
            ScenarioKind::HardFaultLockup => "hardfault-lockup",
            ScenarioKind::PowerPathTvn => "power-path-tvn",
            ScenarioKind::DebugLockdown => "debug-lockdown",
        }
    }
}

// ---------------------------------------------------------------------
// Device-side TAP
// ---------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum TapEvent {
    Tlr,
    IrUpdate(u32),
    DrUpdate(Vec<bool>),
}

pub struct JtagTap {
    pub state: TapState,
    pub ir: u32,
    pub irlen: u32,
    idcode: u32,
    ir_shift: Vec<bool>,
    dr_out: Vec<bool>,
    dr_in: Vec<bool>,
    last_tdo: bool,
    pub events: Vec<TapEvent>,
    /// DPACC/APACC data shifted out next (posted read result).
    pub dp_pending: u32,
}

impl JtagTap {
    pub fn new(idcode: u32, irlen: u32) -> JtagTap {
        JtagTap {
            state: TapState::TestLogicReset,
            ir: tap_ir::IDCODE,
            irlen,
            idcode,
            ir_shift: Vec::new(),
            dr_out: Vec::new(),
            dr_in: Vec::new(),
            last_tdo: false,
            events: Vec::new(),
            dp_pending: 0,
        }
    }

    /// One TCK. `bsr_in` feeds Capture-DR for boundary instructions.
    /// Returns the TDO value driven since the previous edge (what the host
    /// samples on THIS rising edge); updates `last_tdo` for the next.
    pub fn tck(&mut self, tms: bool, tdi: bool, bsr_in: &[bool]) -> bool {
        let prev_tdo = self.last_tdo;
        let prev = self.state;
        self.state = tap_next(prev, tms);
        match (prev, self.state) {
            (_, TapState::TestLogicReset) => {
                if !matches!(prev, TapState::TestLogicReset) {
                    self.events.push(TapEvent::Tlr);
                }
                self.ir = tap_ir::IDCODE;
            }
            (TapState::CaptureDr, TapState::ShiftDr) => {
                self.dr_out = self.capture_dr(bsr_in);
                self.dr_in.clear();
            }
            (TapState::CaptureIr, TapState::ShiftIr) => {
                let mut v = vec![false; self.irlen as usize];
                v[0] = true; // captured IR value 0b...0001
                self.ir_shift = v;
            }
            (TapState::ShiftIr, TapState::ShiftIr) => {
                if !self.ir_shift.is_empty() {
                    self.ir_shift.remove(0);
                }
                self.ir_shift.push(tdi);
            }
            (TapState::ShiftIr, TapState::Exit1Ir) => {
                // exit-on-last-shift: the final bit still enters the chain
                if !self.ir_shift.is_empty() {
                    self.ir_shift.remove(0);
                }
                self.ir_shift.push(tdi);
            }
            (TapState::ShiftDr, TapState::ShiftDr) => {
                self.dr_in.push(tdi);
            }
            (TapState::ShiftDr, TapState::Exit1Dr) => {
                self.dr_in.push(tdi);
            }
            (TapState::Exit1Ir, TapState::UpdateIr) => {
                let mut ir = 0u32;
                for (k, b) in self.ir_shift.iter().enumerate() {
                    if *b {
                        ir |= 1 << k;
                    }
                }
                self.ir = ir;
                self.events.push(TapEvent::IrUpdate(ir));
            }
            (TapState::Exit1Dr, TapState::UpdateDr) => {
                self.events.push(TapEvent::DrUpdate(self.dr_in.clone()));
            }
            _ => {}
        }
        // Drive TDO for the NEXT sample.
        if self.state == TapState::ShiftIr {
            self.last_tdo = self.ir_shift.first().copied().unwrap_or(false);
        } else if self.state == TapState::ShiftDr {
            if self.dr_out.is_empty() {
                self.last_tdo = false;
            } else {
                self.last_tdo = self.dr_out.remove(0);
            }
        } else {
            self.last_tdo = false;
        }
        prev_tdo
    }

    fn capture_dr(&self, bsr_in: &[bool]) -> Vec<bool> {
        match self.ir {
            tap_ir::IDCODE => (0..32).map(|k| (self.idcode >> k) & 1 == 1).collect(),
            tap_ir::DPACC | tap_ir::APACC => {
                let mut v = vec![false; 3];
                v.extend((0..32).map(|k| (self.dp_pending >> k) & 1 == 1));
                v
            }
            tap_ir::EXTEST | tap_ir::SAMPLE_PRELOAD => bsr_in.to_vec(),
            _ => vec![false],
        }
    }
}

// ---------------------------------------------------------------------
// Device-side SWD decoder
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwdPhase {
    Idle,
    CollectRequest,
    /// Request parsed; the next turnaround gives the device the line.
    PrepAck,
    AckDrive {
        bits: [bool; 3],
        pos: u8,
        next: SwdNext,
    },
    ReadDrive {
        data: u32,
        parity: bool,
        pos: u8,
    },
    /// OK'd write: waiting for the turnaround that hands the line back.
    WaitTrnWrite,
    WriteCollect {
        bits: u64,
        count: u8,
    },
    /// Read data fully driven; final turnaround returns to idle.
    ReadDone,
    /// WAIT/FAULT ack driven; turnaround returns to idle.
    EndWaitTrn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwdNext {
    End,
    Write,
    Read,
}

pub struct SwdDevice {
    phase: SwdPhase,
    high_run: u32,
    req: u8,
    req_count: u8,
    pub line_reset_seen: bool,
    pub request: Option<(bool, bool, u8)>,
    pub read_value: u32,
    pub write_word: Option<u32>,
}

impl Default for SwdDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl SwdDevice {
    pub fn new() -> SwdDevice {
        SwdDevice {
            phase: SwdPhase::Idle,
            high_run: 0,
            req: 0,
            req_count: 0,
            line_reset_seen: false,
            request: None,
            read_value: 0,
            write_word: None,
        }
    }

    pub fn to_idle(&mut self) {
        self.phase = SwdPhase::Idle;
        self.request = None;
        self.write_word = None;
    }

    pub fn host_bit(&mut self, bit: bool) {
        if bit {
            self.high_run += 1;
            if self.high_run >= 50 {
                // Line reset (ADIv5): holds while SWDIO stays high; the DP
                // re-arms only after a low clock. Requests cannot start
                // mid-reset because every high clock re-triggers.
                self.phase = SwdPhase::Idle;
                self.request = None;
                self.write_word = None;
                self.line_reset_seen = true;
                return;
            }
        } else {
            self.high_run = 0;
        }
        match self.phase {
            SwdPhase::Idle => {
                if bit {
                    self.req = 1;
                    self.req_count = 1;
                    self.phase = SwdPhase::CollectRequest;
                }
            }
            SwdPhase::CollectRequest => {
                if bit {
                    self.req |= 1 << self.req_count;
                }
                self.req_count += 1;
                if self.req_count == 8 {
                    let start = self.req & 1 == 1;
                    let ap = (self.req >> 1) & 1 == 1;
                    let rnw = (self.req >> 2) & 1 == 1;
                    let a2 = (self.req >> 3) & 1;
                    let a3 = (self.req >> 4) & 1;
                    let parity = (self.req >> 5) & 1;
                    let stop = (self.req >> 6) & 1 == 0;
                    let park = (self.req >> 7) & 1 == 1;
                    let want = (ap as u8) ^ (rnw as u8) ^ a2 ^ a3;
                    if start && stop && park && parity == want {
                        self.request = Some((ap, rnw, (a2 << 2) | (a3 << 3)));
                        self.phase = SwdPhase::PrepAck;
                    } else {
                        self.phase = SwdPhase::Idle;
                    }
                }
            }
            SwdPhase::WriteCollect { bits, count } if count < 33 => {
                let nb = if bit { bits | (1 << count) } else { bits };
                if count + 1 == 33 {
                    self.write_word = Some(nb as u32); // parity is bit 32
                    self.phase = SwdPhase::Idle;
                } else {
                    self.phase = SwdPhase::WriteCollect {
                        bits: nb,
                        count: count + 1,
                    };
                }
            }
            _ => {}
        }
    }

    /// Device drives one bit (ack or read data).
    pub fn target_bit(&mut self) -> bool {
        match self.phase {
            SwdPhase::AckDrive {
                bits,
                ref mut pos,
                next,
            } => {
                let b = bits[*pos as usize];
                *pos += 1;
                if *pos >= 3 {
                    let ok = bits == [true, false, false];
                    if ok {
                        match next {
                            SwdNext::End => self.phase = SwdPhase::EndWaitTrn,
                            SwdNext::Write => self.phase = SwdPhase::WaitTrnWrite,
                            SwdNext::Read => {
                                let data = self.read_value;
                                let parity = data.count_ones() & 1 == 1;
                                self.phase = SwdPhase::ReadDrive {
                                    data,
                                    parity,
                                    pos: 0,
                                };
                            }
                        }
                    } else {
                        self.phase = SwdPhase::EndWaitTrn;
                    }
                }
                b
            }
            SwdPhase::ReadDrive {
                data,
                parity,
                ref mut pos,
            } => {
                let b = if *pos < 32 {
                    (data >> *pos) & 1 == 1
                } else {
                    parity
                };
                *pos += 1;
                if *pos > 32 {
                    self.phase = SwdPhase::ReadDone;
                }
                b
            }
            _ => false,
        }
    }

    /// Turnaround: ownership flips.
    pub fn turnaround(&mut self) {
        self.high_run = 0;
        match self.phase {
            SwdPhase::WaitTrnWrite => {
                self.phase = SwdPhase::WriteCollect { bits: 0, count: 0 };
            }
            SwdPhase::ReadDone => {
                self.phase = SwdPhase::Idle;
                self.request = None;
            }
            SwdPhase::EndWaitTrn => {
                self.phase = SwdPhase::Idle;
                self.request = None;
            }
            _ => {}
        }
    }

    // Arming methods, called by SimTarget while in PrepAck.

    pub fn arm_ok_read(&mut self, data: u32) {
        self.read_value = data;
        self.phase = SwdPhase::AckDrive {
            bits: [true, false, false],
            pos: 0,
            next: SwdNext::Read,
        };
    }

    pub fn arm_ok_write(&mut self) {
        self.phase = SwdPhase::AckDrive {
            bits: [true, false, false],
            pos: 0,
            next: SwdNext::Write,
        };
    }

    pub fn arm_wait(&mut self) {
        self.phase = SwdPhase::AckDrive {
            bits: [false, true, false],
            pos: 0,
            next: SwdNext::End,
        };
    }

    pub fn arm_fault(&mut self) {
        self.phase = SwdPhase::AckDrive {
            bits: [false, false, true],
            pos: 0,
            next: SwdNext::End,
        };
    }
}

// ---------------------------------------------------------------------
// Boot-ROM shell state machine
// ---------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Bsm {
    WaitSync,
    Magic {
        got: usize,
    },
    Cmd {
        buf: Vec<u8>,
    },
    AuthResp {
        challenge: [u8; 8],
        resp: [u8; 8],
        got: usize,
    },
    Download {
        addr: u32,
        total: u32,
        got: u32,
        chunk: Vec<u8>,
    },
}

// ---------------------------------------------------------------------
// SimTarget
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireMode {
    Jtag,
    Swd,
}

pub struct SimTarget {
    // board identity & map
    pub profile: ControllerProfile,
    pub scenario: ScenarioKind,
    // life support
    pub rails_alive: bool,
    pub debug_locked: bool,
    pub faulted_at_boot: bool,
    // memory & devices
    pub sram: Vec<u8>,
    pub nand: NandCtrl,
    pub core: Core,
    // wire state
    wire_mode: WireMode,
    swd_switch: u16,
    jtag_tms_run: u32,
    pub tap: JtagTap,
    pub swd: SwdDevice,
    // DP/AP register file
    dpidr: u32,
    ctrl_stat: u32,
    select: u32,
    csw: u32,
    tar: u32,
    rdbuff: u32,
    // BROM
    bsm: Bsm,
    pub brom_enabled: bool,
    pub brom_jumped: bool,
    pub brom_authed: bool,
    pub brom_params: BromParams,
    // UART
    pub uart_out: VecDeque<u8>,
    pending_jump: Option<u32>,
    pub rng: XorShift,
    /// Statistics for reports.
    pub swd_transactions: u64,
    pub jtag_clocks: u64,
}

impl SimTarget {
    pub fn new(
        profile: ControllerProfile,
        scenario: ScenarioKind,
        dies: Vec<NandDie>,
        rng: XorShift,
    ) -> SimTarget {
        let sram_size = profile.sram_size;
        let nand_mmio = profile.nand_mmio;
        let dpidr = profile.swd_dpidr.unwrap_or(0x2BA0_1477);
        let tap = JtagTap::new(
            profile.jtag_idcode.unwrap_or(0x4BA0_0477),
            profile.jtag_irlen,
        );
        let brom_params = profile.brom.clone();
        let sram = vec![0u8; sram_size as usize];
        let nand = NandCtrl::new(nand_mmio, dies);
        let mut core = Core::new();
        let faulted_at_boot = scenario == ScenarioKind::HardFaultLockup;
        if faulted_at_boot {
            // Stuck in a HardFault loop, interrupts dead — alive enough to
            // trip the watchdog forever, dead to the world otherwise.
            core.halted = true;
        }
        let (rails_alive, debug_locked, brom_enabled) = match scenario {
            ScenarioKind::FirmwareCorrupt => (true, false, true),
            ScenarioKind::HardFaultLockup => (true, false, false),
            ScenarioKind::PowerPathTvn => (false, false, true),
            ScenarioKind::DebugLockdown => (true, true, false),
        };
        SimTarget {
            profile,
            scenario,
            rails_alive,
            debug_locked,
            faulted_at_boot,
            sram,
            nand,
            core,
            wire_mode: WireMode::Jtag,
            swd_switch: 0xFFFF,
            jtag_tms_run: 0,
            tap,
            swd: SwdDevice::new(),
            dpidr,
            ctrl_stat: 0,
            select: 0,
            csw: 0,
            tar: 0,
            rdbuff: 0,
            bsm: Bsm::WaitSync,
            brom_enabled,
            brom_jumped: false,
            brom_authed: false,
            brom_params,
            uart_out: VecDeque::new(),
            pending_jump: None,
            rng,
            swd_transactions: 0,
            jtag_clocks: 0,
        }
    }

    /// External bench power (Class C resurrection step).
    pub fn rig_apply_power(&mut self) {
        self.rails_alive = true;
    }

    // ---------------- wire: JTAG ----------------

    pub fn jtag_tck(&mut self, tms: bool, tdi: bool) -> bool {
        if !self.rails_alive {
            return false;
        }
        self.jtag_clocks += 1;
        if self.wire_mode == WireMode::Swd {
            // TMS rides the shared pin: five highs return to JTAG (TLR).
            if tms {
                self.jtag_tms_run += 1;
                if self.jtag_tms_run >= 5 {
                    self.wire_mode = WireMode::Jtag;
                    self.jtag_tms_run = 0;
                }
            } else {
                self.jtag_tms_run = 0;
            }
            return false;
        }
        let bsr = self.bsr_in();
        let tdo = self.tap.tck(tms, tdi, &bsr);
        self.process_tap_events();
        self.service();
        tdo
    }

    /// Boundary cells as Capture-DR sees them: DQ[7:0], CLE, ALE, nCE, nWE,
    /// nRE, R/nB, pad.
    fn bsr_in(&self) -> Vec<bool> {
        let len = self.profile.bsr_len as usize;
        let mut v = vec![false; len];
        let pins = self.nand.pins;
        for (k, cell) in v.iter_mut().enumerate().take(8) {
            *cell = (pins.dq >> k) & 1 == 1;
        }
        if len > 8 {
            v[8] = pins.cle;
        }
        if len > 9 {
            v[9] = pins.ale;
        }
        if len > 10 {
            v[10] = pins.ce_n;
        }
        if len > 11 {
            v[11] = pins.we_n;
        }
        if len > 12 {
            v[12] = pins.re_n;
        }
        if len > 13 {
            v[13] = pins.rb_n;
        }
        if len > 14 {
            v[14] = self.nand.selected & 1 == 1;
        }
        v
    }

    fn apply_bsr(&mut self, bits: &[bool]) {
        if bits.len() < 14 {
            return;
        }
        let mut dq = 0u8;
        for (k, bit) in bits.iter().take(8).enumerate() {
            if *bit {
                dq |= 1 << k;
            }
        }
        let pins = NandPins {
            cle: bits[8],
            ale: bits[9],
            ce_n: bits[10],
            we_n: bits[11],
            re_n: bits[12],
            dq,
            rb_n: self.nand.pins.rb_n,
            die_sel: if bits.len() > 14 && bits[14] { 1 } else { 0 },
        };
        self.nand.pins_update(pins);
    }

    fn process_tap_events(&mut self) {
        let events: Vec<TapEvent> = std::mem::take(&mut self.tap.events);
        for ev in events {
            match ev {
                TapEvent::Tlr => {
                    self.wire_mode = WireMode::Jtag;
                }
                TapEvent::IrUpdate(_) => {}
                TapEvent::DrUpdate(bits) => {
                    let ir = self.tap.ir;
                    match ir {
                        tap_ir::EXTEST | tap_ir::SAMPLE_PRELOAD => {
                            self.apply_bsr(&bits);
                        }
                        tap_ir::DPACC | tap_ir::APACC if bits.len() == 35 => {
                            let a2 = bits[0];
                            let a3 = bits[1];
                            let rnw = bits[2];
                            let mut data = 0u32;
                            for k in 0..32 {
                                if bits[3 + k] {
                                    data |= 1 << k;
                                }
                            }
                            let addr = (a2 as u8) << 2 | (a3 as u8) << 3;
                            let ap = ir == tap_ir::APACC;
                            let res = if ap && self.debug_locked {
                                Err(BusError)
                            } else {
                                self.dp_access(ap, rnw, addr, data)
                            };
                            self.tap.dp_pending = res.unwrap_or(0xBAAD_F00D);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // ---------------- wire: SWD ----------------

    pub fn swd_host_bit(&mut self, bit: bool) {
        if !self.rails_alive {
            return;
        }
        if self.wire_mode == WireMode::Jtag {
            self.swd_switch = (self.swd_switch << 1) | bit as u16;
            if self.swd_switch == 0xE79E {
                self.wire_mode = WireMode::Swd;
                self.swd.to_idle();
            }
            return;
        }
        self.swd.host_bit(bit);
        self.swd_transactions += 1;
        if let Some(word) = self.swd.write_word.take() {
            if let Some((ap, _rnw, addr)) = self.swd.request {
                let _ = self.dp_access(ap, false, addr, word);
            }
            self.swd.to_idle();
        }
        self.service();
    }

    pub fn swd_target_bit(&mut self) -> bool {
        if !self.rails_alive {
            return false;
        }
        let b = self.swd.target_bit();
        self.service();
        b
    }

    pub fn swd_trn(&mut self) {
        if !self.rails_alive {
            return;
        }
        if matches!(self.swd.phase, SwdPhase::PrepAck) {
            if let Some((ap, rnw, addr)) = self.swd.request {
                let locked = ap && self.debug_locked;
                if locked {
                    self.swd.arm_fault();
                } else if rnw {
                    match self.dp_access(ap, true, addr, 0) {
                        Ok(v) => self.swd.arm_ok_read(v),
                        Err(_) => self.swd.arm_fault(),
                    }
                } else {
                    self.swd.arm_ok_write();
                }
            } else {
                self.swd.arm_wait();
            }
        }
        self.swd.turnaround();
        self.service();
    }

    // ---------------- Debug Port register file ----------------

    fn dp_access(&mut self, ap: bool, rnw: bool, addr: u8, wdata: u32) -> Result<u32, BusError> {
        if ap && self.debug_locked {
            return Err(BusError);
        }
        if !ap {
            match addr {
                dp_reg::DPIDR_OR_ABORT => {
                    if rnw {
                        Ok(self.dpidr)
                    } else {
                        // ABORT write: clear sticky flags.
                        self.ctrl_stat &= !ctrl_stat::CSTICKYERR;
                        Ok(0)
                    }
                }
                dp_reg::CTRL_STAT => {
                    if rnw {
                        let mut v = self.ctrl_stat;
                        if v & ctrl_stat::CDBGPWRUPREQ != 0 {
                            v |= ctrl_stat::CDBGPWRUPACK;
                        }
                        if v & ctrl_stat::CSYSPWRUPREQ != 0 {
                            v |= ctrl_stat::CSYSPWRUPACK;
                        }
                        Ok(v)
                    } else {
                        self.ctrl_stat = wdata;
                        Ok(0)
                    }
                }
                dp_reg::SELECT => {
                    if rnw {
                        Ok(0)
                    } else {
                        self.select = wdata;
                        Ok(0)
                    }
                }
                dp_reg::RDBUFF => {
                    if rnw {
                        Ok(self.rdbuff)
                    } else {
                        Err(BusError)
                    }
                }
                _ => Err(BusError),
            }
        } else {
            let bank = (self.select & 0xFF) as u8;
            // Requests carry only A[3:2]; the bank SELECT register rebuilds
            // the full register offset (bank << 4 | addr).
            let full = ((bank as u16) << 4) | (addr as u16);
            let res = match full {
                x if x == ap_reg::CSW as u16 => {
                    if rnw {
                        Ok(self.csw)
                    } else {
                        self.csw = wdata;
                        Ok(0)
                    }
                }
                x if x == ap_reg::TAR as u16 => {
                    if rnw {
                        Ok(self.tar)
                    } else {
                        self.tar = wdata;
                        Ok(0)
                    }
                }
                x if x == ap_reg::DRW as u16 => {
                    if rnw {
                        let v = self.bus_read32(self.tar)?;
                        self.tar = self.tar.wrapping_add(4);
                        Ok(v)
                    } else {
                        let t = self.tar;
                        self.bus_write32(t, wdata)?;
                        self.tar = t.wrapping_add(4);
                        Ok(0)
                    }
                }
                x if x == ap_reg::IDR as u16 => Ok(0x2477_0011),
                _ => Ok(0),
            };
            let out = res?;
            // ADIv5: every AP read is posted through RDBUFF.
            if rnw {
                self.rdbuff = out;
            }
            Ok(out)
        }
    }

    // ---------------- wire: UART / BROM ----------------

    pub fn uart_rx(&mut self, byte: u8) {
        if !self.rails_alive || !self.brom_enabled {
            return;
        }
        // Run the shell state machine on a local so all &mut self helpers
        // (peek/poke/store/jump) stay borrow-friendly.
        let mut bsm = std::mem::replace(&mut self.bsm, Bsm::Cmd { buf: Vec::new() });
        match &mut bsm {
            Bsm::WaitSync => {
                if byte == self.brom_params.sync {
                    self.uart_out.push_back(self.brom_params.ack);
                    bsm = Bsm::Magic { got: 0 };
                }
            }
            Bsm::Magic { got } => {
                // Re-sent sync byte re-triggers auto-baud (the rig probes
                // before the mission handshake; a real BROM tolerates this).
                if *got == 0 && byte == self.brom_params.sync {
                    self.uart_out.push_back(self.brom_params.ack);
                    bsm = Bsm::Magic { got: 0 };
                } else {
                    match self.brom_params.magic.get(*got).copied() {
                        Some(e) if e == byte => {
                            *got += 1;
                            if *got == self.brom_params.magic.len() {
                                let crc = crc16_xmodem(&self.brom_params.magic);
                                self.uart_out.extend(crc.to_le_bytes().iter().copied());
                                bsm = Bsm::Cmd { buf: Vec::new() };
                            }
                        }
                        _ => bsm = Bsm::WaitSync,
                    }
                }
            }
            Bsm::Cmd { buf } => {
                buf.push(byte);
                let need = match buf.first() {
                    Some(&brom_cmd::AUTH) => Some(3usize),
                    Some(&brom_cmd::PEEK) => Some(7),
                    Some(&brom_cmd::POKE) => Some(11),
                    Some(&brom_cmd::JUMP) => Some(7),
                    Some(&brom_cmd::DOWNLOAD) => Some(11),
                    _ => None,
                };
                if let Some(need) = need {
                    if buf.len() == need {
                        let frame = std::mem::take(buf);
                        self.brom_exec(&mut bsm, frame);
                    }
                } else if buf.len() > 12 {
                    buf.clear();
                }
            }
            Bsm::AuthResp {
                challenge,
                resp,
                got,
            } => {
                resp[*got] = byte;
                *got += 1;
                if *got == 8 {
                    let ch = *challenge;
                    let rp = *resp;
                    let mut material = self.brom_params.key.clone();
                    material.extend_from_slice(&ch);
                    let ok = sha256(&material)[..8] == rp;
                    self.uart_out
                        .push_back(if ok { brom_cmd::ACK } else { brom_cmd::NAK });
                    if ok {
                        self.brom_authed = true;
                        bsm = Bsm::Cmd { buf: Vec::new() };
                    } else {
                        bsm = Bsm::WaitSync; // locked out
                    }
                }
            }
            Bsm::Download {
                addr,
                total,
                got,
                chunk,
            } => {
                chunk.push(byte);
                if chunk.len() >= 2 {
                    let n = u16::from_le_bytes([chunk[0], chunk[1]]) as usize;
                    let expect = 2 + n + 2;
                    if chunk.len() == expect {
                        let data = chunk[2..2 + n].to_vec();
                        let crc = u16::from_le_bytes([chunk[2 + n], chunk[3 + n]]);
                        if crc16_xmodem(&data) == crc {
                            let base = addr.wrapping_add(*got);
                            for (i, b) in data.iter().enumerate() {
                                self.store8(base.wrapping_add(i as u32), *b);
                            }
                            *got += n as u32;
                            self.uart_out.push_back(brom_cmd::ACK);
                        } else {
                            self.uart_out.push_back(brom_cmd::NAK);
                        }
                        chunk.clear();
                        if *got >= *total {
                            bsm = Bsm::Cmd { buf: Vec::new() };
                        }
                    }
                }
            }
        }
        self.bsm = bsm;
    }

    /// Host reads one byte from the target's UART (replies + heartbeats).
    pub fn uart_read(&mut self) -> Option<u8> {
        self.service();
        self.uart_out.pop_front()
    }

    fn brom_exec(&mut self, bsm: &mut Bsm, frame: Vec<u8>) {
        if frame.len() < 3 {
            *bsm = Bsm::Cmd { buf: Vec::new() };
            return;
        }
        let body = &frame[..frame.len() - 2];
        let want = u16::from_le_bytes([frame[frame.len() - 2], *frame.last().unwrap()]);
        if crc16_xmodem(body) != want {
            self.uart_out.push_back(brom_cmd::NAK);
            *bsm = Bsm::Cmd { buf: Vec::new() };
            return;
        }
        match frame[0] {
            brom_cmd::AUTH => {
                let mut challenge = [0u8; 8];
                for (i, b) in challenge.iter_mut().enumerate() {
                    *b = self.rng.next_u64() as u8 ^ (i as u8).wrapping_mul(0x5A);
                }
                let crc = crc16_xmodem(&challenge);
                self.uart_out.extend(challenge.iter().copied());
                self.uart_out.extend(crc.to_le_bytes());
                *bsm = Bsm::AuthResp {
                    challenge,
                    resp: [0; 8],
                    got: 0,
                };
            }
            brom_cmd::PEEK => {
                let addr = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
                let val = self.bus_read32(addr).unwrap_or(0xDEAD_DEAD);
                let crc = crc16_xmodem(&val.to_le_bytes());
                self.uart_out.extend(val.to_le_bytes().iter().copied());
                self.uart_out.extend(crc.to_le_bytes());
                *bsm = Bsm::Cmd { buf: Vec::new() };
            }
            brom_cmd::POKE => {
                let addr = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
                let val = u32::from_le_bytes([frame[5], frame[6], frame[7], frame[8]]);
                let _ = self.bus_write32(addr, val);
                self.uart_out.push_back(brom_cmd::ACK);
                *bsm = Bsm::Cmd { buf: Vec::new() };
            }
            brom_cmd::DOWNLOAD => {
                if self.brom_params.auth_required && !self.brom_authed {
                    self.uart_out.push_back(brom_cmd::NAK);
                    *bsm = Bsm::Cmd { buf: Vec::new() };
                    return;
                }
                let addr = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
                let len = u32::from_le_bytes([frame[5], frame[6], frame[7], frame[8]]);
                self.uart_out.push_back(brom_cmd::ACK);
                *bsm = Bsm::Download {
                    addr,
                    total: len,
                    got: 0,
                    chunk: Vec::new(),
                };
            }
            brom_cmd::JUMP => {
                // Repeated download+jump cycles are the whole dev flow:
                // probe first, then the full kernel.
                self.uart_out.push_back(brom_cmd::ACK);
                let entry = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
                self.brom_jumped = true;
                self.pending_jump = Some(entry);
                *bsm = Bsm::Cmd { buf: Vec::new() };
            }
            _ => {
                self.uart_out.push_back(brom_cmd::NAK);
                *bsm = Bsm::Cmd { buf: Vec::new() };
            }
        }
    }

    // ---------------- memory bus ----------------

    fn store8(&mut self, addr: u32, b: u8) {
        let base = self.profile.sram_base;
        let len = self.sram.len() as u32;
        if addr >= base && addr < base + len {
            self.sram[(addr - base) as usize] = b;
        }
    }

    pub fn bus_read32(&mut self, addr: u32) -> Result<u32, BusError> {
        self.core_read(addr, Width::W)
    }

    pub fn bus_write32(&mut self, addr: u32, value: u32) -> Result<(), BusError> {
        self.core_write(addr, value, Width::W)
    }

    /// Heartbeat frame from the nucleus UART TX register.
    fn uart_tx(&mut self, w: u32) {
        let hb_type = (w & 0xFF) as u8;
        let block = ((w >> 8) & 0xFFFF) as u16;
        let data = (w >> 24) & 0xFF;
        let mut body = Vec::with_capacity(7);
        body.push(hb_type);
        body.extend_from_slice(&block.to_le_bytes());
        body.extend_from_slice(&[data as u8, 0, 0, 0]);
        let crc = crc16_xmodem(&body);
        self.uart_out.push_back(b'R');
        self.uart_out.push_back(b'Z');
        self.uart_out.extend(body);
        self.uart_out.extend(crc.to_le_bytes());
    }

    // ---------------- core service ----------------

    pub fn service(&mut self) {
        if let Some(entry) = self.pending_jump.take() {
            let _ = self.core.start(entry);
        }
        if self.core.running && !self.core.parked {
            let mut core = std::mem::take(&mut self.core);
            let _ = core.run(self, 400_000);
            self.core = core;
        }
    }

    pub fn core_outcome(&self) -> RunOutcome {
        if self.core.fault.is_some() {
            RunOutcome::Fault
        } else if self.core.parked {
            RunOutcome::Parked
        } else if self.core.halted {
            RunOutcome::Halted
        } else {
            RunOutcome::Running
        }
    }
}

impl CoreBus for SimTarget {
    fn core_read(&mut self, addr: u32, w: Width) -> Result<u32, BusError> {
        let p = &self.profile;
        let sram_base = p.sram_base;
        let sram_len = self.sram.len() as u32;
        if (sram_base..sram_base + sram_len).contains(&addr) {
            let off = (addr - sram_base) as usize;
            let n = match w {
                Width::B => 1,
                Width::H => 2,
                Width::W => 4,
            };
            if off + n > self.sram.len() {
                return Err(BusError);
            }
            let mut v = 0u32;
            for i in 0..n {
                v |= (self.sram[off + i] as u32) << (i * 8);
            }
            return Ok(v);
        }
        let nand_base = p.nand_mmio;
        if (nand_base..nand_base + 0x20).contains(&addr) {
            let off = addr - nand_base;
            return Ok(self.nand.mmio_read(off));
        }
        let uart = p.uart_mmio;
        if (uart..uart + 0x10).contains(&addr) {
            return Ok(0);
        }
        let dbg = p.dbg_mmio;
        if (dbg..dbg + 0x10).contains(&addr) {
            let off = addr - dbg;
            return Ok(match off {
                0x08 => {
                    let mut st = 0u32;
                    if self.core.running {
                        st |= 1;
                    }
                    if self.core.parked {
                        st |= 2;
                    }
                    if self.core.halted {
                        st |= 4;
                    }
                    if self.faulted_at_boot {
                        st |= 8;
                    }
                    if self.core.fault.is_some() {
                        st |= 16;
                    }
                    st
                }
                0x0C => (self.core.executed & 0xFFFF_FFFF) as u32,
                _ => 0,
            });
        }
        Err(BusError)
    }

    fn core_write(&mut self, addr: u32, value: u32, w: Width) -> Result<(), BusError> {
        let p = &self.profile;
        let sram_base = p.sram_base;
        let sram_len = self.sram.len() as u32;
        if (sram_base..sram_base + sram_len).contains(&addr) {
            let off = (addr - sram_base) as usize;
            let n = match w {
                Width::B => 1,
                Width::H => 2,
                Width::W => 4,
            };
            if off + n > self.sram.len() {
                return Err(BusError);
            }
            for i in 0..n {
                self.sram[off + i] = (value >> (i * 8)) as u8;
            }
            return Ok(());
        }
        let nand_base = p.nand_mmio;
        if (nand_base..nand_base + 0x20).contains(&addr) {
            let off = addr - nand_base;
            self.nand.mmio_write(off, value);
            return Ok(());
        }
        let uart = p.uart_mmio;
        if (uart..uart + 0x10).contains(&addr) {
            if addr == uart && w == Width::W {
                self.uart_tx(value);
            }
            return Ok(());
        }
        let dbg = p.dbg_mmio;
        if (dbg..dbg + 0x10).contains(&addr) {
            let off = addr - dbg;
            match off {
                0x00 => {
                    if value & 1 == 1 {
                        self.core.halt();
                    }
                }
                0x04 => {
                    self.pending_jump = Some(value);
                }
                _ => {}
            }
            return Ok(());
        }
        Err(BusError)
    }
}
