//! IEEE 1149.1 JTAG — Test Access Port engine.
//!
//! Host side: a mirror of the 16-state TAP controller, chain discovery by
//! IDCODE scan, IR/DR shifting, and the 35-bit DPACC/APACC transactions used
//! by the ARM JTAG-DP.
//!
//! Conventions (both sides of the wire agree, simulator included):
//!
//! * IR and DR shift LSB-first.
//! * After Test-Logic-Reset the instruction register reads out IDCODE
//!   (IR=0xE); BYPASS is 0xF, EXTEST is 0x0, SAMPLE/PRELOAD is 0x1,
//!   DPACC is 0xA and APACC is 0xB (ARM JTAG-DP encodings).
//! * A JTAG-DP DPACC/APACC transaction is a 35-bit DR scan:
//!   bit0 = A[2], bit1 = A[3], bit2 = RnW, bits 3..34 = data, LSB first.
//!   The request executes on Update-DR; the data shifted *out* during a
//!   transaction is the result of the *previous* posted request — which is
//!   exactly why RDBUFF reads exist. [`JtagDp`] performs the two-transaction
//!   dance for you.

use crate::dp::{DpPort, dp_reg};
use crate::hal::{JtagLink, LinkError};

/// JTAG instruction register encodings (ARM TAP + boundary scan).
pub mod tap_ir {
    pub const EXTEST: u32 = 0x0;
    pub const SAMPLE_PRELOAD: u32 = 0x1;
    pub const DPACC: u32 = 0xA;
    pub const APACC: u32 = 0xB;
    pub const IDCODE: u32 = 0xE;
    pub const BYPASS: u32 = 0xF;
}

/// The 16 TAP controller states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TapState {
    TestLogicReset,
    RunTestIdle,
    SelectDr,
    CaptureDr,
    ShiftDr,
    Exit1Dr,
    PauseDr,
    Exit2Dr,
    UpdateDr,
    SelectIr,
    CaptureIr,
    ShiftIr,
    Exit1Ir,
    PauseIr,
    Exit2Ir,
    UpdateIr,
}

use TapState::*;

/// Canonical TAP state transition (IEEE 1149.1 figure with all 16 states).
pub fn tap_next(state: TapState, tms: bool) -> TapState {
    match (state, tms) {
        (TestLogicReset, true) => TestLogicReset,
        (TestLogicReset, false) => RunTestIdle,
        (RunTestIdle, true) => SelectDr,
        (RunTestIdle, false) => RunTestIdle,
        (SelectDr, true) => SelectIr,
        (SelectDr, false) => CaptureDr,
        (CaptureDr, true) => Exit1Dr,
        (CaptureDr, false) => ShiftDr,
        (ShiftDr, true) => Exit1Dr,
        (ShiftDr, false) => ShiftDr,
        (Exit1Dr, true) => UpdateDr,
        (Exit1Dr, false) => PauseDr,
        (PauseDr, true) => Exit2Dr,
        (PauseDr, false) => PauseDr,
        (Exit2Dr, true) => UpdateDr,
        (Exit2Dr, false) => ShiftDr,
        (UpdateDr, true) => SelectDr,
        (UpdateDr, false) => RunTestIdle,
        (SelectIr, true) => TestLogicReset,
        (SelectIr, false) => CaptureIr,
        (CaptureIr, true) => Exit1Ir,
        (CaptureIr, false) => ShiftIr,
        (ShiftIr, true) => Exit1Ir,
        (ShiftIr, false) => ShiftIr,
        (Exit1Ir, true) => UpdateIr,
        (Exit1Ir, false) => PauseIr,
        (PauseIr, true) => Exit2Ir,
        (PauseIr, false) => PauseIr,
        (Exit2Ir, true) => UpdateIr,
        (Exit2Ir, false) => ShiftIr,
        (UpdateIr, true) => SelectDr,
        (UpdateIr, false) => RunTestIdle,
    }
}

/// A discovered device on the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapInfo {
    pub idcode: u32,
}

impl TapInfo {
    /// IEEE 1149.1 IDCODE fields: version[31:28], part[27:12], manufacturer[11:1].
    pub fn version(&self) -> u32 {
        self.idcode >> 28
    }
    pub fn part_number(&self) -> u32 {
        (self.idcode >> 12) & 0xFFFF
    }
    pub fn manufacturer(&self) -> u32 {
        (self.idcode >> 1) & 0x7FF
    }
    /// ARM Ltd (JEP106 compressed 11-bit form).
    pub fn is_arm(&self) -> bool {
        self.manufacturer() == 0x23B
    }
}

/// Host-side JTAG engine driving a [`JtagLink`].
pub struct JtagEngine<L: JtagLink> {
    link: L,
    state: TapState,
}

impl<L: JtagLink> JtagEngine<L> {
    pub fn new(link: L) -> Self {
        JtagEngine {
            link,
            state: TestLogicReset,
        }
    }

    pub fn into_inner(self) -> L {
        self.link
    }

    /// One TCK: track the TAP mirror, return TDO.
    fn clock(&mut self, tms: bool, tdi: bool) -> bool {
        let tdo = self.link.tck(tms, tdi);
        self.state = tap_next(self.state, tms);
        tdo
    }

    pub fn state(&self) -> TapState {
        self.state
    }

    /// Five TMS=1 clocks from anywhere -> Test-Logic-Reset.
    pub fn test_reset(&mut self) {
        for _ in 0..5 {
            self.clock(true, false);
        }
    }

    /// Route into Shift-DR. From Run-Test/Idle this is three clocks and —
    /// critically — does NOT pass through TLR, so the latched instruction
    /// register survives (EXTEST/DPACC sessions depend on this). Any other
    /// state first resets (IR reverts to IDCODE, as the spec demands).
    pub fn goto_shift_dr(&mut self) {
        if self.state == RunTestIdle {
            self.clock(true, false); // Select-DR
            self.clock(false, false); // Capture-DR
            self.clock(false, false); // Shift-DR
        } else {
            self.test_reset();
            self.clock(false, false); // Run-Test/Idle
            self.clock(true, false); // Select-DR
            self.clock(false, false); // Capture-DR
            self.clock(false, false); // Shift-DR
        }
    }

    /// Route into Shift-IR (preserving nothing: an IR scan always ends by
    /// latching a new instruction at Update-IR).
    pub fn goto_shift_ir(&mut self) {
        if self.state == RunTestIdle {
            self.clock(true, false); // Select-DR
            self.clock(true, false); // Select-IR
            self.clock(false, false); // Capture-IR
            self.clock(false, false); // Shift-IR
        } else {
            self.test_reset();
            self.clock(false, false); // RTI
            self.clock(true, false); // Select-DR
            self.clock(true, false); // Select-IR
            self.clock(false, false); // Capture-IR
            self.clock(false, false); // Shift-IR
        }
    }

    /// From Exit1-x: Update then Run-Test/Idle.
    pub fn exit_to_idle(&mut self) {
        self.clock(true, false); // Update
        self.clock(false, false); // RTI
        self.link.idle_clocks(1);
    }

    /// Shift a bit stream through DR, LSB first. Must be in Shift-DR.
    /// Returns the captured TDO stream (same length). On the final bit TMS
    /// is raised, moving to Exit1-DR.
    pub fn shift_dr_bits(&mut self, tdi: &[bool]) -> Vec<bool> {
        debug_assert_eq!(self.state, ShiftDr);
        let mut out = Vec::with_capacity(tdi.len());
        let last = tdi.len().saturating_sub(1);
        for (i, &b) in tdi.iter().enumerate() {
            let tms = i == last;
            out.push(self.clock(tms, b));
        }
        debug_assert_eq!(self.state, Exit1Dr);
        out
    }

    /// Shift `len` bits of `value` (LSB first) into IR. Enters/exits the
    /// IR column itself.
    pub fn shift_ir(&mut self, value: u32, len: u32) {
        self.goto_shift_ir();
        let last = len.saturating_sub(1);
        for i in 0..len {
            let tms = i == last;
            self.clock(tms, (value >> i) & 1 == 1);
        }
        // Exit1-IR -> Update-IR -> RTI
        self.exit_to_idle();
    }

    /// Shift a value through DR (LSB first) and capture TDO as u32.
    /// Enters via TLR route and exits to RTI.
    pub fn shift_dr(&mut self, tdi: &[bool]) -> Vec<bool> {
        self.goto_shift_dr();
        let out = self.shift_dr_bits(tdi);
        self.exit_to_idle();
        out
    }

    /// Discover the chain: post-TLR every TAP with an IDCODE puts it in DR,
    /// so shifting reads IDCODEs (bit0=1) and BYPASS bits (bit0=0).
    /// Stops after `max_zeros` consecutive BYPASS bits.
    pub fn scan_chain(&mut self, max_bits: usize, max_zeros: usize) -> Vec<TapInfo> {
        self.goto_shift_dr();
        let mut stream: Vec<bool> = Vec::with_capacity(max_bits);
        let mut zeros = 0;
        for _ in 0..max_bits {
            let b = self.clock(false, false);
            stream.push(b);
            if !b {
                zeros += 1;
                if zeros >= max_zeros {
                    break;
                }
            } else {
                zeros = 0;
            }
        }
        // shift one bit with TMS=1 to exit, then Update + RTI
        self.clock(true, false);
        self.clock(true, false);
        self.clock(false, false);
        self.link.idle_clocks(1);

        // Parse: skip leading BYPASS zeros? Post-TLR the first device's DR
        // bit0 comes out first; a 0 there means that device is in BYPASS
        // (no IDCODE). Every IDCODE starts with a 1 and is 32 bits.
        let mut taps = Vec::new();
        let mut i = 0;
        let mut consecutive_zeros = 0usize;
        while i < stream.len() {
            if !stream[i] {
                i += 1;
                consecutive_zeros += 1;
                if consecutive_zeros >= max_zeros {
                    break;
                }
                continue;
            }
            consecutive_zeros = 0;
            if i + 32 > stream.len() {
                break;
            }
            let mut idcode: u32 = 0;
            for k in 0..32 {
                if stream[i + k] {
                    idcode |= 1 << k;
                }
            }
            if idcode != 0 && idcode != 0xFFFF_FFFF {
                taps.push(TapInfo { idcode });
            }
            i += 32;
        }
        taps
    }
}

/// ARM JTAG-DP debug port — DPACC/APACC 35-bit DR transactions over [`JtagEngine`].
pub struct JtagDp<'a, L: JtagLink> {
    eng: &'a mut JtagEngine<L>,
    irlen: u32,
}

const IR_DPACK: u32 = 0xA;
const IR_APACC: u32 = 0xB;

impl<'a, L: JtagLink> JtagDp<'a, L> {
    pub fn new(eng: &'a mut JtagEngine<L>, irlen: u32) -> Self {
        JtagDp { eng, irlen }
    }

    /// One 35-bit DPACC/APACC scan. Returns the data field shifted out
    /// (result of the *previous* posted request).
    fn transact(&mut self, ap: bool, rnw: bool, addr: u8, data: u32) -> Result<u32, LinkError> {
        let ir = if ap { IR_APACC } else { IR_DPACK };
        self.eng.shift_ir(ir, self.irlen);
        let a2 = (addr >> 2) & 1 == 1;
        let a3 = (addr >> 3) & 1 == 1;
        let mut tdi = Vec::with_capacity(35);
        tdi.push(a2);
        tdi.push(a3);
        tdi.push(rnw);
        for k in 0..32 {
            tdi.push((data >> k) & 1 == 1);
        }
        let out = self.eng.shift_dr(&tdi);
        if out.len() != 35 {
            return Err(LinkError::Fault("short DR scan"));
        }
        let mut val: u32 = 0;
        for k in 0..32 {
            if out[3 + k] {
                val |= 1 << k;
            }
        }
        Ok(val)
    }
}

impl<'a, L: JtagLink> DpPort for JtagDp<'a, L> {
    fn dp_read(&mut self, addr: u8) -> Result<u32, LinkError> {
        // Transaction 1 issues the request; transaction 2 (RDBUFF) shifts out
        // its result — posted reads, JTAG-DP style.
        self.transact(false, true, addr, 0)?;
        self.transact(false, true, dp_reg::RDBUFF, 0)
    }

    fn dp_write(&mut self, addr: u8, value: u32) -> Result<(), LinkError> {
        self.transact(false, false, addr, value).map(|_| ())
    }

    fn ap_read(&mut self, addr: u8) -> Result<u32, LinkError> {
        self.transact(true, true, addr, 0)?;
        self.transact(false, true, dp_reg::RDBUFF, 0)
    }

    fn ap_write(&mut self, addr: u8, value: u32) -> Result<(), LinkError> {
        self.transact(true, false, addr, value).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full 16-state transition table check against IEEE 1149.1.
    #[test]
    fn tap_transition_table_is_canonical() {
        // (state, tms) -> next; exhaustive over all 32 combinations.
        let cases: &[(TapState, bool, TapState)] = &[
            (TestLogicReset, true, TestLogicReset),
            (TestLogicReset, false, RunTestIdle),
            (RunTestIdle, true, SelectDr),
            (RunTestIdle, false, RunTestIdle),
            (SelectDr, true, SelectIr),
            (SelectDr, false, CaptureDr),
            (CaptureDr, true, Exit1Dr),
            (CaptureDr, false, ShiftDr),
            (ShiftDr, true, Exit1Dr),
            (ShiftDr, false, ShiftDr),
            (Exit1Dr, true, UpdateDr),
            (Exit1Dr, false, PauseDr),
            (PauseDr, true, Exit2Dr),
            (PauseDr, false, PauseDr),
            (Exit2Dr, true, UpdateDr),
            (Exit2Dr, false, ShiftDr),
            (UpdateDr, true, SelectDr),
            (UpdateDr, false, RunTestIdle),
            (SelectIr, true, TestLogicReset),
            (SelectIr, false, CaptureIr),
            (CaptureIr, true, Exit1Ir),
            (CaptureIr, false, ShiftIr),
            (ShiftIr, true, Exit1Ir),
            (ShiftIr, false, ShiftIr),
            (Exit1Ir, true, UpdateIr),
            (Exit1Ir, false, PauseIr),
            (PauseIr, true, Exit2Ir),
            (PauseIr, false, PauseIr),
            (Exit2Ir, true, UpdateIr),
            (Exit2Ir, false, ShiftIr),
            (UpdateIr, true, SelectDr),
            (UpdateIr, false, RunTestIdle),
        ];
        for &(s, tms, want) in cases {
            assert_eq!(tap_next(s, tms), want, "state {s:?} tms {tms}");
        }
    }

    #[test]
    fn idcode_fields() {
        let t = TapInfo {
            idcode: 0x4BA0_0477,
        };
        assert_eq!(t.version(), 0x4);
        assert_eq!(t.part_number(), 0xBA00);
        assert!(t.is_arm());
    }
}
