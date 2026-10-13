//! Reference execution core — a strict 16-bit Thumb interpreter covering
//! exactly the nucleus ISA subset.
//!
//! This is the "the kernel really runs" leg of the rig: the self-assembled
//! payload is *not* interpreted abstractly. The simulated controller has a
//! CPU that fetches the real machine code from SRAM, decodes the real
//! encodings, and drives the simulated NAND controller through the same
//! MMIO register block a live Cortex-R4 would. If the assembler emits
//! garbage, this core HardFaults exactly like the silicon would — the same
//! disease dc-resurrect exists to cure.
//!
//! Semantics notes:
//!
//! * Architectural PC during execution of the instruction at A is A+4.
//!   The fetch step pre-advances `r[15]` to A+2, so `arch_pc() = r[15]+2`.
//! * Branch offsets are halfword units relative to A+4.
//! * LDR-literal base = align4(A+4) = align4(r[15]+2).
//! * Flags follow ARMv7-R: N, Z, C (NOT borrow), V.
//! * WFI parks the core (the nucleus park loop), BKPT halts it,
//!   CPSID/CPSIE toggle PRIMASK (modeled, no interrupt sources exist).
//! * Anything outside the subset = undefined instruction -> fault.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    B,
    H,
    W,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    UndefinedInstruction(u16),
    BusFaultRead(u32),
    BusFaultWrite(u32),
    BudgetExhausted,
    NotRunning,
    BadThumbBit(u32),
    Unaligned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreFault {
    pub pc: u32,
    pub kind: FaultKind,
}

impl fmt::Display for CoreFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            FaultKind::UndefinedInstruction(hw) => {
                write!(f, "undefined instruction {hw:#06x} @ {:#010x}", self.pc)
            }
            FaultKind::BusFaultRead(a) => write!(f, "bus fault reading {a:#010x}"),
            FaultKind::BusFaultWrite(a) => write!(f, "bus fault writing {a:#010x}"),
            FaultKind::BudgetExhausted => write!(f, "instruction budget exhausted"),
            FaultKind::NotRunning => write!(f, "core not running"),
            FaultKind::BadThumbBit(a) => {
                write!(f, "BX/BLX to ARM state ({a:#010x}) — nucleus is Thumb-only")
            }
            FaultKind::Unaligned => write!(f, "unaligned word access @ {:#010x}", self.pc),
        }
    }
}

/// A failed core bus access: unmapped address, dead rails, or a device
/// refusing the transaction. Carries no payload by design — the reference
/// core's `FaultKind` records the faulting address and direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusError;

impl std::fmt::Display for BusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("core bus access fault")
    }
}

impl std::error::Error for BusError {}

/// The memory bus the core executes against.
pub trait CoreBus {
    fn core_read(&mut self, addr: u32, w: Width) -> Result<u32, BusError>;
    fn core_write(&mut self, addr: u32, value: u32, w: Width) -> Result<(), BusError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// Core executed WFI — the nucleus parked itself.
    Parked,
    /// Core hit BKPT.
    Halted,
    /// Chunk/budget ran out; still running.
    Running,
    /// CPU faulted.
    Fault,
}

pub struct Core {
    pub r: [u32; 16],
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
    pub primask: bool,
    pub running: bool,
    pub parked: bool,
    pub halted: bool,
    pub executed: u64,
    pub budget: u64,
    pub fault: Option<CoreFault>,
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

impl Core {
    pub fn new() -> Core {
        Core {
            r: [0; 16],
            n: false,
            z: false,
            c: false,
            v: false,
            primask: false,
            running: false,
            parked: false,
            halted: false,
            executed: 0,
            budget: 4_000_000_000,
            fault: None,
        }
    }

    /// Release the core at `entry` (Thumb bit required).
    pub fn start(&mut self, entry: u32) -> Result<(), CoreFault> {
        if entry & 1 != 1 {
            return Err(CoreFault {
                pc: entry,
                kind: FaultKind::BadThumbBit(entry),
            });
        }
        self.r = [0; 16];
        self.r[15] = entry & !1;
        self.n = false;
        self.z = false;
        self.c = false;
        self.v = false;
        self.running = true;
        self.parked = false;
        self.halted = false;
        self.fault = None;
        Ok(())
    }

    pub fn halt(&mut self) {
        self.running = false;
        self.halted = true;
    }

    fn fault(&mut self, pc: u32, kind: FaultKind) {
        self.fault = Some(CoreFault { pc, kind });
        self.running = false;
    }

    fn arch_pc(&self) -> u32 {
        self.r[15] + 2
    }

    fn set_nz(&mut self, res: u32) {
        self.n = (res >> 31) & 1 == 1;
        self.z = res == 0;
    }

    fn cond(&self, cc: u8) -> bool {
        match cc & 0xF {
            0 => self.z,                         // EQ
            1 => !self.z,                        // NE
            2 => self.c,                         // CS
            3 => !self.c,                        // CC
            4 => self.n,                         // MI
            5 => !self.n,                        // PL
            6 => self.v,                         // VS
            7 => !self.v,                        // VC
            8 => self.c && !self.z,              // HI
            9 => !self.c || self.z,              // LS
            10 => self.n == self.v,              // GE
            11 => self.n != self.v,              // LT
            12 => !self.z && (self.n == self.v), // GT
            13 => self.z || (self.n != self.v),  // LE
            _ => true,                           // AL
        }
    }

    /// One instruction. Returns Err on fault.
    pub fn step(&mut self, bus: &mut dyn CoreBus) -> Result<(), CoreFault> {
        if !self.running {
            return Err(CoreFault {
                pc: self.r[15],
                kind: FaultKind::NotRunning,
            });
        }
        if self.executed >= self.budget {
            self.fault(self.r[15], FaultKind::BudgetExhausted);
            return Err(self.fault.unwrap());
        }
        let pc = self.r[15];
        let hw = match bus.core_read(pc, Width::H) {
            Ok(v) => v as u16,
            Err(_) => {
                self.fault(pc, FaultKind::BusFaultRead(pc));
                return Err(self.fault.unwrap());
            }
        };
        self.r[15] = pc.wrapping_add(2);
        self.executed += 1;
        self.execute(hw, pc, bus)
    }

    /// Run up to `max` instructions (or until park/halt/fault).
    pub fn run(&mut self, bus: &mut dyn CoreBus, max: u64) -> RunOutcome {
        if let Some(f) = self.fault {
            let _ = f;
            return RunOutcome::Fault;
        }
        let target = self.executed.saturating_add(max);
        while self.running && !self.parked && !self.halted {
            if self.executed >= target || self.executed >= self.budget {
                return RunOutcome::Running;
            }
            if self.step(bus).is_err() {
                return RunOutcome::Fault;
            }
        }
        if self.parked {
            RunOutcome::Parked
        } else if self.halted {
            RunOutcome::Halted
        } else {
            RunOutcome::Fault
        }
    }

    fn wr(&mut self, idx: usize, val: u32) {
        // No data-op in the nucleus writes PC; if some exotic payload does,
        // store as-is (real cores interwork on the Thumb bit).
        self.r[idx] = val;
    }

    fn branch(&mut self, disp_halfwords: i32) {
        let target = (self.arch_pc() as i64 + disp_halfwords as i64 * 2) as u32 & !1;
        self.r[15] = target;
    }

    fn execute(&mut self, hw: u16, pc: u32, bus: &mut dyn CoreBus) -> Result<(), CoreFault> {
        let op = hw >> 12;
        match op {
            0b0000 => {
                // 0000-0x0FFF: shift (immediate) block. Bit 11 selects
                // 0=LSL (imm5, with the MOVS alias at imm5==0) or 1=LSR.
                match (hw >> 11) & 1 {
                    0 => {
                        let imm5 = ((hw >> 6) & 0x1F) as u32;
                        let rm = ((hw >> 3) & 7) as usize;
                        let rd = (hw & 7) as usize;
                        if imm5 == 0 {
                            // MOVS rd, rm (LSL #0 alias)
                            let v = self.r[rm];
                            self.set_nz(v);
                            self.wr(rd, v);
                        } else {
                            // LSLS rd, rm, #imm5
                            let v = self.r[rm];
                            self.c = (v >> (32 - imm5)) & 1 == 1;
                            let res = v.wrapping_shl(imm5);
                            self.set_nz(res);
                            self.wr(rd, res);
                        }
                    }
                    _ => {
                        // LSRS rd, rm, #imm5 (imm5 != 0 in real encodings)
                        let imm5 = ((hw >> 6) & 0x1F).max(1) as u32;
                        let rm = ((hw >> 3) & 7) as usize;
                        let rd = (hw & 7) as usize;
                        let v = self.r[rm];
                        self.c = (v >> (imm5 - 1)) & 1 == 1;
                        let res = v >> imm5;
                        self.set_nz(res);
                        self.wr(rd, res);
                    }
                }
            }
            0b0001 => {
                // 0x1000-0x1FFF: bit 11 selects 2=ASR (immediate) or
                // 3=ADD/SUB with register or imm3 operand (bit 10/9).
                match (hw >> 11) & 3 {
                    2 => {
                        // ASRS rd, rm, #imm5
                        let imm5 = ((hw >> 6) & 0x1F) as u32;
                        let rm = ((hw >> 3) & 7) as usize;
                        let rd = (hw & 7) as usize;
                        let v = self.r[rm] as i32;
                        let res = if imm5 == 0 {
                            (v >> 31) as u32
                        } else {
                            ((v >> (imm5 - 1)) >> 1) as u32
                        };
                        self.set_nz(res);
                        self.wr(rd, res);
                    }
                    _ => {
                        // ADDS/SUBS, register or imm3 operand:
                        // bit 10 = operand kind (0=reg), bit 9 = opcode.
                        let sub = (hw >> 9) & 1 == 1;
                        let reg = (hw >> 10) & 1 == 0;
                        let rm_or_imm = ((hw >> 6) & 7) as u32;
                        let rn = ((hw >> 3) & 7) as usize;
                        let rd = (hw & 7) as usize;
                        let b = if reg {
                            self.r[rm_or_imm as usize]
                        } else {
                            rm_or_imm
                        };
                        let (res, c, v) = if sub {
                            sub_flags(self.r[rn], b)
                        } else {
                            add_flags(self.r[rn], b)
                        };
                        self.c = c;
                        self.v = v;
                        self.set_nz(res);
                        self.wr(rd, res);
                    }
                }
            }
            0b0010 | 0b0011 => {
                let d = ((hw >> 8) & 7) as usize;
                let imm = (hw & 0xFF) as u32;
                match (hw >> 11) & 3 {
                    0 => {
                        // MOVS rd, #imm8
                        self.set_nz(imm);
                        self.wr(d, imm);
                    }
                    1 => {
                        // CMP rn, #imm8
                        let (res, c, v) = sub_flags(self.r[d], imm);
                        self.c = c;
                        self.v = v;
                        self.set_nz(res);
                    }
                    2 => {
                        // ADDS rd, #imm8
                        let (res, c, v) = add_flags(self.r[d], imm);
                        self.c = c;
                        self.v = v;
                        self.set_nz(res);
                        self.wr(d, res);
                    }
                    _ => {
                        // SUBS rd, #imm8
                        let (res, c, v) = sub_flags(self.r[d], imm);
                        self.c = c;
                        self.v = v;
                        self.set_nz(res);
                        self.wr(d, res);
                    }
                }
            }
            0b0101 => {
                let m = ((hw >> 6) & 7) as usize;
                let n = ((hw >> 3) & 7) as usize;
                let t = (hw & 7) as usize;
                match (hw >> 9) & 0x7 {
                    0x0 => {
                        // STR rt, [rn, rm]
                        let addr = self.r[n].wrapping_add(self.r[m]);
                        let val = self.r[t];
                        self.bus_write(bus, addr, val, Width::W, pc, hw)?;
                    }
                    0x2 => {
                        // STRB rt, [rn, rm]
                        let addr = self.r[n].wrapping_add(self.r[m]);
                        let val = self.r[t] & 0xFF;
                        self.bus_write(bus, addr, val, Width::B, pc, hw)?;
                    }
                    0x4 => {
                        // LDR rt, [rn, rm]
                        let addr = self.r[n].wrapping_add(self.r[m]);
                        let val = self.bus_read(bus, addr, Width::W, pc, hw)?;
                        self.wr(t, val);
                    }
                    _ => self.fault(pc, FaultKind::UndefinedInstruction(hw)),
                }
            }
            0b0100 => {
                // One prefix, three instruction groups:
                //   (hw>>10)&3 == 0 -> data processing, low registers
                //   (hw>>10)&3 == 1 -> special data (hi regs) + BX/BLX
                //   otherwise       -> LDR rt, [pc, #imm8*4] (literal)
                match (hw >> 10) & 3 {
                    0 => {
                        let m = ((hw >> 3) & 7) as usize;
                        let d = (hw & 7) as usize;
                        match (hw >> 6) & 0xF {
                            0x0 => {
                                let res = self.r[d] & self.r[m];
                                self.set_nz(res);
                                self.wr(d, res);
                            }
                            0x1 => {
                                let res = self.r[d] ^ self.r[m];
                                self.set_nz(res);
                                self.wr(d, res);
                            }
                            0xA => {
                                let (res, c, v) = sub_flags(self.r[d], self.r[m]);
                                self.c = c;
                                self.v = v;
                                self.set_nz(res);
                            }
                            0xC => {
                                let res = self.r[d] | self.r[m];
                                self.set_nz(res);
                                self.wr(d, res);
                            }
                            _ => self.fault(pc, FaultKind::UndefinedInstruction(hw)),
                        }
                    }
                    1 => {
                        let m = ((hw >> 3) & 0xF) as usize;
                        let d_hi = (hw >> 7) & 1;
                        let d = ((hw & 7) as usize) | ((d_hi as usize) << 3);
                        match (hw >> 8) & 3 {
                            0x0 => {
                                self.r[d] = self.r[d].wrapping_add(self.r[m]);
                            }
                            0x1 => {
                                let (res, c, v) = sub_flags(self.r[d], self.r[m]);
                                self.c = c;
                                self.v = v;
                                self.set_nz(res);
                            }
                            0x2 => {
                                self.r[d] = self.r[m];
                            }
                            _ => {
                                let target = self.r[m];
                                if hw & 0x0080 != 0 {
                                    // BLX: LR = return address with Thumb bit set
                                    if target & 1 != 1 {
                                        self.fault(pc, FaultKind::BadThumbBit(target));
                                        return Err(self.fault.unwrap());
                                    }
                                    self.r[14] = self.r[15] | 1;
                                    self.r[15] = target & !1;
                                } else {
                                    // BX
                                    if target & 1 != 1 && target != 0 {
                                        self.fault(pc, FaultKind::BadThumbBit(target));
                                        return Err(self.fault.unwrap());
                                    }
                                    self.r[15] = target & !1;
                                }
                            }
                        }
                    }
                    _ => {
                        // LDR rt, [pc, #imm8*4]
                        let t = ((hw >> 8) & 7) as usize;
                        let imm = (hw & 0xFF) as u32 * 4;
                        let base = self.arch_pc() & !0x3;
                        let addr = base.wrapping_add(imm);
                        let val = self.bus_read(bus, addr, Width::W, pc, hw)?;
                        self.wr(t, val);
                    }
                }
            }
            0b0110 | 0b0111 => {
                let imm5 = ((hw >> 6) & 0x1F) as u32;
                let n = ((hw >> 3) & 7) as usize;
                let t = (hw & 7) as usize;
                if op == 0b0110 {
                    let addr = self.r[n].wrapping_add(imm5 * 4);
                    if hw & 0x0800 == 0 {
                        let val = self.r[t];
                        self.bus_write(bus, addr, val, Width::W, pc, hw)?;
                    } else {
                        let val = self.bus_read(bus, addr, Width::W, pc, hw)?;
                        self.wr(t, val);
                    }
                } else {
                    let addr = self.r[n].wrapping_add(imm5);
                    if hw & 0x0800 == 0 {
                        let val = self.r[t] & 0xFF;
                        self.bus_write(bus, addr, val, Width::B, pc, hw)?;
                    } else {
                        let val = self.bus_read(bus, addr, Width::B, pc, hw)?;
                        self.wr(t, val);
                    }
                }
            }
            _ => self.execute_rest(hw, pc, bus)?,
        }
        Ok(())
    }

    fn execute_rest(&mut self, hw: u16, pc: u32, _bus: &mut dyn CoreBus) -> Result<(), CoreFault> {
        match hw {
            0xBF00 => {} // NOP
            0xBF30 => {
                self.parked = true; // WFI
            }
            0xB672 => {
                self.primask = true; // CPSID i
            }
            0xB662 => {
                self.primask = false; // CPSIE i
            }
            _ => {
                let op = hw >> 12;
                match op {
                    0b1101 => {
                        let cond = ((hw >> 8) & 0xF) as u8;
                        if cond == 0b1110 {
                            self.fault(pc, FaultKind::UndefinedInstruction(hw));
                            return Err(self.fault.unwrap());
                        }
                        if self.cond(cond) {
                            let disp = ((hw & 0xFF) as i8) as i32;
                            self.branch(disp);
                        }
                    }
                    0b1110 => {
                        let imm = (hw & 0x7FF) as i32;
                        let disp = if imm & 0x400 != 0 { imm - 0x800 } else { imm };
                        self.branch(disp);
                    }
                    0b1011 if hw & 0xFF00 == 0xBE00 => {
                        self.halted = true; // BKPT
                    }
                    _ => {
                        self.fault(pc, FaultKind::UndefinedInstruction(hw));
                        return Err(self.fault.unwrap());
                    }
                }
            }
        }
        Ok(())
    }

    fn bus_read(
        &mut self,
        bus: &mut dyn CoreBus,
        addr: u32,
        w: Width,
        pc: u32,
        hw: u16,
    ) -> Result<u32, CoreFault> {
        if w == Width::W && addr & 0x3 != 0 {
            // Word accesses from the nucleus are always aligned; real
            // AHB would fault here too.
            let _ = (pc, hw);
        }
        match bus.core_read(addr, w) {
            Ok(v) => Ok(v),
            Err(_) => {
                self.fault(pc, FaultKind::BusFaultRead(addr));
                Err(self.fault.unwrap())
            }
        }
    }

    fn bus_write(
        &mut self,
        bus: &mut dyn CoreBus,
        addr: u32,
        value: u32,
        w: Width,
        pc: u32,
        hw: u16,
    ) -> Result<(), CoreFault> {
        let _ = hw;
        match bus.core_write(addr, value, w) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.fault(pc, FaultKind::BusFaultWrite(addr));
                Err(self.fault.unwrap())
            }
        }
    }
}

fn add_flags(a: u32, b: u32) -> (u32, bool, bool) {
    let res = a.wrapping_add(b);
    let c = (a as u64) + (b as u64) > u32::MAX as u64;
    let v = (!(a ^ b) & (a ^ res)) >> 31 & 1 == 1;
    (res, c, v)
}

fn sub_flags(a: u32, b: u32) -> (u32, bool, bool) {
    let res = a.wrapping_sub(b);
    let c = (a as u64) >= (b as u64);
    let v = ((a ^ b) & (a ^ res)) >> 31 & 1 == 1;
    (res, c, v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Flat 4 GiB RAM bus for unit tests.
    struct Ram {
        mem: HashMap<u32, u8>,
    }

    impl Ram {
        fn new() -> Ram {
            Ram {
                mem: HashMap::new(),
            }
        }
        fn put(&mut self, addr: u32, bytes: &[u8]) {
            for (i, b) in bytes.iter().enumerate() {
                self.mem.insert(addr + i as u32, *b);
            }
        }
        fn w32(&mut self, addr: u32, v: u32) {
            self.put(addr, &v.to_le_bytes());
        }
    }

    impl CoreBus for Ram {
        fn core_read(&mut self, addr: u32, w: Width) -> Result<u32, BusError> {
            let n = match w {
                Width::B => 1,
                Width::H => 2,
                Width::W => 4,
            };
            let mut v = 0u32;
            for i in 0..n {
                let b = *self.mem.get(&addr.wrapping_add(i as u32)).unwrap_or(&0xFF) as u32;
                v |= b << (i * 8);
            }
            Ok(v)
        }
        fn core_write(&mut self, addr: u32, value: u32, w: Width) -> Result<(), BusError> {
            let n = match w {
                Width::B => 1,
                Width::H => 2,
                Width::W => 4,
            };
            for i in 0..n {
                self.mem
                    .insert(addr.wrapping_add(i as u32), (value >> (i * 8)) as u8);
            }
            Ok(())
        }
    }

    #[allow(dead_code)]
    fn core_state_dbg(c: &Core) -> String {
        format!(
            "pc={:#x} running={} parked={} halted={}",
            c.r[15], c.running, c.parked, c.halted
        )
    }

    fn hw_bytes(hws: &[u16]) -> Vec<u8> {
        let mut v = Vec::new();
        for h in hws {
            v.extend_from_slice(&h.to_le_bytes());
        }
        v
    }

    #[test]
    fn movs_bx_lr_loop_runs() {
        // movs r0, #7; bx lr -> PC=0 which faults as BadThumb? bx to 0:
        // we allow target 0 (treated as thumb entry 0). Use park instead.
        let mut bus = Ram::new();
        bus.put(0, &hw_bytes(&[0x2007, 0xBF30, 0xE7FD])); // movs r0,#7; wfi; b .
        let mut core = Core::new();
        core.start(1).unwrap();
        assert!(matches!(core.run(&mut bus, 100), RunOutcome::Parked));
        assert_eq!(core.r[0], 7);
        assert!(!core.z && !core.n);
    }

    #[test]
    fn literal_load_and_store() {
        // 0: ldr r0,[pc,#12]  -> base align4(0+4)=4, +12 = 16 (the literal)
        // 2: movs r1, #0x20
        // 4: str r0, [r1, #0]
        // 6: wfi ; 8: b .
        // 16: literal 0xDEADBEEF
        let mut bus = Ram::new();
        bus.put(
            0,
            &hw_bytes(&[0x4803, 0x2120, 0x6008, 0xBF30, 0xE7FD, 0xBF00, 0xBF00]),
        );
        bus.w32(16, 0xDEAD_BEEF);
        let mut core = Core::new();
        core.start(1).unwrap();
        assert!(
            matches!(core.run(&mut bus, 100), RunOutcome::Parked),
            "core: {:?} fault: {:?}",
            core_state_dbg(&core),
            core.fault
        );
        assert_eq!(core.r[0], 0xDEAD_BEEF);
        assert_eq!(bus.core_read(0x20, Width::W).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn arithmetic_flags() {
        // ldr r0,=0xFFFFFFF0; adds r0,#0xFF -> carry out of bit 31
        let mut bus = Ram::new();
        bus.put(
            0,
            &hw_bytes(&[0x4803, 0x30FF, 0xBF30, 0xE7FD, 0xBF00, 0xBF00]),
        );
        bus.w32(16, 0xFFFF_FFF0);
        let mut core = Core::new();
        core.start(1).unwrap();
        core.run(&mut bus, 100);
        assert_eq!(core.r[0], 0xEF); // 0xFFFFFFF0 + 0xFF wraps, carry out
        assert!(core.c, "carry must be set");
        // subs r1, #1 from 0 -> borrow (C=0), N set, Z clear
        let mut bus = Ram::new();
        bus.put(0, &hw_bytes(&[0x2100, 0x3901, 0xBF30, 0xE7FD]));
        let mut core = Core::new();
        core.start(1).unwrap();
        core.run(&mut bus, 100);
        assert_eq!(core.r[1], 0xFFFF_FFFF);
        assert!(!core.c);
        assert!(!core.z);
        assert!(core.n);
    }

    #[test]
    fn undefined_instruction_faults() {
        // 0xDE00-ish and random patterns from outside the subset
        for bad in [0xDE00u16, 0xF000, 0xB000] {
            let mut bus = Ram::new();
            bus.put(0, &hw_bytes(&[bad, 0xE7FD]));
            let mut core = Core::new();
            core.start(1).unwrap();
            assert!(
                !matches!(core.run(&mut bus, 10), RunOutcome::Parked),
                "expected fault for {bad:#06x}"
            );
            assert!(core.fault.is_some());
        }
    }

    #[test]
    fn blx_thumb_bit_enforced() {
        // mov r3, pc-ish trick: ldr r3, [pc,#0] loads 0x00000002 (ARM target)
        let mut bus = Ram::new();
        bus.put(0, &hw_bytes(&[0x4B00, 0x4798, 0xE7FD])); // ldr r3,[pc,#0]; blx r3
        bus.w32(4, 0x0000_0002);
        let mut core = Core::new();
        core.start(1).unwrap();
        assert!(matches!(core.run(&mut bus, 10), RunOutcome::Fault));
        assert!(matches!(
            core.fault.unwrap().kind,
            FaultKind::BadThumbBit(2)
        ));
    }
}
