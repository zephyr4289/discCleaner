//! A 16-bit Thumb assembler for the RAM-resident nucleus — the "assembler"
//! half of self-assembling.
//!
//! The nucleus is never shipped as a static binary. At injection time the
//! host emits a handful of well-understood 16-bit Thumb instructions
//! (the portable subset every ARM7TDMI, Cortex-R and Cortex-M core decodes),
//! patches literal pools and label fixups against the *actual* controller
//! profile, NAND geometry and erase strategy discovered during triage, and
//! links the result into one position-fixed SRAM image.
//!
//! Encoding reference (Thumb, ARMv6-M/v7-M/v7-R compatible):
//!
//! ```text
//! MOVS rd,#i8   001 00 ddd iiiiiiii   0x2ddd
//! CMP  rn,#i8   001 01 nnn iiiiiiii   0x28nn
//! ADDS rd,#i8   001 10 ddd iiiiiiii   0x3ddd
//! SUBS rd,#i8   001 11 ddd iiiiiiii   0x3ddd
//! STR  rt,[rn,w] 0110 0 iiiii nnn ttt
//! LDR  rt,[rn,w] 0110 1 iiiii nnn ttt   (w = imm5 words)
//! STRB rt,[rn,b] 0111 0 iiiii nnn ttt
//! LDRB rt,[rn,b] 0111 1 iiiii nnn ttt   (b = imm5 bytes)
//! STR  rt,[rn,rm] 0101 000 mmm nnn ttt
//! LDR  rt,[rn,rm] 0101 100 mmm nnn ttt
//! LSLS rd,rm,#i5  000 00 iiiii mmm ddd
//! LSRS rd,rm,#i5  000 01 iiiii mmm ddd
//! ADDS rd,rn,#i3  000 111 iii nnn ddd
//! ADDS rd,rn,rm   000 1100 mmm nnn ddd
//! ANDS rd,rm      0100 000000 mmm ddd
//! EORS rd,rm      0100 000001 mmm ddd
//! ORRS rd,rm      0100 000110 mmm ddd
//! MOVS rd,rm      000 0000000 mmm ddd
//! MOV  rd,rm (hi) 0100 0110 D mmm ddd
//! ADD  rd,rm (hi) 0100 0100 D mmm ddd
//! BLX  rm         0100 0111 1 mmm 000
//! BX   rm         0100 0111 0 mmm 000
//! B    label      11100 iiiiiiiiiii   (±2 KiB)
//! B<cc> label     1101 cccc iiiiiiii   (±256 B)
//! LDR  rt,[pc,#w] 0100 1 ttt iiiiiiii
//! NOP/BF00  WFI/BF30  BKPT/BE00  CPSID i/B672  CPSIE i/B662
//! ```

use std::collections::HashMap;

/// Condition codes (CS/HS and CC/LO are aliases in Thumb encodings).
pub mod cc {
    pub const EQ: u8 = 0;
    pub const NE: u8 = 1;
    pub const CS: u8 = 2;
    pub const HS: u8 = 2;
    pub const CC: u8 = 3;
    pub const LO: u8 = 3;
    pub const MI: u8 = 4;
    pub const PL: u8 = 5;
    pub const VS: u8 = 6;
    pub const VC: u8 = 7;
    pub const HI: u8 = 8;
    pub const LS: u8 = 9;
    pub const GE: u8 = 10;
    pub const LT: u8 = 11;
    pub const GT: u8 = 12;
    pub const LE: u8 = 13;
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Fixup {
    /// Conditional branch, 8-bit halfword displacement.
    Branch8 { at: u32, target: String, cond: u8 },
    /// Unconditional branch, 11-bit halfword displacement.
    Branch11 { at: u32, target: String },
}

/// Literal pool entry (resolved at `pool()` time).
#[derive(Clone, Debug)]
enum Literal {
    Const {
        instr_at: u32,
        value: u32,
    },
    Symbol {
        instr_at: u32,
        name: String,
        thumb: bool,
    },
}

/// One recorded relocation, for the payload manifest / proof chain.
#[derive(Clone, Debug)]
pub struct Reloc {
    pub at: u32,
    pub kind: &'static str,
    pub value: u32,
}

pub struct Asm {
    base: u32,
    out: Vec<u8>,
    labels: HashMap<String, u32>,
    fixups: Vec<Fixup>,
    pending_lits: Vec<Literal>,
    relocs: Vec<Reloc>,
    trampoline_seq: u32,
}

fn align4(v: u32) -> u32 {
    v & !0x3
}

impl Asm {
    pub fn new(base: u32) -> Asm {
        Asm {
            base,
            out: Vec::new(),
            labels: HashMap::new(),
            fixups: Vec::new(),
            pending_lits: Vec::new(),
            relocs: Vec::new(),
            trampoline_seq: 0,
        }
    }

    /// Current absolute emit address.
    pub fn here(&self) -> u32 {
        self.base + self.out.len() as u32
    }

    pub fn label_addr(&self, name: &str) -> Option<u32> {
        self.labels.get(name).copied()
    }

    pub fn relocs(&self) -> &[Reloc] {
        &self.relocs
    }

    /// Bind a label at the current address.
    pub fn bind(&mut self, name: &str) {
        let addr = self.here();
        if self.labels.insert(name.to_string(), addr).is_some() {
            panic!("duplicate label {name}");
        }
    }

    fn emit16(&mut self, hw: u16) {
        self.out.extend_from_slice(&hw.to_le_bytes());
    }

    fn patch16(&mut self, at: u32, hw: u16) {
        let off = (at - self.base) as usize;
        self.out[off..off + 2].copy_from_slice(&hw.to_le_bytes());
    }

    fn read16(&self, at: u32) -> u16 {
        let off = (at - self.base) as usize;
        u16::from_le_bytes([self.out[off], self.out[off + 1]])
    }

    // ---- data movement ------------------------------------------------

    pub fn movs(&mut self, rd: u8, imm: u8) {
        self.emit16(0x2000 | (rd as u16) << 8 | imm as u16);
    }

    pub fn cmp_imm(&mut self, rn: u8, imm: u8) {
        self.emit16(0x2800 | (rn as u16) << 8 | imm as u16);
    }

    pub fn cmp_reg(&mut self, rn: u8, rm: u8) {
        self.emit16(0x4280 | (rm as u16) << 3 | rn as u16);
    }

    pub fn adds_imm(&mut self, rd: u8, imm: u8) {
        self.emit16(0x3000 | (rd as u16) << 8 | imm as u16);
    }

    pub fn subs_imm(&mut self, rd: u8, imm: u8) {
        self.emit16(0x3800 | (rd as u16) << 8 | imm as u16);
    }

    pub fn str_off(&mut self, rt: u8, rn: u8, imm_words: u8) {
        debug_assert!(imm_words < 32);
        self.emit16(0x6000 | (imm_words as u16) << 6 | (rn as u16) << 3 | rt as u16);
    }

    pub fn ldr_off(&mut self, rt: u8, rn: u8, imm_words: u8) {
        debug_assert!(imm_words < 32);
        self.emit16(0x6800 | (imm_words as u16) << 6 | (rn as u16) << 3 | rt as u16);
    }

    pub fn strb_off(&mut self, rt: u8, rn: u8, imm_bytes: u8) {
        debug_assert!(imm_bytes < 32);
        self.emit16(0x7000 | (imm_bytes as u16) << 6 | (rn as u16) << 3 | rt as u16);
    }

    pub fn ldrb_off(&mut self, rt: u8, rn: u8, imm_bytes: u8) {
        debug_assert!(imm_bytes < 32);
        self.emit16(0x7800 | (imm_bytes as u16) << 6 | (rn as u16) << 3 | rt as u16);
    }

    pub fn str_reg(&mut self, rt: u8, rn: u8, rm: u8) {
        self.emit16(0x5000 | (rm as u16) << 6 | (rn as u16) << 3 | rt as u16);
    }

    pub fn strb_reg(&mut self, rt: u8, rn: u8, rm: u8) {
        // 0101 010 Rm Rn Rt — STRB (register). (0x5200 would be STRH!)
        self.emit16(0x5400 | (rm as u16) << 6 | (rn as u16) << 3 | rt as u16);
    }

    pub fn ldr_reg(&mut self, rt: u8, rn: u8, rm: u8) {
        self.emit16(0x5800 | (rm as u16) << 6 | (rn as u16) << 3 | rt as u16);
    }

    pub fn lsls(&mut self, rd: u8, rm: u8, imm: u8) {
        debug_assert!(imm < 32);
        self.emit16(((imm as u16) << 6) | (rm as u16) << 3 | rd as u16);
    }

    pub fn lsrs(&mut self, rd: u8, rm: u8, imm: u8) {
        debug_assert!(imm < 32);
        self.emit16(0x0800 | (imm as u16) << 6 | (rm as u16) << 3 | rd as u16);
    }

    pub fn adds3(&mut self, rd: u8, rn: u8, imm: u8) {
        debug_assert!(imm < 8);
        self.emit16(0x1C00 | (imm as u16) << 6 | (rn as u16) << 3 | rd as u16);
    }

    pub fn adds_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        self.emit16(0x1800 | (rm as u16) << 6 | (rn as u16) << 3 | rd as u16);
    }

    pub fn ands(&mut self, rd: u8, rm: u8) {
        self.emit16(0x4000 | (rm as u16) << 3 | rd as u16);
    }

    pub fn eors(&mut self, rd: u8, rm: u8) {
        self.emit16(0x4040 | (rm as u16) << 3 | rd as u16);
    }

    pub fn orrs(&mut self, rd: u8, rm: u8) {
        self.emit16(0x4300 | (rm as u16) << 3 | rd as u16);
    }

    /// MOVS rd, rm (flag-setting register move, low regs).
    pub fn movs_reg(&mut self, rd: u8, rm: u8) {
        self.emit16(((rm as u16) << 3) | rd as u16);
    }

    /// MOV rd, rm (non-flag-setting, any regs).
    pub fn mov_reg(&mut self, rd: u8, rm: u8) {
        let d = (rd >> 3) & 1;
        self.emit16(0x4600 | (d as u16) << 7 | (rm as u16) << 3 | (rd & 7) as u16);
    }

    /// ADD rd, rm (non-flag-setting, any regs).
    pub fn add_reg(&mut self, rd: u8, rm: u8) {
        let d = (rd >> 3) & 1;
        self.emit16(0x4400 | (d as u16) << 7 | (rm as u16) << 3 | (rd & 7) as u16);
    }

    pub fn blx(&mut self, rm: u8) {
        self.emit16(0x4780 | (rm as u16) << 3);
    }

    pub fn bx(&mut self, rm: u8) {
        self.emit16(0x4700 | (rm as u16) << 3);
    }

    // ---- branches ------------------------------------------------------

    /// Unconditional B (±2 KiB).
    pub fn b(&mut self, target: &str) {
        let at = self.here();
        self.emit16(0xE000);
        self.fixups.push(Fixup::Branch11 {
            at,
            target: target.to_string(),
        });
    }

    /// Conditional branch (±256 B) — for tight loops only.
    pub fn bcond(&mut self, cond: u8, target: &str) {
        let at = self.here();
        self.emit16(0xD000 | (cond as u16) << 8);
        self.fixups.push(Fixup::Branch8 {
            at,
            target: target.to_string(),
            cond,
        });
    }

    /// Conditional branch to a possibly-far label: emits
    /// `B<not cond> skip; B target; skip:` — safe at any fragment distance.
    pub fn bcond_far(&mut self, cond: u8, target: &str) {
        let inv = invert_cond(cond);
        self.trampoline_seq += 1;
        let skip_label = format!("@trampoline{}", self.trampoline_seq);
        self.bcond(inv, &skip_label);
        self.b(target);
        self.bind(&skip_label);
    }

    // ---- pseudo / privileged -------------------------------------------

    pub fn nop(&mut self) {
        self.emit16(0xBF00);
    }

    pub fn wfi(&mut self) {
        self.emit16(0xBF30);
    }

    pub fn bkpt(&mut self, imm: u8) {
        self.emit16(0xBE00 | imm as u16);
    }

    /// CPSID i — mask interrupts (IRQ/FIQ via PRIMASK).
    pub fn cpsid(&mut self) {
        self.emit16(0xB672);
    }

    pub fn cpsie(&mut self) {
        self.emit16(0xB662);
    }

    // ---- literals & pools ----------------------------------------------

    /// LDR rt, =value (via nearest pool).
    pub fn ldr_const(&mut self, rt: u8, value: u32) {
        let instr_at = self.here();
        self.emit16(0x4800 | (rt as u16) << 8);
        self.pending_lits.push(Literal::Const { instr_at, value });
    }

    /// LDR rt, =symbol (absolute address), optionally with Thumb bit.
    pub fn ldr_symbol(&mut self, rt: u8, name: &str, thumb: bool) {
        let instr_at = self.here();
        self.emit16(0x4800 | (rt as u16) << 8);
        self.pending_lits.push(Literal::Symbol {
            instr_at,
            name: name.to_string(),
            thumb,
        });
    }

    /// Flush the pending literal pool (aligns to 4 first).
    pub fn pool(&mut self) {
        if self.pending_lits.is_empty() {
            return;
        }
        // Align to 4 bytes with NOPs so pool words are 4-aligned.
        while !self.out.len().is_multiple_of(4) {
            self.emit16(0xBF00);
        }
        let lits = std::mem::take(&mut self.pending_lits);
        let mut resolved: Vec<(u32, u32, u32)> = Vec::new();
        for lit in lits {
            let entry_addr = self.here();
            let value = match &lit {
                Literal::Const { value, .. } => *value,
                Literal::Symbol { name, thumb, .. } => {
                    let sym = *self
                        .labels
                        .get(name)
                        .unwrap_or_else(|| panic!("unknown symbol {name} in literal pool"));
                    if *thumb { sym | 1 } else { sym }
                }
            };
            self.emit32_raw(value);
            let instr_at = match &lit {
                Literal::Const { instr_at, .. } => *instr_at,
                Literal::Symbol { instr_at, .. } => *instr_at,
            };
            resolved.push((instr_at, entry_addr, value));
        }
        for (instr_at, entry_addr, value) in resolved {
            let base_addr = align4(instr_at + 4);
            let off = entry_addr
                .checked_sub(base_addr)
                .expect("literal pool before its LDR");
            assert!(off <= 1020 && off % 4 == 0, "literal out of range");
            let hw = self.read16(instr_at) & !0xFF;
            self.patch16(instr_at, hw | (off / 4) as u16);
            self.relocs.push(Reloc {
                at: entry_addr,
                kind: "lit32",
                value,
            });
        }
    }

    /// Raw u32 data word (aligns to 4 first).
    pub fn emit32_raw(&mut self, value: u32) {
        while !self.out.len().is_multiple_of(4) {
            self.emit16(0xBF00);
        }
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    // ---- link -----------------------------------------------------------

    pub fn link(mut self) -> Result<Vec<u8>, String> {
        self.pool();
        for fix in std::mem::take(&mut self.fixups) {
            let target = *self
                .labels
                .get(match &fix {
                    Fixup::Branch8 { target, .. } => target,
                    Fixup::Branch11 { target, .. } => target,
                })
                .ok_or_else(|| "branch to unknown label".to_string())?;
            let (at, hw, span) = match fix {
                Fixup::Branch8 { at, .. } => (at, self.read16(at), 8u32),
                Fixup::Branch11 { at, .. } => (at, self.read16(at), 11),
            };
            let disp = target as i64 - (at as i64 + 4);
            assert!(disp % 2 == 0, "odd branch displacement");
            let half = disp / 2;
            let limit = (1i64 << (span - 1)) - 1;
            if half < -limit - 1 || half > limit {
                return Err(format!(
                    "branch out of range: {} halfwords (limit {})",
                    half, limit
                ));
            }
            let masked = (half as u32) & ((1u32 << span) - 1);
            let cond_bits = hw & 0xFF00;
            self.patch16(at, cond_bits | masked as u16);
        }
        Ok(self.out)
    }
}

pub fn invert_cond(cond: u8) -> u8 {
    match cond {
        cc::EQ => cc::NE,
        cc::NE => cc::EQ,
        cc::CS => cc::CC,
        cc::CC => cc::CS,
        cc::MI => cc::PL,
        cc::PL => cc::MI,
        cc::HI => cc::LS,
        cc::LS => cc::HI,
        cc::GE => cc::LT,
        cc::LT => cc::GE,
        cc::GT => cc::LE,
        cc::LE => cc::GT,
        other => other,
    }
}

/// Disassemble the nucleus subset (for `dc-resurrect inspect-payload`).
pub fn disasm(blob: &[u8], base: u32) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < blob.len() {
        let hw = u16::from_le_bytes([blob[i], blob[i + 1]]);
        let addr = base + i as u32;
        out.push(format!("{:08x}: {:04x}  {}", addr, hw, decode(hw)));
        i += 2;
    }
    out
}

fn decode(hw: u16) -> String {
    let low = |x: u16| (x & 7) as u8; // Rt/Rd field (bits 2:0)

    match hw {
        0xBF00 => "nop".into(),
        0xBF30 => "wfi".into(),
        0xB672 => "cpsid i".into(),
        0xB662 => "cpsie i".into(),
        _ => {
            let op = hw >> 12;
            match op {
                0b0000 => match (hw >> 11) & 1 {
                    0 => {
                        if (hw >> 6) & 0x1F == 0 {
                            format!("movs r{}, r{}", low(hw), (hw >> 3) & 7)
                        } else {
                            format!(
                                "lsls r{}, r{}, #{}",
                                low(hw),
                                (hw >> 3) & 7,
                                (hw >> 6) & 0x1F
                            )
                        }
                    }
                    _ => format!(
                        "lsrs r{}, r{}, #{}",
                        low(hw),
                        (hw >> 3) & 7,
                        (hw >> 6) & 0x1F
                    ),
                },
                0b0001 => {
                    if (hw >> 11) & 3 == 2 {
                        format!(
                            "asrs r{}, r{}, #{}",
                            low(hw),
                            (hw >> 3) & 7,
                            (hw >> 6) & 0x1F
                        )
                    } else {
                        let sub = (hw >> 9) & 1 == 1;
                        let reg = (hw >> 10) & 1 == 0;
                        let m = ((hw >> 6) & 7) as u8;
                        let n = ((hw >> 3) & 7) as u8;
                        if reg {
                            if sub {
                                format!("subs r{}, r{}, r{}", low(hw), n, m)
                            } else {
                                format!("adds r{}, r{}, r{}", low(hw), n, m)
                            }
                        } else if sub {
                            format!("subs r{}, r{}, #{}", low(hw), n, m)
                        } else {
                            format!("adds r{}, r{}, #{}", low(hw), n, m)
                        }
                    }
                }
                0b0010 | 0b0011 => {
                    let d = ((hw >> 8) & 7) as u8;
                    match (hw >> 11) & 3 {
                        0 => format!("movs r{}, #{}", d, hw & 0xFF),
                        1 => format!("cmp r{}, #{}", d, hw & 0xFF),
                        2 => format!("adds r{}, #{}", d, hw & 0xFF),
                        _ => format!("subs r{}, #{}", d, hw & 0xFF),
                    }
                }
                0b0100 => match (hw >> 10) & 3 {
                    0 => {
                        let m = ((hw >> 3) & 7) as u8;
                        let d = low(hw);
                        match (hw >> 6) & 0xF {
                            0x0 => format!("ands r{}, r{}", d, m),
                            0x1 => format!("eors r{}, r{}", d, m),
                            0xA => format!("cmp r{}, r{}", d, m),
                            0xC => format!("orrs r{}, r{}", d, m),
                            _ => format!(".hword {:04x}", hw),
                        }
                    }
                    1 => {
                        let m = ((hw >> 3) & 0xF) as u8;
                        let d = low(hw) | (((hw >> 7) & 1) << 3) as u8;
                        match (hw >> 8) & 3 {
                            0x0 => format!("add r{}, r{}", d, m),
                            0x1 => format!("cmp r{}, r{}", d, m),
                            0x2 => format!("mov r{}, r{}", d, m),
                            _ => {
                                if hw & 0x0080 != 0 {
                                    format!("blx r{}", m)
                                } else {
                                    format!("bx r{}", m)
                                }
                            }
                        }
                    }
                    _ => format!("ldr r{}, [pc, #{}]", ((hw >> 8) & 7) as u8, (hw & 0xFF) * 4),
                },
                0b0101 => {
                    let m = ((hw >> 6) & 7) as u8;
                    let n = ((hw >> 3) & 7) as u8;
                    match (hw >> 9) & 0x7 {
                        0x0 => format!("str r{}, [r{}, r{}]", low(hw), n, m),
                        0x2 => format!("strb r{}, [r{}, r{}]", low(hw), n, m),
                        0x4 => format!("ldr r{}, [r{}, r{}]", low(hw), n, m),
                        _ => format!(".hword {:04x}", hw),
                    }
                }
                0b0110 => {
                    if hw & 0x0800 == 0 {
                        format!(
                            "str r{}, [r{}, #{}]",
                            low(hw),
                            (hw >> 3) & 7,
                            ((hw >> 6) & 0x1F) * 4
                        )
                    } else {
                        format!(
                            "ldr r{}, [r{}, #{}]",
                            low(hw),
                            (hw >> 3) & 7,
                            ((hw >> 6) & 0x1F) * 4
                        )
                    }
                }
                0b0111 => {
                    if hw & 0x0800 == 0 {
                        format!(
                            "strb r{}, [r{}, #{}]",
                            low(hw),
                            (hw >> 3) & 7,
                            (hw >> 6) & 0x1F
                        )
                    } else {
                        format!(
                            "ldrb r{}, [r{}, #{}]",
                            low(hw),
                            (hw >> 3) & 7,
                            (hw >> 6) & 0x1F
                        )
                    }
                }
                0b1101 => {
                    let cond = (hw >> 8) & 0xF;
                    format!("b{:02x} #{:+}", cond, ((hw & 0xFF) as i8 as i32) * 2)
                }
                0b1110 => format!("b #{:+}", sign11(hw)),
                0b1011 if hw & 0xFF00 == 0xBE00 => format!("bkpt #{:x}", hw & 0xFF),
                _ => format!(".hword {:04x}", hw),
            }
        }
    }
}

fn sign11(hw: u16) -> i32 {
    let imm = (hw & 0x7FF) as i32;
    let disp = if imm & 0x400 != 0 { imm - 0x800 } else { imm };
    disp * 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_match_reference() {
        let mut a = Asm::new(0);
        a.movs(0, 0x2A); // movs r0, #42
        a.bx(14); // bx lr
        a.bkpt(0);
        a.wfi();
        a.cpsid();
        let blob = a.link().unwrap();
        let hws: Vec<u16> = blob
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(hws[0], 0x202A);
        assert_eq!(hws[1], 0x4770);
        assert_eq!(hws[2], 0xBE00);
        assert_eq!(hws[3], 0xBF30);
        assert_eq!(hws[4], 0xB672);
    }

    #[test]
    fn literal_pool_patching() {
        let mut a = Asm::new(0x1000);
        a.movs(0, 1);
        a.ldr_const(0, 0xDEAD_BEEF);
        a.ldr_const(1, 0x1234_5678);
        a.bx(14);
        let blob = a.link().unwrap();
        // LDR r0, [pc, #0] at 0x1002 reads word at align4(0x1002+4)=0x1004
        // pool starts after bx (aligned): movs(2) + ldr(2) + ldr(2) + bx(2) = 8 bytes -> 0x1008
        // first literal @0x1008: base for instr @0x1002 = (0x1006)&~3 = 0x1004, off=4 -> imm=1
        let hw0 = u16::from_le_bytes([blob[2], blob[3]]);
        assert_eq!(hw0 & 0xFF, 1);
        let hw1 = u16::from_le_bytes([blob[4], blob[5]]);
        assert_eq!(hw1 & 0xFF, 1);
        let w0 = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]);
        let w1 = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]);
        assert_eq!(w0, 0xDEAD_BEEF);
        assert_eq!(w1, 0x1234_5678);
    }

    #[test]
    fn branch_fixup_forward_and_back() {
        let mut a = Asm::new(0);
        a.bind("loop");
        for _ in 0..4 {
            a.nop();
        }
        a.bcond_far(cc::EQ, "loop"); // bcond NE skip; b loop; skip:
        a.bcond(cc::NE, "loop");
        a.b("loop");
        let blob = a.link().unwrap();
        assert_eq!(blob.len(), 16);
        let hws: Vec<u16> = blob
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        // bcond_far: inverted bcond (NE) skips over the B (imm8 = 0)...
        assert_eq!(hws[4] & 0xFF, 0);
        // ...and the B jumps back to "loop": disp = 0-(10+4) = -14B = -7 hw
        assert_eq!(hws[5] & 0x7FF, 0x7F9);
        // plain bcond(NE) back to loop: disp = 0-(12+4) = -16B = -8 hw
        assert_eq!(hws[6] & 0xFF, 0xF8);
        // final b: disp = 0-(14+4) = -18B = -9 hw
        assert_eq!(hws[7] & 0x7FF, 0x7F7);
    }
}
