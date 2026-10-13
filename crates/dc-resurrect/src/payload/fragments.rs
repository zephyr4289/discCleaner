//! Nucleus code fragments — what actually runs inside the dead drive.
//!
//! Register ABI (documented contract between these fragments and the
//! reference core in `sim/core.rs`):
//!
//! ```text
//! r0  scratch / argument 0 / return value
//! r1  dispatch-owned: CRC-32 state (live across page loops)
//! r2  dispatch-owned: non-erased byte counter (live across page loops)
//! r3  scratch / BLX call target (reloadable)
//! r4  VARS block pointer — set once at entry, never clobbered
//! r5  CRC table base during verify loops; mailbox base during records
//! r6  erase retry counter, then general temp
//! r7  page byte countdown
//! sp  unused (no push/pop anywhere)
//! ```
//!
//! Helpers (called through the HLP_* linkage table, BLX r3) may clobber
//! **r0 and r3 only** — r1/r2 stay live across calls.
//!
//! Status codes the kernel writes into mailbox records: 0 erased,
//! 1 skipped (factory bad), 2 failed after retries, 3 die ID mismatch.

use super::asm::{Asm, cc};
use super::{MB_SUM_DONE, MB_SUM_MAGIC, PayloadParams, layout, vars};

fn call(a: &mut Asm, slot: u8) {
    a.ldr_off(3, 4, slot);
    a.blx(3);
}

fn hlp_cmd(a: &mut Asm, byte: u8) {
    a.movs(0, byte);
    call(a, vars::HLP_CMD);
}

fn hlp_addr(a: &mut Asm, byte: u8) {
    a.movs(0, byte);
    call(a, vars::HLP_ADDR);
}

fn wait_ready(a: &mut Asm) {
    call(a, vars::HLP_READY);
}

/// The five MMIO-touching helpers, shared by both stages.
fn emit_helpers(a: &mut Asm) {
    // void hlp_ce(u32 die)  — chip-enable select
    a.bind("hlp_ce");
    a.ldr_off(3, 4, vars::OFF_CE);
    a.str_off(0, 3, 0);
    a.bx(14);

    // void hlp_cmd(u8 cmd)
    a.bind("hlp_cmd");
    a.ldr_off(3, 4, vars::OFF_CMD);
    a.strb_off(0, 3, 0);
    a.bx(14);

    // void hlp_addr(u8 addr_byte)
    a.bind("hlp_addr");
    a.ldr_off(3, 4, vars::OFF_ADDR);
    a.strb_off(0, 3, 0);
    a.bx(14);

    // u8 hlp_read()
    a.bind("hlp_read");
    a.ldr_off(3, 4, vars::OFF_DATA);
    a.ldrb_off(0, 3, 0);
    a.bx(14);

    // u8 hlp_wait_ready() — 0xDE on timeout
    a.bind("hlp_ready");
    a.movs(3, 200);
    a.bind("hlp_wait_poll");
    a.ldr_off(0, 4, vars::OFF_STATUS);
    a.ldrb_off(0, 0, 0);
    a.lsls(0, 0, 24); // N = bit7 (READY)
    a.bcond(cc::MI, "hlp_ready_done");
    a.subs_imm(3, 1);
    a.bcond(cc::NE, "hlp_wait_poll");
    a.movs(0, 0xDE);
    a.bx(14);
    a.bind("hlp_ready_done");
    a.ldr_off(0, 4, vars::OFF_STATUS);
    a.ldrb_off(0, 0, 0);
    a.bx(14);
}

/// r0 = 24-bit row address; emit 3 address cycles LSB first.
fn emit_row_cycles(a: &mut Asm) {
    for k in 0..3 {
        call(a, vars::HLP_ADDR);
        if k < 2 {
            a.lsrs(0, 0, 8);
        }
    }
}

/// r0 = ((die << l2bpl) + block) << l2ppb
/// Uses r2 as temp: r2 is the nonzero counter only inside the verify byte
/// loop, and is free everywhere this helper runs (bad-check, erase, retry).
fn emit_row_for_block(a: &mut Asm, l2bpl: u8, l2ppb: u8) {
    a.ldr_off(0, 4, vars::DIE);
    a.lsls(0, 0, l2bpl);
    a.ldr_off(2, 4, vars::BLOCK);
    a.adds_reg(0, 0, 2);
    a.lsls(0, 0, l2ppb);
}

/// Mailbox record writer. Status in the immediate; when `with_crc` the
/// r1 CRC state and r2 nonzero counter are consumed and stored.
fn emit_record(a: &mut Asm, status: u8, with_crc: bool) {
    a.ldr_off(5, 4, vars::TMP0); // current mailbox write pointer
    // w0: magic
    a.ldr_off(0, 4, vars::MB_MAGIC);
    a.str_off(0, 5, 0);
    // w1: die<<16 | block
    a.ldr_off(0, 4, vars::DIE);
    a.lsls(0, 0, 16);
    a.ldr_off(6, 4, vars::BLOCK);
    a.adds_reg(0, 0, 6);
    a.str_off(0, 5, 1);
    // w2: status
    a.movs(0, status);
    a.str_off(0, 5, 2);
    // w3/w4: nonzero / crc
    if with_crc {
        a.str_off(2, 5, 3);
        a.ldr_const(0, 0xFFFF_FFFF);
        a.eors(1, 0);
        a.str_off(1, 5, 4);
    } else {
        a.movs(0, 0);
        a.str_off(0, 5, 3);
        a.str_off(0, 5, 4);
    }
    // advance TMP0
    a.adds_imm(5, 20);
    a.str_off(5, 4, vars::TMP0);
}

fn emit_counter_bump(a: &mut Asm, slot: u8) {
    a.ldr_off(0, 4, slot);
    a.adds_imm(0, 1);
    a.str_off(0, 4, slot);
}

/// Heartbeat: word = type | (block << 8) | (erased << 24), if a UART exists.
fn emit_heartbeat(a: &mut Asm, hb_type: u8) {
    let skip = format!("hb_skip_{}", hb_type);
    a.ldr_off(3, 4, vars::OFF_UART);
    a.cmp_imm(3, 0);
    a.bcond(cc::EQ, &skip);
    if hb_type == 1 {
        a.ldr_off(0, 4, vars::BLOCK);
        a.lsls(0, 0, 8);
        a.movs(6, 1); // HB_PROGRESS
        a.orrs(0, 6);
        a.ldr_off(6, 4, vars::ERASED);
        a.lsls(6, 6, 24);
        a.orrs(0, 6);
    } else {
        // done word: type | 0x5A << 24
        a.ldr_const(0, (0x5Au32 << 24) | hb_type as u32);
    }
    a.str_off(0, 3, 0);
    a.bind(&skip);
}

// ----------------------------------------------------------------------
// Stage 1: ONFI probe
// ----------------------------------------------------------------------

pub fn emit_probe(a: &mut Asm, p: &PayloadParams) {
    a.bind("entry");
    a.cpsid();
    a.ldr_const(4, p.load_base + layout::VARS);
    a.ldr_const(5, p.load_base + layout::MAILBOX);

    // Select die 0 and reset the NAND array.
    a.movs(0, 0);
    call(a, vars::HLP_CE);
    hlp_cmd(a, 0xFF);
    wait_ready(a);

    // READ ID (0x90, addr 0x00): 4 bytes -> mailbox[0..4]
    hlp_cmd(a, 0x90);
    hlp_addr(a, 0x00);
    a.movs(6, 0);
    a.bind("probe_id");
    call(a, vars::HLP_READ);
    a.strb_reg(0, 5, 6);
    a.adds_imm(6, 1);
    a.cmp_imm(6, 4);
    a.bcond(cc::LO, "probe_id");

    // READ PARAM PAGE (0xEC, addr 0x00): 64 bytes -> mailbox[4..68]
    hlp_cmd(a, 0xEC);
    hlp_addr(a, 0x00);
    wait_ready(a);
    a.movs(6, 4);
    a.bind("probe_pp");
    call(a, vars::HLP_READ);
    a.strb_reg(0, 5, 6);
    a.adds_imm(6, 1);
    a.cmp_imm(6, 68);
    a.bcond(cc::LO, "probe_pp");

    // Done heartbeat.
    a.ldr_off(3, 4, vars::OFF_UART);
    a.cmp_imm(3, 0);
    a.bcond(cc::EQ, "probe_park");
    a.ldr_const(0, (0x5Au32 << 24) | 0x02);
    a.str_off(0, 3, 0);

    a.bind("probe_park");
    a.wfi();
    a.b("probe_park");

    emit_helpers(a);
    a.pool();
}

// ----------------------------------------------------------------------
// Stage 2: autonomous die-level erase kernel
// ----------------------------------------------------------------------

pub fn emit_kernel(a: &mut Asm, p: &PayloadParams) {
    let g = &p.geometry;
    assert!(
        g.pages_per_block.is_power_of_two(),
        "pages_per_block must be pow2"
    );
    assert!(
        g.blocks_per_lun.is_power_of_two(),
        "blocks_per_lun must be pow2"
    );
    let l2ppb = g.log2_pages_per_block() as u8;
    let l2bpl = g.log2_blocks_per_lun() as u8;
    let col_lo = (p.geometry.bytes_per_page & 0xFF) as u8;
    let col_hi = ((p.geometry.bytes_per_page >> 8) & 0xFF) as u8;

    a.bind("entry");
    a.cpsid();

    // ---- build the CRC-32 table (self-reliant: no host tables needed)
    a.ldr_const(0, p.load_base + layout::CRCTAB);
    a.ldr_const(4, 0xEDB8_8320);
    a.movs(5, 0);
    a.bind("kt_outer");
    a.movs_reg(2, 5); // c = i
    a.movs(3, 0);
    a.bind("kt_inner");
    a.lsrs(2, 2, 1);
    a.bcond(cc::CC, "kt_skip");
    a.eors(2, 4);
    a.bind("kt_skip");
    a.adds_imm(3, 1);
    a.cmp_imm(3, 8);
    a.bcond(cc::LO, "kt_inner");
    a.lsls(6, 5, 2);
    a.str_reg(2, 0, 6);
    a.adds_imm(5, 1);
    a.cmp_imm(5, 255);
    a.bcond(cc::LS, "kt_outer");

    // ---- set up VARS/Mailbox pointers, zero counters
    a.ldr_const(4, p.load_base + layout::VARS);
    a.ldr_const(0, p.load_base + layout::MAILBOX);
    a.str_off(0, 4, vars::TMP0);
    a.movs(0, 0);
    for slot in [
        vars::DIE,
        vars::BLOCK,
        vars::PAGE,
        vars::ERASED,
        vars::SKIPPED,
        vars::FAILED,
    ] {
        a.str_off(0, 4, slot);
    }

    // ============================ die loop ============================
    a.bind("k_die");
    a.ldr_off(0, 4, vars::DIE);
    call(a, vars::HLP_CE);
    hlp_cmd(a, 0xFF); // NAND RESET
    wait_ready(a);

    // READ ID and compare against the expected word.
    hlp_cmd(a, 0x90);
    hlp_addr(a, 0x00);
    a.movs(1, 0);
    for k in 0..4u8 {
        call(a, vars::HLP_READ);
        if k == 0 {
            a.movs_reg(1, 0);
        } else {
            a.lsls(0, 0, k * 8);
            a.orrs(1, 0);
        }
    }
    a.ldr_off(2, 4, vars::EXPECT_ID);
    a.cmp_reg(1, 2);
    a.bcond_far(cc::NE, "k_die_idfail");

    a.movs(0, 0);
    a.str_off(0, 4, vars::BLOCK);

    // =========================== block loop ===========================
    a.bind("k_block");
    // -- bad check: spare byte 0 of page 0 must read 0xFF after erase...
    //    before erase it tells us whether the block is factory-bad.
    hlp_cmd(a, 0x00); // READ_SETUP
    hlp_addr(a, col_lo);
    hlp_addr(a, col_hi);
    emit_row_for_block(a, l2bpl, l2ppb);
    emit_row_cycles(a);
    hlp_cmd(a, 0x30); // READ_CONFIRM
    wait_ready(a);
    a.cmp_imm(0, 0xDE);
    a.bcond_far(cc::EQ, "k_blk_fail");
    call(a, vars::HLP_READ);
    a.cmp_imm(0, 0xFF);
    a.bcond_far(cc::NE, "k_blk_bad");

    // -- erase, up to 3 attempts (marginal-block retry)
    a.movs(6, 0);
    a.bind("k_erase");
    hlp_cmd(a, 0x60); // ERASE_SETUP
    emit_row_for_block(a, l2bpl, l2ppb);
    emit_row_cycles(a);
    hlp_cmd(a, 0xD0); // ERASE_CONFIRM
    wait_ready(a);
    a.cmp_imm(0, 0xDE);
    a.bcond_far(cc::EQ, "k_erase_bad");
    a.lsls(0, 0, 31); // N = bit0 (FAIL)
    a.bcond_far(cc::MI, "k_erase_bad");

    // -- verify pages read back 0xFF, CRC-32 the stream as we go
    a.ldr_off(6, 4, vars::VERIFY_STRIDE);
    a.cmp_imm(6, 0);
    a.bcond_far(cc::EQ, "k_verify_done");
    a.ldr_const(1, 0xFFFF_FFFF); // crc state
    a.movs(2, 0); // nonzero counter
    a.movs(0, 0);
    a.str_off(0, 4, vars::PAGE);

    a.bind("k_page");
    a.ldr_off(5, 4, vars::CRCTAB); // r5 = table base
    hlp_cmd(a, 0x00);
    hlp_addr(a, 0);
    hlp_addr(a, 0);
    a.ldr_off(0, 4, vars::DIE);
    a.lsls(0, 0, l2bpl);
    a.ldr_off(6, 4, vars::BLOCK);
    a.adds_reg(0, 0, 6);
    a.lsls(0, 0, l2ppb);
    // page joins AFTER the block shift: row = block_row | page
    a.ldr_off(6, 4, vars::PAGE);
    a.adds_reg(0, 0, 6);
    emit_row_cycles(a);
    hlp_cmd(a, 0x30);
    wait_ready(a);
    a.cmp_imm(0, 0xDE);
    a.bcond_far(cc::EQ, "k_blk_fail");

    a.ldr_off(3, 4, vars::OFF_DATA);
    a.ldr_off(7, 4, vars::PAGE_BYTES);
    a.bind("k_byte");
    a.ldrb_off(0, 3, 0);
    a.cmp_imm(0, 0xFF);
    a.bcond(cc::EQ, "k_byte_ok");
    a.adds_imm(2, 1);
    a.bind("k_byte_ok");
    // crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    a.mov_reg(6, 1);
    a.eors(6, 0);
    a.lsls(6, 6, 24);
    a.lsrs(6, 6, 24);
    a.lsls(6, 6, 2);
    a.ldr_reg(6, 5, 6);
    a.lsrs(1, 1, 8);
    a.eors(1, 6);
    a.subs_imm(7, 1);
    a.bcond(cc::NE, "k_byte");

    // PAGE += stride
    a.ldr_off(6, 4, vars::VERIFY_STRIDE);
    a.ldr_off(0, 4, vars::PAGE);
    a.adds_reg(0, 0, 6);
    a.str_off(0, 4, vars::PAGE);
    a.ldr_off(6, 4, vars::PPB);
    a.cmp_reg(0, 6);
    a.bcond(cc::LO, "k_page");

    a.bind("k_verify_done");
    // -- attestation record: erased
    emit_record(a, 0, true);
    emit_counter_bump(a, vars::ERASED);
    emit_heartbeat(a, 1);
    a.b("k_next_block");

    // ------------------------- loop control -------------------------
    a.bind("k_next_block");
    a.ldr_off(0, 4, vars::BLOCK);
    a.adds_imm(0, 1);
    a.str_off(0, 4, vars::BLOCK);
    a.ldr_off(6, 4, vars::BLOCKS);
    a.cmp_reg(0, 6);
    a.bcond_far(cc::LO, "k_block");

    a.bind("k_die_next");
    a.ldr_off(0, 4, vars::DIE);
    a.adds_imm(0, 1);
    a.str_off(0, 4, vars::DIE);
    a.ldr_off(6, 4, vars::DIES);
    a.cmp_reg(0, 6);
    a.bcond_far(cc::LO, "k_die");

    // --------------------------- summary ---------------------------
    a.ldr_off(5, 4, vars::TMP0);
    a.ldr_const(0, MB_SUM_MAGIC);
    a.str_off(0, 5, 0);
    a.ldr_off(0, 4, vars::TOTAL);
    a.str_off(0, 5, 1);
    a.ldr_off(0, 4, vars::ERASED);
    a.str_off(0, 5, 2);
    a.ldr_off(0, 4, vars::SKIPPED);
    a.str_off(0, 5, 3);
    a.ldr_off(0, 4, vars::FAILED);
    a.str_off(0, 5, 4);
    a.ldr_const(0, MB_SUM_DONE);
    a.str_off(0, 5, 5);
    emit_heartbeat(a, 2);

    a.bind("k_park");
    a.wfi();
    a.b("k_park");

    // --------------------- alternate paths ------------------------
    a.bind("k_die_idfail");
    a.ldr_off(5, 4, vars::TMP0);
    a.ldr_off(0, 4, vars::MB_MAGIC);
    a.str_off(0, 5, 0);
    a.ldr_off(0, 4, vars::DIE);
    a.lsls(0, 0, 16);
    a.ldr_const(6, 0xFFFF);
    a.orrs(0, 6);
    a.str_off(0, 5, 1);
    a.movs(0, 3);
    a.str_off(0, 5, 2);
    a.movs(0, 0);
    a.str_off(0, 5, 3);
    a.str_off(0, 5, 4);
    a.adds_imm(5, 20);
    a.str_off(5, 4, vars::TMP0);
    emit_counter_bump(a, vars::FAILED);
    a.b("k_die_next");

    a.bind("k_blk_bad");
    emit_record(a, 1, false);
    emit_counter_bump(a, vars::SKIPPED);
    a.b("k_next_block");

    a.bind("k_blk_fail");
    emit_record(a, 2, false);
    emit_counter_bump(a, vars::FAILED);
    a.b("k_next_block");

    a.bind("k_erase_bad");
    a.adds_imm(6, 1);
    a.cmp_imm(6, 3);
    a.bcond(cc::CS, "k_blk_fail");
    a.b("k_erase");

    emit_helpers(a);
    a.pool();
}
