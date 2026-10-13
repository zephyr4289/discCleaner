//! `dc fpga` — Autonomous Self-Verifying RISC-V Open-Silicon
//! Firmware Payload (v0.13.0, Frontier 3).
//!
//! * `simulate` — run the Hardware Security Interceptor state
//!   machine on the virtual softcore board: gate, sanitize,
//!   self-verify, burn the eFuse, latch the lanes. Prints the
//!   operator console transcript and the final fuse word.
//! * `info` — the payload protocol, board map, and build recipe.

use crate::{FpgaArgs, FpgaSubcommands};
use dc_core::DcError;
use dc_fpga::hal::Mmio;

pub fn cmd_fpga(args: FpgaArgs) -> Result<(), DcError> {
    match &args.sub {
        FpgaSubcommands::Simulate {
            lanes,
            pattern,
            windows,
        } => cmd_simulate(*lanes, *pattern, *windows),
        FpgaSubcommands::Info => cmd_info(),
    }
}

fn cmd_simulate(lanes: usize, pattern: Option<u32>, windows: u32) -> Result<(), DcError> {
    if lanes == 0 || lanes > dc_fpga::lane::MAX_LANES {
        return Err(DcError::Usage(format!(
            "lanes must be 1..={} (interceptor core gate width)",
            dc_fpga::lane::MAX_LANES
        )));
    }
    let mut board = dc_fpga::hal::SimBoard::new();
    for lane in 0..lanes {
        board.attach_target(lane);
    }
    board.write32(0x38, dc_fpga::statemachine::ARM_MAGIC);
    let mut console = dc_fpga::hal::SinkConsole::default();
    let cfg = dc_fpga::statemachine::RunConfig { windows, pattern };
    println!("[FPGA] ghost silicon drill: {lanes} lane(s) gated, {windows} windows/lane");
    if let Some(p) = pattern {
        println!("[FPGA] final pattern word: {p:#010x}");
    } else {
        println!("[FPGA] final surface: pure zero (block erase)");
    }

    let state = {
        let mut machine =
            dc_fpga::statemachine::InterceptorMachine::new(&mut board, &mut console, cfg);
        machine.run(10_000)
    };

    println!("--- interceptor console transcript ---");
    for line in console.bytes.as_str().split('\n') {
        if !line.is_empty() {
            println!("{line}");
        }
    }
    println!("-------------------------------------");

    let fuse = dc_fpga::efuse::EfuseBank::read(&mut board);
    println!("[FPGA] terminal state     : {}", state.as_str());
    println!("[FPGA] eFuse word         : {:#010x}", fuse.word());
    println!(
        "[FPGA] per-target fuses   : {} blown",
        fuse.burned_target_count()
    );
    println!(
        "[FPGA] lane gate latch    : {}",
        if board.read32(dc_fpga::hal::regs::LANE_LATCH) != 0 {
            "ENGAGED (one-way)"
        } else {
            "open"
        }
    );
    println!("[FPGA] transcript digest  : see CERTIFY step above (FNV-1a word chain)");

    match state {
        dc_fpga::statemachine::State::Halted if fuse.completed() => {
            println!("[FPGA] ROOT OF DESTRUCTION COMPLETE — silicon-level proof burned");
            Ok(())
        }
        dc_fpga::statemachine::State::Fault => Err(DcError::Internal(format!(
            "interceptor run faulted (fuse {:#010x}) — board must be physically inspected",
            fuse.word()
        ))),
        other => Err(DcError::Internal(format!(
            "machine stopped in non-terminal state {other:?} — this is a bug"
        ))),
    }
}

fn cmd_info() -> Result<(), DcError> {
    println!("dc-fpga — Ghost Silicon: the RISC-V open-silicon root of destruction");
    println!();
    println!("THE TRUST PROBLEM: every software stack — even the 24 KB Ghost Boot — runs on");
    println!("proprietary silicon: Intel ME, AMD PSP, Ring -2/-3 microcode nobody has read.");
    println!("A decommission proof that bottoms out in 'trust the chip vendor' has a hole.");
    println!();
    println!("THE ANSWER: open silicon. A pure-Rust no_std payload for RISC-V softcores");
    println!("(NEORV32, VexRiscv) on open FPGAs, or OpenBMC service processors. The");
    println!("Hardware Security Interceptor sits directly on the target's PCIe/SATA");
    println!("storage lanes, gates every transaction, and runs the sanitization state");
    println!("machine autonomously — no host CPU, no host OS, no vendor microcode.");
    println!();
    println!("STATE MACHINE:");
    println!(
        "  SELF-TEST -> ENUMERATE -> AWAIT-ARM -> SANITIZE -> VERIFY -> CERTIFY -> SEAL -> HALT"
    );
    println!("  any fault -> FAULT (burns ONLY the fault fuse; COMPLETE is never burned)");
    println!();
    println!("EFUSE SEMANTICS (one-way metal links, microscopically auditable):");
    println!("  bits 0..27 : per-target completion");
    println!("  bit 28     : FAULT — the run ended in the fault path");
    println!("  bit 29     : VERIFIED — readback self-verification passed");
    println!("  bit 30     : COMPLETE — the root of destruction ran to the end");
    println!();
    println!("LANE GATE: BYPASS -> GATED (payload drives the target; host in electrical");
    println!("idle) -> LATCHED (one-way after completion: all writes refused forever,");
    println!("read-only audit path stays up).");
    println!();
    println!("BUILD (needs the RISC-V bare-metal target installed):");
    println!("  rustup target add riscv32imc-unknown-none-elf");
    println!("  cargo build -p dc-fpga --target riscv32imc-unknown-none-elf \\");
    println!("             --profile ghost --features silicon");
    println!();
    println!("BOARD MAP (port by overriding the constants in src/bin/ghost_silicon.rs):");
    println!("  0x4000_0000  interceptor core MMIO bank");
    println!("  0x4001_0000  UART16550-compatible console");
    println!();
    println!("SECURITY: see docs/FPGA.md; CI tests every state machine against SimBoard.");
    Ok(())
}
