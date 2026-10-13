//! # dc-fpga — Autonomous Self-Verifying RISC-V Open-Silicon Firmware
//! Payload (v0.13.0, Frontier 3)
//!
//! **The trust problem this crate kills:** every software stack in
//! this workspace — even the 24 KB Ghost Boot — ultimately executes
//! on proprietary silicon: x86 CPUs with Intel ME / AMD PSP, ARM
//! cores with TrustZone ROM, Ring -2/-3 microcode nobody outside the
//! vendor has ever read. A decommission proof that bottoms out in
//! "trust the chip vendor" is a proof with a hole in it.
//!
//! The answer is **open silicon running a root of destruction**: a
//! pure-Rust, `no_std`, zero-dependency payload for open RISC-V
//! softcores ([NEORV32](https://github.com/stnolink/neorv32),
//! [VexRiscv](https://github.com/SpinalHDL/VexRiscv)) on open FPGA
//! fabrics, or open BMC service processors (OpenBMC on ASPEED
//! AST2600). The design here is the **Hardware Security
//! Interceptor**: a small open-silicon device (or BMC image) that
//! sits directly on the target's PCIe/SATA storage lanes, gates
//! every transaction, and executes the sanitization state machine
//! autonomously — no host CPU, no host OS, no host firmware in the
//! trust chain. On completion it burns a **physical eFuse**: a
//! one-time, microscopically visible, silicon-level proof that the
//! destruction path ran to the end.
//!
//! ## Module map
//!
//! * [`hal`] — MMIO access traits + the `SimBoard` virtual softcore
//!   (every hardware state machine in this crate is CI-tested
//!   against it, exactly like dc-baremetal's `SimBus` discipline).
//! * [`lane`] — the storage-lane gate: BYPASS → SANITIZE → LATCHED,
//!   with per-lane target discovery behind the interceptor.
//! * [`statemachine`] — the autonomous sanitization state machine:
//!   SELF-TEST → ENUMERATE → ARM → SANITIZE → VERIFY → CERTIFY →
//!   BURN-EFUSE → HALT, with an explicit fault path that never
//!   burns the completion fuse.
//! * [`efuse`] — the one-way eFuse bank model (burn is irreversible
//!   by physics; the model is honest about it).
//! * [`verify`] — self-verification: lane readback with a
//!   zero-dependency digest and zero-entropy classification.
//! * `bin/ghost_silicon.rs` — the payload image: naked RISC-V entry
//!   (`_start`), stack + BSS setup, UART console, state machine over
//!   the real MMIO map, WFI halt. Build:
//!
//! ```text
//! cargo build -p dc-fpga --target riscv32imc-unknown-none-elf \
//!            --profile ghost --features silicon
//! ```
//!
//! ## Threat model
//!
//! 1. **Host-side malware / compromised OS** — the target host is
//!    assumed hostile from the first clock: the interceptor gates
//!    every storage lane, and the payload runs on its own die with
//!    its own SRAM. The host cannot inject code into the payload
//!    (there is no code-loading interface at all).
//! 2. **Ring -2/-3 closed microcode** — none executes: the payload
//!    runs on an open RTL softcore whose entire gate-level netlist is
//!    public and reproducible from vendor-neutral toolchains.
//! 3. **Premature completion claim** — the completion eFuse burns
//!    only after every enumerated target passed readback
//!    verification; the burn record is in the fuse bank forever.
//! 4. **Re-use of a "wiped" board** — the lane gate latches
//!    LATCHED after completion: the interceptor refuses every later
//!    write transaction (a blown-fuse board can still be audited,
//!    but never quietly re-serviced as clean storage).

#![cfg_attr(not(test), no_std)]

pub mod efuse;
pub mod hal;
pub mod lane;
pub mod statemachine;
pub mod verify;

/// Payload protocol/banner magic ("DCGS" — dc ghost silicon).
pub const MAGIC: [u8; 4] = *b"DCGS";

/// Payload version reported over the console.
pub const PAYLOAD_VERSION: &str = "0.13.0";
