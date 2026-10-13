//! # dc-resurrect — Forensic Autonomous Self-Assembling Kernel for Dead / Damaged Silicon
//!
//! **PR16 of the discCleaner suite.**
//!
//! Every sanitization tool in existence — including everything else in
//! `dc` — assumes the drive's firmware and main controller are alive and
//! answering PCIe/SATA handshakes. In the real world, half the
//! decommissioned drives in data centers are **bricked**:
//!
//! * the SPI flash firmware corrupted during a brownout,
//! * the controller's ARM Cortex-R4 crashed into a HardFault loop,
//! * the PCB power path has a blown TVS diode,
//! * or the vendor's debug bridges are locked.
//!
//! When the controller is dead, sysadmins have no choice but to feed the
//! drive to an industrial shredder. This crate is the alternative.
//!
//! ## What it does
//!
//! 1. **Speaks raw JTAG, SWD and UART Boot-ROM protocols** (Marvell,
//!    Silicon Motion, Phison and Samsung BROM families) over an
//!    FTDI/USB-to-GPIO rig or direct board GPIOs.
//! 2. **Injects a microscopic, self-assembled, RAM-resident nucleus**
//!    into the controller's internal SRAM — bypassing the corrupted SPI
//!    flash and the vendor firmware entirely. The payload is synthesized
//!    at injection time from the controller profile, the ONFI geometry the
//!    stage-1 probe discovers on the drive itself, and the chosen erase
//!    strategy.
//! 3. **Takes over the raw NAND flash controller from inside the chip**,
//!    executes physical die-level erase, retries marginal blocks, verifies
//!    pages read back as erased, and streams per-block CRC-32 attestations
//!    into an SRAM mailbox — autonomously, no host babysitting.
//! 4. **Proves the wipe**: one Merkle leaf per addressed block, no gaps,
//!    with sampled inclusion proofs, written to a `.drz` receipt the
//!    auditor can verify offline.
//!
//! When even the debug ports are locked, the boundary-scan fallback drives
//! the NAND bus pins (CLE/ALE/nCE/nWE/nRE/DQ) directly through the
//! JTAG boundary register — erase on a corpse, no CPU required.
//!
//! ## Module map
//!
//! ```text
//! hal        transport traits (JTAG / SWD / UART / bench power)
//! jtag       IEEE 1149.1 TAP engine, chain scan, 35-bit DPACC/APACC
//! swd        ADIv5 wire engine: request/ack/parity, WAIT/FAULT handling
//! dp         Debug-Port abstraction + MEM-AP (TAR/DRW, power-up)
//! uart_brom  vendor Boot-ROM protocol: autobaud, auth, download, JUMP
//! vendors    controller profile database (built-ins + TOML-lite)
//! nand       raw NAND layer, ONFI parameter page, die/block model
//! payload    the self-assembling nucleus (Thumb assembler + fragments)
//! sim        device-side JTAG/SWD/BROM, reference core, dead-drive scenarios
//! bitbang    boundary-scan NAND pin takeover + cost model
//! attest     block records, Merkle proof, .drz writer/verifier
//! pipeline   scan -> triage -> assemble -> inject -> erase -> prove
//! ```
//!
//! Everything in-tree runs against a bit-level simulator implementing the
//! *device* side of each protocol — the same engine bits that would talk
//! to a real brick over an FTDI rig. See `README.md` for the hardware
//! bring-up path and the modeling-gap ledger.

#![deny(unsafe_code)]

pub mod attest;
pub mod bitbang;
pub mod crc;
pub mod dp;
pub mod failure;
pub mod hal;
pub mod jtag;
pub mod nand;
pub mod payload;
pub mod pipeline;
pub mod rng;
pub mod sha256;
pub mod sim;
pub mod swd;
pub mod tomlite;
pub mod uart_brom;
pub mod vendors;
