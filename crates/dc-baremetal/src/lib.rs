//! # dc-baremetal — Ghost Boot (v0.12.0, Miracle 3)
//!
//! A **100% pure-Rust bare-metal Ring 0 UEFI payload** — no Linux
//! kernel, no systemd, no drivers, no rootfs, no glibc. A technician
//! plugs the USB stick into any bricked, corrupted, virus-riddled or
//! unbootable server; the firmware loads this image directly; it
//! sanitizes every storage device it can see on the PCIe bus at raw
//! line rate, renders progress on the framebuffer, and powers the
//! machine down.
//!
//! ## What makes this possible (and safe to ship)
//!
//! * **No OS assumptions.** The payload speaks to the motherboard's
//!   PCIe Root Complex through I/O ports `0xCF8/0xCFC`, discovers
//!   AHCI HBAs and NVMe controllers via their Base Address Registers,
//!   enables bus mastering, and drives the devices itself.
//! * **Every hardware state machine is CI-tested.** All register
//!   access flows through two traits ([`hal::PortIo`], [`hal::Mmio`]).
//!   The same code that toggles a real HBA's doorbell register runs in
//!   CI against [`hal::SimBus`] — a bit-accurate simulated bus (see
//!   `tests/`).
//! * **Keystreams without an OS CSPRNG.** [`chacha`] is a no_std,
//!   zero-dependency ChaCha20 (RFC 8439) seeded by `RDRAND` —
//!   KAT-verified against the RFC's official test vectors.
//! * **Poweroff without ACPI daemons.** [`acpi`] walks the RSDP →
//!   XSDT → FADT chain the firmware hands us and writes the S5 sleep
//!   type into PM1a — the same field Linux uses, minus 40 MB of
//!   userspace.
//!
//! ## Boot protocol
//!
//! Build the image (`scripts/build-ghost.sh` or
//! `dc baremetal build`) → copy `dc-ghost-efi.efi` to
//! `/EFI/BOOT/BOOTX64.EFI` on any FAT32 USB → boot. The payload never
//! executes code from the target's disks.
//!
//! ## Module map
//!
//! * [`hal`] — hardware access traits + the CI simulation bus.
//! * [`chacha`] — no_std ChaCha20 keystream.
//! * [`pci`] — config-space enumeration, BAR decode.
//! * [`ahci`] — SATA host bus adapter driver (write DMA EXT).
//! * [`nvme`] — NVMe 1.x admin/IO queues (Write DMA + Format NVM).
//! * [`fb`] — linear framebuffer console (8×16 bitmap font).
//! * [`acpi`] — table walk + S5 poweroff.
//! * [`wipe`] — the Ghost run orchestrator (per-device plan, progress,
//!   verdicts).
//! * [`uefi`] — EFI entry + ExitBootServices handoff (UEFI target only).

#![cfg_attr(not(test), no_std)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::no_effect)]
#![allow(clippy::manual_clamp)]
// Hosted builds see the UEFI-only glue and hardware constructors as
// dead code (they compile for x86_64-unknown-uefi, verified in the
// release pipeline); the sim tests cover the state machines.
#![allow(dead_code)]

pub mod acpi;
pub mod ahci;
pub mod chacha;
pub mod fb;
pub mod hal;
pub mod nvme;
pub mod pci;
pub mod uefi;
pub mod wipe;

/// Payload identity (rendered on the framebuffer header).
pub const GHOST_NAME: &str = "discCleaner Ghost Boot";
pub const GHOST_VERSION: &str = env!("CARGO_PKG_VERSION");
