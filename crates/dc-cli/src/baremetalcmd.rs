//! `dc baremetal` — Ghost Boot payload management (v0.12.0, Miracle 3).
//!
//! * `info` — explain what the Ghost Boot payload is, its boot
//!   protocol, and the hardware requirements.
//! * `build` — compile `dc-ghost-efi.efi` for `x86_64-unknown-uefi`
//!   (invokes cargo with the right target/features; the resulting
//!   image is a pure-Rust Ring-0 payload with no kernel, no drivers,
//!   no OS — ~25 KB).
//! * `deploy` — copy the built image to a USB stick as
//!   `EFI/BOOT/BOOTX64.EFI`.

use crate::{BaremetalArgs, BaremetalSubcommands};
use dc_core::DcError;
use std::path::PathBuf;

pub fn cmd_baremetal(args: BaremetalArgs) -> Result<(), DcError> {
    match &args.sub {
        BaremetalSubcommands::Info => cmd_info(),
        BaremetalSubcommands::Build { release } => cmd_build(*release),
        BaremetalSubcommands::Deploy { device, release } => cmd_deploy(device, *release),
    }
}

const INFO: &str = "\
discCleaner Ghost Boot (v0.12.0, Miracle 3)
============================================

A 100% pure-Rust bare-metal Ring 0 UEFI payload — no Linux kernel, no
systemd, no drivers, no rootfs, no glibc (~25 KB release build). A
technician plugs the USB stick into any bricked, corrupted, virus-
riddled or unbootable server; the firmware loads this image directly;
it sanitizes every storage device it can see on the PCIe bus at raw
line rate, renders progress on the framebuffer, and powers the machine
off (ACPI S5).

WHAT IT DOES
  1. UEFI handoff: GOP framebuffer + ACPI RSDP + ExitBootServices.
  2. PCIe scan via I/O ports 0xCF8/0xCFC (class 01:06:01 AHCI,
     01:08:02 NVMe), bus mastering enabled per function.
  3. NVMe: controller bring-up, Identify, Format NVM with cryptographic
     erase + a ChaCha20(RDRAND) full-namespace pattern pass.
  4. SATA: HBA init, port spin-up, full-band 48-bit WRITE DMA EXT
     pattern pass.
  5. Framebuffer console (8x16 bitmap font) with per-device progress.
  6. ACPI S5 soft-off via the FADT PM1a control block.

SECURITY MODEL
  - Every hardware state machine (PCI/AHCI/NVMe/ACPI) is unit-tested
    in CI against a register-accurate simulated bus (dc-baremetal
    SimBus); the release image is the same code path.
  - The payload never executes code from the target's disks.
  - Keystreams are seeded by RDRAND (x86-64) with a documented TSC
    fallback for CPUs without the instruction.

BOOT PROTOCOL
  Build (or `dc baremetal build`), then copy the image to any FAT32
  USB stick as /EFI/BOOT/BOOTX64.EFI and boot it. The machine must be
  x86-64 UEFI (any vendor). The payload runs in the UEFI identity
  mapping; the DMA window is AllocateMaxAddress'd below 4 GiB so
  every 32-bit-capable storage controller can reach it.";

fn cmd_info() -> Result<(), DcError> {
    println!("{INFO}");
    Ok(())
}

fn repo_root() -> Result<PathBuf, DcError> {
    // The binary lives in target/{debug,release}/; the workspace root
    // is three levels up.
    let exe = std::env::current_exe()
        .map_err(|e| DcError::Usage(format!("cannot locate myself: {e}")))?;
    for anc in exe.ancestors() {
        if anc.join("Cargo.toml").is_file() && anc.join("crates/dc-baremetal").is_dir() {
            return Ok(anc.to_path_buf());
        }
    }
    Err(DcError::Usage(
        "cannot locate the workspace root (run from a built binary inside the repo tree)".into(),
    ))
}

fn run_cargo(root: &std::path::Path, profile: &str) -> Result<PathBuf, DcError> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = std::process::Command::new(&cargo)
        .current_dir(root)
        .args([
            "build",
            "-p",
            "dc-baremetal",
            "--target",
            "x86_64-unknown-uefi",
            "--features",
            "efi",
        ])
        .args(if profile == "release" {
            vec!["--release"]
        } else {
            vec![]
        })
        .status()
        .map_err(|e| DcError::Usage(format!("cannot run cargo: {e}")))?;
    if !status.success() {
        return Err(DcError::Usage(
            "cargo build failed (is the x86_64-unknown-uefi target installed? run: \
             rustup target add x86_64-unknown-uefi)"
                .into(),
        ));
    }
    let out = root
        .join("target/x86_64-unknown-uefi")
        .join(profile)
        .join("dc-ghost-efi.efi");
    if !out.is_file() {
        return Err(DcError::Usage(format!(
            "build artifact missing: {} (did cargo name it differently?)",
            out.display()
        )));
    }
    Ok(out)
}

fn cmd_build(release: bool) -> Result<(), DcError> {
    let root = repo_root()?;
    eprintln!("[ghost] building the EFI payload (target x86_64-unknown-uefi)…");
    let out = run_cargo(&root, if release { "release" } else { "debug" })?;
    let size = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    println!("Ghost Boot payload: {}", out.display());
    println!("  size:    {size} bytes ({:.1} KB)", size as f64 / 1024.0);
    if release && size > 307_200 {
        eprintln!("[ghost] WARNING: payload exceeds the 300 KB budget ({size} bytes)");
    }
    println!();
    println!(
        "Deploy: dc baremetal deploy --device /dev/sdX   (FAT32 USB stick, boots as BOOTX64.EFI)"
    );
    Ok(())
}

fn cmd_deploy(device: &std::path::Path, release: bool) -> Result<(), DcError> {
    let root = repo_root()?;
    let efi = run_cargo(&root, if release { "release" } else { "debug" })?;

    // Mount-point discovery: the device (or partition) must already be
    // mounted somewhere under /media or /run/media, or be given as the
    // mount point directly.
    let mount_point = if device.is_dir() {
        device.to_path_buf()
    } else {
        find_mount_point(device)?
    };
    let boot_dir = mount_point.join("EFI/BOOT");
    std::fs::create_dir_all(&boot_dir)
        .map_err(|e| DcError::Usage(format!("mkdir {}: {e}", boot_dir.display())))?;
    let dest = boot_dir.join("BOOTX64.EFI");
    std::fs::copy(&efi, &dest).map_err(|e| DcError::Usage(format!("copy: {e}")))?;
    let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    println!("deployed: {} ({} bytes)", dest.display(), size);
    println!();
    println!("The stick is a Ghost Boot medium: plug it into the target, power on,");
    println!("confirm the wipe on screen, and the machine powers itself off (S5).");
    Ok(())
}

fn find_mount_point(device: &std::path::Path) -> Result<PathBuf, DcError> {
    // /proc/mounts walk — device → mount point.
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(|e| DcError::Usage(format!("cannot read /proc/mounts: {e}")))?;
    let dev = device.display().to_string();
    let canonical = std::fs::canonicalize(device)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| dev.clone());
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let (Some(source), Some(target), Some(fstype)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if (source == dev || source == canonical) && (fstype == "vfat" || fstype == "exfat") {
            return Ok(PathBuf::from(target));
        }
    }
    Err(DcError::Usage(format!(
        "{} is not a mounted FAT32 medium — mount it first or pass the mount point directly",
        dev
    )))
}
