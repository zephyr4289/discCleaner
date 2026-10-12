//! `dc cxl` — CXL Type 3 memory device sanitization (v0.11.0, Frontier 2).
//!
//! * `list` — enumerate `/sys/bus/cxl` memdevs with their PCI context.
//! * `sanitize` — opcode 0x4400 (background overwrite of all media).
//! * `erase` — opcode 0x4401 (foreground cryptographic erase).
//! * `status` — Identify + security state report.
//!
//! `--mock` runs the same lifecycle against the in-memory Type 3
//! simulator (operator drills, CI) and writes the same evidence
//! artifact shape as production.

use crate::{CxlArgs, CxlSubcommands};
use dc_core::DcError;
use dc_cxl::EraseCommand;
use dc_cxl::mailbox::{Mailbox, MockCxlDevice};

pub fn cmd_cxl(args: CxlArgs) -> Result<(), DcError> {
    match &args.sub {
        CxlSubcommands::List { sysfs } => cmd_list(sysfs.as_deref().unwrap_or("/sys")),
        CxlSubcommands::Status { device, mock } => cmd_status(device, *mock),
        CxlSubcommands::Sanitize {
            device,
            mock,
            evidence_out,
        } => cmd_erase(
            device,
            *mock,
            EraseCommand::Sanitize,
            evidence_out.as_deref(),
        ),
        CxlSubcommands::Erase {
            device,
            mock,
            evidence_out,
        } => cmd_erase(
            device,
            *mock,
            EraseCommand::SecureErase,
            evidence_out.as_deref(),
        ),
    }
}

fn cmd_list(sysfs: &str) -> Result<(), DcError> {
    let devices = dc_cxl::discovery::scan_cxl_bus(std::path::Path::new(sysfs));
    match devices {
        Ok(devs) if devs.is_empty() => {
            println!("No CXL memory devices under {}", sysfs);
            println!("(the cxl_mem kernel driver exposes them at /sys/bus/cxl/devices/mem*)");
            Ok(())
        }
        Ok(devs) => {
            println!(
                "{:<8} {:<15} {:>14}  REGISTER BLOCK",
                "MEMDEV", "PCI BDF", "MEDIA SIZE"
            );
            for d in &devs {
                let size = d
                    .media_size
                    .map(|s| {
                        if s >= 1 << 30 {
                            format!("{} GiB", s >> 30)
                        } else {
                            format!("{} MiB", s >> 20)
                        }
                    })
                    .unwrap_or_else(|| "-".into());
                let rb = d
                    .resource_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unresolved".into());
                println!("{:<8} {:<15} {:>14}  {}", d.name, d.bdf, size, rb);
            }
            Ok(())
        }
        Err(e) => Err(DcError::Usage(format!("CXL discovery failed: {}", e))),
    }
}

fn cmd_status(device: &str, mock: bool) -> Result<(), DcError> {
    if mock {
        let mut mbox = Mailbox::new(MockCxlDevice::new(1 << 20));
        let id = dc_cxl::identify(&mut mbox).map_err(cli_err)?;
        let sec = dc_cxl::security_state(&mut mbox).map_err(cli_err)?;
        println!("device:          {} (simulated Type 3 device)", device);
        println!("serial:          {}", id.serial_hex);
        println!("capacity:        {} bytes", id.total_capacity_bytes);
        println!("security enabled: {}", sec.enabled);
        println!("locked:           {}", sec.locked);
        println!("encrypted:        {}", sec.encrypted);
        return Ok(());
    }
    // Production path: resolve the memdev and open the MMIO mailbox.
    let devs = dc_cxl::discovery::scan_cxl_bus(std::path::Path::new("/sys"))
        .map_err(|e| DcError::Usage(format!("CXL discovery failed: {}", e)))?;
    let dev = devs.into_iter().find(|d| d.name == device).ok_or_else(|| {
        DcError::Usage(format!(
            "CXL device '{}' not found under /sys/bus/cxl/devices",
            device
        ))
    })?;
    let resource = dev.resource_file.clone().ok_or_else(|| {
        DcError::Usage(format!(
            "CXL device {} has no resolved register block (DVSEC locator failed)",
            device
        ))
    })?;
    let window = dc_cxl::mmio::MmioWindow::open(&resource, dev.register_block_offset, 64 * 1024)
        .map_err(cli_err)?;
    let mut mbox = Mailbox::new(dc_cxl::mmio::MmioBackend::new(
        window,
        dc_cxl::regs::MBOX_OFFSET,
    ));
    let id = dc_cxl::identify(&mut mbox).map_err(cli_err)?;
    let sec = dc_cxl::security_state(&mut mbox).map_err(cli_err)?;
    println!("device:          {} ({})", dev.name, dev.bdf);
    println!("serial:          {}", id.serial_hex);
    println!("capacity:        {} bytes", id.total_capacity_bytes);
    println!("security enabled: {}", sec.enabled);
    println!("locked:           {}", sec.locked);
    println!("encrypted:        {}", sec.encrypted);
    Ok(())
}

fn cmd_erase(
    device: &str,
    mock: bool,
    command: EraseCommand,
    evidence_out: Option<&std::path::Path>,
) -> Result<(), DcError> {
    let outcome = if mock {
        let mut mbox = Mailbox::new(MockCxlDevice::new(1 << 20));
        dc_cxl::run_erase(
            device,
            "0000:00:00.0",
            &mut mbox,
            command,
            &[0x5a; 128],
            &[0xa5; 128],
        )
        .map_err(cli_err)?
    } else {
        let devs = dc_cxl::discovery::scan_cxl_bus(std::path::Path::new("/sys"))
            .map_err(|e| DcError::Usage(format!("CXL discovery failed: {}", e)))?;
        let dev = devs.into_iter().find(|d| d.name == device).ok_or_else(|| {
            DcError::Usage(format!(
                "CXL device '{}' not found under /sys/bus/cxl/devices",
                device
            ))
        })?;
        let resource = dev.resource_file.clone().ok_or_else(|| {
            DcError::Usage(format!(
                "CXL device {} has no resolved register block (DVSEC locator failed)",
                device
            ))
        })?;
        // Snapshot the register window bytes for the pre-state hash.
        let regs_pre = register_block_bytes(&resource, dev.register_block_offset, 128)?;
        let window =
            dc_cxl::mmio::MmioWindow::open(&resource, dev.register_block_offset, 64 * 1024)
                .map_err(cli_err)?;
        let mut mbox = Mailbox::new(dc_cxl::mmio::MmioBackend::new(
            window,
            dc_cxl::regs::MBOX_OFFSET,
        ));
        let mut outcome = dc_cxl::run_erase(device, &dev.bdf, &mut mbox, command, &regs_pre, &[])
            .map_err(cli_err)?;
        drop(mbox);
        // post-state register snapshot (file re-read after the lifecycle)
        let regs_post = register_block_bytes(&resource, dev.register_block_offset, 128)?;
        outcome.evidence.component_regs_sha256_post = dc_cxl::verify::hex_sha256(&regs_post);
        outcome
    };

    println!(
        "command:        {} (opcode {:#06x})",
        command.label(),
        command.opcode()
    );
    println!("device:         {}", outcome.evidence.device);
    println!("serial:         {}", outcome.evidence.identify_serial_hex);
    println!(
        "return code:    {:#06x} ({})",
        outcome.evidence.return_code,
        dc_cxl::regs::return_code_name(outcome.evidence.return_code)
    );
    println!(
        "media verified: {} windows sampled, all zero: {}",
        outcome.evidence.media.sampled_windows, outcome.evidence.media.all_zero
    );
    if !outcome.evidence.progress.is_empty() {
        let last = outcome.evidence.progress.last().unwrap();
        println!(
            "progress:       {} samples, completed in {} ms",
            outcome.evidence.progress.len(),
            last.0
        );
    }
    println!(
        "regs pre-hash:  {}",
        outcome.evidence.component_regs_sha256_pre
    );
    println!("identify hash:  {}", outcome.evidence.identify_sha256);

    if let Some(path) = evidence_out {
        let json = serde_json::to_string_pretty(&outcome.evidence)
            .map_err(|e| DcError::Usage(format!("I/O: {}", e)))?;
        std::fs::write(path, json).map_err(|e| DcError::Usage(format!("I/O: {}", e)))?;
        println!(
            "evidence:       {} (embed into a certificate via --cxl-evidence)",
            path.display()
        );
    }
    Ok(())
}

/// Read `len` bytes of the register block for hashing (pre-state
/// evidence). Falls back to the file's first bytes via a plain read.
fn register_block_bytes(
    resource: &std::path::Path,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, DcError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(resource)
        .map_err(|e| DcError::Usage(format!("cannot open {}: {}", resource.display(), e)))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| DcError::Usage(format!("I/O: {}", e)))?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)
        .map_err(|e| DcError::Usage(format!("I/O: {}", e)))?;
    Ok(buf)
}

fn cli_err<E: std::fmt::Display>(e: E) -> DcError {
    DcError::Usage(format!("CXL operation failed: {}", e))
}
