//! Device discovery: enumerate CXL Type 3 memory devices from
//! `/sys/bus/cxl` (kernel cxl_mem driver) with a PCI DVSEC fallback.

use crate::dvsec;
use std::path::{Path, PathBuf};

/// A discovered CXL Type 3 memory device.
#[derive(Debug, Clone, PartialEq)]
pub struct CxlDevice {
    /// sysfs name, e.g. `mem0`.
    pub name: String,
    /// PCI BDF, e.g. `0000:41:00.0`.
    pub bdf: String,
    /// sysfs path of the memdev.
    pub sysfs_path: PathBuf,
    /// resource file for the register block BAR (best-effort mapping).
    pub resource_file: Option<PathBuf>,
    /// Offset of the device register block in the BAR (from DVSEC RBL).
    pub register_block_offset: u64,
    /// Mapped media size in bytes (from identify or sysfs), if known.
    pub media_size: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("sysfs inaccessible: {0}")]
    Sysfs(String),
    #[error("device {0} has no usable register block")]
    NoRegisterBlock(String),
}

/// Scan `/sys/bus/cxl/devices` for memory devices (`mem*`).
///
/// The kernel exposes each CXL.mem device with:
/// * `devtype` = `cxl_mem_device`
/// * a symlink to the backing PCI function.
pub fn scan_cxl_bus(sysfs_root: &Path) -> Result<Vec<CxlDevice>, DiscoveryError> {
    let devices = sysfs_root.join("bus/cxl/devices");
    let entries = std::fs::read_dir(&devices)
        .map_err(|e| DiscoveryError::Sysfs(format!("{}: {}", devices.display(), e)))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("mem") || !entry.path().is_dir() {
            continue;
        }
        let devtype = read_trim(entry.path().join("devtype"));
        if let Some(dt) = &devtype
            && dt != "cxl_mem_device"
        {
            continue;
        }
        let bdf = resolve_bdf(&entry.path());
        let (resource_file, register_block_offset) = match &bdf {
            Some(b) => pci_register_block(sysfs_root, b),
            None => (None, 0),
        };
        let media_size = read_trim(entry.path().join("size")).and_then(|s| s.parse::<u64>().ok());
        out.push(CxlDevice {
            name,
            bdf: bdf.unwrap_or_default(),
            sysfs_path: entry.path(),
            resource_file,
            register_block_offset,
            media_size,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn read_trim(p: PathBuf) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Resolve the PCI BDF of a memdev via its `device` symlink
/// (`.../mem0/device -> ../../pci0000:40/0000:40:00.0`).
fn resolve_bdf(memdev: &Path) -> Option<String> {
    let link = std::fs::read_link(memdev.join("device")).ok()?;
    let s = link.to_string_lossy().to_string();
    // The last path component matching the BDF pattern.
    for part in s.split('/').rev() {
        let bytes = part.as_bytes();
        if bytes.len() >= 7 && bytes[4] == b':' && bytes[7] == b':' && part.ends_with(".0") {
            return Some(part.to_string());
        }
    }
    // Also accept direct BDF-shaped names.
    if s.split('/')
        .next_back()
        .map(|p| p.contains(':'))
        .unwrap_or(false)
    {
        return s.split('/').next_back().map(|p| p.to_string());
    }
    None
}

/// Read the PCI config space of `bdf`, find the CXL DVSEC, and derive the
/// resource file + register block offset for the mailbox.
fn pci_register_block(sysfs_root: &Path, bdf: &str) -> (Option<PathBuf>, u64) {
    let pci_dir = sysfs_root.join("bus/pci/devices").join(bdf);
    let config = std::fs::read(pci_dir.join("config")).unwrap_or_default();
    if config.len() < 256 {
        return (None, 0);
    }
    let dvsecs = dvsec::find_cxl_dvsecs(&config).unwrap_or_default();
    for d in dvsecs {
        if d.id == 0
            && let Ok(loc) = dvsec::register_block_locator(&d)
        {
            let resource = pci_dir.join(format!("resource{}", loc.bar_index));
            if resource.exists() {
                return (Some(resource), loc.bar_offset);
            }
        }
    }
    (None, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fake_sysfs(root: &Path) {
        // /sys/bus/cxl/devices/mem0/{devtype,device->...}
        let mem0 = root.join("bus/cxl/devices/mem0");
        std::fs::create_dir_all(&mem0).unwrap();
        std::fs::write(mem0.join("devtype"), "cxl_mem_device\n").unwrap();
        std::fs::write(mem0.join("size"), "1073741824\n").unwrap();
        // device symlink -> ../../0000:41:00.0 (BDF-shaped leaf)
        let pci = root.join("pci_devices/0000:41:00.0");
        std::fs::create_dir_all(&pci).unwrap();
        std::os::unix::fs::symlink(&pci, mem0.join("device")).unwrap();
        // /sys/bus/pci/devices/0000:41:00.0 (the sysfs lookup path)
        let pci_sys = root.join("bus/pci/devices/0000:41:00.0");
        std::fs::create_dir_all(&pci_sys).unwrap();
        std::fs::write(pci_sys.join("config"), build_config()).unwrap();
        std::fs::write(pci_sys.join("resource1"), [0u8; 8192]).unwrap();
    }

    fn build_config() -> Vec<u8> {
        let mut c = vec![0u8; 512];
        let base = 0x100;
        c[base..base + 2].copy_from_slice(&0x0023u16.to_le_bytes());
        c[base + 2..base + 4].copy_from_slice(&0x0000u16.to_le_bytes());
        // DVSEC header 1: CXL vendor, rev 1, length 0x18
        let hdr1 = u32::from(0x1e98u16) | (1u32 << 16) | (0x18u32 << 20);
        c[base + 4..base + 8].copy_from_slice(&hdr1.to_le_bytes());
        // DVSEC header 2: id 0 (CXL Device)
        c[base + 8..base + 10].copy_from_slice(&0x0000u16.to_le_bytes());
        // RBL at +0x0C: BAR 1 + identified bit
        c[base + 12..base + 16].copy_from_slice(&0x5u32.to_le_bytes());
        c
    }

    #[test]
    fn discovers_memdev_with_pci_context() {
        let tmp = tempfile::tempdir().unwrap();
        make_fake_sysfs(tmp.path());
        let devs = scan_cxl_bus(tmp.path()).unwrap();
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.name, "mem0");
        assert_eq!(d.bdf, "0000:41:00.0");
        assert_eq!(d.media_size, Some(1_073_741_824));
        assert!(d.resource_file.is_some(), "resource1 must be resolved");
        assert_eq!(d.register_block_offset, 0);
    }

    #[test]
    fn empty_bus_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("bus/cxl/devices")).unwrap();
        let devs = scan_cxl_bus(tmp.path()).unwrap();
        assert!(devs.is_empty());
    }
}
