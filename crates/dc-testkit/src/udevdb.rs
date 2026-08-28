use std::fs;
use std::path::{Path, PathBuf};

pub struct UdevDb;

impl UdevDb {
    /// Get the path to the udev database entry for a block device (e.g. /run/udev/data/b<maj>:<min>).
    pub fn entry_path(major: u32, minor: u32) -> PathBuf {
        PathBuf::from(format!("/run/udev/data/b{}:{}", major, minor))
    }

    /// Snapshot the udev database entry for a block device.
    pub fn snapshot_entry(major: u32, minor: u32) -> Option<String> {
        let path = Self::entry_path(major, minor);
        fs::read_to_string(path).ok()
    }

    /// Replay / restore a udev database entry to simulate deterministic staleness (Δ33).
    pub fn replay_entry(major: u32, minor: u32, content: &str) -> Result<(), String> {
        let path = Self::entry_path(major, minor);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&path, content).map_err(|e| format!("Failed to write udev db entry: {}", e))?;
        Ok(())
    }

    /// Remove a udev database entry.
    pub fn remove_entry(major: u32, minor: u32) -> Result<(), String> {
        let path = Self::entry_path(major, minor);
        if path.exists() {
            fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
