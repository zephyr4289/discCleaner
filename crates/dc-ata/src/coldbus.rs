//! Cold-bus ATA freeze unlocking — lights-out remediation of SECURITY
//! FREEZE LOCK without rebooting the host (v0.7.0, Vector 2).
//!
//! THE PROBLEM: most BIOS/UEFI firmware issues SECURITY FREEZE LOCK at
//! power-on; a frozen drive refuses every destructive security command.
//! In automated data centers and remote edge racks there is no human to
//! power-cycle the drive, so v0.6.0's "call an operator" advisory means
//! the purge never happens.
//!
//! THE REMEDIATION LADDER (kernel-sanctioned, no host reboot):
//!
//! 1. LUN DELETE + HOST RESCAN (`/sys/block/sdX/device/delete`,
//!    `/sys/class/scsi_host/hostN/scan`): the kernel detaches the LUN
//!    and re-probes it, which drives a libata hard reset (COMRESET) of
//!    the SATA link. The freeze lock is volatile power-state: a hard
//!    reset clears it on controllers that wire it per-spec. This is the
//!    same mechanism a hot-unplug/replug by hand performs.
//! 2. ATA PORT RUNTIME-PM CYCLE (`/sys/class/ata_port/ataN/power/control`
//!    `auto` -> wait for `suspended` -> `on`): drops the port into
//!    runtime suspend and resumes it, forcing a link power management
//!    (LPM) transition on the bus while the OS stays up.
//! 3. PHYSICAL POWER-CYCLE ADVISORY: if the controller does not drop
//!    freeze on either step, the ladder stops honestly and re-issues the
//!    manual remedy (never fabricates success).
//!
//! HONESTY: neither step is guaranteed on every controller (some AHCI
//! implementations keep the device powered across COMRESET). Every step
//! is followed by a fresh IDENTIFY re-probe; only a re-probe that reports
//! `frozen == false` counts as success. The full step record lands in the
//! certificate.

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

/// The sysfs operations the ladder performs, abstracted for test rigs.
pub trait SysfsOps {
    /// Read a sysfs attribute as a trimmed string.
    fn read_str(&self, path: &Path) -> Result<String, String>;
    /// Write a sysfs attribute (root-only in production).
    fn write_str(&self, path: &Path, value: &str) -> Result<(), String>;
    /// Whether a path exists.
    fn exists(&self, path: &Path) -> bool;
    /// Read a directory symlink target (sysfs symlinks are absolute).
    fn read_link(&self, path: &Path) -> Result<PathBuf, String>;
    /// Enumerate child entries of a directory.
    fn list_dir(&self, path: &Path) -> Result<Vec<String>, String>;
}

/// Production sysfs backend: direct filesystem operations.
pub struct RealSysfs;

impl SysfsOps for RealSysfs {
    fn read_str(&self, path: &Path) -> Result<String, String> {
        std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("read {}: {}", path.display(), e))
    }

    fn write_str(&self, path: &Path, value: &str) -> Result<(), String> {
        std::fs::write(path, value.as_bytes())
            .map_err(|e| format!("write {} <- '{}': {}", path.display(), value, e))
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read_link(&self, path: &Path) -> Result<PathBuf, String> {
        std::fs::read_link(path).map_err(|e| format!("readlink {}: {}", path.display(), e))
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<String>, String> {
        let mut names = Vec::new();
        let entries =
            std::fs::read_dir(path).map_err(|e| format!("readdir {}: {}", path.display(), e))?;
        for entry in entries.flatten() {
            names.push(entry.file_name().to_string_lossy().to_string());
        }
        names.sort();
        Ok(names)
    }
}

/// One executed (or refused) ladder step, for the certificate evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdBusStepRecord {
    /// Which step of the ladder this was.
    pub step: String,
    /// Sysfs writes the step performed, in order (path <- value).
    pub sysfs_writes: Vec<(String, String)>,
    /// Human-readable result of the step.
    pub outcome: String,
}

/// Result of the cold-unfreeze ladder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColdBusOutcome {
    /// A re-probe after a step reported the freeze lock cleared.
    Cleared { steps: Vec<ColdBusStepRecord> },
    /// The ladder is exhausted; the freeze lock survived every step.
    /// `advisory` is the manual remedy to disclose.
    StillFrozen {
        steps: Vec<ColdBusStepRecord>,
        advisory: String,
    },
}

/// Manual power-cycle advisory (the v0.6.0 remedy, still the last resort).
pub const PHYSICAL_POWER_CYCLE_ADVISORY: &str = "Drive is frozen by host firmware/BIOS and \
survived the cold-bus reset ladder. Power-cycle the drive WITHOUT letting firmware re-freeze \
(hot-plug the drive, or attach it to a controller that does not assert freeze-lock at \
power-on), then retry the purge.";

/// Resolve the SCSI host (`hostN`) serving a block device, e.g. `sda` ->
/// `host3`, by walking the device chain under `/sys/block`.
pub fn resolve_scsi_host(sysfs: &dyn SysfsOps, block_name: &str) -> Result<String, String> {
    let link = sysfs.read_link(&PathBuf::from(format!("/sys/block/{}", block_name)))?;
    // The resolved chain contains ".../ata3/host3/target3:0:0/3:0:0:0" —
    // the LAST `hostN` component is the owning SCSI host.
    let mut found: Option<String> = None;
    for component in link.components() {
        let name = component.as_os_str().to_string_lossy().to_string();
        if name.starts_with("host") && name[4..].chars().all(|c| c.is_ascii_digit()) {
            found = Some(name.clone());
        }
    }
    found.ok_or_else(|| {
        format!(
            "no scsi_host component in the device chain of /sys/block/{} ({})",
            block_name,
            link.display()
        )
    })
}

/// Resolve the ATA port (`ataN`) of a block device, e.g. `sda` -> `ata3`.
pub fn resolve_ata_port(sysfs: &dyn SysfsOps, block_name: &str) -> Result<String, String> {
    let link = sysfs.read_link(&PathBuf::from(format!("/sys/block/{}", block_name)))?;
    let mut found: Option<String> = None;
    for component in link.components() {
        let name = component.as_os_str().to_string_lossy().to_string();
        if name.starts_with("ata") && name[3..].chars().all(|c| c.is_ascii_digit()) {
            found = Some(name.clone());
        }
    }
    found.ok_or_else(|| {
        format!(
            "no ata_port component in the device chain of /sys/block/{} ({}) — not a libata device?",
            block_name,
            link.display()
        )
    })
}

/// The cold-bus ladder itself.
///
/// `recheck` is invoked after every disruptive step: it must re-open the
/// device transport and run a fresh IDENTIFY, returning whether the drive
/// still reports frozen (true = still frozen). The closure exists because
/// step 1 deletes the LUN — the caller's existing SG_IO fd must be
/// dropped and the (possibly renumbered) node reopened by the caller's
/// own logic.
pub fn attempt_cold_unfreeze(
    sysfs: &dyn SysfsOps,
    block_name: &str,
    mut recheck: impl FnMut() -> Result<bool, String>,
) -> ColdBusOutcome {
    let mut steps: Vec<ColdBusStepRecord> = Vec::new();

    // ---------------- Step 1: LUN delete + host rescan ----------------
    let host = match resolve_scsi_host(sysfs, block_name) {
        Ok(h) => h,
        Err(reason) => {
            steps.push(ColdBusStepRecord {
                step: "lun-delete-host-rescan".to_string(),
                sysfs_writes: Vec::new(),
                outcome: format!("SKIPPED: {}", reason),
            });
            return ColdBusOutcome::StillFrozen {
                steps,
                advisory: PHYSICAL_POWER_CYCLE_ADVISORY.to_string(),
            };
        }
    };
    let delete_path = format!("/sys/block/{}/device/delete", block_name);
    let scan_path = format!("/sys/class/scsi_host/{}/scan", host);
    let mut writes: Vec<(String, String)> = Vec::new();
    let step_outcome = (|| -> Result<String, String> {
        sysfs.write_str(Path::new(&delete_path), "1")?;
        writes.push((delete_path.clone(), "1".to_string()));
        // Give the kernel the detach + re-probe; the recheck closure
        // performs its own bounded retries around the node's (possibly
        // slow) reappearance.
        sysfs.write_str(Path::new(&scan_path), "- - -")?;
        writes.push((scan_path.clone(), "- - -".to_string()));
        Ok("EXECUTED".to_string())
    })()
    .unwrap_or_else(|e| format!("FAILED: {}", e));
    let still_frozen = match recheck() {
        Ok(frozen) => frozen,
        Err(reason) => {
            // The node may have renumbered or not reappeared yet: treat as
            // unresolved (still frozen) with the reason recorded.
            steps.push(ColdBusStepRecord {
                step: "lun-delete-host-rescan".to_string(),
                sysfs_writes: writes,
                outcome: format!("RECHECK_UNRESOLVED: {}", reason),
            });
            return ColdBusOutcome::StillFrozen {
                steps,
                advisory: PHYSICAL_POWER_CYCLE_ADVISORY.to_string(),
            };
        }
    };
    steps.push(ColdBusStepRecord {
        step: "lun-delete-host-rescan".to_string(),
        sysfs_writes: writes,
        outcome: if still_frozen {
            step_outcome
        } else {
            format!("{} — freeze cleared on re-probe", step_outcome)
        },
    });
    if !still_frozen {
        return ColdBusOutcome::Cleared { steps };
    }

    // ---------------- Step 2: ATA port runtime-PM cycle ----------------
    let ata_port = match resolve_ata_port(sysfs, block_name) {
        Ok(p) => p,
        Err(reason) => {
            steps.push(ColdBusStepRecord {
                step: "ata-port-runtime-pm-cycle".to_string(),
                sysfs_writes: Vec::new(),
                outcome: format!("SKIPPED: {}", reason),
            });
            return ColdBusOutcome::StillFrozen {
                steps,
                advisory: PHYSICAL_POWER_CYCLE_ADVISORY.to_string(),
            };
        }
    };
    let control_path = format!("/sys/class/ata_port/{}/power/control", ata_port);
    let status_path = format!("/sys/class/ata_port/{}/power/runtime_status", ata_port);
    let mut writes: Vec<(String, String)> = Vec::new();
    let pm_outcome = (|| -> Result<String, String> {
        // Enable runtime PM (auto), observe the port actually suspend,
        // then force resume (on) — the resume path performs the port
        // re-initialization/hard reset on LPM-capable controllers.
        sysfs.write_str(Path::new(&control_path), "auto")?;
        writes.push((control_path.clone(), "auto".to_string()));
        match sysfs.read_str(Path::new(&status_path)) {
            Ok(status) if status == "suspended" => {}
            Ok(other) => {
                return Err(format!(
                    "port did not reach runtime suspend (status '{}')",
                    other
                ))
            }
            Err(e) => return Err(e),
        }
        sysfs.write_str(Path::new(&control_path), "on")?;
        writes.push((control_path.clone(), "on".to_string()));
        Ok("EXECUTED".to_string())
    })()
    .unwrap_or_else(|e| format!("FAILED: {}", e));
    let still_frozen = match recheck() {
        Ok(frozen) => frozen,
        Err(reason) => {
            steps.push(ColdBusStepRecord {
                step: "ata-port-runtime-pm-cycle".to_string(),
                sysfs_writes: writes,
                outcome: format!("RECHECK_UNRESOLVED: {}", reason),
            });
            return ColdBusOutcome::StillFrozen {
                steps,
                advisory: PHYSICAL_POWER_CYCLE_ADVISORY.to_string(),
            };
        }
    };
    steps.push(ColdBusStepRecord {
        step: "ata-port-runtime-pm-cycle".to_string(),
        sysfs_writes: writes,
        outcome: if still_frozen {
            pm_outcome
        } else {
            format!("{} — freeze cleared on re-probe", pm_outcome)
        },
    });
    if !still_frozen {
        return ColdBusOutcome::Cleared { steps };
    }

    // ---------------- Step 3: manual advisory ----------------
    ColdBusOutcome::StillFrozen {
        steps,
        advisory: PHYSICAL_POWER_CYCLE_ADVISORY.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// Scripted sysfs: attribute map + recorded writes.
    struct ScriptedSysfs {
        attrs: RefCell<BTreeMap<String, String>>,
        links: BTreeMap<String, PathBuf>,
        writes: RefCell<Vec<(String, String)>>,
    }

    impl ScriptedSysfs {
        fn with_device_chain() -> Self {
            let mut links = BTreeMap::new();
            links.insert(
                "/sys/block/sda".to_string(),
                PathBuf::from(
                    "/sys/devices/pci0000:00/0000:00:17.0/ata3/host3/target3:0:0/3:0:0:0/block/sda",
                ),
            );
            Self {
                attrs: RefCell::new(BTreeMap::new()),
                links,
                writes: RefCell::new(Vec::new()),
            }
        }

        fn set(&self, path: &str, value: &str) {
            self.attrs
                .borrow_mut()
                .insert(path.to_string(), value.to_string());
        }

        fn written(&self) -> Vec<(String, String)> {
            self.writes.borrow().clone()
        }
    }

    impl SysfsOps for ScriptedSysfs {
        fn read_str(&self, path: &Path) -> Result<String, String> {
            self.attrs
                .borrow()
                .get(&path.display().to_string())
                .cloned()
                .ok_or_else(|| format!("no such attribute {}", path.display()))
        }

        fn write_str(&self, path: &Path, value: &str) -> Result<(), String> {
            self.writes
                .borrow_mut()
                .push((path.display().to_string(), value.to_string()));
            // Mirror the attribute state like the kernel would.
            self.attrs
                .borrow_mut()
                .insert(path.display().to_string(), value.to_string());
            Ok(())
        }

        fn exists(&self, path: &Path) -> bool {
            self.attrs
                .borrow()
                .contains_key(&path.display().to_string())
                || self.links.contains_key(&path.display().to_string())
        }

        fn read_link(&self, path: &Path) -> Result<PathBuf, String> {
            self.links
                .get(&path.display().to_string())
                .cloned()
                .ok_or_else(|| format!("no such link {}", path.display()))
        }

        fn list_dir(&self, _path: &Path) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn host_and_port_resolution_walk_the_device_chain() {
        let sysfs = ScriptedSysfs::with_device_chain();
        assert_eq!(resolve_scsi_host(&sysfs, "sda").unwrap(), "host3");
        assert_eq!(resolve_ata_port(&sysfs, "sda").unwrap(), "ata3");
    }

    #[test]
    fn ladder_cleared_after_lun_rescan() {
        // REG-COLDBUS-RESET-LADDER (clear case): delete+rescan clears the
        // lock on re-probe; the PM step must NOT run.
        let sysfs = ScriptedSysfs::with_device_chain();
        let mut rechecks = 0;
        let outcome = attempt_cold_unfreeze(&sysfs, "sda", || {
            rechecks += 1;
            Ok(false) // first re-probe already reports the lock cleared
        });
        match outcome {
            ColdBusOutcome::Cleared { steps } => {
                assert_eq!(steps.len(), 1);
                assert_eq!(steps[0].step, "lun-delete-host-rescan");
                assert!(steps[0].outcome.contains("freeze cleared"));
            }
            other => panic!("expected Cleared, got {:?}", other),
        }
        let writes = sysfs.written();
        assert_eq!(
            writes[0],
            ("/sys/block/sda/device/delete".to_string(), "1".to_string())
        );
        assert_eq!(
            writes[1],
            (
                "/sys/class/scsi_host/host3/scan".to_string(),
                "- - -".to_string()
            )
        );
    }

    #[test]
    fn ladder_still_frozen_walks_all_steps_and_advises() {
        // REG-COLDBUS-RESET-LADDER (fail case): the lock survives both
        // steps; the ladder must end with the manual advisory, never a
        // fabricated success.
        let sysfs = ScriptedSysfs::with_device_chain();
        sysfs.set("/sys/class/ata_port/ata3/power/runtime_status", "suspended");
        let outcome = attempt_cold_unfreeze(&sysfs, "sda", || Ok(true));
        match outcome {
            ColdBusOutcome::StillFrozen { steps, advisory } => {
                assert_eq!(steps.len(), 2);
                assert_eq!(steps[0].step, "lun-delete-host-rescan");
                assert_eq!(steps[1].step, "ata-port-runtime-pm-cycle");
                // PM cycle: auto -> (suspended observed) -> on.
                let pm_writes: Vec<_> = steps[1]
                    .sysfs_writes
                    .iter()
                    .filter(|(p, _)| p.ends_with("power/control"))
                    .collect();
                assert_eq!(pm_writes.len(), 2);
                assert_eq!(pm_writes[0].1, "auto");
                assert_eq!(pm_writes[1].1, "on");
                assert!(advisory.contains("Power-cycle"));
            }
            other => panic!("expected StillFrozen, got {:?}", other),
        }
    }

    #[test]
    fn pm_cycle_waits_for_actual_runtime_suspend() {
        // If the port never reaches 'suspended', the step records the
        // refusal and the ladder still re-probes (state ambiguous).
        let sysfs = ScriptedSysfs::with_device_chain();
        sysfs.set("/sys/class/ata_port/ata3/power/runtime_status", "active");
        let outcome = attempt_cold_unfreeze(&sysfs, "sda", || Ok(true));
        match outcome {
            ColdBusOutcome::StillFrozen { steps, advisory } => {
                assert!(steps[1].outcome.contains("did not reach runtime suspend"));
                assert!(advisory.contains("Power-cycle"));
            }
            other => panic!("expected StillFrozen, got {:?}", other),
        }
    }

    #[test]
    fn non_libata_chain_short_circuits_to_advisory() {
        let mut links = BTreeMap::new();
        links.insert(
            "/sys/block/sdz".to_string(),
            PathBuf::from("/sys/devices/virtual/block/sdz"),
        );
        let sysfs = ScriptedSysfs {
            attrs: RefCell::new(BTreeMap::new()),
            links,
            writes: RefCell::new(Vec::new()),
        };
        let outcome = attempt_cold_unfreeze(&sysfs, "sdz", || Ok(true));
        match outcome {
            ColdBusOutcome::StillFrozen { steps, advisory } => {
                assert!(steps[0].outcome.starts_with("SKIPPED:"));
                assert!(advisory.contains("Power-cycle"));
            }
            other => panic!("expected StillFrozen, got {:?}", other),
        }
    }
}
