//! T26 — COLD-BUS FREEZE REMEDIATION & THERMAL SAFETY MATRIX (v0.7.0,
//! Vector 2).
//!
//! - The sysfs cold-unfreeze ladder (LUN delete + host rescan, ATA-port
//!   runtime-PM cycle, manual advisory) over a scripted sysfs.
//! - The thermal governor thresholds and the three thermometers (SMART
//!   attr 194/190 via the SAT purge client, SCSI LOG SENSE 0x0D via the
//!   SCSI purge client, kernel hwmon millidegrees).
//! - The CLI surfaces: --cold-unfreeze / --thermal-* flags.

use dc_ata::coldbus::{ColdBusOutcome, SysfsOps, attempt_cold_unfreeze};
use dc_ata::purge::{AtaPurgeClient, SatPurgeTransport, SatReply, SatXfer};
use dc_hw::thermal::{
    ThermalDecision, ThermalGovernor, ThermalLimits, ThermalReading, ThermalSource,
    decode_log_sense_temperature, decode_smart_temperature,
};
use dc_scsi::purge::{ScsiPurgeClient, ScsiPurgeTransport, ScsiReply, ScsiXfer};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Scripted sysfs (mirrors the dc-ata unit rig at integration level).
// ---------------------------------------------------------------------------

struct ScriptedSysfs {
    attrs: RefCell<BTreeMap<String, String>>,
    links: BTreeMap<String, PathBuf>,
    writes: RefCell<Vec<(String, String)>>,
}

impl ScriptedSysfs {
    fn new() -> Self {
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
        self.attrs
            .borrow_mut()
            .insert(path.display().to_string(), value.to_string());
        Ok(())
    }

    fn exists(&self, _path: &Path) -> bool {
        true
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

// ---------------------------------------------------------------------------
// Scripted SAT transport that answers SMART READ DATA with a temperature
// table and READ LOG EXT with Device Statistics pages.
// ---------------------------------------------------------------------------

struct ThermalSat {
    smart_temp_c: u8,
    devstat_pages: Vec<u8>,
    seen: RefCell<Vec<[u8; 16]>>,
}

impl SatPurgeTransport for ThermalSat {
    fn issue(&mut self, cdb: &[u8; 16], x: SatXfer, _t: u32) -> Result<SatReply, String> {
        self.seen.borrow_mut().push(*cdb);
        match (cdb[14], cdb[4]) {
            // IDENTIFY DEVICE (0xEC)
            (0xEC, _) => {
                let raw = vec![0u8; 512];
                // word 128 (security): frozen bit is what we vary per test.
                Ok(SatReply {
                    status: 0x00,
                    sense: Vec::new(),
                    data_in: raw,
                })
            }
            // SMART READ DATA (0xB0/0xD0)
            (0xB0, 0xD0) => {
                let mut raw = vec![0u8; 512];
                raw[2] = 194; // attribute 194 = Temperature_Celsius
                raw[2 + 5] = self.smart_temp_c;
                Ok(SatReply {
                    status: 0x00,
                    sense: Vec::new(),
                    data_in: raw,
                })
            }
            // SMART READ LOG / READ LOG EXT (log 0x04 pages)
            (0x2F, _) | (0xB0, 0xD5) => {
                let _ = x;
                Ok(SatReply {
                    status: 0x00,
                    sense: Vec::new(),
                    data_in: self.devstat_pages.clone(),
                })
            }
            _ => Ok(SatReply::good()),
        }
    }
}

struct ThermalScsi;

impl ScsiPurgeTransport for ThermalScsi {
    fn issue(&mut self, cdb: &[u8], _x: ScsiXfer, _t: u32) -> Result<ScsiReply, String> {
        match cdb[0] {
            0x12 => {
                // INQUIRY: SEAGATE ST1200MM0123 rev 0004.
                let mut raw = vec![0u8; 36];
                raw[0] = 0x00;
                raw[8..16].copy_from_slice(b"SEAGATE ");
                raw[16..32].copy_from_slice(b" ST1200MM0123   ");
                raw[32..36].copy_from_slice(b"0004");
                Ok(ScsiReply {
                    status: 0x00,
                    sense: Vec::new(),
                    data_in: raw,
                })
            }
            0x4D => {
                // LOG SENSE page 0x0D: current temp 44 C + reference 50 C.
                let mut page = vec![0x0D, 0x00, 0x00, 0x0C];
                page.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 44]);
                page.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 50]);
                Ok(ScsiReply {
                    status: 0x00,
                    sense: Vec::new(),
                    data_in: page,
                })
            }
            _ => Ok(ScsiReply {
                status: 0x00,
                sense: Vec::new(),
                data_in: Vec::new(),
            }),
        }
    }
}

fn devstat_page4_fixture() -> Vec<u8> {
    let mut page = vec![0u8; 512];
    page[0..2].copy_from_slice(&0x04u16.to_le_bytes());
    page[4..8].copy_from_slice(&1u32.to_le_bytes());
    page[8..10].copy_from_slice(&0x0001u16.to_le_bytes());
    page[10] = 0x10;
    page[12] = 23; // 23% endurance used
    page
}

#[test]
fn test_t26_coldbus_thermal_matrix() {
    println!("\n[>>> T26 COLD-BUS & THERMAL MATRIX <<<]");

    coldbus_ladder_cells();
    thermal_governor_cells();
    ata_thermometer_and_devstat_cells();
    scsi_thermometer_and_inquiry_cells();

    println!("\n[=== T26 COLD-BUS & THERMAL MATRIX PASSED ALL CELLS ===]\n");
}

fn coldbus_ladder_cells() {
    println!("\n[>> T26-COLDBUS: sysfs reset ladder <<]");

    // Cell 1: lock survives both steps -> advisory, never a fake success.
    let sysfs = ScriptedSysfs::new();
    sysfs.set("/sys/class/ata_port/ata3/power/runtime_status", "suspended");
    match attempt_cold_unfreeze(&sysfs, "sda", || Ok(true)) {
        ColdBusOutcome::StillFrozen { steps, advisory } => {
            assert_eq!(steps.len(), 2);
            assert!(
                steps[0]
                    .sysfs_writes
                    .iter()
                    .any(|(p, v)| p.ends_with("/device/delete") && v == "1")
            );
            assert!(
                steps[0]
                    .sysfs_writes
                    .iter()
                    .any(|(p, v)| p.ends_with("host3/scan") && v == "- - -")
            );
            assert!(
                steps[1]
                    .sysfs_writes
                    .iter()
                    .any(|(p, v)| p.ends_with("power/control") && v == "auto")
            );
            assert!(
                steps[1]
                    .sysfs_writes
                    .iter()
                    .any(|(p, v)| p.ends_with("power/control") && v == "on")
            );
            assert!(advisory.contains("Power-cycle"));
        }
        other => panic!("expected StillFrozen, got {:?}", other),
    }

    // Cell 2: cleared on the first re-probe (LUN delete + rescan alone).
    let sysfs = ScriptedSysfs::new();
    match attempt_cold_unfreeze(&sysfs, "sda", || Ok(false)) {
        ColdBusOutcome::Cleared { steps } => {
            assert_eq!(steps.len(), 1);
            assert!(steps[0].outcome.contains("freeze cleared"));
        }
        other => panic!("expected Cleared, got {:?}", other),
    }

    // Cell 3: port never reaches runtime suspend -> recorded refusal, the
    // ladder still re-probes and closes honestly.
    let sysfs = ScriptedSysfs::new();
    sysfs.set("/sys/class/ata_port/ata3/power/runtime_status", "active");
    match attempt_cold_unfreeze(&sysfs, "sda", || Ok(true)) {
        ColdBusOutcome::StillFrozen { steps, .. } => {
            assert!(steps[1].outcome.contains("did not reach runtime suspend"));
        }
        other => panic!("expected StillFrozen, got {:?}", other),
    }

    // Cell 4: recheck that cannot reopen the device (renumbered node) is
    // disclosed, not ignored.
    let sysfs = ScriptedSysfs::new();
    match attempt_cold_unfreeze(&sysfs, "sda", || Err("node vanished".to_string())) {
        ColdBusOutcome::StillFrozen { steps, advisory } => {
            assert!(steps[0].outcome.contains("RECHECK_UNRESOLVED"));
            assert!(advisory.contains("Power-cycle"));
        }
        other => panic!("expected StillFrozen, got {:?}", other),
    }

    println!("    [PASS] ladder cells: survive/clear/no-suspend/renumber");
}

fn thermal_governor_cells() {
    println!("\n[>> T26-GOV: thermal governor thresholds <<]");

    let g = ThermalGovernor::default();
    assert_eq!(
        g.evaluate(&ThermalReading::from_ata_smart(40)),
        ThermalDecision::Continue
    );
    match g.evaluate(&ThermalReading::from_ata_smart(60)) {
        ThermalDecision::Pace(d) => assert_eq!(d, Duration::from_millis(1250)),
        other => panic!("60 C must pace 1250 ms, got {:?}", other),
    }
    assert_eq!(
        g.evaluate(&ThermalReading::from_ata_smart(70)),
        ThermalDecision::Abort {
            temperature_c: 70,
            limit_c: 70
        }
    );

    // Operator-tuned limits are honored end to end.
    let hot = ThermalGovernor::with_limits(ThermalLimits {
        throttle_c: 45,
        critical_c: 50,
    });
    assert_eq!(
        hot.evaluate(&ThermalReading::from_nvme_kelvin(318)), // 45 C
        ThermalDecision::Pace(Duration::from_millis(0))
    );
    assert!(matches!(
        hot.evaluate(&ThermalReading::from_hwmon_millidegrees(49_999)),
        ThermalDecision::Pace(_)
    ));

    println!("    [PASS] 55/70 defaults + tuned limits");
}

fn ata_thermometer_and_devstat_cells() {
    println!("\n[>> T26-ATA: SMART 194 + Device Statistics probes <<]");

    // SMART temperature through the real purge client framing.
    let mut sat = ThermalSat {
        smart_temp_c: 47,
        devstat_pages: devstat_page4_fixture(),
        seen: RefCell::new(Vec::new()),
    };
    let reading = AtaPurgeClient::new(&mut sat).read_temperature().unwrap();
    assert_eq!(reading.temperature_c, 47);
    assert_eq!(reading.source, ThermalSource::AtaSmartAttr194);

    // The CDB that reached the transport: SMART READ DATA key bytes.
    let seen = sat.seen.borrow();
    assert_eq!(seen[0][14], 0xB0);
    assert_eq!(seen[0][4], 0xD0);
    drop(seen);

    // Device Statistics page 0x04 through READ LOG EXT framing.
    let (page, raw) = AtaPurgeClient::new(&mut sat)
        .read_device_statistics(0x04)
        .unwrap();
    assert_eq!(page.percentage_used_endurance(), Some(23));
    assert_eq!(raw.len(), 512);
    let seen = sat.seen.borrow();
    // READ LOG EXT: opcode 0x2F in the ATA command byte, log|page in LBA.
    let read_log_cdb = seen
        .iter()
        .find(|c| c[14] == 0x2F)
        .expect("READ LOG EXT must be issued");
    let lba = ((read_log_cdb[11] as u64) << 40)
        | ((read_log_cdb[9] as u64) << 32)
        | ((read_log_cdb[7] as u64) << 24)
        | ((read_log_cdb[12] as u64) << 16)
        | ((read_log_cdb[10] as u64) << 8)
        | read_log_cdb[8] as u64;
    assert_eq!(lba, 0x04 | (0x04 << 8), "log 0x04 page 4 in the LBA field");

    // 190 fallback when 194 is absent.
    let mut raw = vec![0u8; 512];
    raw[2] = 190;
    raw[2 + 5] = 39;
    let reading = decode_smart_temperature(&raw).unwrap();
    assert_eq!(reading.temperature_c, 39);

    println!("    [PASS] SMART 194/190 + READ LOG EXT devstat");
}

fn scsi_thermometer_and_inquiry_cells() {
    println!("\n[>> T26-SCSI: LOG SENSE 0x0D + INQUIRY identity <<]");

    let mut scsi = ThermalScsi;
    let reading = ScsiPurgeClient::new(&mut scsi).read_temperature().unwrap();
    assert_eq!(reading.temperature_c, 44);
    assert_eq!(reading.source, ThermalSource::ScsiLogSense0d);

    let identity = ScsiPurgeClient::new(&mut scsi).identify().unwrap();
    assert_eq!(identity.vendor, "SEAGATE");
    assert_eq!(identity.product, "ST1200MM0123");
    assert_eq!(identity.revision, "0004");

    // LOG SENSE decode: reference parameter (0x0001) is skipped, current
    // temperature (0x0000) is selected.
    let mut page = vec![0x0D, 0x00, 0x00, 0x0C];
    page.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 50]); // reference first
    page.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 41]); // current second
    let reading = decode_log_sense_temperature(&page).unwrap();
    assert_eq!(reading.temperature_c, 41);

    println!("    [PASS] SAS thermal + firmware identity");
}
