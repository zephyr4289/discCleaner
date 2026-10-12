//! Thermal safety for sanitization media — the flash-cell guardian
//! (v0.7.0, Vector 2).
//!
//! Heavy multi-pass overwrites on 20TB+ enterprise drives generate
//! extreme controller and NAND heat. Above ~55 C, flash cells and
//! controller logic risk thermal throttling and write errors — silently
//! corrupted purge traffic is exactly what a defense certificate must
//! never paper over.
//!
//! THE GOVERNOR (transport-uniform):
//! - below `throttle_c` (default 55 C): full speed;
//! - `[throttle_c, critical_c)` (default 70 C): adaptive I/O pacing —
//!   the per-window sleep grows linearly with the overshoot;
//! - at/above `critical_c`: hard ABORT (media health over completion).
//!
//! THERMOMETERS:
//! - ATA/SAT: SMART READ DATA attribute 194 (Temperature_Celsius, raw
//!   first byte; attr 190 as fallback), read on the SAME SG_IO fd the
//!   purge client holds (no device contention);
//! - NVMe: Health Log 0x02 composite temperature (Kelvin - 273);
//! - SCSI/SAS: LOG SENSE page 0x0D (Temperature), parameter 0x0000;
//! - `dc execute` overwrite path: kernel hwmon
//!   (`/sys/class/nvme/*/hwmon*/temp1_input`,
//!   `/sys/class/scsi_disk/.../hwmon*/temp1_input` in millidegrees) —
//!   read-only, zero contention with the engine's block fd.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Governor thresholds; the defaults follow the flash-cell guidance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThermalLimits {
    /// C above which writes are paced (default 55).
    pub throttle_c: i32,
    /// C at which the run aborts to protect the media (default 70).
    pub critical_c: i32,
}

impl Default for ThermalLimits {
    fn default() -> Self {
        Self {
            throttle_c: 55,
            critical_c: 70,
        }
    }
}

/// Where a temperature reading came from (certificate provenance).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalSource {
    /// SMART READ DATA attr 194 (or 190 fallback), raw low byte, C.
    AtaSmartAttr194,
    /// NVMe SMART/Health log composite temperature.
    NvmeHealthLog,
    /// SCSI LOG SENSE page 0x0D parameter 0x0000.
    ScsiLogSense0d,
    /// Kernel hwmon temp1_input (millidegrees C).
    SysfsHwmon,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThermalReading {
    pub temperature_c: i32,
    pub source: ThermalSource,
}

impl ThermalReading {
    pub fn from_ata_smart(raw_c: i32) -> Self {
        Self {
            temperature_c: raw_c,
            source: ThermalSource::AtaSmartAttr194,
        }
    }

    pub fn from_nvme_kelvin(k: u16) -> Self {
        Self {
            temperature_c: k as i32 - 273,
            source: ThermalSource::NvmeHealthLog,
        }
    }

    pub fn from_scsi_c(raw_c: i32) -> Self {
        Self {
            temperature_c: raw_c,
            source: ThermalSource::ScsiLogSense0d,
        }
    }

    pub fn from_hwmon_millidegrees(md: i64) -> Self {
        Self {
            temperature_c: (md / 1000) as i32,
            source: ThermalSource::SysfsHwmon,
        }
    }
}

/// What the governor wants the I/O loop to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThermalDecision {
    /// Continue at full speed.
    Continue,
    /// Sleep this long before the next window.
    Pace(Duration),
    /// Abort: media health takes precedence over completion.
    Abort { temperature_c: i32, limit_c: i32 },
}

/// The decision core — pure, unit-testable.
#[derive(Clone, Debug, Default)]
pub struct ThermalGovernor {
    pub limits: ThermalLimits,
}

impl ThermalGovernor {
    pub fn with_limits(limits: ThermalLimits) -> Self {
        Self { limits }
    }

    /// Evaluate one temperature sample.
    ///
    /// Pacing model: at `throttle_c` the delay is zero; each degree of
    /// overshoot adds 250 ms per window up to a 2 s ceiling — enough to
    /// let the controller cool between bursts without stalling a 24 h
    /// security-erase into the week.
    pub fn evaluate(&self, reading: &ThermalReading) -> ThermalDecision {
        let t = reading.temperature_c;
        if t >= self.limits.critical_c {
            return ThermalDecision::Abort {
                temperature_c: t,
                limit_c: self.limits.critical_c,
            };
        }
        if t >= self.limits.throttle_c {
            let overshoot = (t - self.limits.throttle_c) as u64;
            let delay_ms = (overshoot * 250).min(2_000);
            return ThermalDecision::Pace(Duration::from_millis(delay_ms));
        }
        ThermalDecision::Continue
    }
}

/// Kernel-hwmon thermometer for the `dc execute` overwrite path:
/// discovers a read-only temperature attribute for a block device
/// WITHOUT touching its block fd (the engine holds it).
pub struct SysfsHwmonThermometer {
    /// Attribute paths discovered at construction (first one wins).
    pub sources: Vec<PathBuf>,
}

impl SysfsHwmonThermometer {
    /// Discover hwmon temperature sources for a block device:
    /// - NVMe namespace `nvme0n1` -> controller `nvme0` ->
    ///   `/sys/class/nvme/nvme0/hwmon*/temp1_input`;
    /// - SATA/SAS `sda` -> `/sys/class/scsi_disk/0:0:0:0/device/../hwmon*`
    ///   (the `drivetemp` driver), plus `/sys/class/block/sda/device/hwmon*`.
    pub fn discover(block_name: &str) -> Self {
        let mut sources = Vec::new();
        let nvme_ctrl = block_name
            .strip_prefix("nvme")
            .and_then(|rest| rest.rfind('n').map(|pos| &rest[..pos]))
            .map(|ctrl| format!("nvme{}", ctrl));
        if let Some(ctrl) = nvme_ctrl {
            for entry in glob_hwmon(&format!("/sys/class/nvme/{}", ctrl)) {
                let candidate = entry.join("temp1_input");
                if candidate.exists() {
                    sources.push(candidate);
                }
            }
        }
        // drivetemp for SATA/SAS via scsi_disk enumeration.
        if let Ok(hosts) = std::fs::read_dir("/sys/class/scsi_disk") {
            let mut disks: Vec<String> = hosts
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            disks.sort();
            for disk in disks {
                for entry in glob_hwmon(&format!("/sys/class/scsi_disk/{}/device", disk)) {
                    let candidate = entry.join("temp1_input");
                    if candidate.exists() {
                        sources.push(candidate);
                    }
                }
            }
        }
        // Generic per-block fallback.
        for entry in glob_hwmon(&format!("/sys/block/{}", block_name)) {
            let candidate = entry.join("temp1_input");
            if candidate.exists() {
                sources.push(candidate);
            }
        }
        for entry in glob_hwmon(&format!("/sys/block/{}/device", block_name)) {
            let candidate = entry.join("temp1_input");
            if candidate.exists() {
                sources.push(candidate);
            }
        }
        Self { sources }
    }

    /// Read the temperature (first readable source). Millidegrees in
    /// sysfs; absent/unreadable -> `None` (the governor goes inert, never
    /// fabricates a reading).
    pub fn read(&self) -> Option<ThermalReading> {
        for source in &self.sources {
            if let Ok(text) = std::fs::read_to_string(source) {
                if let Ok(milli) = text.trim().parse::<i64>() {
                    return Some(ThermalReading::from_hwmon_millidegrees(milli));
                }
            }
        }
        None
    }

    pub fn available(&self) -> bool {
        !self.sources.is_empty()
    }
}

fn glob_hwmon(dir: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("hwmon") {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    out
}

/// Parse SMART READ DATA for the temperature attribute (194 preferred,
/// 190 fallback). The raw low byte is the Celsius figure on the modern
/// attribute variants (the 16-bit min/max packed forms are vendor-legacy;
/// the low byte remains the current temperature in both).
pub fn decode_smart_temperature(raw: &[u8]) -> Result<ThermalReading, String> {
    if raw.len() < 512 {
        return Err("SMART READ DATA buffer must be 512 bytes".to_string());
    }
    let mut attr194: Option<i32> = None;
    let mut attr190: Option<i32> = None;
    for entry_idx in 0..30 {
        let base = 2 + entry_idx * 12; // attribute table starts at byte 2
        if base + 12 > 512 {
            break;
        }
        let id = raw[base];
        if id == 0x00 {
            break;
        }
        if id == 194 {
            attr194 = Some(raw[base + 5] as i32);
        } else if id == 190 {
            attr190 = Some(raw[base + 5] as i32);
        }
    }
    if let Some(t) = attr194 {
        return Ok(ThermalReading::from_ata_smart(t));
    }
    if let Some(t) = attr190 {
        return Ok(ThermalReading::from_ata_smart(t));
    }
    Err("SMART attribute 194/190 (temperature) not reported by this drive".to_string())
}

/// Decode SCSI LOG SENSE page 0x0D (Temperature) for parameter 0x0000.
/// The parameter value is the current temperature in Celsius (signed
/// byte per SBC-3, though drives above 127 C do not exist).
pub fn decode_log_sense_temperature(page: &[u8]) -> Result<ThermalReading, String> {
    if page.len() < 4 {
        return Err("LOG SENSE page too short".to_string());
    }
    if page[0] != 0x0D {
        return Err(format!(
            "expected LOG SENSE page 0x0D, got 0x{:02X}",
            page[0]
        ));
    }
    let page_len = u16::from_be_bytes([page[2], page[3]]) as usize;
    let body_end = (4 + page_len).min(page.len());
    let mut off = 4usize;
    while off + 4 <= body_end {
        let param_code = u16::from_be_bytes([page[off], page[off + 1]]);
        let param_len = page[off + 3] as usize;
        let value = page
            .get(off + 4..off + 4 + param_len)
            .ok_or("LOG SENSE parameter truncated")?;
        if param_code == 0x0000 {
            if let Some(&first) = value.first() {
                let c = first as i8 as i32;
                return Ok(ThermalReading::from_scsi_c(c));
            }
        }
        off += 4 + param_len;
    }
    Err("temperature parameter 0x0000 not present in page 0x0D".to_string())
}

/// Rate-limited thermal pacer for the overwrite engines: consulted from
/// the progress callback (per window), polls the thermometer at most once
/// per `poll_interval`, sleeps pacing delays, and surfaces aborts.
pub struct ThermalPacer {
    governor: ThermalGovernor,
    thermometer: SysfsHwmonThermometer,
    poll_interval: Duration,
    last_poll: Option<std::time::Instant>,
    /// Cumulative pacing time inserted (journal evidence).
    pub paced_ms_total: u64,
    /// Highest temperature observed.
    pub max_temperature_c: Option<i32>,
    /// Set when the governor aborted; the engine loop must stop.
    pub aborted: Option<(i32, i32)>,
}

impl ThermalPacer {
    pub fn new(limits: ThermalLimits, block_name: &str, poll_interval: Duration) -> Self {
        Self {
            governor: ThermalGovernor::with_limits(limits),
            thermometer: SysfsHwmonThermometer::discover(block_name),
            poll_interval,
            last_poll: None,
            paced_ms_total: 0,
            max_temperature_c: None,
            aborted: None,
        }
    }

    pub fn hwmon_available(&self) -> bool {
        self.thermometer.available()
    }

    /// Call once per window from the engine progress callback. Returns
    /// `false` when the run must abort (media-health critical).
    pub fn on_window_progress(&mut self) -> bool {
        if self.aborted.is_some() {
            return false;
        }
        // Rate-limit the (cheap but real) sysfs reads.
        let due = match self.last_poll {
            None => true,
            Some(last) => last.elapsed() >= self.poll_interval,
        };
        if !due {
            return true;
        }
        self.last_poll = Some(std::time::Instant::now());
        let Some(reading) = self.thermometer.read() else {
            return true; // inert, never fabricated
        };
        self.max_temperature_c = Some(
            self.max_temperature_c
                .map_or(reading.temperature_c, |m| m.max(reading.temperature_c)),
        );
        match self.governor.evaluate(&reading) {
            ThermalDecision::Continue => true,
            ThermalDecision::Pace(delay) => {
                self.paced_ms_total += delay.as_millis() as u64;
                std::thread::sleep(delay);
                true
            }
            ThermalDecision::Abort {
                temperature_c,
                limit_c,
            } => {
                self.aborted = Some((temperature_c, limit_c));
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governor_thresholds() {
        // REG-THERMAL-GOVERNOR: 54 C full speed, 58 C paced, 70+ C abort.
        let g = ThermalGovernor::default();
        assert_eq!(
            g.evaluate(&ThermalReading::from_ata_smart(54)),
            ThermalDecision::Continue
        );
        match g.evaluate(&ThermalReading::from_ata_smart(55)) {
            ThermalDecision::Pace(d) => assert_eq!(d, Duration::from_millis(0)),
            other => panic!("55 C must pace (0 ms), got {:?}", other),
        }
        match g.evaluate(&ThermalReading::from_ata_smart(58)) {
            ThermalDecision::Pace(d) => assert_eq!(d, Duration::from_millis(750)),
            other => panic!("58 C must pace 750 ms, got {:?}", other),
        }
        match g.evaluate(&ThermalReading::from_ata_smart(64)) {
            // Ceiling: max pacing 2 s even deep in the throttle band
            // ((64-55)*250 = 2250 -> capped).
            ThermalDecision::Pace(d) => assert_eq!(d, Duration::from_millis(2000)),
            other => panic!("64 C must pace at the 2 s ceiling, got {:?}", other),
        }
        assert_eq!(
            g.evaluate(&ThermalReading::from_ata_smart(90)),
            ThermalDecision::Abort {
                temperature_c: 90,
                limit_c: 70
            }
        );
        assert_eq!(
            g.evaluate(&ThermalReading::from_nvme_kelvin(343)), // 70 C
            ThermalDecision::Abort {
                temperature_c: 70,
                limit_c: 70
            }
        );
    }

    #[test]
    fn smart_temperature_decode_prefers_attr_194() {
        let mut raw = [0u8; 512];
        // Entry 0: attribute 194 (Temperature_Celsius), raw low byte 41 C.
        let base = 2;
        raw[base] = 194;
        raw[base + 5] = 41;
        // Entry 1: attribute 190 with a decoy 88 C.
        let base2 = 2 + 12;
        raw[base2] = 190;
        raw[base2 + 5] = 88;
        let reading = decode_smart_temperature(&raw).unwrap();
        assert_eq!(reading.temperature_c, 41);
        assert_eq!(reading.source, ThermalSource::AtaSmartAttr194);

        // 190 fallback when 194 is absent.
        raw[base] = 3; // some other attribute
        let reading = decode_smart_temperature(&raw).unwrap();
        assert_eq!(reading.temperature_c, 88);
    }

    #[test]
    fn log_sense_temperature_page_decode() {
        // Page 0x0D, len 0x000A, param 0x0000 len 1 value 0x2D (45 C).
        let mut page = vec![0x0D, 0x00, 0x00, 0x0A];
        page.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x2D]);
        // A second parameter (reference temperature 0x0001) to prove the
        // walk skips it.
        page.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x37]);
        let reading = decode_log_sense_temperature(&page).unwrap();
        assert_eq!(reading.temperature_c, 45);
        assert_eq!(reading.source, ThermalSource::ScsiLogSense0d);

        assert!(decode_log_sense_temperature(&[0x0B, 0, 0, 0]).is_err());
    }

    #[test]
    fn hwmon_thermometer_reads_millidegrees() {
        assert_eq!(
            ThermalReading::from_hwmon_millidegrees(52_312).temperature_c,
            52
        );
        // Discover on a machine without matching hwmon nodes: inert.
        let t = SysfsHwmonThermometer::discover("definitely-not-a-real-device");
        assert!(!t.available());
        assert!(t.read().is_none());
    }

    #[test]
    fn nvme_kelvin_conversion() {
        assert_eq!(ThermalReading::from_nvme_kelvin(318).temperature_c, 45);
    }
}
