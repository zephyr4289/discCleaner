//! Telemetry capture backends (v0.12.0, Miracle 2 — "The Pickup").
//!
//! The probe's mechanical ring is observed through whatever physics
//! the platform exposes from OUTSIDE the drive — the point is that
//! none of these channels can be influenced by drive FIRMWARE:
//!
//! * **IIO accelerometers** (`/sys/bus/iio/devices/iio:deviceN`,
//!   `in_accel_[xyz]_raw`): sampled in a tight timestamped loop.
//!   Enterprise boards (ADXL345-class and up) expose the chassis
//!   vibration the actuator excites.
//! * **hwmon channels** (`/sys/class/hwmon/hwmonN`): temperature,
//!   voltage and fan-tach resistance telemetry — slow (1–10 Hz) but
//!   an independent physical observer (regulator/load transients).
//! * **Replay captures** (`replay::CaptureReplay`): recorded channel
//!   data from a previous run — used for tests, forensic
//!   re-derivation and CI.
//!
//! Each backend reports its kind and effective sample rate; the
//! feature extractor adapts (frequency-domain features for kHz-class
//! channels, time-domain transient features for slow channels).

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Errors from the telemetry layer.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("I/O reading telemetry source: {0}")]
    Io(#[from] std::io::Error),
    #[error("no usable telemetry source found")]
    NoSource,
    #[error("malformed telemetry value: {0}")]
    Parse(String),
}

/// What physical channel a capture observed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryKind {
    /// 3-axis accelerometer (IIO) — chassis vibration.
    Accelerometer,
    /// Temperature channel (hwmon).
    Temperature,
    /// Voltage rail (hwmon).
    Voltage,
    /// Fan tachometer (hwmon).
    Fan,
    /// Recorded/replayed data.
    Replay,
}

/// One synchronized telemetry capture (multi-channel).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Capture {
    pub kind: TelemetryKind,
    /// Human-readable source id (e.g. "iio:device0", "hwmon3/temp1_input").
    pub source: String,
    /// Effective samples per second (per channel).
    pub sample_hz: f64,
    /// Channel names.
    pub channels: Vec<String>,
    /// Time series per channel (same length).
    pub series: Vec<Vec<f32>>,
    /// Nominal capture duration.
    pub duration_ms: u64,
}

/// A telemetry source that can record a synchronized capture.
pub trait TelemetrySource {
    fn kind(&self) -> TelemetryKind;
    fn describe(&self) -> String;
    /// Capture for `duration` (with per-sample timestamps dropped —
    /// uniform rate assumed and reported).
    fn capture(&mut self, duration: Duration) -> Result<Capture, TelemetryError>;
}

// ---------------------------------------------------------------------------
// IIO accelerometer backend
// ---------------------------------------------------------------------------

/// Polling IIO accelerometer source. Reads `in_accel_{x,y,z}_raw`
/// sysfs attributes in a tight loop with timestamps; typical effective
/// rate on sysfs: 1–8 kHz — spindle/actuator fundamentals and their
/// first harmonics live well inside this band.
pub struct IioAccel {
    device_dir: PathBuf,
    id: String,
}

/// Discover IIO accelerometer devices under `sysroot` (default `/sys`).
pub fn iio_accel(sysroot: &std::path::Path) -> Vec<IioAccel> {
    let mut out = Vec::new();
    let bus = sysroot.join("bus/iio/devices");
    let Ok(entries) = std::fs::read_dir(&bus) else {
        return out;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    for name in names {
        let dir = bus.join(&name);
        if dir.join("in_accel_x_raw").is_file() {
            out.push(IioAccel {
                device_dir: dir,
                id: name,
            });
        }
    }
    out
}

fn read_iio_int(path: &std::path::Path) -> Result<i32, TelemetryError> {
    let mut s = String::new();
    std::fs::File::open(path)?.read_to_string(&mut s)?;
    s.trim()
        .parse::<i32>()
        .map_err(|e| TelemetryError::Parse(format!("{path:?}: {e}")))
}

impl TelemetrySource for IioAccel {
    fn kind(&self) -> TelemetryKind {
        TelemetryKind::Accelerometer
    }

    fn describe(&self) -> String {
        format!("iio:{}", self.id)
    }

    fn capture(&mut self, duration: Duration) -> Result<Capture, TelemetryError> {
        let axes = ["x", "y", "z"];
        let mut paths = Vec::new();
        for a in axes {
            let p = self.device_dir.join(format!("in_accel_{a}_raw"));
            if p.is_file() {
                paths.push((a.to_string(), p));
            }
        }
        if paths.is_empty() {
            return Err(TelemetryError::NoSource);
        }
        let mut series: Vec<Vec<f32>> = vec![Vec::new(); paths.len()];
        let mut timestamps: Vec<Instant> = Vec::new();
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            for (i, (_, p)) in paths.iter().enumerate() {
                let v = read_iio_int(p)?;
                series[i].push(v as f32);
            }
            timestamps.push(Instant::now());
        }
        let n = timestamps.len().max(1) as f64;
        let hz = 1000.0 * n / duration.as_millis().max(1) as f64;
        Ok(Capture {
            kind: TelemetryKind::Accelerometer,
            source: self.describe(),
            sample_hz: hz,
            channels: paths.iter().map(|(a, _)| a.clone()).collect(),
            series,
            duration_ms: duration.as_millis() as u64,
        })
    }
}

// ---------------------------------------------------------------------------
// hwmon backend (temperature / voltage / fan)
// ---------------------------------------------------------------------------

/// One hwmon channel (slow physics observer).
pub struct HwmonChannel {
    pub source: String,
    pub kind: TelemetryKind,
    pub path: PathBuf,
}

/// Discover hwmon channels under `sysroot` (default `/sys`).
pub fn sysfs_hwmon(sysroot: &std::path::Path) -> Vec<HwmonChannel> {
    let mut out = Vec::new();
    let class = sysroot.join("class/hwmon");
    let Ok(entries) = std::fs::read_dir(&class) else {
        return out;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    for hw in names {
        let dir = class.join(&hw);
        let Ok(files) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut attrs: Vec<String> = files
            .flatten()
            .map(|f| f.file_name().to_string_lossy().to_string())
            .collect();
        attrs.sort();
        for a in attrs {
            let kind = if a.starts_with("temp") && a.ends_with("_input") {
                TelemetryKind::Temperature
            } else if a.starts_with("in") && a.ends_with("_input") {
                TelemetryKind::Voltage
            } else if a.starts_with("fan") && a.ends_with("_input") {
                TelemetryKind::Fan
            } else {
                continue;
            };
            out.push(HwmonChannel {
                source: format!("{hw}/{a}"),
                kind,
                path: dir.join(&a),
            });
        }
    }
    out
}

fn read_hwmon_value(path: &std::path::Path) -> Result<f32, TelemetryError> {
    let mut s = String::new();
    std::fs::File::open(path)?.read_to_string(&mut s)?;
    s.trim()
        .parse::<f32>()
        .map_err(|e| TelemetryError::Parse(format!("{path:?}: {e}")))
}

impl TelemetrySource for HwmonChannel {
    fn kind(&self) -> TelemetryKind {
        self.kind
    }

    fn describe(&self) -> String {
        format!("hwmon:{}", self.source)
    }

    fn capture(&mut self, duration: Duration) -> Result<Capture, TelemetryError> {
        // hwmon updates at ~1–10 Hz: poll at 20 Hz to be safe and
        // record the effective count.
        let mut series = Vec::new();
        let started = Instant::now();
        while started.elapsed() < duration {
            series.push(read_hwmon_value(&self.path)?);
            std::thread::sleep(Duration::from_millis(50));
        }
        let hz = series.len() as f64 / duration.as_secs_f64().max(1e-9);
        Ok(Capture {
            kind: self.kind,
            source: self.describe(),
            sample_hz: hz,
            channels: vec!["value".to_string()],
            series: vec![series],
            duration_ms: duration.as_millis() as u64,
        })
    }
}

// ---------------------------------------------------------------------------
// Replay backend
// ---------------------------------------------------------------------------

/// Replays a previously recorded capture — used by tests, CI and
/// forensic re-derivation of fingerprints from archived evidence.
pub mod replay {
    use super::*;

    pub struct CaptureReplay {
        pub capture: Capture,
    }

    impl TelemetrySource for CaptureReplay {
        fn kind(&self) -> TelemetryKind {
            TelemetryKind::Replay
        }

        fn describe(&self) -> String {
            format!("replay:{}", self.capture.source)
        }

        fn capture(&mut self, _duration: Duration) -> Result<Capture, TelemetryError> {
            Ok(self.capture.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iio_discovery_on_missing_sysfs() {
        // A path with no iio bus simply yields zero sources — the
        // caller degrades to other channels (documented behavior).
        let sources = iio_accel(std::path::Path::new("/nonexistent"));
        assert!(sources.is_empty());
        let hw = sysfs_hwmon(std::path::Path::new("/nonexistent"));
        assert!(hw.is_empty());
    }

    #[test]
    fn replay_roundtrip() {
        let cap = Capture {
            kind: TelemetryKind::Accelerometer,
            source: "iio:device0".into(),
            sample_hz: 1000.0,
            channels: vec!["x".into()],
            series: vec![(0..256).map(|i| (i as f32 * 0.1).sin()).collect()],
            duration_ms: 256,
        };
        let mut replay = replay::CaptureReplay {
            capture: cap.clone(),
        };
        let got = replay.capture(Duration::from_millis(1)).unwrap();
        assert_eq!(got, cap);
        assert_eq!(replay.describe(), "replay:iio:device0");
    }
}
