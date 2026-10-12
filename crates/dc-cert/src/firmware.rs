//! Firmware attestation & vendor telemetry evidence (v0.7.0, Vector 4).
//!
//! Hostile or firmware-compromised SSDs can maintain shadow firmware
//! blocks or hidden controller state; a certificate that only names the
//! model and serial cannot prove WHICH firmware sanitized the media.
//! This module carries the deep controller forensics into the signed
//! evidence package:
//!
//! - NVMe Telemetry Host-Initiated Log (LID 0x07) snapshots — reason
//!   identifier + generation counter before/after the purge.
//! - ATA Device Statistics Log (GP Log 0x04) — raw SSD wear indicators
//!   (percentage-used endurance, logical sectors written/read) with
//!   before/after deltas that must MOVE when media was really rewritten.
//! - Firmware identity (revision + PCIe subsystem IDs for NVMe, IDENTIFY
//!   words 23-26 firmware string for ATA, SCSI INQUIRY revision for SAS)
//!   captured pre AND post — a revision that CHANGED mid-run is disclosed
//!   as a defense warning (the drive ran unapproved firmware at some
//!   point of the sanitization window).

use serde::{Deserialize, Serialize};

/// One raw vendor-telemetry snapshot (bytes + provenance).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Provenance label, e.g. "nvme-telemetry-host-0x07-pre".
    pub label: String,
    /// BLAKE3 of the raw log bytes (the full bytes ride as a PDF/A-3
    /// attachment named after this label).
    pub blake3_hex: String,
    /// Captured byte length.
    pub len_bytes: u64,
}

/// NVMe Telemetry Host-Initiated log (LID 0x07) decoded header fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeTelemetryEvidence {
    /// ASCII reason identifier of the snapshot (bytes 8..24 of the log).
    pub reason_identifier: String,
    /// Generation counter (byte 1) — increments per telemetry creation.
    pub generation: u8,
    /// Telemetry data-area support bits (byte 0).
    pub data_areas_supported: u8,
    /// Last block of Data Area 1 (offset 509..512, 24-bit LE).
    pub area1_last_block: u32,
    /// Last block of Data Area 2 (offset 512..515, 24-bit LE).
    pub area2_last_block: u32,
    /// Last block of Data Area 3 (offset 515..518, 24-bit LE).
    pub area3_last_block: u32,
}

/// ATA Device Statistics (GP Log 0x04) decoded wear entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaDeviceStatisticsEvidence {
    /// "Percentage Used Endurance Indicator" (page 0x04, entry 0x0001,
    /// 1 byte) — the SSD wear figure smartctl surfaces.
    pub percentage_used_endurance: Option<u8>,
    /// Logical Sectors Written (page 0x00 entry 0x0004, 6-byte counter).
    pub logical_sectors_written: Option<u64>,
    /// Number of Write Commands (page 0x00 entry 0x0005).
    pub write_commands: Option<u64>,
    /// Logical Sectors Read (page 0x00 entry 0x0006).
    pub logical_sectors_read: Option<u64>,
    /// Number of Read Commands (page 0x00 entry 0x0007).
    pub read_commands: Option<u64>,
    /// Power-on Hours (page 0x00 entry 0x0002).
    pub power_on_hours: Option<u64>,
    /// True when the drive publishes the Solid State Device Statistics
    /// page at all (page 0x04 present in the page directory).
    pub ssd_statistics_page_present: bool,
}

impl AtaDeviceStatisticsEvidence {
    /// Deltas between a pre and post snapshot that MUST move when media
    /// was actually rewritten by the host or the controller.
    pub fn delta_against(&self, post: &Self) -> AtaDeviceStatisticsDelta {
        AtaDeviceStatisticsDelta {
            logical_sectors_written: delta_opt(
                self.logical_sectors_written,
                post.logical_sectors_written,
            ),
            write_commands: delta_opt(self.write_commands, post.write_commands),
            logical_sectors_read: delta_opt(self.logical_sectors_read, post.logical_sectors_read),
            percentage_endurance_growth: match (
                self.percentage_used_endurance,
                post.percentage_used_endurance,
            ) {
                (Some(a), Some(b)) if b >= a => Some((b - a) as u64),
                _ => None,
            },
        }
    }
}

fn delta_opt(pre: Option<u64>, post: Option<u64>) -> Option<u64> {
    match (pre, post) {
        (Some(a), Some(b)) if b >= a => Some(b - a),
        _ => None,
    }
}

/// Signed counters moved during the sanitization window.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaDeviceStatisticsDelta {
    pub logical_sectors_written: Option<u64>,
    pub write_commands: Option<u64>,
    pub logical_sectors_read: Option<u64>,
    pub percentage_endurance_growth: Option<u64>,
}

/// One transport firmware identity captured at a point in time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareIdentity {
    /// Bus label ("nvme" | "ata" | "scsi").
    pub bus: String,
    /// Drive model string.
    pub model: String,
    /// Drive serial.
    pub serial: String,
    /// Firmware revision exactly as the controller reported it
    /// (NVMe Identify FR / ATA IDENTIFY words 23-26 / SCSI INQUIRY rev).
    pub firmware_revision: String,
    /// PCIe subsystem vendor ID (NVMe Identify SSVID), hex, when known.
    pub subsystem_vendor: Option<String>,
    /// PCIe subsystem device ID (NVMe Identify), hex, when known.
    pub subsystem_device: Option<String>,
}

/// The full Vector-4 evidence block embedded into Purge certificates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareAttestationEvidence {
    /// Firmware identity captured BEFORE the purge ran.
    pub pre: FirmwareIdentity,
    /// Firmware identity captured AFTER the purge ran.
    pub post: FirmwareIdentity,
    /// NVMe Telemetry (0x07) decoded headers, pre and post.
    pub nvme_telemetry_pre: Option<NvmeTelemetryEvidence>,
    pub nvme_telemetry_post: Option<NvmeTelemetryEvidence>,
    /// ATA Device Statistics wear snapshots, pre and post.
    pub ata_devstat_pre: Option<AtaDeviceStatisticsEvidence>,
    pub ata_devstat_post: Option<AtaDeviceStatisticsEvidence>,
    /// Raw snapshot digests (telemetry/devstat/log bytes as captured).
    pub raw_snapshots: Vec<TelemetrySnapshot>,
}

impl FirmwareAttestationEvidence {
    /// Defense warnings derived from the pre/post comparison:
    /// - firmware revision changed inside the sanitization window;
    /// - SSD wear did not move although a host-written purge ran.
    pub fn defense_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.pre.firmware_revision != self.post.firmware_revision {
            warnings.push(format!(
                "DEFENSE_WARNING: drive firmware revision changed during the sanitization \
                 window ('{}' -> '{}'); the media may have been serviced by an unapproved \
                 firmware image. Physical destruction recommended per NIST SP 800-88 Rev 1.",
                self.pre.firmware_revision, self.post.firmware_revision
            ));
        }
        if let (Some(pre), Some(post)) = (&self.ata_devstat_pre, &self.ata_devstat_post) {
            let delta = pre.delta_against(post);
            if let (Some(sectors), Some(cmds)) =
                (delta.logical_sectors_written, delta.write_commands)
            {
                // Zeros logical sectors written with zero write commands
                // while a host-written mechanism claims to have run.
                if sectors == 0 && cmds == 0 {
                    warnings.push(
                        "DEFENSE_WARNING: Device Statistics counters show ZERO host writes \
                         during the sanitization window while a write-based mechanism was \
                         certified; controller counter suppression suspected — treat the \
                         media as untrusted (NIST SP 800-88 Rev 1)."
                            .to_string(),
                    );
                }
            }
        }
        warnings
    }

    /// Certificate field lines (visual PDF front page).
    pub fn field_lines(&self) -> Vec<(String, String)> {
        let mut fields = vec![
            (
                "Firmware revision (pre)".to_string(),
                self.pre.firmware_revision.clone(),
            ),
            (
                "Firmware revision (post)".to_string(),
                self.post.firmware_revision.clone(),
            ),
        ];
        if let Some(sub) = &self.pre.subsystem_vendor {
            fields.push((
                "PCIe subsystem".to_string(),
                format!(
                    "{}:{}",
                    sub,
                    self.pre
                        .subsystem_device
                        .clone()
                        .unwrap_or_else(|| "????".into())
                ),
            ));
        }
        if let Some(t) = &self.nvme_telemetry_pre {
            fields.push((
                "NVMe telemetry reason (pre)".to_string(),
                t.reason_identifier.clone(),
            ));
            fields.push((
                "NVMe telemetry generation".to_string(),
                format!("{} -> {}", t.generation, {
                    self.nvme_telemetry_post
                        .as_ref()
                        .map(|p| p.generation)
                        .unwrap_or(t.generation)
                }),
            ));
        }
        if let Some(d) = &self.ata_devstat_pre {
            if let Some(end) = d.percentage_used_endurance {
                let post_end = self
                    .ata_devstat_post
                    .as_ref()
                    .and_then(|p| p.percentage_used_endurance)
                    .unwrap_or(end);
                fields.push((
                    "SSD endurance used (pre -> post)".to_string(),
                    format!("{}% -> {}%", end, post_end),
                ));
            }
            if let Some(w) = d.logical_sectors_written {
                fields.push((
                    "Logical sectors written (pre)".to_string(),
                    format!("{}", w),
                ));
            }
        }
        fields
    }
}
