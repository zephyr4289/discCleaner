//! `dc purge` — controller-attested hardware purge, UNIVERSAL DISPATCH
//! (v0.6.0, REG-PURGE-UNIVERSAL-DISPATCH).
//!
//! One verb, three real transports:
//! - NVMe: admin ioctl ladder (Sanitize Crypto -> Sanitize Block ->
//!   Format NVM Crypto Erase) via the controller char device.
//! - SATA / SAT (incl. USB-SATA docks): SG_IO ATA PASS-THROUGH ladder
//!   (geometry restoration -> Sanitize Crypto Scramble -> Sanitize Block
//!   Erase -> Security Erase Enhanced -> Security Erase Normal) with
//!   random lifeline discipline (`dc-ata`).
//! - SAS / SCSI: SG_IO native ladder (SANITIZE Crypto Erase -> Block
//!   Erase -> FORMAT UNIT FMTDATA=0) with sense-progress polling
//!   (`dc-scsi`).
//!
//! Every ladder performs the NIST SP 800-88 "Purge" action by the
//! controller itself: crypto erases destroy the media encryption key in
//! seconds instead of hours of overwrite traffic.
//!
//! Fail-closed rules:
//! - Refuses buses with no controller purge transport (Virtio, loop,
//!   DM, file-backed) — never certifies a purge a firmware cannot do.
//! - Refuses when the controller attests no purge mechanism.
//! - Transport faults are fatal; only controller rejections walk the
//!   ladder down.
//! - A failed ATA security erase discloses the rescue lifeline (stderr +
//!   journal) so the drive is never left bricked.
//! - Every run ends with a signed certificate AND an ISO 19005-3
//!   (PDF/A-3) archival copy embedding the certificate and journal.

use crate::{PurgeArgs, chrono_now_iso, cli_signal_injection, signal_was_seen};
use dc_ata::coldbus::{ColdBusOutcome, ColdBusStepRecord};
use dc_ata::purge::{AtaPurgeClient, AtaPurgeMechanism, AtaPurgePermit, LinuxSatPurge};
use dc_cert::{
    AtaDeviceStatisticsEvidence, ExecutionDetails, FirmwareAttestationEvidence, FirmwareIdentity,
    HealthSnapshotEvidence, NvmeTelemetryEvidence, OperatorKeyPair, PurgeCertificateEvidence,
    PurgeFallbackRecord, SanitizationCertificate, TelemetrySnapshot,
};
use dc_core::{
    AuditLogger, AuditOutcome, AuditRecord, BusType, DcError, DeviceIdentity, EngineTuning,
    FsmOrchestrator, Mechanism, SanitizationPlan, StrategyCompiler, StrategyLadder, ToolBuild,
    VerifyLevel,
};
use dc_io::Engine as _;
use dc_nvme::NvmeAdminTransport;
use dc_nvme::purge::{NvmePurgeClient, PurgeMechanism};
use dc_nvme::{
    HealthSnapshot, LinuxNvmeAdmin, attest_capabilities, controller_char_dev_for,
    identify_controller, read_health,
};
use dc_probe::{Guardian, GuardianFlags, InventoryScanner};
use dc_scsi::purge::{LinuxScsiPurge, ScsiPurgeClient, ScsiPurgeMechanism, ScsiPurgePermit};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Compile the hardware purge ladder for a target, attesting capabilities
/// from the controller when possible. Returns None when the controller
/// transport cannot be read (no fabricated ladders).
pub fn compile_target_ladder(identity: &DeviceIdentity) -> Option<StrategyLadder> {
    match identity.stable.bus {
        BusType::Nvme => {
            let ctrl = controller_char_dev_for(Path::new(&identity.dev_path));
            let mut admin = LinuxNvmeAdmin::open(&ctrl).ok()?;
            let id = identify_controller(&mut admin).ok()?;
            let caps = attest_capabilities(&id);
            StrategyCompiler::compile_strategy(dc_core::DeviceTransportClass::Nvme, &caps, true)
                .ok()
        }
        BusType::Sata | BusType::Usb => {
            let mut sat = LinuxSatPurge::open(Path::new(&identity.dev_path)).ok()?;
            let id = AtaPurgeClient::new(&mut sat).identify().ok()?;
            let caps = dc_core::AttestedCapabilities {
                supports_sanitize_crypto: id.sanitize.crypto_scramble_supported,
                supports_sanitize_block: id.sanitize.block_erase_supported,
                supports_format_nvm: false,
                supports_ata_security_enhanced: id.security.enhanced_erase_supported,
                supports_dco_hpa: true,
                supports_scsi_sanitize: false,
            };
            StrategyCompiler::compile_strategy(dc_core::DeviceTransportClass::SataSsd, &caps, true)
                .ok()
        }
        BusType::Sas => {
            // SBC provides no non-destructive sanitize-capability query:
            // the conservative planning ladder is FORMAT UNIT (always legal
            // on format-capable media); SANITIZE mechanisms attest by
            // acceptance at execution time and the certificate records the
            // ladder that actually ran.
            let _scsi_open_check = LinuxScsiPurge::open(Path::new(&identity.dev_path)).ok()?;
            let caps = dc_core::AttestedCapabilities {
                supports_sanitize_crypto: false,
                supports_sanitize_block: false,
                supports_format_nvm: false,
                supports_ata_security_enhanced: false,
                supports_dco_hpa: false,
                supports_scsi_sanitize: false,
            };
            StrategyCompiler::compile_strategy(dc_core::DeviceTransportClass::ScsiSas, &caps, true)
                .ok()
        }
        _ => None,
    }
}

/// Unified mechanism request across the three transports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestedMechanism {
    Auto,
    /// Controller destroys the media encryption key (all buses).
    SanitizeCrypto,
    /// Electrical block erase (all buses).
    SanitizeBlock,
    /// NVMe Format NVM Crypto Erase.
    FormatCrypto,
    /// ATA Security Erase, enhanced (cryptographic pre-load invalidation).
    SecurityEraseEnhanced,
    /// ATA Security Erase, normal (firmware zero overwrite).
    SecurityEraseNormal,
    /// SCSI FORMAT UNIT (FMTDATA=0).
    FormatUnit,
}

fn parse_mechanism(spec: &str) -> Result<RequestedMechanism, DcError> {
    let m = match spec {
        "auto" => RequestedMechanism::Auto,
        "sanitize-crypto" => RequestedMechanism::SanitizeCrypto,
        "sanitize-block" => RequestedMechanism::SanitizeBlock,
        "format-crypto" => RequestedMechanism::FormatCrypto,
        "security-erase-enhanced" => RequestedMechanism::SecurityEraseEnhanced,
        "security-erase-normal" => RequestedMechanism::SecurityEraseNormal,
        "format-unit" => RequestedMechanism::FormatUnit,
        other => {
            return Err(DcError::Usage(format!(
                "unknown --mechananism '{}': expected auto | sanitize-crypto | sanitize-block | \
                 format-crypto | security-erase-enhanced | security-erase-normal | format-unit",
                other
            )));
        }
    };
    Ok(m)
}

impl RequestedMechanism {
    /// Validate the mechanism against a bus's transport menu (usage-class
    /// refusal on mismatch; library-public for regression guards).
    ///
    /// Buses WITHOUT a controller purge transport (loop, virtio, DM, MMC,
    /// file) pass here by design: their refusal is the fail-closed
    /// `PURGE_TRANSPORT_UNSUPPORTED` Guardian exit owned by the dispatch
    /// below (pinned end-to-end by t14 F6) — this gate only polices
    /// cross-bus mechanism mistakes on the capable buses.
    pub fn validate_for_bus(&self, bus: BusType) -> Result<(), DcError> {
        use RequestedMechanism::*;
        let ok = match bus {
            BusType::Nvme => matches!(self, Auto | SanitizeCrypto | SanitizeBlock | FormatCrypto),
            BusType::Sata | BusType::Usb => matches!(
                self,
                Auto | SanitizeCrypto | SanitizeBlock | SecurityEraseEnhanced | SecurityEraseNormal
            ),
            BusType::Sas => matches!(self, Auto | SanitizeCrypto | SanitizeBlock | FormatUnit),
            // Transport-less buses are refused at dispatch (exit 2),
            // not by the mechanism menu.
            _ => return Ok(()),
        };
        if ok {
            Ok(())
        } else {
            Err(DcError::Usage(format!(
                "--mechanism '{}' is not available on the {} bus (see `dc purge --help`)",
                self.cli_name(),
                bus
            )))
        }
    }

    fn cli_name(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::SanitizeCrypto => "sanitize-crypto",
            Self::SanitizeBlock => "sanitize-block",
            Self::FormatCrypto => "format-crypto",
            Self::SecurityEraseEnhanced => "security-erase-enhanced",
            Self::SecurityEraseNormal => "security-erase-normal",
            Self::FormatUnit => "format-unit",
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn health_evidence(h: &HealthSnapshot) -> HealthSnapshotEvidence {
    HealthSnapshotEvidence {
        critical_warning: h.critical_warning,
        temperature_celsius: h.temperature_celsius,
        available_spare_percent: h.available_spare_percent,
        percentage_used: h.percentage_used,
        media_errors: h.media_errors,
        power_cycles: h.power_cycles,
        power_on_hours: h.power_on_hours,
        data_units_written: h.data_units_written,
        captured_via: h.captured_via.clone(),
    }
}

/// Thermal limits from CLI flags (Vector 2).
fn thermal_limits_from_args(args: &PurgeArgs) -> dc_ata::ThermalLimits {
    let mut limits = dc_ata::ThermalLimits::default();
    if let Some(t) = args.thermal_throttle_c {
        limits.throttle_c = t;
    }
    if let Some(c) = args.thermal_critical_c {
        limits.critical_c = c;
    }
    limits
}

/// Live thermal monitor for controller-driven purges: reads the kernel
/// hwmon view (no fd contention with the SG_IO/admin transports), paces
/// between sanitize polls, and flags critical temperatures that must
/// block certification. Owned by the progress-sink closure.
struct PurgeThermalMonitor {
    governor: dc_ata::ThermalGovernor,
    thermometer: dc_ata::SysfsHwmonThermometer,
    pub max_temperature_c: Option<i32>,
    pub paced_ms: u64,
    pub critical: Option<(i32, i32)>,
}

impl PurgeThermalMonitor {
    fn new(limits: dc_ata::ThermalLimits, block_name: &str) -> Self {
        Self {
            governor: dc_ata::ThermalGovernor::with_limits(limits),
            thermometer: dc_ata::SysfsHwmonThermometer::discover(block_name),
            max_temperature_c: None,
            paced_ms: 0,
            critical: None,
        }
    }

    fn on_poll(&mut self) {
        let Some(reading) = self.thermometer.read() else {
            return; // inert when the kernel exposes no temperature
        };
        self.max_temperature_c = Some(
            self.max_temperature_c
                .map_or(reading.temperature_c, |m| m.max(reading.temperature_c)),
        );
        match self.governor.evaluate(&reading) {
            dc_ata::ThermalDecision::Continue => {}
            dc_ata::ThermalDecision::Pace(delay) => {
                self.paced_ms += delay.as_millis() as u64;
                std::thread::sleep(delay);
            }
            dc_ata::ThermalDecision::Abort {
                temperature_c,
                limit_c,
            } => {
                self.critical = Some((temperature_c, limit_c));
            }
        }
    }

    fn report(&self) -> Option<String> {
        self.max_temperature_c.map(|max| {
            if let Some((t, limit)) = self.critical {
                format!(
                    "CRITICAL {} C (limit {} C) — certification refused",
                    t, limit
                )
            } else if self.paced_ms > 0 {
                format!("max {} C, throttled {} ms", max, self.paced_ms)
            } else {
                format!("max {} C", max)
            }
        })
    }
}

/// Deep controller forensics captured around a purge (Vector 4):
/// firmware identity pre/post + transport-specific telemetry snapshots.
struct TransportForensics {
    identity: FirmwareIdentity,
    telemetry: Option<NvmeTelemetryEvidence>,
    telemetry_raw: Vec<u8>,
    devstat: Option<AtaDeviceStatisticsEvidence>,
    devstat_raw: Vec<u8>,
}

impl TransportForensics {
    /// NVMe: Identify Controller (FR + SSVID/SSVID product identity) and
    /// the Telemetry Host-Initiated log (LID 0x07) snapshot.
    fn capture_nvme(
        admin: &mut LinuxNvmeAdmin,
        id: &dc_hw::NvmeIdentifyController,
    ) -> Result<Self, String> {
        let identity = FirmwareIdentity {
            bus: "nvme".to_string(),
            model: id.mn.clone(),
            serial: id.sn.clone(),
            firmware_revision: id.fr.clone(),
            subsystem_vendor: Some(format!("{:04x}", id.ssvid)),
            subsystem_device: None,
        };
        let mut telemetry = None;
        let mut telemetry_raw = Vec::new();
        // Create a fresh host-initiated snapshot (LSP bit 0) and read the
        // 512-byte header.
        let cmd = dc_hw::NvmeCodec::encode_get_telemetry_log(true);
        if let Ok(raw) = admin.admin_passthrough(&cmd)
            && let Ok(header) = dc_hw::NvmeCodec::decode_telemetry_header(&raw)
        {
            telemetry = Some(NvmeTelemetryEvidence {
                reason_identifier: header.reason_identifier.clone(),
                generation: header.generation,
                data_areas_supported: header.data_areas_supported,
                area1_last_block: header.area1_last_block,
                area2_last_block: header.area2_last_block,
                area3_last_block: header.area3_last_block,
            });
            telemetry_raw = raw;
        }
        Ok(Self {
            identity,
            telemetry,
            telemetry_raw,
            devstat: None,
            devstat_raw: Vec::new(),
        })
    }

    /// ATA/SAT: IDENTIFY firmware string + Device Statistics pages 0x00
    /// (General) and 0x04 (Solid State Device Statistics).
    fn capture_ata(sat: &mut LinuxSatPurge) -> Result<Self, String> {
        let id = AtaPurgeClient::new(sat).identify()?;
        let identity = FirmwareIdentity {
            bus: "ata".to_string(),
            model: id.model.clone(),
            serial: id.serial.clone(),
            firmware_revision: id.firmware.clone(),
            subsystem_vendor: None,
            subsystem_device: None,
        };
        let mut devstat = AtaDeviceStatisticsEvidence::default();
        let mut raw: Vec<u8> = Vec::new();
        let mut has_any = false;
        if let Ok((page0, page_raw)) = AtaPurgeClient::new(sat).read_device_statistics(0x00) {
            raw.extend_from_slice(&page_raw);
            has_any = true;
            if let Some(e) = page0.entry(0x0004) {
                devstat.logical_sectors_written = Some(e.value);
            }
            if let Some(e) = page0.entry(0x0005) {
                devstat.write_commands = Some(e.value);
            }
            if let Some(e) = page0.entry(0x0006) {
                devstat.logical_sectors_read = Some(e.value);
            }
            if let Some(e) = page0.entry(0x0007) {
                devstat.read_commands = Some(e.value);
            }
            if let Some(e) = page0.entry(0x0002) {
                devstat.power_on_hours = Some(e.value);
            }
        }
        if let Ok((page4, page_raw)) = AtaPurgeClient::new(sat).read_device_statistics(0x04) {
            raw.extend_from_slice(&page_raw);
            has_any = true;
            devstat.ssd_statistics_page_present = true;
            devstat.percentage_used_endurance = page4.percentage_used_endurance();
        }
        let devstat = if has_any { Some(devstat) } else { None };
        Ok(Self {
            identity,
            telemetry: None,
            telemetry_raw: Vec::new(),
            devstat,
            devstat_raw: raw,
        })
    }

    /// SCSI/SAS: standard INQUIRY identity (vendor/product/revision).
    fn capture_scsi(scsi: &mut LinuxScsiPurge) -> Result<Self, String> {
        let id = ScsiPurgeClient::new(scsi).identify()?;
        Ok(Self {
            identity: FirmwareIdentity {
                bus: "scsi".to_string(),
                model: format!("{} {}", id.vendor, id.product),
                serial: String::new(),
                firmware_revision: id.revision.clone(),
                subsystem_vendor: None,
                subsystem_device: None,
            },
            telemetry: None,
            telemetry_raw: Vec::new(),
            devstat: None,
            devstat_raw: Vec::new(),
        })
    }

    /// Build the certificate evidence block from pre/post captures and
    /// the raw snapshot digests.
    fn into_evidence(
        pre: TransportForensics,
        post: TransportForensics,
    ) -> FirmwareAttestationEvidence {
        let mut raw_snapshots = Vec::new();
        if !pre.telemetry_raw.is_empty() {
            raw_snapshots.push(TelemetrySnapshot {
                label: format!(
                    "nvme-telemetry-host-0x07-pre-{}",
                    pre.telemetry.as_ref().map(|t| t.generation).unwrap_or(0)
                ),
                blake3_hex: blake3::hash(&pre.telemetry_raw).to_hex().to_string(),
                len_bytes: pre.telemetry_raw.len() as u64,
            });
        }
        if !post.telemetry_raw.is_empty() {
            raw_snapshots.push(TelemetrySnapshot {
                label: format!(
                    "nvme-telemetry-host-0x07-post-{}",
                    post.telemetry.as_ref().map(|t| t.generation).unwrap_or(0)
                ),
                blake3_hex: blake3::hash(&post.telemetry_raw).to_hex().to_string(),
                len_bytes: post.telemetry_raw.len() as u64,
            });
        }
        if !pre.devstat_raw.is_empty() {
            raw_snapshots.push(TelemetrySnapshot {
                label: "ata-devstat-0x04-pre".to_string(),
                blake3_hex: blake3::hash(&pre.devstat_raw).to_hex().to_string(),
                len_bytes: pre.devstat_raw.len() as u64,
            });
        }
        if !post.devstat_raw.is_empty() {
            raw_snapshots.push(TelemetrySnapshot {
                label: "ata-devstat-0x04-post".to_string(),
                blake3_hex: blake3::hash(&post.devstat_raw).to_hex().to_string(),
                len_bytes: post.devstat_raw.len() as u64,
            });
        }
        FirmwareAttestationEvidence {
            pre: pre.identity,
            post: post.identity,
            nvme_telemetry_pre: pre.telemetry,
            nvme_telemetry_post: post.telemetry,
            ata_devstat_pre: pre.devstat,
            ata_devstat_post: post.devstat,
            raw_snapshots,
        }
    }
}

/// The execution outcome every transport runner returns; the certificate
/// assembly is transport-uniform.
struct PurgeRunOutcome {
    executed_mechanism: String,
    fallbacks: Vec<PurgeFallbackRecord>,
    completion_evidence: String,
    progress_permille: u16,
    readback_expectation: String,
    controller_device: String,
    /// Extra advisory lines (e.g. lifeline disclosure instructions).
    operator_notes: Vec<String>,
    duration_ms: u64,
    /// Cold-bus freeze remediation steps executed before arming
    /// (v0.7.0, Vector 2) — recorded into the certificate.
    coldbus_steps: Vec<ColdBusStepRecord>,
    /// Thermal monitor statistics (max temperature, pacing time) when a
    /// thermometer was observable during the run.
    thermal_report: Option<String>,
}

/// v0.8.0 runtime evidence captured around the purge and folded into the
/// certificate by the assembly tail.
#[derive(Debug)]
pub struct V08Evidence {
    /// Verified TPM2_Quote bundle (Vector 1).
    pub tpm_quote: Option<dc_tpm::QuoteBundle>,
    /// Micro-KVM vault execution report (Vector 2).
    pub vault_report: Option<dc_cert::VaultReportEvidence>,
    /// Fabric session record (Vector 4).
    pub fabric_session: Option<dc_cert::FabricSessionEvidence>,
}

pub fn cmd_purge(args: PurgeArgs, audit: &mut Option<AuditLogger>) -> Result<(), DcError> {
    let requested = parse_mechanism(&args.mechanism)?;

    // ------------------------------------------------------------------
    // v0.8.0 Vector 4: fabric URI target — connect, resolve the block
    // device of the appeared controller, purge through the normal NVMe
    // ladder, disconnect afterwards (including on failure), and carry the
    // session record into the certificate.
    // ------------------------------------------------------------------
    let target_str = args.target.to_string_lossy().to_string();
    if let Ok(fabric_target) = dc_nvme::FabricTarget::parse(&target_str) {
        return run_fabric_purge(args, fabric_target, audit);
    }

    // ------------------------------------------------------------------
    // v0.8.0 Vectors 1+2: opportunistic (or required) TPM attestation and
    // vault enclave execution, captured before arming.
    // ------------------------------------------------------------------
    let v08 = capture_v08_evidence(&args)?;
    let identity = InventoryScanner::probe_device_or_refuse(&args.target)?;
    let args = if v08.is_some() {
        let mut a = args;
        a.v08_evidence = v08;
        a
    } else {
        args
    };

    // Guardian evaluation (same 15-rule normative table as execute).
    let flags = GuardianFlags {
        allow_system_disk: args.allow_system_disk,
        serial_confirm: None,
        allow_loop: args.allow_loop,
        allow_inactive_signatures: args.allow_inactive_signatures,
        allow_member: args.allow_member,
    };
    if let Err(e) = Guardian::evaluate(&args.target, &identity, &flags) {
        if let DcError::Guardian(ref g) = e
            && let Some(a) = audit
        {
            let _ = a.log(&AuditRecord {
                timestamp_utc: chrono_now_iso(),
                argv_hash: "purge".to_string(),
                target_path: Some(identity.dev_path.clone()),
                outcome: AuditOutcome::Refusal {
                    code: g.code.to_string(),
                    detail: g.detail.clone(),
                },
            });
        }
        return Err(e);
    }

    // UNIVERSAL DISPATCH (v0.6.0): each controller family gets its real
    // transport; buses without one are refused fail-closed.
    requested.validate_for_bus(identity.stable.bus)?;
    match identity.stable.bus {
        BusType::Nvme => run_nvme_purge(args, identity, audit),
        BusType::Sata | BusType::Usb => run_ata_purge(args, identity, audit),
        BusType::Sas => run_scsi_purge(args, identity, audit),
        other => Err(DcError::Guardian(dc_core::GuardianRefusal {
            code: "PURGE_TRANSPORT_UNSUPPORTED",
            detail: format!(
                "target {} is on the {} bus: no controller purge transport exists for it",
                args.target.display(),
                other
            ),
            hint: "for loop/DM/virtio/file-backed media use `dc execute` (logical overwrite, \
                   verified); attach real SATA/SAS/NVMe media for firmware purges"
                .to_string(),
        })),
    }
}

/// Shared confirmation gate: interactive token or --serial-confirm.
fn confirm_destructive_purge(
    args: &PurgeArgs,
    identity: &DeviceIdentity,
    mechanism_label: &str,
) -> Result<String, DcError> {
    let stdin_is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    if !stdin_is_tty && args.serial_confirm.is_none() {
        return Err(DcError::Guardian(dc_core::GuardianRefusal {
            code: "NON_INTERACTIVE_CONFIRM_REQUIRED",
            detail: "Refusing to run a hardware purge from a non-interactive session \
                     without an explicit confirmation token"
                .to_string(),
            hint: "Re-run with `--serial-confirm <SERIAL>` (see `dc check` output).".to_string(),
        }));
    }

    let expected_token = identity
        .stable
        .dm_uuid
        .clone()
        .or(identity.stable.serial.clone())
        .unwrap_or_else(|| identity.kernel_name.clone());

    cli_signal_injection("prompt-wait");
    if signal_was_seen() {
        return Err(DcError::Interrupted {
            completed_through: None,
        });
    }

    if let Some(ref provided) = args.serial_confirm {
        if provided != &expected_token {
            eprintln!(
                "[ERROR] Confirmation token mismatch: expected '{}', got '{}'",
                expected_token, provided
            );
            return Err(DcError::Usage("Confirmation token mismatch".to_string()));
        }
    } else {
        println!("\n[WARNING] YOU ARE ABOUT TO ISSUE A CONTROLLER-ATTESTED HARDWARE PURGE:");
        println!("  Target Device:  {}", identity.dev_path);
        println!(
            "  Device Model:   {}",
            identity.stable.model.as_deref().unwrap_or("Unknown")
        );
        println!("  Mechanism:      {}", mechanism_label);
        println!("  Confirm Token:  {}", expected_token);
        println!(
            "\nType the exact confirmation token '{}' to confirm the purge:",
            expected_token
        );
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(DcError::StdIo)?;
        if input.trim() != expected_token {
            println!("Confirmation token mismatch. Aborting.");
            return Err(DcError::OperatorAbort);
        }
    }
    cli_signal_injection("pre-arm");
    if signal_was_seen() {
        return Err(DcError::Interrupted {
            completed_through: None,
        });
    }
    Ok(expected_token)
}

/// Shared journal + certificate + archival-PDF pipeline. Returns after the
/// certificate and PDF/A-3 are on disk.
#[allow(clippy::too_many_arguments)]
/// Capture the v0.8.0 runtime evidence requested by flags.
fn capture_v08_evidence(args: &PurgeArgs) -> Result<Option<std::sync::Arc<V08Evidence>>, DcError> {
    let want_vault = args.vault || args.vault_encrypted_required;
    if !args.tpm_quote && !args.tpm_quote_required && !want_vault {
        return Ok(None);
    }
    let mut evidence = V08Evidence {
        tpm_quote: None,
        vault_report: None,
        fabric_session: None,
    };
    if args.tpm_quote || args.tpm_quote_required {
        evidence.tpm_quote = crate::quote::capture_for_certificate(args.tpm_quote_required)?;
    }
    if want_vault {
        let requirement = if args.vault_encrypted_required {
            dc_vault::VaultRequirement::EncryptedEnclave
        } else {
            dc_vault::VaultRequirement::Enclave
        };
        let mut session = dc_vault::VaultSession::execute(requirement)
            .map_err(|e| DcError::Internal(format!("{e}")))?;
        // Seal the run's own identifying evidence into the chain.
        let plan_binding = format!(
            "purge-target={} mechanism={}",
            args.target.display(),
            args.mechanism
        );
        session
            .seal_record(plan_binding.as_bytes())
            .map_err(|e| DcError::Internal(format!("vault seal: {e}")))?;
        let report = session.report();
        eprintln!(
            "[vault] enclave executed: {} ({} records sealed)",
            report.memory_encryption, report.chain_records
        );
        evidence.vault_report = Some(dc_cert::VaultReportEvidence {
            kvm_api_version: report.kvm_api_version,
            memory_encryption: report.memory_encryption,
            encrypted: report.encrypted,
            guest_payload_blake3: report.guest_payload_blake3,
            session_key_fingerprint: report.session_key_fingerprint,
            chain_head_hex: report.chain_head_hex,
            chain_records: report.chain_records,
            vcpu_exits: report.vcpu_exits,
            elapsed_us: report.elapsed_us,
        });
    }
    Ok(Some(std::sync::Arc::new(evidence)))
}

/// Fabric-target purge: the full connect → sanitize → disconnect cycle
/// with fail-safe timeouts; the session record rides the certificate.
fn run_fabric_purge(
    mut args: PurgeArgs,
    target: dc_nvme::FabricTarget,
    audit: &mut Option<AuditLogger>,
) -> Result<(), DcError> {
    let timeouts = dc_nvme::FabricTimeouts::default();
    eprintln!(
        "[fabric] connecting to {}://{} (subsystem {})…",
        target.transport, target.traddr, target.nqn
    );
    let session = dc_nvme::fabric_connect(&target, &timeouts)
        .map_err(|e| DcError::Guardian(dc_core::GuardianRefusal {
            code: "FABRIC_CONNECT_REFUSED",
            detail: format!("{e}"),
            hint: "verify the fabric address, transport service id and subsystem NQN;                    the target must ACK the connection within the timeout budget"
                .to_string(),
        }))?;
    eprintln!("[fabric] controller {} online", session.ctrl_name);
    FABRIC_TARGET_SNAPSHOT.with(|cell| {
        cell.borrow_mut().replace((
            target.transport.kernel_name().to_string(),
            target.traddr.clone(),
            target.trsvcid.clone(),
            target.nqn.clone(),
        ));
    });

    // Resolve the first namespace block device of the controller.
    let block_dev = wait_for_namespace(&session.ctrl_name).inspect_err(|_e| {
        let _ = dc_nvme::fabric_disconnect(&target, &timeouts);
    })?;
    eprintln!("[fabric] purging namespace {}", block_dev.display());

    // Evidence stash: fabric session + optional TPM quote / vault.
    let mut evidence = capture_v08_evidence(&args)?;
    if evidence.is_none() {
        evidence = Some(std::sync::Arc::new(V08Evidence {
            tpm_quote: None,
            vault_report: None,
            fabric_session: None,
        }));
    }
    // Snapshot the session while connected; disconnect updates the record.
    let connected_at = session.connected_at;

    args.target = block_dev;
    args.v08_evidence = evidence;

    let identity = InventoryScanner::probe_device_or_refuse(&args.target).inspect_err(|_e| {
        let _ = dc_nvme::fabric_disconnect(&target, &timeouts);
    })?;

    let flags = GuardianFlags {
        allow_system_disk: args.allow_system_disk,
        serial_confirm: None,
        allow_loop: args.allow_loop,
        allow_inactive_signatures: args.allow_inactive_signatures,
        allow_member: args.allow_member,
    };
    if let Err(e) = Guardian::evaluate(&args.target, &identity, &flags) {
        let _ = dc_nvme::fabric_disconnect(&target, &timeouts);
        return Err(e);
    }

    let requested = parse_mechanism(&args.mechanism)?;
    requested.validate_for_bus(identity.stable.bus)?;

    // Mutate the target clone for the NVMe runner, but keep the fabric
    // session around for the disconnect after the run.
    let run_result = run_nvme_purge(args, identity, audit);

    // Always disconnect (fail-safe: an open session is disclosed).
    let disconnected_cleanly = dc_nvme::fabric_disconnect(&target, &timeouts).is_ok();
    let session_ms = connected_at.elapsed().as_millis() as u64;
    eprintln!(
        "[fabric] controller {} disconnected ({})",
        session.ctrl_name,
        if disconnected_cleanly {
            "clean"
        } else {
            "FAILED"
        }
    );

    // Attach the fabric session record onto the certificate the runner
    // wrote: the runner stashed its evidence under `v08_evidence`, so we
    // re-read the latest cert in the out dir? No — the evidence stash is
    // consumed by assemble_purge_certificate through the moved args. To
    // carry the disconnect outcome we patch a thread-local the assembly
    // reads (see FABRIC_OUTCOME).
    FABRIC_OUTCOME.with(|cell| {
        cell.borrow_mut().replace((
            session.ctrl_name.clone(),
            session.ctrl_char_dev.to_string_lossy().to_string(),
            disconnected_cleanly,
            session_ms,
        ));
    });

    let _ = &target;
    run_result
}

thread_local! {
    /// (ctrl_name, ctrl_char_dev, disconnected_cleanly, session_ms) of the
    /// fabric session around the current purge — consumed by the
    /// certificate assembly tail.
    static FABRIC_OUTCOME: std::cell::RefCell<Option<(String, String, bool, u64)>> =
        const { std::cell::RefCell::new(None) };
    /// (transport, traddr, trsvcid, nqn) of the current fabric target.
    static FABRIC_TARGET_SNAPSHOT: std::cell::RefCell<Option<(String, String, String, String)>> =
        const { std::cell::RefCell::new(None) };
}

/// Wait for the first namespace block device of a just-connected fabric
/// controller (`nvme4` → `nvme4n1`), bounded by the controller's
/// namespace scan.
fn wait_for_namespace(ctrl: &str) -> Result<std::path::PathBuf, DcError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if let Ok(rd) = std::fs::read_dir(format!("/sys/class/nvme/{ctrl}")) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(ctrl) && name.contains('n') {
                    let dev = std::path::Path::new("/dev").join(&name);
                    if dev.exists() {
                        return Ok(dev);
                    }
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(DcError::Guardian(dc_core::GuardianRefusal {
                code: "FABRIC_NO_NAMESPACE",
                detail: format!(
                    "fabric controller {ctrl} exposed no namespace block device within the timeout"
                ),
                hint: "check the subsystem's namespace configuration".to_string(),
            }));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn assemble_purge_certificate(
    args: &PurgeArgs,
    identity: &DeviceIdentity,
    expected_token: &str,
    mechanism_label: &str,
    outcome: &PurgeRunOutcome,
    keypair: &OperatorKeyPair,
    journal: &mut dc_core::JournalWriter,
    journal_path: &std::path::PathBuf,
    timestamp_str: &str,
    defense_warnings: Vec<String>,
    health: Option<(HealthSnapshotEvidence, HealthSnapshotEvidence)>,
    verify_level_note: &str,
    firmware: Option<FirmwareAttestationEvidence>,
    extra_attachments: &[(String, Vec<u8>, &'static str)],
) -> Result<(), DcError> {
    use dc_verify::StreamVerifier;

    let plan = SanitizationPlan {
        plan_schema: "dc-plan/1".to_string(),
        target: identity.stable.clone(),
        mechanism: Mechanism::HardwarePurge {
            ladder: StrategyLadder { steps: Vec::new() },
            selected_mechanism: mechanism_label.to_string(),
        },
        verification: VerifyLevel::None, // controller-attested
        window_bytes: SanitizationPlan::DEFAULT_WINDOW_BYTES,
        fast_path: dc_core::FastPathPolicy::ForbidWriteZeroes,
        strategy_ladder: None,
        legacy_note: None,
    };

    let mut fsm = FsmOrchestrator::new();
    let plan_hash = fsm.compile_plan(plan.clone())?;
    fsm.approve_plan()?;
    fsm.arm()?;
    fsm.begin_verify()?;
    fsm.certify()?;

    let verifier_report = StreamVerifier::new(
        VerifyLevel::None,
        plan.window_bytes,
        identity.logical_block_size,
        false,
        false,
    )
    .finalize();

    journal.append(&dc_core::JournalRecord::Verify {
        level: verify_level_note.to_string(),
        windows_checked: verifier_report.windows_checked,
        mismatch_count: verifier_report.mismatch_count,
        first_mismatch_lbas: verifier_report.first_mismatch_lbas.clone(),
        stream_hash_blake3: verifier_report.stream_hash_blake3.clone(),
        stream_hash_sha256: verifier_report.stream_hash_sha256.clone(),
        fast_path_used: false,
    })?;

    let finished_time_str = chrono_now_iso();
    journal.append(&dc_core::JournalRecord::Completed {
        at: finished_time_str.clone(),
        duration_mono_ms: outcome.duration_ms,
    })?;

    let evidence = PurgeCertificateEvidence {
        executed_mechanism: outcome.executed_mechanism.clone(),
        fallbacks: outcome.fallbacks.clone(),
        completion_evidence: outcome.completion_evidence.clone(),
        sanitize_progress_permille: outcome.progress_permille,
        readback_expectation: outcome.readback_expectation.clone(),
        controller_device: outcome.controller_device.clone(),
    };

    let mut cert = SanitizationCertificate::new(
        plan,
        plan_hash,
        identity.clone(),
        ExecutionDetails {
            started_utc: timestamp_str.to_string(),
            finished_utc: finished_time_str.clone(),
            duration_mono_ms: outcome.duration_ms,
            interruptions: vec![],
            failures: vec![],
            passes: vec![],
        },
        verifier_report,
        journal.summary(),
        keypair.public_key_hex(),
        keypair.key_fingerprint_blake3(),
    )
    .with_purge(evidence)
    .with_defense_warnings(defense_warnings);
    if let Some((pre, post)) = health {
        cert = cert.with_health(Some(pre), Some(post));
    }
    if let Some(fw) = firmware {
        // with_firmware_attestation derives the firmware-drift defense
        // warnings into the signed payload (Vector 4).
        cert = cert.with_firmware_attestation(fw);
    }
    // ------------------------------------------------------------------
    // v0.8.0 evidence embedding: TPM quote (Vector 1), vault report
    // (Vector 2), fabric session (Vector 4).
    // ------------------------------------------------------------------
    let mut v08_attachments: Vec<(String, Vec<u8>, &'static str)> = Vec::new();
    if let Some(evidence) = args.v08_evidence.as_ref() {
        if let Some(bundle) = &evidence.tpm_quote {
            cert = cert.with_tpm_attestation(crate::quote::bundle_to_evidence(bundle));
            v08_attachments.push((
                "tpm2-quote-raw.hex".to_string(),
                bundle.quote_response_hex.as_bytes().to_vec(),
                "text/plain",
            ));
        }
        if let Some(report) = &evidence.vault_report {
            cert = cert.with_vault_report(report.clone());
        }
    }
    // Fabric outcome is captured by run_fabric_purge into the thread-local.
    let fabric_evidence = FABRIC_OUTCOME.with(|cell| {
        cell.borrow().clone().map(
            |(ctrl_name, ctrl_char_dev, disconnected_cleanly, session_ms)| {
                let (transport, traddr, trsvcid, nqn) = FABRIC_TARGET_SNAPSHOT.with(|t| {
                    t.borrow().clone().unwrap_or((
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ))
                });
                dc_cert::FabricSessionEvidence {
                    transport,
                    traddr,
                    trsvcid,
                    nqn,
                    ctrl_name,
                    ctrl_char_dev,
                    disconnected_cleanly,
                    session_ms,
                    fc_host_port_name: None,
                }
            },
        )
    });
    if let Some(fabric) = fabric_evidence {
        cert = cert.with_fabric_session(fabric);
    }
    crate::hybridsign::sign_certificate(&mut cert, keypair, args.key.as_deref())?;

    let cert_json = serde_json::to_string_pretty(&cert)?;
    let stem = format!(
        "{}-purge-{}",
        expected_token.replace('/', "_"),
        timestamp_str.replace(':', "-")
    );
    let cert_path = args.out_dir.join(format!("{}.cert.json", stem));
    std::fs::write(&cert_path, &cert_json)?;

    // ISO 19005-3 (PDF/A-3) archival copy: certificate + journal + the
    // raw controller forensics embedded as verifiable attachments
    // (v0.6.0 core; v0.7.0 adds telemetry/devstat snapshots).
    let journal_bytes = std::fs::read(journal_path).unwrap_or_default();
    let mut visual_fields: Vec<(String, String)> = vec![
        (
            "Executed mechanism".to_string(),
            outcome.executed_mechanism.clone(),
        ),
        (
            "Completion evidence".to_string(),
            outcome.completion_evidence.clone(),
        ),
        (
            "Controller device".to_string(),
            outcome.controller_device.clone(),
        ),
        (
            "Sanitize progress".to_string(),
            format!("{} permille", outcome.progress_permille),
        ),
        (
            "Read-back expectation".to_string(),
            outcome.readback_expectation.clone(),
        ),
        ("Plan hash".to_string(), cert.plan_hash.clone()),
        (
            "Operator key".to_string(),
            cert.operator.key_fingerprint_blake3.clone(),
        ),
        (
            "Journal chain head".to_string(),
            journal.current_chain_head(),
        ),
    ];
    if let Some(fw) = cert.firmware_attestation.as_ref() {
        visual_fields.extend(fw.field_lines());
    }
    if let Some(tpm) = cert.tpm_attestation.as_ref() {
        visual_fields.extend(tpm.field_lines());
    }
    if let Some(vault) = cert.vault_report.as_ref() {
        visual_fields.extend(vault.field_lines());
    }
    if let Some(fabric) = cert.fabric_session.as_ref() {
        visual_fields.extend(fabric.field_lines());
    }
    if let Some(ref report) = outcome.thermal_report {
        visual_fields.push(("Thermal monitor".to_string(), report.clone()));
    }
    let mut attachments_storage: Vec<dc_report::ArchiveAttachment> = vec![
        dc_report::ArchiveAttachment {
            filename: "certificate.json",
            bytes: cert_json.as_bytes(),
            mime: "application/json",
            relationship: "Source",
        },
        dc_report::ArchiveAttachment {
            filename: "journal.dcj",
            bytes: &journal_bytes,
            mime: "application/octet-stream",
            relationship: "Supplement",
        },
    ];
    for (name, bytes, mime) in extra_attachments {
        attachments_storage.push(dc_report::ArchiveAttachment {
            filename: name,
            bytes,
            mime,
            relationship: "Supplement",
        });
    }
    for (name, bytes, mime) in &v08_attachments {
        attachments_storage.push(dc_report::ArchiveAttachment {
            filename: name.as_str(),
            bytes,
            mime,
            relationship: "Supplement",
        });
    }
    // Cold-bus remediation evidence (v0.7.0, Vector 2): the sysfs reset
    // ladder steps ride as a signed-context attachment.
    let coldbus_json: Vec<u8> = if outcome.coldbus_steps.is_empty() {
        Vec::new()
    } else {
        serde_json::to_vec(&outcome.coldbus_steps).unwrap_or_default()
    };
    if !coldbus_json.is_empty() {
        attachments_storage.push(dc_report::ArchiveAttachment {
            filename: "coldbus-reset-steps.json",
            bytes: &coldbus_json,
            mime: "application/json",
            relationship: "Supplement",
        });
    }
    let pdf_bytes = dc_report::render_sanitization_archive(
        if cert.verification.mismatch_count > 0 {
            "Sanitization Report — VERIFICATION FAILED"
        } else {
            "Certificate of Sanitization"
        },
        &format!(
            "Hardware Purge — {} — {}",
            mechanism_label,
            identity
                .stable
                .serial
                .as_deref()
                .unwrap_or("serial unknown")
        ),
        "Purge",
        cert.verification.mismatch_count == 0,
        &visual_fields,
        &outcome.operator_notes,
        &finished_time_str,
        &attachments_storage,
    );
    let pdf_path = args.out_dir.join(format!("{}.pdf", stem));
    std::fs::write(&pdf_path, pdf_bytes)?;

    if !args.no_progress {
        println!("\n{}", cert.render_summary());
        for note in &outcome.operator_notes {
            println!("[NOTE] {}", note);
        }
        println!(
            "\n[+] Purge certificate written to: {}",
            cert_path.display()
        );
        println!(
            "[+] Journal written to:           {}",
            journal_path.display()
        );
        println!("[+] PDF/A-3 archival copy:         {}", pdf_path.display());
    }
    Ok(())
}

/// Create the sealed journal common to all transports.
fn create_purge_journal(
    args: &PurgeArgs,
    identity: &DeviceIdentity,
    expected_token: &str,
    keypair: &OperatorKeyPair,
    engine_name: &str,
    timestamp_str: &str,
    ladder: StrategyLadder,
    mechanism_label: &str,
) -> Result<(std::path::PathBuf, dc_core::JournalWriter), DcError> {
    let journal_filename = format!(
        "{}-purge-{}.dcj",
        expected_token.replace('/', "_"),
        timestamp_str.replace(':', "-")
    );
    let journal_path = args.out_dir.join(&journal_filename);

    let is_sealed = args.key.is_some();
    let plan = SanitizationPlan {
        plan_schema: "dc-plan/1".to_string(),
        target: identity.stable.clone(),
        mechanism: Mechanism::HardwarePurge {
            ladder: ladder.clone(),
            selected_mechanism: mechanism_label.to_string(),
        },
        verification: VerifyLevel::None,
        window_bytes: SanitizationPlan::DEFAULT_WINDOW_BYTES,
        fast_path: dc_core::FastPathPolicy::ForbidWriteZeroes,
        strategy_ladder: Some(ladder),
        legacy_note: None,
    };
    let mut fsm = FsmOrchestrator::new();
    let plan_hash = fsm.compile_plan(plan.clone())?;

    let mut journal = dc_core::JournalWriter::create_new(
        &journal_path,
        format!("dcj-{}", timestamp_str.replace([':', '-', 'T', 'Z'], "")),
        if is_sealed {
            Some(keypair.signing_key.clone())
        } else {
            None
        },
    )?;
    journal.append(&dc_core::JournalRecord::Header {
        uuid: format!("dcj-{}", timestamp_str.replace([':', '-', 'T', 'Z'], "")),
        sealed: is_sealed,
        operator_pubkey: if is_sealed {
            Some(keypair.public_key_hex())
        } else {
            None
        },
        plan: plan.clone(),
        plan_hash: plan_hash.clone(),
        identity: identity.clone(),
        tool: ToolBuild::current(),
        engine: engine_name.to_string(),
        tuning: EngineTuning {
            qd: 0,
            pool_mib: 0,
            window_bytes: plan.window_bytes,
            checkpoint_mib: 0,
            checkpoint_ms: 0,
        },
        argv_hash: "cli-purge".to_string(),
        started_utc: timestamp_str.to_string(),
    })?;
    journal.append(&dc_core::JournalRecord::Armed {
        overrides: Vec::new(),
        locks_held: vec![format!(
            "{}:{}",
            identity.kernel.major, identity.kernel.minor
        )],
        at: chrono_now_iso(),
    })?;
    Ok((journal_path, journal))
}

// ---------------------------------------------------------------------------
// NVMe runner (unchanged semantics since v0.5.0)
// ---------------------------------------------------------------------------

fn run_nvme_purge(
    args: PurgeArgs,
    identity: DeviceIdentity,
    audit: &mut Option<AuditLogger>,
) -> Result<(), DcError> {
    let ctrl_path = controller_char_dev_for(&args.target);
    let nsid = NvmePurgeClient::nsid_of_target(&args.target.to_string_lossy());
    let mut admin = LinuxNvmeAdmin::open(&ctrl_path).map_err(|e| {
        DcError::Guardian(dc_core::GuardianRefusal {
            code: "PURGE_TRANSPORT_UNAVAILABLE",
            detail: format!(
                "cannot open NVMe controller char device {} for admin passthrough: {:?}",
                ctrl_path.display(),
                e
            ),
            hint: "run as root; verify the controller device node exists".to_string(),
        })
    })?;

    let id_ctrl = identify_controller(&mut admin).map_err(|e| {
        DcError::Guardian(dc_core::GuardianRefusal {
            code: "PURGE_IDENTIFY_FAILED",
            detail: format!("Identify Controller failed: {:?}", e),
            hint: "controller did not answer the identify admin command".to_string(),
        })
    })?;
    let caps = attest_capabilities(&id_ctrl);
    let ladder =
        StrategyCompiler::compile_strategy(dc_core::DeviceTransportClass::Nvme, &caps, true)
            .map_err(DcError::Usage)?;

    let primary = match crate::purge::parse_mechanism(&args.mechanism)? {
        crate::purge::RequestedMechanism::SanitizeCrypto => PurgeMechanism::SanitizeCryptoErase,
        crate::purge::RequestedMechanism::SanitizeBlock => PurgeMechanism::SanitizeBlockErase,
        crate::purge::RequestedMechanism::FormatCrypto => PurgeMechanism::FormatNvmCryptoErase,
        _ => primary_mechanism_for(&caps).ok_or_else(|| {
            DcError::Guardian(dc_core::GuardianRefusal {
                code: "PURGE_UNSUPPORTED_BY_CONTROLLER",
                detail: format!(
                    "controller {} ({}) attests no hardware purge mechanism \
                     (OACS bit1 = {}, SANICAP crypto/block = {}/{}); refusing to \
                     certify a purge that cannot be performed",
                    id_ctrl.mn,
                    id_ctrl.sn,
                    caps.supports_format_nvm,
                    caps.supports_sanitize_crypto,
                    caps.supports_sanitize_block
                ),
                hint: "use `dc execute` for a tool-verified logical overwrite instead".to_string(),
            })
        })?,
    };
    let mechanism_label = format!("{:?}", primary);

    // Dry run: print the attested ladder and exit before any confirmation.
    if args.dry_run {
        print_dry_run(
            &identity,
            &ctrl_path.to_string_lossy(),
            &mechanism_label,
            &ladder,
            &format!("namespace {}", nsid),
        );
        return Ok(());
    }

    let health_pre = read_health(&mut admin).ok();
    // Vector 4 pre-forensics: firmware identity + telemetry snapshot.
    let forensics_pre = TransportForensics::capture_nvme(&mut admin, &id_ctrl).ok();
    let expected_token = confirm_destructive_purge(&args, &identity, &mechanism_label)?;

    // Arm + lock the block node (O_EXCL), then journal.
    let _lock = Guardian::arm_and_lock(&args.target, &identity.stable)?;
    let timestamp_str = chrono_now_iso();
    let keypair = match &args.key {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => OperatorKeyPair::generate(),
    };
    let (journal_path, mut journal) = create_purge_journal(
        &args,
        &identity,
        &expected_token,
        &keypair,
        "nvme-admin",
        &timestamp_str,
        ladder.clone(),
        &mechanism_label,
    )?;

    if !args.no_progress {
        println!(
            "[>] Issuing {:?} on {} (this may take seconds to minutes; sanitize \
             progress is polled from Log 0x81)...",
            primary,
            ctrl_path.display()
        );
    }
    let started = std::time::Instant::now();
    let permit = dc_nvme::PurgePermit::mint(
        &args.target.to_string_lossy(),
        identity.stable.serial.as_deref().unwrap_or(""),
        now_unix(),
    );
    let no_progress = args.no_progress;
    let thermal_shared: Option<std::rc::Rc<std::cell::RefCell<PurgeThermalMonitor>>> =
        if args.no_thermal_guard {
            None
        } else {
            Some(std::rc::Rc::new(std::cell::RefCell::new(
                PurgeThermalMonitor::new(thermal_limits_from_args(&args), &identity.kernel_name),
            )))
        };
    let sink_thermal = thermal_shared.clone();
    let summary = NvmePurgeClient::new(&mut admin)
        .with_poll_budget(24 * 60 * 4, Duration::from_millis(250)) // up to 24h of polling
        .with_progress_sink(move |permille| {
            if !no_progress {
                eprint!(
                    "\r    sanitize progress: {:>3}.{}%   ",
                    permille / 10,
                    permille % 10
                );
            }
            // Thermal pacing between Log 0x81 polls (Vector 2).
            if let Some(monitor) = sink_thermal.as_ref() {
                monitor.borrow_mut().on_poll();
            }
        })
        .execute_purge_ladder(&permit, primary)
        .map_err(|reason| {
            let _ = journal.append(&dc_core::JournalRecord::Failed {
                code: "PURGE_FAILED".to_string(),
                errno: None,
                op: Some(format!("{:?}", primary)),
                at_lba: None,
                detail: reason.clone(),
            });
            DcError::Guardian(dc_core::GuardianRefusal {
                code: "PURGE_FAILED",
                detail: reason,
                hint: "controller reported a non-terminal or failed sanitize state; \
                       the media state is UNTRUSTED — re-run or fall back to `dc execute`"
                    .to_string(),
            })
        })?;

    let health_post = read_health(&mut admin).ok();
    // Vector 4 post-forensics: firmware identity + telemetry generation.
    let forensics_post = TransportForensics::capture_nvme(&mut admin, &id_ctrl).ok();
    let readback_expectation = match summary.executed_mechanism {
        PurgeMechanism::FormatNvmCryptoErase => "Zeros",
        _ => "VendorRandom",
    };

    // Format NVM crypto erase attests Zeros: sampled zero read-back through
    // the production engine (kept identical to v0.5.0 semantics).
    if summary.executed_mechanism == PurgeMechanism::FormatNvmCryptoErase {
        let span = dc_io::LbaSpan::new(
            identity.stable.size_bytes,
            identity.logical_block_size,
            SanitizationPlan::DEFAULT_WINDOW_BYTES,
        );
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&args.target)
            .map_err(DcError::StdIo)?;
        let mut engine =
            dc_io::SyncEngine::new(file, SanitizationPlan::DEFAULT_WINDOW_BYTES as usize, false)?;
        let mut verifier = dc_verify::StreamVerifier::new(
            VerifyLevel::Sampled { stride: 64 },
            SanitizationPlan::DEFAULT_WINDOW_BYTES,
            identity.logical_block_size,
            false,
            true,
        );
        let mut noop = |_: dc_io::EngineProgress| {};
        engine.read_verify(&dc_core::ZeroPattern, &span, 64, &mut verifier, &mut noop)?;
        let report = verifier.finalize();
        if report.mismatch_count > 0 {
            let _ = journal.append(&dc_core::JournalRecord::Failed {
                code: "VERIFICATION_FAILED".to_string(),
                errno: None,
                op: Some("purge-readback".to_string()),
                at_lba: report.first_mismatch_lbas.first().copied(),
                detail: format!(
                    "Format NVM crypto erase reported success but the sampled zero \
                     read-back found {} mismatching windows; evidence conflict, refusing to certify",
                    report.mismatch_count
                ),
            });
            return Err(DcError::VerificationFailed {
                mismatches: report.mismatch_count,
                sample: report.first_mismatch_lbas,
            });
        }
    }

    let outcome = PurgeRunOutcome {
        executed_mechanism: format!("{:?}", summary.executed_mechanism),
        fallbacks: summary
            .fallbacks
            .iter()
            .map(|f| PurgeFallbackRecord {
                from: format!("{:?}", f.from),
                to: format!("{:?}", f.to),
                reason: f.reason.clone(),
            })
            .collect(),
        completion_evidence: match summary.completion_evidence() {
            dc_nvme::purge::CompletionEvidence::SanitizeStatusLog => {
                "sanitize-status-log".to_string()
            }
            dc_nvme::purge::CompletionEvidence::BlockingFormatReturn => {
                "blocking-format-return".to_string()
            }
        },
        progress_permille: summary.status.progress_permille,
        readback_expectation: readback_expectation.to_string(),
        controller_device: ctrl_path.to_string_lossy().to_string(),
        operator_notes: Vec::new(),
        duration_ms: started.elapsed().as_millis() as u64,
        coldbus_steps: Vec::new(),
        thermal_report: thermal_shared.as_ref().and_then(|t| t.borrow().report()),
    };

    // Thermal critical: refuse certification (media health over
    // completion, v0.7.0 Vector 2).
    if let Some(monitor) = thermal_shared.as_ref() {
        let monitor = monitor.borrow();
        if monitor.critical.is_some() {
            let _ = journal.append(&dc_core::JournalRecord::Failed {
                code: "THERMAL_CRITICAL".to_string(),
                errno: None,
                op: Some("thermal-monitor".to_string()),
                at_lba: None,
                detail: format!(
                    "drive temperature reached the critical limit (max {} C); the purge \
                     may have completed but certification is refused",
                    monitor.max_temperature_c.unwrap_or(0)
                ),
            });
            return Err(DcError::Guardian(dc_core::GuardianRefusal {
                code: "THERMAL_CRITICAL",
                detail: format!(
                    "drive temperature reached the critical limit (max observed {} C) — \
                     refusing to certify the purge",
                    monitor.max_temperature_c.unwrap_or(0)
                ),
                hint: "let the drive cool, verify media state, and re-run the purge".to_string(),
            }));
        }
    }

    let health = health_pre
        .as_ref()
        .zip(health_post.as_ref())
        .map(|(pre, post)| (health_evidence(pre), health_evidence(post)));
    let verify_note = if summary.executed_mechanism == PurgeMechanism::FormatNvmCryptoErase {
        "Sampled (1-in-64) zero read-back + controller-attested"
    } else {
        "Controller-attested (sanitize-status-log)"
    };

    // Vector 4: firmware attestation evidence + raw telemetry PDF
    // attachments (pre/post snapshots).
    let telemetry_pre_raw = forensics_pre
        .as_ref()
        .map(|f| f.telemetry_raw.clone())
        .unwrap_or_default();
    let telemetry_post_raw = forensics_post
        .as_ref()
        .map(|f| f.telemetry_raw.clone())
        .unwrap_or_default();
    let firmware = forensics_pre
        .zip(forensics_post)
        .map(|(pre, post)| TransportForensics::into_evidence(pre, post));
    let mut extra_attachments: Vec<(String, Vec<u8>, &'static str)> = Vec::new();
    if !telemetry_pre_raw.is_empty() {
        extra_attachments.push((
            "nvme-telemetry-pre.bin".to_string(),
            telemetry_pre_raw,
            "application/octet-stream",
        ));
    }
    if !telemetry_post_raw.is_empty() {
        extra_attachments.push((
            "nvme-telemetry-post.bin".to_string(),
            telemetry_post_raw,
            "application/octet-stream",
        ));
    }

    assemble_purge_certificate(
        &args,
        &identity,
        &expected_token,
        &mechanism_label,
        &outcome,
        &keypair,
        &mut journal,
        &journal_path,
        &timestamp_str,
        Vec::new(),
        health,
        verify_note,
        firmware,
        &extra_attachments,
    )?;

    if let Some(a) = audit {
        let _ = a.log(&AuditRecord {
            timestamp_utc: chrono_now_iso(),
            argv_hash: "purge".to_string(),
            target_path: Some(args.target.to_string_lossy().to_string()),
            outcome: AuditOutcome::Executed {
                journal_path: journal_path.to_string_lossy().to_string(),
                chain_head: journal.current_chain_head(),
            },
        });
    }
    Ok(())
}

fn primary_mechanism_for(caps: &dc_core::AttestedCapabilities) -> Option<PurgeMechanism> {
    if caps.supports_sanitize_crypto {
        Some(PurgeMechanism::SanitizeCryptoErase)
    } else if caps.supports_sanitize_block {
        Some(PurgeMechanism::SanitizeBlockErase)
    } else if caps.supports_format_nvm {
        Some(PurgeMechanism::FormatNvmCryptoErase)
    } else {
        None
    }
}

fn print_dry_run(
    identity: &DeviceIdentity,
    controller: &str,
    mechanism: &str,
    ladder: &StrategyLadder,
    address: &str,
) {
    println!("================================================================================");
    println!("               HARDWARE PURGE PLAN — DRY RUN (NO WRITES)");
    println!("================================================================================");
    println!("Target Device:     {}", identity.dev_path);
    println!("Controller:        {}", controller);
    println!(
        "Model:             {}",
        identity.stable.model.as_deref().unwrap_or("Unknown")
    );
    println!(
        "Serial:            {}",
        identity.stable.serial.as_deref().unwrap_or("Unknown")
    );
    println!("Address:           {}", address);
    println!("Selected Mechanism: {}", mechanism);
    println!("--------------------------------------------------------------------------------");
    println!("Attested purge strategy ladder:");
    for (i, step) in ladder.steps.iter().enumerate() {
        println!(
            "  {:>2}. {:<30} NIST class: {:<6} read-back: {}",
            i + 1,
            step.name,
            step.nist_class,
            step.readback_expectation
        );
    }
    println!("================================================================================");
    println!("DRY RUN COMPLETE: nothing was purged, no journal was created.");
    println!("================================================================================");
}

// ---------------------------------------------------------------------------
// SATA / SAT runner (v0.6.0)
// ---------------------------------------------------------------------------

fn run_ata_purge(
    args: PurgeArgs,
    identity: DeviceIdentity,
    audit: &mut Option<AuditLogger>,
) -> Result<(), DcError> {
    let transport_refusal = |e: String| {
        DcError::Guardian(dc_core::GuardianRefusal {
            code: "PURGE_TRANSPORT_UNAVAILABLE",
            detail: format!(
                "cannot open {} for SG_IO ATA pass-through: {}",
                args.target.display(),
                e
            ),
            hint: "run as root; SATA targets are addressed through the block node (SAT \
                   bridges on USB docks are supported; /dev/sg* is refused)"
                .to_string(),
        })
    };
    let mut sat = LinuxSatPurge::open(&args.target).map_err(transport_refusal)?;

    let mut identify = AtaPurgeClient::new(&mut sat).identify().map_err(|e| {
        DcError::Guardian(dc_core::GuardianRefusal {
            code: "PURGE_IDENTIFY_FAILED",
            detail: format!("SAT IDENTIFY DEVICE failed: {}", e),
            hint: "the drive or bridge did not answer the identify command".to_string(),
        })
    })?;

    // ------------------------------------------------------------------
    // COLD-BUS FREEZE REMEDIATION (v0.7.0, Vector 2): a frozen drive
    // gets the sysfs reset ladder instead of the manual power-cycle
    // advisory when --cold-unfreeze is set (lights-out racks).
    // ------------------------------------------------------------------
    let mut coldbus_steps: Vec<ColdBusStepRecord> = Vec::new();
    if identify.security.frozen && args.cold_unfreeze {
        if !args.no_progress {
            eprintln!(
                "[COLDBUS] Freeze lock detected and --cold-unfreeze set: walking the \
                 LUN-delete + host-rescan / ATA-port runtime-PM ladder..."
            );
        }
        // The LUN delete removes the node: drop the SG_IO fd first.
        let block_name = identity.kernel_name.clone();
        drop(sat);
        let target_path = args.target.clone();
        let recheck = || {
            // Bounded wait for the (possibly renumbered) node: we insist
            // the SAME node re-appears; a renumbered drive is disclosed,
            // not silently chased.
            for _ in 0..20 {
                if let Ok(mut probe) = LinuxSatPurge::open(&target_path)
                    && let Ok(id) = AtaPurgeClient::new(&mut probe).identify()
                {
                    return Ok(id.security.frozen);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(format!(
                "device {} did not re-appear with a readable IDENTIFY after the cold-bus \
                 step (it may have renumbered — run `dc list` and re-target)",
                target_path.display()
            ))
        };
        let outcome = dc_ata::attempt_cold_unfreeze(&dc_ata::RealSysfs, &block_name, recheck);
        match outcome {
            ColdBusOutcome::Cleared { steps } => {
                coldbus_steps = steps;
                sat = LinuxSatPurge::open(&args.target).map_err(transport_refusal)?;
                identify = AtaPurgeClient::new(&mut sat).identify().map_err(|e| {
                    DcError::Guardian(dc_core::GuardianRefusal {
                        code: "PURGE_IDENTIFY_FAILED",
                        detail: format!("post-coldbus SAT IDENTIFY DEVICE failed: {}", e),
                        hint: "the cold-bus reset dropped the link; re-run the purge".to_string(),
                    })
                })?;
                if !args.no_progress {
                    println!(
                        "[COLDBUS] Freeze lock cleared after {} step(s); ladder proceeding.",
                        coldbus_steps.len()
                    );
                }
            }
            ColdBusOutcome::StillFrozen { steps, advisory } => {
                coldbus_steps = steps;
                return Err(DcError::Guardian(dc_core::GuardianRefusal {
                    code: "PURGE_FROZEN",
                    detail: format!(
                        "cold-bus ladder exhausted after {} step(s): the freeze lock \
                         survived. {}",
                        coldbus_steps.len(),
                        advisory
                    ),
                    hint: "hot-plug the drive or attach it to a controller that does not \
                           assert freeze-lock at power-on, then retry"
                        .to_string(),
                }));
            }
        }
    }

    let caps = dc_core::AttestedCapabilities {
        supports_sanitize_crypto: identify.sanitize.crypto_scramble_supported,
        supports_sanitize_block: identify.sanitize.block_erase_supported,
        supports_format_nvm: false,
        supports_ata_security_enhanced: identify.security.enhanced_erase_supported,
        supports_dco_hpa: true,
        supports_scsi_sanitize: false,
    };
    let ladder =
        StrategyCompiler::compile_strategy(dc_core::DeviceTransportClass::SataSsd, &caps, true)
            .map_err(DcError::Usage)?;

    let requested = match crate::purge::parse_mechanism(&args.mechanism)? {
        crate::purge::RequestedMechanism::SanitizeCrypto => {
            Some(AtaPurgeMechanism::SanitizeCryptoScramble)
        }
        crate::purge::RequestedMechanism::SanitizeBlock => {
            Some(AtaPurgeMechanism::SanitizeBlockErase)
        }
        crate::purge::RequestedMechanism::SecurityEraseEnhanced => {
            Some(AtaPurgeMechanism::SecurityEraseEnhanced)
        }
        crate::purge::RequestedMechanism::SecurityEraseNormal => {
            Some(AtaPurgeMechanism::SecurityEraseNormal)
        }
        _ => None,
    };

    if args.dry_run {
        let glist = AtaPurgeClient::new(&mut sat)
            .read_reallocated_sectors()
            .ok();
        print_dry_run(
            &identity,
            &args.target.to_string_lossy(),
            &requested
                .map(|m| m.label().to_string())
                .unwrap_or_else(|| "auto (sanitize -> security-erase ladder)".to_string()),
            &ladder,
            &format!(
                "SAT over {} | freeze: {} | sanitize: {}/{} | enhanced-erase: {} | reallocated sectors: {}",
                args.target.display(),
                if identify.security.frozen {
                    "FROZEN"
                } else {
                    "clear"
                },
                identify.sanitize.crypto_scramble_supported,
                identify.sanitize.block_erase_supported,
                identify.security.enhanced_erase_supported,
                glist
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "unreported".to_string())
            ),
        );
        if identify.security.frozen {
            if args.cold_unfreeze {
                println!(
                    "[!] FREEZE LOCK active: with --cold-unfreeze the run will walk the \
                       cold-bus sysfs reset ladder (LUN delete + host rescan, ATA-port \
                       runtime-PM cycle) before arming."
                );
            } else {
                println!(
                    "[!] FREEZE LOCK active: the purge will refuse at intake. Power-cycle \
                       the host without firmware re-freeze (hot-plug or a non-freezing \
                       controller) and retry — or re-run with --cold-unfreeze for the \
                       autonomous sysfs reset ladder."
                );
            }
        }
        return Ok(());
    }

    let expected_token = confirm_destructive_purge(
        &args,
        &identity,
        &requested
            .map(|m| m.label().to_string())
            .unwrap_or_else(|| "auto (sanitize -> security-erase ladder)".to_string()),
    )?;

    let _lock = Guardian::arm_and_lock(&args.target, &identity.stable)?;
    let timestamp_str = chrono_now_iso();
    let keypair = match &args.key {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => OperatorKeyPair::generate(),
    };
    let (journal_path, mut journal) = create_purge_journal(
        &args,
        &identity,
        &expected_token,
        &keypair,
        "sat-sgio",
        &timestamp_str,
        ladder.clone(),
        &requested
            .map(|m| m.label().to_string())
            .unwrap_or_else(|| "auto".to_string()),
    )?;

    // Vector 4 pre-forensics: IDENTIFY firmware string + Device
    // Statistics wear snapshots (best-effort; absence is disclosed).
    let forensics_pre = TransportForensics::capture_ata(&mut sat).ok();

    if !args.no_progress {
        println!(
            "[>] Executing the ATA purge ladder on {} (sanitize progress is \
             polled from the Sanitize Status log 0x30)...",
            args.target.display()
        );
    }
    let started = std::time::Instant::now();
    let permit = AtaPurgePermit::mint(
        &args.target.to_string_lossy(),
        identity.stable.serial.as_deref().unwrap_or(""),
        now_unix(),
    );

    let no_progress = args.no_progress;
    let thermal_shared: Option<std::rc::Rc<std::cell::RefCell<PurgeThermalMonitor>>> =
        if args.no_thermal_guard {
            None
        } else {
            Some(std::rc::Rc::new(std::cell::RefCell::new(
                PurgeThermalMonitor::new(thermal_limits_from_args(&args), &identity.kernel_name),
            )))
        };
    let sink_thermal = thermal_shared.clone();
    let summary = {
        let client = AtaPurgeClient::new(&mut sat).with_progress_sink(move |permille| {
            if !no_progress {
                eprint!(
                    "\r    sanitize progress: {:>3}.{}%   ",
                    permille / 10,
                    permille % 10
                );
            }
            // Thermal pacing between Sanitize Status polls (Vector 2).
            if let Some(monitor) = sink_thermal.as_ref() {
                monitor.borrow_mut().on_poll();
            }
        });
        client.execute_purge_ladder(&permit, requested)
    };

    let summary = match summary {
        Ok(s) => s,
        Err(dc_ata::purge::AtaPurgeError::EraseFailedLockedDisclosed {
            detail,
            rescue_password,
        }) => {
            let _ = journal.append(&dc_core::JournalRecord::Failed {
                code: "PURGE_FAILED_LIFELINE_DISCLOSED".to_string(),
                errno: None,
                op: Some("SecurityEraseUnit".to_string()),
                at_lba: None,
                detail: format!(
                    "{} — RESCUE LIFELINE PASSWORD (unlock with `hdparm --security-unlock \
                     --user user {} <dev>` then retry): {}",
                    detail, rescue_password, rescue_password
                ),
            });
            eprintln!("\n[!!!] SECURITY ERASE FAILED — DRIVE MAY BE LOCKED");
            eprintln!("[!!!] RESCUE LIFELINE PASSWORD: {}", rescue_password);
            eprintln!(
                "[!!!] Unlock with: hdparm --security-unlock --user user {} {}   then re-run.",
                rescue_password,
                args.target.display()
            );
            return Err(DcError::Guardian(dc_core::GuardianRefusal {
                code: "PURGE_FAILED_LIFELINE_DISCLOSED",
                detail: format!(
                    "{} — the rescue lifeline password is disclosed above and journaled",
                    detail
                ),
                hint: "unlock the drive with the disclosed lifeline and re-run".to_string(),
            }));
        }
        Err(dc_ata::purge::AtaPurgeError::Fatal(reason)) => {
            let _ = journal.append(&dc_core::JournalRecord::Failed {
                code: "PURGE_FAILED".to_string(),
                errno: None,
                op: Some("ata-ladder".to_string()),
                at_lba: None,
                detail: reason.clone(),
            });
            return Err(DcError::Guardian(dc_core::GuardianRefusal {
                code: "PURGE_FAILED",
                detail: reason,
                hint: "media state is UNTRUSTED — re-run or fall back to `dc execute`".to_string(),
            }));
        }
    };

    let outcome = PurgeRunOutcome {
        executed_mechanism: summary.executed_mechanism.label().to_string(),
        fallbacks: summary
            .fallbacks
            .iter()
            .map(|f| PurgeFallbackRecord {
                from: f.from.clone(),
                to: f.to.clone(),
                reason: f.reason.clone(),
            })
            .collect(),
        completion_evidence: match summary.completion_evidence {
            dc_ata::purge::AtaCompletionEvidence::SanitizeStatusLog => {
                "ata-sanitize-status-log-0x30".to_string()
            }
            dc_ata::purge::AtaCompletionEvidence::BlockingEraseReturn => {
                "blocking-erase-return".to_string()
            }
        },
        progress_permille: summary.progress_permille,
        readback_expectation: "VendorRandom".to_string(),
        controller_device: args.target.to_string_lossy().to_string(),
        operator_notes: {
            let mut notes = Vec::new();
            if !summary.lifeline_id.is_empty() && summary.lifeline_voided {
                notes.push(format!(
                    "Security-erase lifeline {} was structurally voided upon clean completion \
                     (no rescue password remains).",
                    summary.lifeline_id
                ));
            }
            if !summary.geometry.stages.is_empty() {
                notes.push(format!(
                    "Geometry restoration applied {} stage(s); hidden capacity is covered \
                     by the purge (three-capacity evidence in journal).",
                    summary.geometry.stages.len()
                ));
            }
            for step in &coldbus_steps {
                notes.push(format!(
                    "Cold-bus step {} executed: {} sysfs write(s) — {}",
                    step.step,
                    step.sysfs_writes.len(),
                    step.outcome
                ));
            }
            notes
        },
        duration_ms: started.elapsed().as_millis() as u64,
        coldbus_steps: coldbus_steps.clone(),
        thermal_report: thermal_shared.as_ref().and_then(|t| t.borrow().report()),
    };

    // Thermal critical: refuse certification (v0.7.0, Vector 2).
    if let Some(monitor) = thermal_shared.as_ref() {
        let monitor = monitor.borrow();
        if monitor.critical.is_some() {
            let _ = journal.append(&dc_core::JournalRecord::Failed {
                code: "THERMAL_CRITICAL".to_string(),
                errno: None,
                op: Some("thermal-monitor".to_string()),
                at_lba: None,
                detail: format!(
                    "drive temperature reached the critical limit (max {} C); the purge \
                     may have completed but certification is refused",
                    monitor.max_temperature_c.unwrap_or(0)
                ),
            });
            return Err(DcError::Guardian(dc_core::GuardianRefusal {
                code: "THERMAL_CRITICAL",
                detail: format!(
                    "drive temperature reached the critical limit (max observed {} C) — \
                     refusing to certify the purge",
                    monitor.max_temperature_c.unwrap_or(0)
                ),
                hint: "let the drive cool, verify media state, and re-run the purge".to_string(),
            }));
        }
    }

    // Vector 4 post-forensics + evidence assembly.
    let forensics_post = TransportForensics::capture_ata(&mut sat).ok();
    let devstat_pre_raw = forensics_pre
        .as_ref()
        .map(|f| f.devstat_raw.clone())
        .unwrap_or_default();
    let devstat_post_raw = forensics_post
        .as_ref()
        .map(|f| f.devstat_raw.clone())
        .unwrap_or_default();
    let firmware = forensics_pre
        .zip(forensics_post)
        .map(|(pre, post)| TransportForensics::into_evidence(pre, post));
    let mut extra_attachments: Vec<(String, Vec<u8>, &'static str)> = Vec::new();
    if !devstat_pre_raw.is_empty() {
        extra_attachments.push((
            "ata-devstat-pre.bin".to_string(),
            devstat_pre_raw,
            "application/octet-stream",
        ));
    }
    if !devstat_post_raw.is_empty() {
        extra_attachments.push((
            "ata-devstat-post.bin".to_string(),
            devstat_post_raw,
            "application/octet-stream",
        ));
    }

    assemble_purge_certificate(
        &args,
        &identity,
        &expected_token,
        &outcome.executed_mechanism,
        &outcome,
        &keypair,
        &mut journal,
        &journal_path,
        &timestamp_str,
        Vec::new(),
        None,
        match summary.completion_evidence {
            dc_ata::purge::AtaCompletionEvidence::SanitizeStatusLog => {
                "Controller-attested (ata-sanitize-status-log-0x30)"
            }
            dc_ata::purge::AtaCompletionEvidence::BlockingEraseReturn => {
                "Controller-attested (blocking-erase-return)"
            }
        },
        firmware,
        &extra_attachments,
    )?;

    if let Some(a) = audit {
        let _ = a.log(&AuditRecord {
            timestamp_utc: chrono_now_iso(),
            argv_hash: "purge".to_string(),
            target_path: Some(args.target.to_string_lossy().to_string()),
            outcome: AuditOutcome::Executed {
                journal_path: journal_path.to_string_lossy().to_string(),
                chain_head: journal.current_chain_head(),
            },
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SAS / SCSI runner (v0.6.0)
// ---------------------------------------------------------------------------

fn run_scsi_purge(
    args: PurgeArgs,
    identity: DeviceIdentity,
    audit: &mut Option<AuditLogger>,
) -> Result<(), DcError> {
    let mut scsi = LinuxScsiPurge::open(&args.target).map_err(|e| {
        DcError::Guardian(dc_core::GuardianRefusal {
            code: "PURGE_TRANSPORT_UNAVAILABLE",
            detail: format!(
                "cannot open {} for SG_IO native SCSI transport: {}",
                args.target.display(),
                e
            ),
            hint: "run as root; SAS targets are addressed through the block node \
                   (/dev/sg* is refused by design)"
                .to_string(),
        })
    })?;

    // SBC provides no non-destructive sanitize-capability query: the
    // planning ladder is conservatively FORMAT UNIT, and the runtime
    // ladder (SANITIZE crypto -> block erase -> FORMAT UNIT) attests
    // itself by controller acceptance; the certificate records what ran.
    let sanitize_live = false;
    let caps = dc_core::AttestedCapabilities {
        supports_sanitize_crypto: sanitize_live,
        supports_sanitize_block: sanitize_live,
        supports_format_nvm: false,
        supports_ata_security_enhanced: false,
        supports_dco_hpa: false,
        supports_scsi_sanitize: sanitize_live,
    };
    let ladder =
        StrategyCompiler::compile_strategy(dc_core::DeviceTransportClass::ScsiSas, &caps, true)
            .map_err(DcError::Usage)?;

    let requested = match crate::purge::parse_mechanism(&args.mechanism)? {
        crate::purge::RequestedMechanism::SanitizeCrypto => {
            Some(ScsiPurgeMechanism::SanitizeCryptoErase)
        }
        crate::purge::RequestedMechanism::SanitizeBlock => {
            Some(ScsiPurgeMechanism::SanitizeBlockErase)
        }
        crate::purge::RequestedMechanism::FormatUnit => Some(ScsiPurgeMechanism::FormatUnit),
        _ => None,
    };

    if args.dry_run {
        let glist = ScsiPurgeClient::new(&mut scsi).read_grown_defects().ok();
        print_dry_run(
            &identity,
            &args.target.to_string_lossy(),
            &requested
                .map(|m| m.label().to_string())
                .unwrap_or_else(|| "auto (sanitize -> format-unit ladder)".to_string()),
            &ladder,
            &format!(
                "SG_IO over {} | sanitize: attests at execution (no non-destructive \
                 SBC query) | grown defects: {}",
                args.target.display(),
                glist
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "unreported".to_string())
            ),
        );
        return Ok(());
    }

    let expected_token = confirm_destructive_purge(
        &args,
        &identity,
        &requested
            .map(|m| m.label().to_string())
            .unwrap_or_else(|| "auto (sanitize -> format-unit ladder)".to_string()),
    )?;

    let _lock = Guardian::arm_and_lock(&args.target, &identity.stable)?;
    let timestamp_str = chrono_now_iso();
    let keypair = match &args.key {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => OperatorKeyPair::generate(),
    };
    let (journal_path, mut journal) = create_purge_journal(
        &args,
        &identity,
        &expected_token,
        &keypair,
        "scsi-sgio",
        &timestamp_str,
        ladder.clone(),
        &requested
            .map(|m| m.label().to_string())
            .unwrap_or_else(|| "auto".to_string()),
    )?;

    // Vector 4 pre-forensics: INQUIRY identity (vendor/product/revision).
    let forensics_pre = TransportForensics::capture_scsi(&mut scsi).ok();

    if !args.no_progress {
        println!(
            "[>] Executing the SCSI purge ladder on {} (progress is polled from \
             REQUEST SENSE: key 0x02 / ASC 0x04 with SKS progress)...",
            args.target.display()
        );
    }
    let started = std::time::Instant::now();
    let permit = ScsiPurgePermit::mint(
        &args.target.to_string_lossy(),
        identity
            .stable
            .wwn
            .as_deref()
            .unwrap_or_else(|| identity.stable.serial.as_deref().unwrap_or("")),
        now_unix(),
    );

    let no_progress = args.no_progress;
    let thermal_shared: Option<std::rc::Rc<std::cell::RefCell<PurgeThermalMonitor>>> =
        if args.no_thermal_guard {
            None
        } else {
            Some(std::rc::Rc::new(std::cell::RefCell::new(
                PurgeThermalMonitor::new(thermal_limits_from_args(&args), &identity.kernel_name),
            )))
        };
    let sink_thermal = thermal_shared.clone();
    let summary = {
        let client = ScsiPurgeClient::new(&mut scsi).with_progress_sink(move |permille| {
            if !no_progress {
                eprint!(
                    "\r    sanitize progress: {:>3}.{}%   ",
                    permille / 10,
                    permille % 10
                );
            }
            // Thermal pacing between sense polls (Vector 2).
            if let Some(monitor) = sink_thermal.as_ref() {
                monitor.borrow_mut().on_poll();
            }
        });
        client.execute_purge_ladder(&permit, requested)
    };

    let summary = match summary {
        Ok(s) => s,
        Err(reason) => {
            let _ = journal.append(&dc_core::JournalRecord::Failed {
                code: "PURGE_FAILED".to_string(),
                errno: None,
                op: Some("scsi-ladder".to_string()),
                at_lba: None,
                detail: reason.clone(),
            });
            return Err(DcError::Guardian(dc_core::GuardianRefusal {
                code: "PURGE_FAILED",
                detail: reason,
                hint: "media state is UNTRUSTED — re-run or fall back to `dc execute`".to_string(),
            }));
        }
    };

    let outcome = PurgeRunOutcome {
        executed_mechanism: summary.executed_mechanism.label().to_string(),
        fallbacks: summary
            .fallbacks
            .iter()
            .map(|f| PurgeFallbackRecord {
                from: f.from.clone(),
                to: f.to.clone(),
                reason: f.reason.clone(),
            })
            .collect(),
        completion_evidence: match summary.completion_evidence {
            dc_scsi::purge::ScsiCompletionEvidence::SensePollTerminal => {
                "scsi-sense-poll-terminal".to_string()
            }
            dc_scsi::purge::ScsiCompletionEvidence::BlockingFormatReturn => {
                "blocking-format-return".to_string()
            }
        },
        progress_permille: summary.progress_permille,
        readback_expectation: "VendorRandom".to_string(),
        controller_device: args.target.to_string_lossy().to_string(),
        operator_notes: Vec::new(),
        duration_ms: started.elapsed().as_millis() as u64,
        coldbus_steps: Vec::new(),
        thermal_report: thermal_shared.as_ref().and_then(|t| t.borrow().report()),
    };

    // Thermal critical: refuse certification (v0.7.0, Vector 2).
    if let Some(monitor) = thermal_shared.as_ref() {
        let monitor = monitor.borrow();
        if monitor.critical.is_some() {
            let _ = journal.append(&dc_core::JournalRecord::Failed {
                code: "THERMAL_CRITICAL".to_string(),
                errno: None,
                op: Some("thermal-monitor".to_string()),
                at_lba: None,
                detail: format!(
                    "drive temperature reached the critical limit (max {} C); the purge \
                     may have completed but certification is refused",
                    monitor.max_temperature_c.unwrap_or(0)
                ),
            });
            return Err(DcError::Guardian(dc_core::GuardianRefusal {
                code: "THERMAL_CRITICAL",
                detail: format!(
                    "drive temperature reached the critical limit (max observed {} C) — \
                     refusing to certify the purge",
                    monitor.max_temperature_c.unwrap_or(0)
                ),
                hint: "let the drive cool, verify media state, and re-run the purge".to_string(),
            }));
        }
    }

    // Vector 4 post-forensics: re-run INQUIRY for the firmware identity.
    let forensics_post = TransportForensics::capture_scsi(&mut scsi).ok();
    let firmware = forensics_pre
        .zip(forensics_post)
        .map(|(pre, post)| TransportForensics::into_evidence(pre, post));

    assemble_purge_certificate(
        &args,
        &identity,
        &expected_token,
        &outcome.executed_mechanism,
        &outcome,
        &keypair,
        &mut journal,
        &journal_path,
        &timestamp_str,
        Vec::new(),
        None,
        match summary.completion_evidence {
            dc_scsi::purge::ScsiCompletionEvidence::SensePollTerminal => {
                "Controller-attested (scsi-sense-poll-terminal)"
            }
            dc_scsi::purge::ScsiCompletionEvidence::BlockingFormatReturn => {
                "Controller-attested (blocking-format-return)"
            }
        },
        firmware,
        &[],
    )?;

    if let Some(a) = audit {
        let _ = a.log(&AuditRecord {
            timestamp_utc: chrono_now_iso(),
            argv_hash: "purge".to_string(),
            target_path: Some(args.target.to_string_lossy().to_string()),
            outcome: AuditOutcome::Executed {
                journal_path: journal_path.to_string_lossy().to_string(),
                chain_head: journal.current_chain_head(),
            },
        });
    }
    Ok(())
}
