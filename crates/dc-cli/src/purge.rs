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
use dc_ata::purge::{AtaPurgeClient, AtaPurgeMechanism, AtaPurgePermit, LinuxSatPurge};
use dc_cert::{
    ExecutionDetails, HealthSnapshotEvidence, OperatorKeyPair, PurgeCertificateEvidence,
    PurgeFallbackRecord, SanitizationCertificate,
};
use dc_core::{
    AuditLogger, AuditOutcome, AuditRecord, BusType, DcError, DeviceIdentity, EngineTuning,
    FsmOrchestrator, Mechanism, SanitizationPlan, StrategyCompiler, StrategyLadder, ToolBuild,
    VerifyLevel,
};
use dc_io::Engine as _;
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
}

pub fn cmd_purge(args: PurgeArgs, audit: &mut Option<AuditLogger>) -> Result<(), DcError> {
    let requested = parse_mechanism(&args.mechanism)?;
    let identity = InventoryScanner::probe_device_or_refuse(&args.target)?;

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
    cert.sign(keypair)?;

    let cert_json = serde_json::to_string_pretty(&cert)?;
    let stem = format!(
        "{}-purge-{}",
        expected_token.replace('/', "_"),
        timestamp_str.replace(':', "-")
    );
    let cert_path = args.out_dir.join(format!("{}.cert.json", stem));
    std::fs::write(&cert_path, &cert_json)?;

    // ISO 19005-3 (PDF/A-3) archival copy: certificate + journal embedded
    // as verifiable attachments (v0.6.0).
    let journal_bytes = std::fs::read(journal_path).unwrap_or_default();
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
        &[
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
        ],
        &outcome.operator_notes,
        &finished_time_str,
        &[
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
        ],
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
    let summary = NvmePurgeClient::new(&mut admin)
        .with_poll_budget(24 * 60 * 4, Duration::from_millis(250)) // up to 24h of polling
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
    };

    let health = health_pre
        .as_ref()
        .zip(health_post.as_ref())
        .map(|(pre, post)| (health_evidence(pre), health_evidence(post)));
    let verify_note = if summary.executed_mechanism == PurgeMechanism::FormatNvmCryptoErase {
        "Sampled (1-in-64) zero read-back + controller-attested"
    } else {
        "Controller-attested (sanitize-status-log)"
    };

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
    let mut sat = LinuxSatPurge::open(&args.target).map_err(|e| {
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
    })?;

    let identify = AtaPurgeClient::new(&mut sat).identify().map_err(|e| {
        DcError::Guardian(dc_core::GuardianRefusal {
            code: "PURGE_IDENTIFY_FAILED",
            detail: format!("SAT IDENTIFY DEVICE failed: {}", e),
            hint: "the drive or bridge did not answer the identify command".to_string(),
        })
    })?;

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
            println!(
                "[!] FREEZE LOCK active: the purge will refuse at intake. Power-cycle \
                   the host without firmware re-freeze (hot-plug or a non-freezing \
                   controller) and retry."
            );
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
    let summary = {
        let client = AtaPurgeClient::new(&mut sat).with_progress_sink(move |permille| {
            if !no_progress {
                eprint!(
                    "\r    sanitize progress: {:>3}.{}%   ",
                    permille / 10,
                    permille % 10
                );
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
            notes
        },
        duration_ms: started.elapsed().as_millis() as u64,
    };

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
    let summary = {
        let client = ScsiPurgeClient::new(&mut scsi).with_progress_sink(move |permille| {
            if !no_progress {
                eprint!(
                    "\r    sanitize progress: {:>3}.{}%   ",
                    permille / 10,
                    permille % 10
                );
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
    };

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
