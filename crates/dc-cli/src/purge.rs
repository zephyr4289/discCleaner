//! `dc purge` — controller-attested NVMe hardware purge.
//!
//! Executes the NVMe purge ladder (Sanitize Crypto Erase -> Sanitize Block
//! Erase -> Format NVM Crypto Erase) through the REAL admin ioctl transport,
//! with two-officer-grade evidence: Sanitize Status Log 0x81 completion,
//! blocking Format NVM return, pre/post SMART-health snapshots, and a signed
//! certificate. A crypto erase destroys the media encryption key: seconds of
//! work instead of hours of overwrite traffic — this is the NIST SP 800-88
//! "Purge" action performed by the controller itself.
//!
//! Fail-closed rules:
//! - Refuses non-NVMe targets (SATA security-erase is a separate ladder).
//! - Refuses when the controller attests no hardware purge mechanism.
//! - Format NVM crypto-erase results are additionally sampled-verified
//!   against the ladder's "Zeros" expectation; mismatch = hard failure.
//! - Sanitize (VendorRandom) completion is evidenced ONLY by Log 0x81
//!   terminal status; the certificate says exactly that, never more.

use crate::{PurgeArgs, chrono_now_iso, cli_signal_injection, signal_was_seen};
use dc_cert::{
    ExecutionDetails, HealthSnapshotEvidence, OperatorKeyPair, PurgeCertificateEvidence,
    PurgeFallbackRecord, SanitizationCertificate,
};
use dc_core::{
    AttestedCapabilities, AuditLogger, AuditOutcome, AuditRecord, BusType, DcError, DeviceIdentity,
    EngineTuning, FsmOrchestrator, Mechanism, SanitizationPlan, StrategyCompiler, StrategyLadder,
    ToolBuild, VerifyLevel,
};
use dc_io::Engine as _;
use dc_nvme::purge::{NvmePurgeClient, PurgeExecutionSummary, PurgeMechanism};
use dc_nvme::{
    HealthSnapshot, LinuxNvmeAdmin, attest_capabilities, controller_char_dev_for,
    identify_controller, read_health,
};
use dc_probe::{Guardian, GuardianFlags, InventoryScanner};
use dc_verify::StreamVerifier;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Compile the hardware purge ladder for a target, attesting capabilities
/// from the controller when possible. Returns None when the target is not
/// NVMe or the controller char device cannot be read (no fabricated ladders).
pub fn compile_target_ladder(identity: &DeviceIdentity) -> Option<StrategyLadder> {
    if identity.stable.bus != BusType::Nvme {
        return None;
    }
    let ctrl = controller_char_dev_for(Path::new(&identity.dev_path));
    let mut admin = LinuxNvmeAdmin::open(&ctrl).ok()?;
    let id = identify_controller(&mut admin).ok()?;
    let caps = attest_capabilities(&id);
    StrategyCompiler::compile_strategy(dc_core::DeviceTransportClass::Nvme, &caps, true).ok()
}

fn parse_mechanism(spec: &str) -> Result<Option<PurgeMechanism>, DcError> {
    match spec {
        "auto" => Ok(None),
        "sanitize-crypto" => Ok(Some(PurgeMechanism::SanitizeCryptoErase)),
        "sanitize-block" => Ok(Some(PurgeMechanism::SanitizeBlockErase)),
        "format-crypto" => Ok(Some(PurgeMechanism::FormatNvmCryptoErase)),
        other => Err(DcError::Usage(format!(
            "unknown --mechananism '{}': expected auto | sanitize-crypto | sanitize-block | format-crypto",
            other
        ))),
    }
}

fn primary_mechanism_for(caps: &AttestedCapabilities) -> Option<PurgeMechanism> {
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

fn purge_evidence(
    summary: &PurgeExecutionSummary,
    readback_expectation: &str,
    controller_dev: &str,
) -> PurgeCertificateEvidence {
    use dc_nvme::purge::CompletionEvidence;
    PurgeCertificateEvidence {
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
            CompletionEvidence::SanitizeStatusLog => "sanitize-status-log".to_string(),
            CompletionEvidence::BlockingFormatReturn => "blocking-format-return".to_string(),
        },
        sanitize_progress_permille: summary.status.progress_permille,
        readback_expectation: readback_expectation.to_string(),
        controller_device: controller_dev.to_string(),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    // NVMe-only ladder (SATA security erase is a separate command surface).
    if identity.stable.bus != BusType::Nvme {
        return Err(DcError::Guardian(dc_core::GuardianRefusal {
            code: "PURGE_NVME_ONLY",
            detail: format!(
                "target {} is on bus {}, but the hardware purge ladder is compiled for \
                 NVMe controllers (Sanitize / Format NVM)",
                args.target.display(),
                identity.stable.bus
            ),
            hint: "for SATA/SAS media use `dc execute` (logical overwrite, verified), or \
                   attach the drive behind an NVMe bridge."
                .to_string(),
        }));
    }

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

    let primary = match requested {
        Some(m) => m,
        None => primary_mechanism_for(&caps).ok_or_else(|| {
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

    // Dry run: print the attested ladder and exit before any confirmation.
    if args.dry_run {
        println!(
            "================================================================================"
        );
        println!("               HARDWARE PURGE PLAN — DRY RUN (NO WRITES)");
        println!(
            "================================================================================"
        );
        println!("Target Device:     {}", identity.dev_path);
        println!(
            "Controller:        {} (serial {})",
            ctrl_path.display(),
            id_ctrl.sn
        );
        println!("Model:             {}", id_ctrl.mn);
        println!("Namespace (NSID):  {}", nsid);
        println!("Selected Mechanism: {:?}", primary);
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("Attested purge strategy ladder:");
        for (i, step) in ladder.steps.iter().enumerate() {
            println!(
                "  {:>2}. {:<28} NIST class: {:<6} read-back: {}",
                i + 1,
                step.name,
                step.nist_class,
                step.readback_expectation
            );
        }
        println!(
            "================================================================================"
        );
        println!("DRY RUN COMPLETE: nothing was purged, no journal was created.");
        println!(
            "================================================================================"
        );
        return Ok(());
    }

    let health_pre = read_health(&mut admin).ok();

    // Confirmation (same discipline as execute).
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
        println!("  Mechanism:      {:?}", primary);
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

    // Arm + lock the block node (O_EXCL), then journal.
    let lock = Guardian::arm_and_lock(&args.target, &identity.stable)?;

    let timestamp_str = chrono_now_iso();
    let journal_filename = format!(
        "{}-purge-{}.dcj",
        expected_token.replace('/', "_"),
        timestamp_str.replace(':', "-")
    );
    let journal_path = args.out_dir.join(&journal_filename);

    let keypair = match &args.key {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => OperatorKeyPair::generate(),
    };
    let is_sealed = args.key.is_some();

    // The purge plan: mechanism = HardwarePurge, no logical passes, ladder
    // recorded, verification level reflects the evidence model below.
    let plan = SanitizationPlan {
        plan_schema: "dc-plan/1".to_string(),
        target: identity.stable.clone(),
        mechanism: Mechanism::HardwarePurge {
            ladder: ladder.clone(),
            selected_mechanism: format!("{:?}", primary),
        },
        verification: VerifyLevel::None, // controller-attested; readback below upgrades the record
        window_bytes: SanitizationPlan::DEFAULT_WINDOW_BYTES,
        fast_path: dc_core::FastPathPolicy::ForbidWriteZeroes,
        strategy_ladder: Some(ladder.clone()),
        legacy_note: None,
    };

    let mut fsm = FsmOrchestrator::new();
    let plan_hash = fsm.compile_plan(plan.clone())?;
    fsm.approve_plan()?;
    fsm.arm()?;

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
        engine: "nvme-admin".to_string(),
        tuning: EngineTuning {
            qd: 0,
            pool_mib: 0,
            window_bytes: plan.window_bytes,
            checkpoint_mib: 0,
            checkpoint_ms: 0,
        },
        argv_hash: "cli-purge".to_string(),
        started_utc: timestamp_str.clone(),
    })?;
    journal.append(&dc_core::JournalRecord::Armed {
        overrides: Vec::new(),
        locks_held: vec![format!(
            "{}:{}",
            identity.kernel.major, identity.kernel.minor
        )],
        at: chrono_now_iso(),
    })?;

    // Execute the purge ladder on the real controller.
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

    // Post-purge health + optional sampled zero read-back for format-crypto.
    let health_post = read_health(&mut admin).ok();
    // Read-back expectation mirrors the compiled ladder step semantics:
    // Format NVM crypto erase attests Zeros; Sanitize mechanisms return a
    // controller vendor pattern and are evidenced only by Log 0x81.
    let readback_expectation = match summary.executed_mechanism {
        PurgeMechanism::FormatNvmCryptoErase => "Zeros",
        _ => "VendorRandom",
    };

    let mut verifier_report = StreamVerifier::new(
        VerifyLevel::None,
        plan.window_bytes,
        identity.logical_block_size,
        false,
        false,
    )
    .finalize();

    let formatted = summary.executed_mechanism == PurgeMechanism::FormatNvmCryptoErase;
    if formatted {
        // Ladder expectation for Format NVM crypto erase is "Zeros":
        // sampled 1-in-64 zero read-back through the production engine.
        fsm.begin_verify()?;
        let span = dc_io::LbaSpan::new(
            identity.stable.size_bytes,
            identity.logical_block_size,
            plan.window_bytes,
        );
        let mut engine = dc_io::SyncEngine::new(lock.disk_file, plan.window_bytes as usize, false)?;
        let mut verifier = StreamVerifier::new(
            VerifyLevel::Sampled { stride: 64 },
            plan.window_bytes,
            identity.logical_block_size,
            false,
            true,
        );
        engine.read_verify(&dc_core::ZeroPattern, &span, 64, &mut verifier, &mut |_| {})?;
        verifier_report = verifier.finalize();
    } else {
        fsm.begin_verify()?;
    }

    journal.append(&dc_core::JournalRecord::Verify {
        level: if formatted {
            "Sampled (1-in-64) + controller-attested".to_string()
        } else {
            "Controller-attested (sanitize-status-log)".to_string()
        },
        windows_checked: verifier_report.windows_checked,
        mismatch_count: verifier_report.mismatch_count,
        first_mismatch_lbas: verifier_report.first_mismatch_lbas.clone(),
        stream_hash_blake3: verifier_report.stream_hash_blake3.clone(),
        stream_hash_sha256: verifier_report.stream_hash_sha256.clone(),
        fast_path_used: false,
    })?;

    if verifier_report.mismatch_count > 0 {
        journal.append(&dc_core::JournalRecord::Failed {
            code: "VERIFICATION_FAILED".to_string(),
            errno: None,
            op: Some("purge-readback".to_string()),
            at_lba: verifier_report.first_mismatch_lbas.first().copied(),
            detail: format!(
                "Format NVM crypto erase reported success but the sampled zero \
                 read-back found {} mismatching windows; the controller formats this \
                 media to a vendor pattern — evidence conflict, refusing to certify",
                verifier_report.mismatch_count
            ),
        })?;
        return Err(DcError::VerificationFailed {
            mismatches: verifier_report.mismatch_count,
            sample: verifier_report.first_mismatch_lbas,
        });
    }

    fsm.certify()?;

    let finished_time_str = chrono_now_iso();
    journal.append(&dc_core::JournalRecord::Completed {
        at: finished_time_str.clone(),
        duration_mono_ms: started.elapsed().as_millis() as u64,
    })?;

    let evidence = purge_evidence(&summary, readback_expectation, &ctrl_path.to_string_lossy());
    let mut cert = SanitizationCertificate::new(
        plan,
        plan_hash,
        identity.clone(),
        ExecutionDetails {
            started_utc: timestamp_str,
            finished_utc: finished_time_str,
            duration_mono_ms: started.elapsed().as_millis() as u64,
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
    .with_health(
        health_pre.as_ref().map(health_evidence),
        health_post.as_ref().map(health_evidence),
    );
    cert.sign(&keypair)?;

    let cert_path = args.out_dir.join(format!(
        "{}.cert.json",
        journal_filename.trim_end_matches(".dcj")
    ));
    std::fs::write(&cert_path, serde_json::to_string_pretty(&cert)?)?;

    if !args.no_progress {
        println!("\n{}", cert.render_summary());
        println!(
            "\n[+] Purge certificate written to: {}",
            cert_path.display()
        );
        println!(
            "[+] Journal written to:           {}",
            journal_path.display()
        );
    }

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
