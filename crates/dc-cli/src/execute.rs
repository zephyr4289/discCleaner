//! Multi-target parallel sanitization execution.
//!
//! Pipeline (per batch invocation):
//! 1. FAIL-FAST argument validation (seeds, verify flag, plan-target arity).
//! 2. ALL-OR-NOTHING PRECHECK: for every `--target`, in order: probe,
//!    plan-to-execute binding verification, Guardian evaluation, plan
//!    compilation. ANY refusal aborts the whole batch before a single device
//!    is armed, locked, or written.
//! 3. Dry run: print every compiled plan, exit 0 (REG-DRYRUN-BOUNDARY).
//! 4. Two-officer (2PI) gate across every plan hash.
//! 5. Batch confirmation: one interactive prompt listing every target with
//!    its token (comma-separated entry), or `--serial-confirm t1,t2,...`.
//! 6. ARM ALL: lock every device O_EXCL sequentially; any failure drops all
//!    held locks and aborts with nothing journaled.
//! 7. PARALLEL WIPE: one worker thread per device — own FSM, hash-chained
//!    journal, I/O engine, verification, and certificate. Per-device progress
//!    bars are multiplexed through an indicatif MultiProgress.
//! 8. Batch summary table + aggregate exit code.

use crate::profiles::{parse_seed_hex, parse_verify_flag};
use dc_cert::{
    AuthorizationSet, ExecutionDetails, ExecutionPassReport, OperatorKeyPair,
    SanitizationCertificate,
};
use dc_core::{
    AuditLogger, AuditOutcome, AuditRecord, DcError, DeviceIdentity, EngineTuning, FastPathPolicy,
    FsmOrchestrator, Mechanism, Pattern, SanitizationPlan, ToolBuild, VerifyLevel,
    create_pattern_source,
};
use dc_io::{LbaSpan, SyncEngine, UringEngine, create_engine};
use dc_probe::{Guardian, GuardianFlags, InventoryScanner, LayerStackDetector};
use dc_verify::StreamVerifier;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::{EngineChoice, ExecuteArgs, chrono_now_iso, cli_signal_injection, signal_was_seen};

/// Shared, immutable-per-run configuration (all devices).
pub struct ExecuteShared {
    pub engine: EngineChoice,
    pub checkpoint_mib: u64,
    pub checkpoint_ms: u64,
    pub no_progress: bool,
    pub sha256: bool,
    pub out_dir: PathBuf,
    pub journal_dir: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub allow_flags: Vec<&'static str>,
    pub multi: Option<MultiProgress>,
    pub audit: Arc<Mutex<Option<AuditLogger>>>,
    /// Thermal pacing limits (v0.7.0, Vector 2): the overwrite engine
    /// consults the governor per window via kernel hwmon.
    pub thermal_limits: dc_hw::ThermalLimits,
    /// v0.8.0 Vector 1: capture a TPM attestation quote into the cert.
    pub tpm_quote: bool,
    /// v0.8.0 Vector 1: refuse certification without a verified quote.
    pub tpm_quote_required: bool,
    /// v0.8.0 Vector 2: run the vault enclave for the verification chain.
    pub vault: bool,
    /// v0.8.0 Vector 2: require SEV/TDX memory encryption in the vault.
    pub vault_encrypted_required: bool,
}

/// A device that passed the all-or-nothing precheck.
pub struct DeviceJob {
    pub target: PathBuf,
    pub identity: DeviceIdentity,
    pub plan: SanitizationPlan,
    pub plan_hash: String,
    pub expected_token: String,
    /// Unique disambiguator for journal filenames within one batch.
    pub file_stem: String,
    /// Mandatory defense advisories (v0.6.0, REG-SMART-GLIST-DISCLOSURE):
    /// reallocated-sector / grown-defect disclosures carried into the
    /// certificate's signed payload.
    pub defense_warnings: Vec<String>,
}

/// Per-device result for the batch summary.
pub struct DeviceRunOutput {
    pub target: String,
    pub serial: String,
    pub ok: bool,
    pub error: Option<String>,
    pub cert_path: Option<PathBuf>,
    pub journal_path: Option<PathBuf>,
    pub duration_ms: u64,
    pub total_bytes_written: u64,
}

fn log_audit(audit: &Arc<Mutex<Option<AuditLogger>>>, record: AuditRecord) {
    if let Ok(mut guard) = audit.lock()
        && let Some(a) = guard.as_mut()
    {
        let _ = a.log(&record);
    }
}

/// Entry point for `dc execute` (single target = degenerate batch).
pub fn cmd_execute(args: ExecuteArgs, audit: &mut Option<AuditLogger>) -> Result<(), DcError> {
    let audit = Arc::new(Mutex::new(audit.take()));

    // ---------------------------------------------------------------
    // 1. FAIL-FAST argument validation
    // ---------------------------------------------------------------
    if args.target.is_empty() {
        return Err(DcError::Usage(
            "at least one --target is required".to_string(),
        ));
    }
    let multi_device = args.target.len() > 1;
    if args.plan.is_some() && multi_device {
        return Err(DcError::Usage(
            "--plan requires exactly one --target (a compiled plan binds to one device)"
                .to_string(),
        ));
    }
    let verify_override = match args.verify.as_deref() {
        Some(spec) => {
            if args.plan.is_some() {
                return Err(DcError::Usage(
                    "--verify cannot be combined with --plan: the compiled plan's \
                     verification level is authoritative (plan-hash binding)"
                        .to_string(),
                ));
            }
            let level = parse_verify_flag(spec).map_err(DcError::Usage)?;
            // DEFENSE PROFILE ENFORCEMENT GATE (v0.6.0,
            // REG-DEFENSE-SAMPLING-REFUSED): refuse lowered verification for
            // defense-mandated profiles before any device is probed or armed.
            crate::profiles::enforce_verification_policy(&args.profile.to_profile(), &level)
                .map_err(DcError::Usage)?;
            Some(level)
        }
        None => None,
    };
    let explicit_seed = match args.seed {
        Some(ref s) => parse_seed_hex(s, args.profile).map_err(DcError::Usage)?,
        None => None,
    };

    // ---------------------------------------------------------------
    // 2. ALL-OR-NOTHING PRECHECK (REG-MULTI-ARM-ALLORNOTHING)
    // ---------------------------------------------------------------
    let stdin_is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    if !stdin_is_tty && args.serial_confirm.is_none() && !args.dry_run {
        return Err(DcError::Guardian(dc_core::GuardianRefusal {
            code: "NON_INTERACTIVE_CONFIRM_REQUIRED",
            detail: "Refusing to run a destructive wipe from a non-interactive session \
                     without an explicit confirmation token"
                .to_string(),
            hint: "Re-run with `--serial-confirm <SERIAL|LOOPNAME>` (see `dc check` output), \
                   or run from an interactive terminal."
                .to_string(),
        }));
    }

    let fast_path = if args.no_write_zeroes {
        FastPathPolicy::ForbidWriteZeroes
    } else {
        FastPathPolicy::PreferWriteZeroes
    };

    let flags = GuardianFlags {
        allow_system_disk: args.allow_system_disk,
        serial_confirm: None, // validated at batch-confirmation step
        allow_loop: args.allow_loop,
        allow_inactive_signatures: args.allow_inactive_signatures,
        allow_member: args.allow_member,
    };

    let mut jobs: Vec<DeviceJob> = Vec::with_capacity(args.target.len());
    for target in &args.target {
        let identity = InventoryScanner::probe_device_or_refuse(target)?;

        // Plan-to-Execute binding (Δ49) — single-target only by arity check.
        if let Some(ref plan_path) = args.plan {
            let plan_content = std::fs::read_to_string(plan_path)?;
            let plan_from_file: SanitizationPlan =
                serde_json::from_str(&plan_content).map_err(|e| DcError::JournalCorrupt {
                    record_index: 0,
                    reason: format!("PLAN_TAMPERED: Invalid JSON: {}", e),
                })?;
            let computed_hash = plan_from_file.compute_plan_hash()?;
            let canonical_json = serde_jcs::to_string(&plan_from_file)?;
            let verify_hash = blake3::hash(canonical_json.as_bytes()).to_hex().to_string();
            if computed_hash != verify_hash {
                return Err(DcError::JournalCorrupt {
                    record_index: 0,
                    reason: "PLAN_TAMPERED".to_string(),
                });
            }
            if let Err(contradiction) = identity.stable.check_compatibility(&plan_from_file.target)
            {
                eprintln!("[ERROR] IDENTITY_DRIFT against plan: {}", contradiction);
                log_audit(
                    &audit,
                    AuditRecord {
                        timestamp_utc: chrono_now_iso(),
                        argv_hash: "execute".to_string(),
                        target_path: Some(identity.dev_path.clone()),
                        outcome: AuditOutcome::Refusal {
                            code: "IDENTITY_DRIFT".to_string(),
                            detail: contradiction.clone(),
                        },
                    },
                );
                return Err(DcError::IdentityDrift {
                    expected: plan_from_file.target,
                    observed: identity.stable,
                });
            }
        }

        if let Err(e) = Guardian::evaluate(target, &identity, &flags) {
            if let DcError::Guardian(ref g) = e {
                log_audit(
                    &audit,
                    AuditRecord {
                        timestamp_utc: chrono_now_iso(),
                        argv_hash: "execute".to_string(),
                        target_path: Some(identity.dev_path.clone()),
                        outcome: AuditOutcome::Refusal {
                            code: g.code.to_string(),
                            detail: g.detail.clone(),
                        },
                    },
                );
            }
            if multi_device {
                eprintln!(
                    "[ERROR] BATCH ABORTED: Guardian refused target {} — no device \
                     in this batch has been armed, locked, or written.",
                    target.display()
                );
            }
            return Err(e);
        }

        let plan = if let Some(ref plan_path) = args.plan {
            let plan_content = std::fs::read_to_string(plan_path)?;
            serde_json::from_str(&plan_content).map_err(|e| DcError::JournalCorrupt {
                record_index: 0,
                reason: format!("PLAN_TAMPERED: Invalid JSON: {}", e),
            })?
        } else {
            let mut p = SanitizationPlan::from_profile(
                args.profile.to_profile(),
                identity.stable.clone(),
                explicit_seed,
                fast_path,
                args.profile.to_profile().default_verification(),
            )?;
            if let Some(v) = verify_override {
                p.verification = v;
            }
            p
        };
        let plan_hash = plan.compute_plan_hash()?;

        let expected_token = identity
            .stable
            .dm_uuid
            .clone()
            .or(identity.stable.serial.clone())
            .unwrap_or_else(|| identity.kernel_name.clone());

        // Batch-unique journal stem: disambiguate same-serial siblings
        // (e.g. two LUNs of one enclosure) by kernel name.
        let file_stem = if multi_device {
            format!(
                "{}-{}",
                expected_token.replace('/', "_"),
                identity.kernel_name
            )
        } else {
            expected_token.replace('/', "_")
        };

        let defense_warnings = audit_target_glist(&identity);
        for warning in &defense_warnings {
            eprintln!("[DEFENSE_WARNING] {}", warning);
        }

        jobs.push(DeviceJob {
            target: target.clone(),
            identity,
            plan,
            plan_hash,
            expected_token,
            file_stem,
            defense_warnings,
        });
    }

    // ---------------------------------------------------------------
    // 3. DRY-RUN BOUNDARY (REG-DRYRUN-BOUNDARY)
    // ---------------------------------------------------------------
    if args.dry_run {
        print_dry_run(&jobs, &args, &audit);
        return Ok(());
    }

    // ---------------------------------------------------------------
    // 4. Two-officer approval gate (Δ448) across every plan hash
    // ---------------------------------------------------------------
    if let Some(ref auth_set_path) = args.auth_set {
        let auth_json = std::fs::read_to_string(auth_set_path)?;
        let auth_set: AuthorizationSet = serde_json::from_str(&auth_json).map_err(|e| {
            DcError::Usage(format!(
                "Invalid AuthorizationSet JSON '{}': {}",
                auth_set_path.display(),
                e
            ))
        })?;
        for job in &jobs {
            match auth_set.verify_pre_arm_authorization(&job.plan_hash, true) {
                Ok(custody) => {
                    println!(
                        "[+] Two-person authorization verified for {} (custody: {:?}).",
                        job.identity.dev_path, custody
                    );
                }
                Err(reason) => {
                    log_audit(
                        &audit,
                        AuditRecord {
                            timestamp_utc: chrono_now_iso(),
                            argv_hash: "execute".to_string(),
                            target_path: Some(job.identity.dev_path.clone()),
                            outcome: AuditOutcome::Refusal {
                                code: "AUTHORIZATION_INCOMPLETE".to_string(),
                                detail: format!("2PI gate refused: {}", reason),
                            },
                        },
                    );
                    return Err(DcError::Guardian(dc_core::GuardianRefusal {
                        code: "AUTHORIZATION_INCOMPLETE",
                        detail: format!("Two-person authorization gate refused: {}", reason),
                        hint: "Re-run `dc approve` with two distinct officer keys for this plan."
                            .to_string(),
                    }));
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // 5. Batch confirmation (interactive tokens OR --serial-confirm)
    // ---------------------------------------------------------------
    cli_signal_injection("prompt-wait");
    if signal_was_seen() {
        return Err(DcError::Interrupted {
            completed_through: None,
        });
    }

    if let Some(ref provided) = args.serial_confirm {
        // Comma-separated tokens, in the order the targets were given.
        let provided_tokens: Vec<String> =
            provided.split(',').map(|t| t.trim().to_string()).collect();
        if provided_tokens.len() != jobs.len() {
            return Err(DcError::Usage(format!(
                "--serial-confirm lists {} token(s) but {} target(s) were given; \
                 provide one token per target, comma-separated, in order",
                provided_tokens.len(),
                jobs.len()
            )));
        }
        for (job, provided) in jobs.iter().zip(provided_tokens.iter()) {
            if provided != &job.expected_token {
                log_audit(
                    &audit,
                    AuditRecord {
                        timestamp_utc: chrono_now_iso(),
                        argv_hash: "execute".to_string(),
                        target_path: Some(job.identity.dev_path.clone()),
                        outcome: AuditOutcome::Refusal {
                            code: "CONFIRM_MISMATCH".to_string(),
                            detail: format!(
                                "Provided token '{}' does not match expected '{}'",
                                provided, job.expected_token
                            ),
                        },
                    },
                );
                eprintln!(
                    "[ERROR] Confirmation token mismatch for {}: expected '{}', got '{}'",
                    job.identity.dev_path, job.expected_token, provided
                );
                return Err(DcError::Usage("Confirmation token mismatch".to_string()));
            }
        }
    } else {
        println!("\n[WARNING] YOU ARE ABOUT TO PERMANENTLY AND IRREVERSIBLY WIPE:");
        for job in &jobs {
            println!(
                "  {} {} ({} GiB) token: {}",
                job.identity.dev_path,
                job.identity.stable.model.as_deref().unwrap_or("Unknown"),
                job.identity.stable.size_bytes / (1024 * 1024 * 1024),
                job.expected_token
            );
        }
        let expected_list = jobs
            .iter()
            .map(|j| j.expected_token.as_str())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "\nType the confirmation token{} for ALL devices, comma-separated, in the \
             order listed above:\n  {}",
            if jobs.len() > 1 { "s" } else { "" },
            expected_list
        );

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(DcError::StdIo)?;

        let typed: Vec<String> = input
            .trim()
            .split(',')
            .map(|t| t.trim().to_string())
            .collect();
        let expected: Vec<String> = jobs.iter().map(|j| j.expected_token.clone()).collect();
        if typed != expected {
            log_audit(
                &audit,
                AuditRecord {
                    timestamp_utc: chrono_now_iso(),
                    argv_hash: "execute".to_string(),
                    target_path: None,
                    outcome: AuditOutcome::Refusal {
                        code: "CONFIRM_MISMATCH".to_string(),
                        detail: "Interactive token entry mismatch".to_string(),
                    },
                },
            );
            println!("Confirmation token mismatch. Aborting.");
            return Err(DcError::OperatorAbort);
        }
    }

    // B-PREARM boundary (Δ87).
    cli_signal_injection("pre-arm");
    if signal_was_seen() {
        return Err(DcError::Interrupted {
            completed_through: None,
        });
    }

    // ---------------------------------------------------------------
    // 6. ARM ALL (all-or-nothing; locks drop on scope exit)
    // ---------------------------------------------------------------
    struct ArmedJob {
        job: DeviceJob,
        lock: dc_probe::GuardianLockHandle,
    }
    let mut armed: Vec<ArmedJob> = Vec::with_capacity(jobs.len());
    for job in jobs {
        match Guardian::arm_and_lock(&job.target, &job.identity.stable) {
            Ok(lock) => armed.push(ArmedJob { job, lock }),
            Err(e) => {
                // Drop every lock taken so far — batch arming is atomic.
                drop(armed);
                eprintln!(
                    "[ERROR] BATCH ABORTED: could not exclusively lock target: {}. All \
                     previously held locks have been released; nothing was written.",
                    e
                );
                return Err(e);
            }
        }
    }

    // ---------------------------------------------------------------
    // 7. PARALLEL WIPE — one worker per device
    // ---------------------------------------------------------------
    let mut allow_flags = Vec::new();
    if args.allow_system_disk {
        allow_flags.push("allow-system-disk");
    }
    if args.allow_loop {
        allow_flags.push("allow-loop");
    }
    if args.allow_member {
        allow_flags.push("allow-member");
    }
    if args.allow_inactive_signatures {
        allow_flags.push("allow-inactive-signatures");
    }

    let engine_name = match args.engine {
        EngineChoice::Auto => "auto",
        EngineChoice::Uring => "uring",
        EngineChoice::Sync => "sync",
    };

    let shared = ExecuteShared {
        engine: args.engine,
        tpm_quote: args.tpm_quote,
        tpm_quote_required: args.tpm_quote_required,
        vault: args.vault,
        vault_encrypted_required: args.vault_encrypted_required,
        checkpoint_mib: args.checkpoint_mib,
        checkpoint_ms: args.checkpoint_ms,
        no_progress: args.no_progress,
        sha256: args.sha256,
        out_dir: args.out_dir.clone(),
        journal_dir: args.journal_dir.clone(),
        key: args.key.clone(),
        allow_flags,
        multi: (!args.no_progress).then(MultiProgress::new),
        audit: audit.clone(),
        thermal_limits: {
            let mut limits = dc_hw::ThermalLimits::default();
            if let Some(t) = args.thermal_throttle_c {
                limits.throttle_c = t;
            }
            if let Some(c) = args.thermal_critical_c {
                limits.critical_c = c;
            }
            limits
        },
    };

    let outputs: Vec<DeviceRunOutput> = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(armed.len());
        for armed_job in armed {
            let shared = &shared;
            handles.push(scope.spawn(move || {
                run_device_pipeline(armed_job.job, armed_job.lock, shared, engine_name)
            }));
        }
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| DeviceRunOutput {
                    target: "<worker panicked>".to_string(),
                    serial: String::new(),
                    ok: false,
                    error: Some("worker thread panicked".to_string()),
                    cert_path: None,
                    journal_path: None,
                    duration_ms: 0,
                    total_bytes_written: 0,
                })
            })
            .collect()
    });

    // ---------------------------------------------------------------
    // 8. Batch summary + aggregate exit code
    // ---------------------------------------------------------------
    if !args.no_progress || multi_device {
        println!(
            "\n================================================================================"
        );
        println!("                             BATCH SANITIZATION SUMMARY");
        println!(
            "================================================================================"
        );
        for out in &outputs {
            let status = if out.ok { "OK" } else { "FAILED" };
            println!(
                "  [{}] {:<16} {} ({} MiB/s avg){}",
                status,
                out.target,
                out.serial,
                if out.duration_ms > 0 {
                    (out.total_bytes_written as f64 / 1024.0 / 1024.0)
                        / (out.duration_ms as f64 / 1000.0)
                } else {
                    0.0
                },
                if let Some(ref e) = out.error {
                    format!(" — {}", e)
                } else {
                    String::new()
                }
            );
            if let Some(ref p) = out.cert_path {
                println!("         certificate: {}", p.display());
            }
        }
        println!(
            "================================================================================"
        );
    }

    if let Some(failed) = outputs.iter().find(|o| !o.ok) {
        return Err(DcError::Usage(format!(
            "batch completed with at least one failed device (first failure: {})",
            failed
                .error
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        )));
    }
    Ok(())
}

/// Per-device worker: everything from journal creation to certificate.
fn run_device_pipeline(
    job: DeviceJob,
    lock: dc_probe::GuardianLockHandle,
    shared: &ExecuteShared,
    engine_name: &str,
) -> DeviceRunOutput {
    let started = Instant::now();
    let dev_short = job
        .identity
        .dev_path
        .rsplit('/')
        .next()
        .unwrap_or("device")
        .to_string();

    let result = execute_device_inner(&job, lock, shared, engine_name, &dev_short);
    match result {
        Ok((cert_path, journal_path, bytes)) => DeviceRunOutput {
            target: job.identity.dev_path.clone(),
            serial: job.identity.stable.serial.clone().unwrap_or_default(),
            ok: true,
            error: None,
            cert_path: Some(cert_path),
            journal_path: Some(journal_path),
            duration_ms: started.elapsed().as_millis() as u64,
            total_bytes_written: bytes,
        },
        Err(e) => DeviceRunOutput {
            target: job.identity.dev_path.clone(),
            serial: job.identity.stable.serial.clone().unwrap_or_default(),
            ok: false,
            error: Some(e.to_string()),
            cert_path: None,
            journal_path: None,
            duration_ms: started.elapsed().as_millis() as u64,
            total_bytes_written: 0,
        },
    }
}

fn device_progress(
    shared: &ExecuteShared,
    dev_short: &str,
    total: u64,
    template: &str,
) -> Option<ProgressBar> {
    shared.multi.as_ref().map(|m| {
        let p = m.add(ProgressBar::new(total));
        p.set_style(
            ProgressStyle::default_bar()
                .template(template)
                .unwrap()
                .progress_chars("=>-"),
        );
        p.set_prefix(dev_short.to_string());
        p
    })
}

/// The device pipeline after arming. Errors are surfaced to the worker result;
/// journalling and audit are best-effort inside.
#[allow(clippy::too_many_lines)]
fn execute_device_inner(
    job: &DeviceJob,
    lock: dc_probe::GuardianLockHandle,
    shared: &ExecuteShared,
    engine_name: &str,
    dev_short: &str,
) -> Result<(PathBuf, PathBuf, u64), DcError> {
    let plan = &job.plan;
    let identity = &job.identity;

    let passes = match &plan.mechanism {
        Mechanism::LogicalOverwrite { passes } => passes.clone(),
        Mechanism::HardwarePurge {
            selected_mechanism, ..
        } => {
            return Err(DcError::Usage(format!(
                "plan targets a hardware purge ({}) — use `dc purge` for this device",
                selected_mechanism
            )));
        }
    };

    let mut fsm = FsmOrchestrator::new();
    fsm.compile_plan(plan.clone())?;
    fsm.approve_plan()?;
    fsm.arm()?;

    // Journal
    let timestamp_str = chrono_now_iso();
    let journal_dir = shared.journal_dir.as_ref().unwrap_or(&shared.out_dir);
    let journal_filename = format!("{}-{}.dcj", job.file_stem, timestamp_str.replace(':', "-"));
    let journal_path = journal_dir.join(&journal_filename);

    let keypair = match &shared.key {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => OperatorKeyPair::generate(),
    };
    let is_sealed = shared.key.is_some();
    let journal_uuid = format!("dcj-{}", timestamp_str.replace([':', '-', 'T', 'Z'], ""));

    let mut journal = dc_core::JournalWriter::create_new(
        &journal_path,
        journal_uuid.clone(),
        if is_sealed {
            Some(keypair.signing_key.clone())
        } else {
            None
        },
    )?;

    journal.append(&dc_core::JournalRecord::Header {
        uuid: journal_uuid.clone(),
        sealed: is_sealed,
        operator_pubkey: if is_sealed {
            Some(keypair.public_key_hex())
        } else {
            None
        },
        plan: plan.clone(),
        plan_hash: job.plan_hash.clone(),
        identity: identity.clone(),
        tool: ToolBuild::current(),
        engine: engine_name.to_string(),
        tuning: EngineTuning {
            qd: 64,
            pool_mib: 128,
            window_bytes: plan.window_bytes,
            checkpoint_mib: shared.checkpoint_mib,
            checkpoint_ms: shared.checkpoint_ms,
        },
        argv_hash: "cli-exec".to_string(),
        started_utc: timestamp_str.clone(),
    })?;

    journal.append(&dc_core::JournalRecord::Armed {
        overrides: shared.allow_flags.iter().map(|s| s.to_string()).collect(),
        locks_held: vec![format!(
            "{}:{}",
            identity.kernel.major, identity.kernel.minor
        )],
        at: chrono_now_iso(),
    })?;

    // Engine
    let span = LbaSpan::new(
        identity.stable.size_bytes,
        identity.logical_block_size,
        plan.window_bytes,
    );
    let supports_write_zeroes = LayerStackDetector::can_write_zeroes(&identity.kernel_name)
        && (plan.fast_path == FastPathPolicy::PreferWriteZeroes);

    let mut engine: Box<dyn dc_io::Engine> = match shared.engine {
        EngineChoice::Sync => Box::new(SyncEngine::new(
            lock.disk_file,
            plan.window_bytes as usize,
            supports_write_zeroes,
        )?),
        EngineChoice::Uring => Box::new(UringEngine::try_new(
            lock.disk_file,
            plan.window_bytes as usize,
            supports_write_zeroes,
            64,
        )?),
        EngineChoice::Auto => create_engine(
            lock.disk_file,
            plan.window_bytes as usize,
            supports_write_zeroes,
            64,
        )?,
    };

    let mut exec_passes = Vec::new();
    let exec_start_time = Instant::now();
    let mut total_bytes_written: u64 = 0;

    // THERMAL PACER (v0.7.0, Vector 2): every engine window consults the
    // governor through the kernel hwmon view — pacing delays sleep inside
    // the progress callback, and a critical temperature requests the same
    // global-cancel the signal handler uses (the engine drains, nothing
    // more is written, the run refuses certification).
    let mut pacer = dc_hw::ThermalPacer::new(
        shared.thermal_limits,
        &identity.kernel_name,
        std::time::Duration::from_secs(2),
    );
    if !pacer.hwmon_available() {
        eprintln!(
            "[THERMAL] note: no kernel hwmon temperature for {} — the thermal guard is \
             inert for this run (the kernel exposes no thermometer for it)",
            identity.kernel_name
        );
    }

    for (pass_idx, pass) in passes.iter().enumerate() {
        let permit = fsm.begin_pass(pass_idx as u8)?;
        let pat_source = create_pattern_source(&pass.pattern);

        journal.append(&dc_core::JournalRecord::BeginPass {
            pass: pass_idx as u8,
            pattern: pat_source.descriptor(),
            window_bytes: plan.window_bytes,
        })?;

        let pb = device_progress(
            shared,
            dev_short,
            span.total_windows(),
            "{spinner:.green} [{prefix}] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | {msg}",
        );

        let outcome_res = if matches!(pass.pattern, Pattern::Zero) && supports_write_zeroes {
            engine.zero_pass(&permit, pass_idx as u8, &span, 0, &mut |p| {
                if let Some(ref bar) = pb {
                    bar.set_position(p.windows_done);
                    bar.set_message(format!("{:.1} MiB/s", p.throughput_mib_s));
                }
                if !pacer.on_window_progress() {
                    dc_io::request_global_cancel();
                }
            })
        } else {
            engine.write_pass(
                &permit,
                pass_idx as u8,
                pat_source.as_ref(),
                &span,
                0,
                &mut |p| {
                    if let Some(ref bar) = pb {
                        bar.set_position(p.windows_done);
                        bar.set_message(format!("{:.1} MiB/s", p.throughput_mib_s));
                    }
                    if !pacer.on_window_progress() {
                        dc_io::request_global_cancel();
                    }
                },
            )
        };

        let outcome = match outcome_res {
            Ok(o) => o,
            Err(DcError::Interrupted { completed_through }) => {
                // THERMAL_CRITICAL (v0.7.0, Vector 2): the pacer requested
                // the global cancel — journal it as a media-health abort,
                // not a signal drain.
                if let Some((temp, limit)) = pacer.aborted {
                    let _ = journal.append(&dc_core::JournalRecord::Failed {
                        code: "THERMAL_CRITICAL".to_string(),
                        errno: None,
                        op: Some("write".to_string()),
                        at_lba: None,
                        detail: format!(
                            "drive temperature {} C reached the critical limit {} C — \
                             the engine drained to protect the media",
                            temp, limit
                        ),
                    });
                    return Err(DcError::Guardian(dc_core::GuardianRefusal {
                        code: "THERMAL_CRITICAL",
                        detail: format!(
                            "drive temperature {} C reached the critical limit {} C — \
                             the overwrite was drained to protect the media",
                            temp, limit
                        ),
                        hint: "let the drive cool and re-run (the journal records the \
                               last completed window)"
                            .to_string(),
                    }));
                }
                let (through_pass, through_window) = match completed_through {
                    Some((p, w)) => (Some(p), Some(w)),
                    None => (Some(pass_idx as u8), None),
                };
                let _ = journal.append(&dc_core::JournalRecord::Interrupted {
                    at: chrono_now_iso(),
                    hint: "Graceful drain on termination signal".to_string(),
                    completed_through_pass: through_pass,
                    completed_through_window: through_window,
                    signals_received: Some(crate::signals_received_count()),
                });
                return Err(DcError::Interrupted { completed_through });
            }
            Err(e) => {
                let (errno, at_lba) = match &e {
                    DcError::Io { errno, at_lba, .. } => (Some(*errno), *at_lba),
                    DcError::StdIo(io_err) => (io_err.raw_os_error(), None),
                    _ => (None, None),
                };
                let _ = journal.append(&dc_core::JournalRecord::Failed {
                    code: "EIO".to_string(),
                    errno,
                    op: Some("write".to_string()),
                    at_lba,
                    detail: e.to_string(),
                });
                log_audit(
                    &shared.audit,
                    AuditRecord {
                        timestamp_utc: chrono_now_iso(),
                        argv_hash: "execute".to_string(),
                        target_path: Some(job.target.to_string_lossy().to_string()),
                        outcome: AuditOutcome::Refusal {
                            code: "EIO".to_string(),
                            detail: e.to_string(),
                        },
                    },
                );
                return Err(e);
            }
        };

        if let Some(bar) = pb {
            bar.finish_with_message("Pass Completed");
        }

        journal.append(&dc_core::JournalRecord::RangeCommit {
            pass: pass_idx as u8,
            first_window: 0,
            num_windows: outcome.windows_written,
        })?;
        journal.append(&dc_core::JournalRecord::EndPass {
            pass: pass_idx as u8,
        })?;

        let elapsed_s = (outcome.duration_ms as f64 / 1000.0).max(0.001);
        let throughput_kib_s = ((outcome.bytes_written as f64 / 1024.0) / elapsed_s) as u64;
        total_bytes_written += outcome.bytes_written;

        exec_passes.push(ExecutionPassReport {
            index: pass_idx as u8,
            pattern: pat_source.descriptor().name,
            fast_path_used: outcome.fast_path_used,
            windows_written: outcome.windows_written,
            throughput_kib_s,
        });

        let flush_permit = fsm.begin_flush(pass_idx as u8)?;
        engine.flush(&flush_permit)?;
        journal.append(&dc_core::JournalRecord::Flushed {
            pass: pass_idx as u8,
        })?;
    }

    // ---------------------------------------------------------------
    // Verification phase (full / sampled / none)
    // ---------------------------------------------------------------
    fsm.begin_verify()?;
    let verify_level = plan.verification;
    let stride = verify_level.effective_stride();

    let verifier_report = match verify_level {
        VerifyLevel::None => {
            let verifier = StreamVerifier::new(
                VerifyLevel::None,
                plan.window_bytes,
                identity.logical_block_size,
                shared.sha256,
                false,
            );
            verifier.finalize()
        }
        _ => {
            let pb_verify = device_progress(
                shared,
                dev_short,
                span.total_windows(),
                "{spinner:.green} [{prefix}] [{elapsed_precise}] [{bar:40.green/white}] {pos}/{len} ({percent}%) | {msg}",
            );
            if !shared.no_progress {
                if let VerifyLevel::Sampled { stride } = verify_level {
                    println!(
                        "[{}] Performing SAMPLED (1-in-{}) read-back verification...",
                        dev_short, stride
                    );
                } else {
                    println!(
                        "[{}] Performing 100% Full LBA read-back verification & stream hashing...",
                        dev_short
                    );
                }
            }

            let last_pass = passes.last().expect("logical plan has passes");
            let verify_pat_source = create_pattern_source(&last_pass.pattern);
            let mut verifier = StreamVerifier::new(
                verify_level,
                plan.window_bytes,
                identity.logical_block_size,
                shared.sha256,
                true,
            );

            if let Err(e) = engine.read_verify(
                verify_pat_source.as_ref(),
                &span,
                stride,
                &mut verifier,
                &mut |p| {
                    if let Some(ref bar) = pb_verify {
                        bar.set_position(p.windows_done);
                        bar.set_message(format!("{:.1} MiB/s", p.throughput_mib_s));
                    }
                    if !pacer.on_window_progress() {
                        dc_io::request_global_cancel();
                    }
                },
            ) {
                match e {
                    DcError::Interrupted { completed_through } => {
                        let _ = journal.append(&dc_core::JournalRecord::Interrupted {
                            at: chrono_now_iso(),
                            hint: "Graceful drain on termination signal during verification"
                                .to_string(),
                            completed_through_pass: completed_through.map(|(p, _)| p),
                            completed_through_window: completed_through.map(|(_, w)| w),
                            signals_received: Some(crate::signals_received_count()),
                        });
                        return Err(DcError::Interrupted { completed_through });
                    }
                    e => {
                        let (errno, at_lba) = match &e {
                            DcError::Io { errno, at_lba, .. } => (Some(*errno), *at_lba),
                            DcError::StdIo(io_err) => (io_err.raw_os_error(), None),
                            _ => (None, None),
                        };
                        let _ = journal.append(&dc_core::JournalRecord::Failed {
                            code: "EIO".to_string(),
                            errno,
                            op: Some("verify-read".to_string()),
                            at_lba,
                            detail: e.to_string(),
                        });
                        return Err(e);
                    }
                }
            }
            if let Some(bar) = pb_verify {
                bar.finish_with_message("Verification Complete");
            }
            verifier.finalize()
        }
    };

    journal.append(&dc_core::JournalRecord::Verify {
        level: verify_level.short_tag(),
        windows_checked: verifier_report.windows_checked,
        mismatch_count: verifier_report.mismatch_count,
        first_mismatch_lbas: verifier_report.first_mismatch_lbas.clone(),
        stream_hash_blake3: verifier_report.stream_hash_blake3.clone(),
        stream_hash_sha256: verifier_report.stream_hash_sha256.clone(),
        fast_path_used: supports_write_zeroes,
    })?;

    if verifier_report.mismatch_count > 0 {
        journal.append(&dc_core::JournalRecord::Failed {
            code: "VERIFICATION_FAILED".to_string(),
            errno: None,
            op: Some("verify".to_string()),
            at_lba: verifier_report.first_mismatch_lbas.first().copied(),
            detail: format!(
                "Found {} mismatching windows",
                verifier_report.mismatch_count
            ),
        })?;
        return Err(DcError::VerificationFailed {
            mismatches: verifier_report.mismatch_count,
            sample: verifier_report.first_mismatch_lbas,
        });
    }

    fsm.certify()?;

    // B-VICTORY boundary (Δ83): past this point a signal does not abandon
    // the certificate — the media is sanitized and evidence must survive.
    cli_signal_injection("post-verify");

    let finished_time_str = chrono_now_iso();
    journal.append(&dc_core::JournalRecord::Completed {
        at: finished_time_str.clone(),
        duration_mono_ms: exec_start_time.elapsed().as_millis() as u64,
    })?;

    // Thermal statistics into the certificate (v0.7.0, Vector 2): max
    // observed temperature and total pacing time are evidence of media
    // stewardship; a paced run completed within thermal limits.
    let mut certificate_defense_warnings = job.defense_warnings.clone();
    if let Some(max_t) = pacer.max_temperature_c {
        certificate_defense_warnings.push(format!(
            "THERMAL_STEWARDSHIP: max observed drive temperature {} C, adaptive pacing \
             inserted {} ms of delay (throttle limit {} C, critical {} C).",
            max_t,
            pacer.paced_ms_total,
            shared.thermal_limits.throttle_c,
            shared.thermal_limits.critical_c
        ));
    }
    if let Some((temp, limit)) = pacer.aborted {
        certificate_defense_warnings.push(format!(
            "DEFENSE_WARNING: thermal abort at {} C (limit {} C) — the media state is \
             incomplete; re-run required (NIST SP 800-88 Rev 1).",
            temp, limit
        ));
    }

    let mut cert = SanitizationCertificate::new(
        plan.clone(),
        job.plan_hash.clone(),
        identity.clone(),
        ExecutionDetails {
            started_utc: timestamp_str,
            finished_utc: finished_time_str.clone(),
            duration_mono_ms: exec_start_time.elapsed().as_millis() as u64,
            interruptions: vec![],
            failures: vec![],
            passes: exec_passes,
        },
        verifier_report.clone(),
        journal.summary(),
        keypair.public_key_hex(),
        keypair.key_fingerprint_blake3(),
    )
    .with_defense_warnings(certificate_defense_warnings.clone());

    // ------------------------------------------------------------------
    // v0.8.0 evidence embedding (Vectors 1+2): TPM attestation quote and
    // the micro-KVM vault execution report with the HMAC verification
    // chain sealed over this run's plan + verification evidence.
    // ------------------------------------------------------------------
    let want_vault = shared.vault || shared.vault_encrypted_required;
    if shared.tpm_quote || shared.tpm_quote_required {
        match crate::quote::capture_for_certificate(shared.tpm_quote_required) {
            Ok(Some(bundle)) => {
                cert = cert.with_tpm_attestation(crate::quote::bundle_to_evidence(&bundle));
            }
            Ok(None) => {} // opportunistic: no TPM, disclosed by absence
            Err(e) => return Err(e),
        }
    }
    if want_vault {
        let requirement = if shared.vault_encrypted_required {
            dc_vault::VaultRequirement::EncryptedEnclave
        } else {
            dc_vault::VaultRequirement::Enclave
        };
        let mut session = dc_vault::VaultSession::execute(requirement)
            .map_err(|e| DcError::Internal(format!("{e}")))?;
        // Seal the binding records: plan identity + verification verdict.
        session
            .seal_record(format!("plan-hash:{}", job.plan_hash).as_bytes())
            .map_err(|e| DcError::Internal(format!("vault seal: {e}")))?;
        session
            .seal_record(
                format!(
                    "verify: checked={} mismatches={}",
                    verifier_report.windows_checked, verifier_report.mismatch_count
                )
                .as_bytes(),
            )
            .map_err(|e| DcError::Internal(format!("vault seal: {e}")))?;
        let report = session.report();
        cert = cert.with_vault_report(dc_cert::VaultReportEvidence {
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
    crate::hybridsign::sign_certificate(&mut cert, &keypair, shared.key.as_deref())?;

    let cert_filename = format!("{}.cert.json", journal_filename.trim_end_matches(".dcj"));
    let cert_path = shared.out_dir.join(&cert_filename);
    let cert_json = serde_json::to_string_pretty(&cert)?;
    std::fs::write(&cert_path, &cert_json)?;

    // ISO 19005-3 (PDF/A-3) archival copy: certificate + journal embedded
    // as verifiable attachments (v0.6.0).
    let mechanism_label = match &plan.mechanism {
        Mechanism::LogicalOverwrite { passes } => {
            format!("Logical Overwrite ({} passes)", passes.len())
        }
        Mechanism::HardwarePurge {
            selected_mechanism, ..
        } => {
            format!("Hardware Purge ({})", selected_mechanism)
        }
    };
    let journal_bytes = std::fs::read(&journal_path).unwrap_or_default();
    // v0.8.0 evidence field lines ride the archival front page.
    let mut visual_fields: Vec<(String, String)> = Vec::new();
    if let Some(tpm) = cert.tpm_attestation.as_ref() {
        visual_fields.extend(tpm.field_lines());
    }
    if let Some(vault) = cert.vault_report.as_ref() {
        visual_fields.extend(vault.field_lines());
    }
    let pdf_bytes = dc_report::render_sanitization_archive(
        if verifier_report.mismatch_count > 0 {
            "Sanitization Report — VERIFICATION FAILED"
        } else {
            "Certificate of Sanitization"
        },
        &format!(
            "{} — {}",
            mechanism_label,
            identity
                .stable
                .serial
                .as_deref()
                .unwrap_or("serial unknown")
        ),
        if plan.verification == dc_core::VerifyLevel::Full {
            "Clear"
        } else {
            "Clear (verified)"
        },
        verifier_report.mismatch_count == 0,
        &[
            (
                "Verification level".to_string(),
                plan.verification.to_string(),
            ),
            (
                "Windows checked".to_string(),
                verifier_report.windows_checked.to_string(),
            ),
            (
                "Stream hash (BLAKE3)".to_string(),
                verifier_report.stream_hash_blake3.clone(),
            ),
            ("Plan hash".to_string(), job.plan_hash.clone()),
            ("Operator key".to_string(), keypair.key_fingerprint_blake3()),
            (
                "Journal chain head".to_string(),
                journal.current_chain_head(),
            ),
        ]
        .into_iter()
        .chain(visual_fields)
        .collect::<Vec<_>>(),
        &certificate_defense_warnings,
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
    let pdf_path = shared
        .out_dir
        .join(format!("{}.pdf", journal_filename.trim_end_matches(".dcj")));
    std::fs::write(&pdf_path, pdf_bytes)?;

    if !shared.no_progress {
        println!("\n{}", cert.render_summary());
        println!("\n[+] Certificate written to: {}", cert_path.display());
        println!("[+] Journal written to:     {}", journal_path.display());
        println!("[+] PDF/A-3 archival copy:  {}", pdf_path.display());
    }

    log_audit(
        &shared.audit,
        AuditRecord {
            timestamp_utc: chrono_now_iso(),
            argv_hash: "execute".to_string(),
            target_path: Some(job.target.to_string_lossy().to_string()),
            outcome: AuditOutcome::Executed {
                journal_path: journal_path.to_string_lossy().to_string(),
                chain_head: journal.current_chain_head(),
            },
        },
    );

    Ok((cert_path, journal_path, total_bytes_written))
}

/// Dry-run output for the whole batch.
fn print_dry_run(jobs: &[DeviceJob], args: &ExecuteArgs, audit: &Arc<Mutex<Option<AuditLogger>>>) {
    println!("================================================================================");
    println!("                        DRY RUN — NO WRITES WILL BE PERFORMED");
    println!("================================================================================");
    for job in jobs {
        println!("Target Device:     {}", job.identity.dev_path);
        println!(
            "  Model:           {}",
            job.identity.stable.model.as_deref().unwrap_or("Unknown")
        );
        println!(
            "  Serial:          {}",
            job.identity.stable.serial.as_deref().unwrap_or("Unknown")
        );
        println!(
            "  Capacity:        {} GiB",
            job.identity.stable.size_bytes / (1024 * 1024 * 1024)
        );
        println!("  Plan Schema:     {}", job.plan.plan_schema);
        println!("  Plan Hash:       {}", job.plan_hash);
        println!("  Verification:    {}", job.plan.verification);
        match &job.plan.mechanism {
            Mechanism::LogicalOverwrite { passes } => {
                println!("  Passes Count:    {}", passes.len());
                for (i, p) in passes.iter().enumerate() {
                    println!("    Pass {}: {}", i + 1, p.label);
                }
            }
            Mechanism::HardwarePurge {
                selected_mechanism, ..
            } => {
                println!("  Mechanism:       HardwarePurge ({})", selected_mechanism);
            }
        }
        if let Some(note) = &job.plan.legacy_note {
            println!("  LEGACY NOTICE:   {}", note);
        }
        for warning in &job.defense_warnings {
            println!("  DEFENSE_WARNING: {}", warning);
        }
        println!("  Guardian:        CLEAN (target is safe for sanitization)");
    }
    println!("Engine:            {}", args.engine_default_name());
    println!(
        "Fast Path:         {}",
        if args.no_write_zeroes {
            "ForbidWriteZeroes"
        } else {
            "PreferWriteZeroes"
        }
    );
    println!("================================================================================");
    println!(
        "DRY RUN COMPLETE: nothing was written, no journal was created. Devices in batch: {}.",
        jobs.len()
    );
    println!("================================================================================");

    log_audit(
        audit,
        AuditRecord {
            timestamp_utc: chrono_now_iso(),
            argv_hash: "execute-dry-run".to_string(),
            target_path: None,
            outcome: AuditOutcome::PlanCompiled {
                plan_hash: jobs
                    .first()
                    .map(|j| j.plan_hash.clone())
                    .unwrap_or_default(),
            },
        },
    );
}

/// SMART G-List / reallocated-sector audit (v0.6.0,
/// REG-SMART-GLIST-DISCLOSURE).
///
/// Queries the media's hidden-defect state through the bus-appropriate
/// door BEFORE any write is armed:
/// - SATA/USB-SAT: SMART attribute 0x05 (Reallocated_Sector_Ct)
/// - SAS/SCSI: READ DEFECT DATA (10) grown list (G-List)
/// - NVMe: SMART/Health Log Page 0x02 media-error counter
///
/// A non-zero count on a LOGICAL overwrite means retired physical sectors
/// holding classified data are unreachable by any host write: the run
/// proceeds, but the certificate carries the mandatory NIST SP 800-88
/// physical-destruction advisory inside its signed payload. Best-effort:
/// a silent drive is disclosed as unreported, never blocking the wipe on
/// a missing SMART door.
fn audit_target_glist(identity: &DeviceIdentity) -> Vec<String> {
    let count: Option<u64> = match identity.stable.bus {
        dc_core::BusType::Sata | dc_core::BusType::Usb => {
            dc_ata::LinuxSatPurge::open(std::path::Path::new(&identity.dev_path))
                .ok()
                .and_then(|mut sat| {
                    dc_ata::purge::AtaPurgeClient::new(&mut sat)
                        .read_reallocated_sectors()
                        .ok()
                })
        }
        dc_core::BusType::Sas => {
            dc_scsi::LinuxScsiPurge::open(std::path::Path::new(&identity.dev_path))
                .ok()
                .and_then(|mut scsi| {
                    dc_scsi::purge::ScsiPurgeClient::new(&mut scsi)
                        .read_grown_defects()
                        .ok()
                })
        }
        dc_core::BusType::Nvme => {
            // SMART/Health Log Page 0x02: media and data-integrity errors
            // (the NVMe mirror of the reallocated-sector disclosure).
            let ctrl = dc_nvme::controller_char_dev_for(std::path::Path::new(&identity.dev_path));
            dc_nvme::LinuxNvmeAdmin::open(&ctrl)
                .ok()
                .and_then(|mut admin| dc_nvme::read_health(&mut admin).ok())
                .map(|h| h.media_errors as u64)
        }
        _ => None,
    };

    match count {
        Some(n) if n > 0 => vec![format!(
            "Media contains {} reallocated sector(s) inaccessible to logical writes. \
             Physical destruction recommended per NIST SP 800-88 Rev 1 (hidden-defect \
             data may survive host overwrites).",
            n
        )],
        _ => Vec::new(),
    }
}
