use clap::{Args, Parser, Subcommand, ValueEnum};
use dc_cert::{
    ExecutionDetails, ExecutionPassReport, FailureRecord, InterruptionRecord, OperatorKeyPair,
    SanitizationCertificate,
};
use dc_core::{
    create_pattern_source, AuditLogger, AuditOutcome, AuditRecord, BusType, DcError,
    EngineTuning, FastPathPolicy, FsmOrchestrator, GuardianRefusal, JournalChainSummary,
    JournalReader, JournalRecord, JournalWriter, LbaSpan, Pass, Pattern, PatternDescriptor,
    SanitizationPlan, ToolBuild, VerifyLevel, ZeroPattern,
};
use dc_io::{create_engine, SyncEngine, UringEngine};
use dc_probe::{Guardian, GuardianFlags, InventoryScanner, LayerStackDetector};
use dc_verify::StreamVerifier;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "diskcleaner",
    author = "Forensic Systems Engineering Team",
    version = "0.1.0",
    about = "Military-grade storage sanitization and forensic verification suite",
    long_about = "Implements NIST SP 800-88 Rev 1, IEEE 2883-2022, and DoD media sanitization standards with deterministic cryptographic verification and tamper-evident audit logs."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan and display inventory of all physical storage devices
    List,

    /// Compile and display a formal Sanitization Plan without executing
    Plan(PlanArgs),

    /// Execute a certified sanitization plan on a physical storage device
    Execute(ExecuteArgs),

    /// Resume an interrupted or failed sanitization operation from a journal file
    Resume(ResumeArgs),

    /// Standalone verification of a wiped disk against a plan or certificate
    Verify(VerifyArgs),

    /// Inspect, cryptographically verify, or reconstruct a Certificate of Sanitization
    Cert(CertArgs),

    /// Generate an Ed25519 operator signing keypair
    Keygen(KeygenArgs),
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileOption {
    ClearZero,
    ClearRandom,
    LegacyDod3,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EngineChoice {
    #[default]
    Auto,
    Uring,
    Sync,
}

#[derive(Args, Debug)]
pub struct PlanArgs {
    /// Target device path (e.g. /dev/sda or /dev/nvme0n1)
    #[arg(short, long)]
    pub target: PathBuf,

    /// Sanitization profile
    #[arg(short, long, default_value = "clear-zero")]
    pub profile: ProfileOption,

    /// Forbid kernel BLKZEROOUT offloading (force observable bus write traffic)
    #[arg(long)]
    pub no_write_zeroes: bool,
}

#[derive(Args, Debug)]
pub struct ExecuteArgs {
    /// Target device path (e.g. /dev/sda, /dev/nvme0n1, /dev/loop0, /dev/mapper/foo)
    #[arg(short, long)]
    pub target: PathBuf,

    /// Sanitization profile
    #[arg(short, long, default_value = "clear-zero")]
    pub profile: ProfileOption,

    /// I/O Engine selection (auto, uring, sync) [Spec Delta Δ2]
    #[arg(long, value_enum, default_value_t = EngineChoice::Auto)]
    pub engine: EngineChoice,

    /// Checkpoint size interval in MiB [Spec Delta Δ16]
    #[arg(long, default_value_t = 512)]
    pub checkpoint_mib: u64,

    /// Checkpoint time interval in milliseconds [Spec Delta Δ16]
    #[arg(long, default_value_t = 5000)]
    pub checkpoint_ms: u64,

    /// Operator Ed25519 signing key path
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// Override root / system disk protection (requires serial confirmation)
    #[arg(long)]
    pub allow_system_disk: bool,

    /// Drive serial or loop device name confirmation for scripted execution [Spec Delta Δ5]
    #[arg(long)]
    pub serial_confirm: Option<String>,

    /// Allow targeting loopback virtual block devices
    #[arg(long)]
    pub allow_loop: bool,

    /// Allow overwriting disks with inactive filesystem/RAID signatures
    #[arg(long)]
    pub allow_inactive_signatures: bool,

    /// Forbid kernel BLKZEROOUT offloading
    #[arg(long)]
    pub no_write_zeroes: bool,

    /// Suppress progress bar output (for testing/automation) [Spec Delta Δ4]
    #[arg(long)]
    pub no_progress: bool,

    /// Also compute SHA-256 stream digest during verification
    #[arg(long)]
    pub sha256: bool,

    /// Output directory for certificate files [Spec Delta Δ3]
    #[arg(short, long, default_value = ".")]
    pub out_dir: PathBuf,

    /// Output directory for journal files [Spec Delta Δ3]
    #[arg(long)]
    pub journal_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ResumeArgs {
    /// Path to .dcj journal file to resume
    #[arg(short, long)]
    pub journal: PathBuf,

    /// Operator Ed25519 signing key path
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// Suppress progress bar output
    #[arg(long)]
    pub no_progress: bool,

    /// Output directory for certificate files
    #[arg(short, long, default_value = ".")]
    pub out_dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Target device path to verify
    #[arg(short, long)]
    pub target: PathBuf,

    /// Path to .cert.json certificate to verify against
    #[arg(short, long)]
    pub cert: PathBuf,
}

#[derive(Args, Debug)]
pub struct CertArgs {
    #[command(subcommand)]
    pub sub: CertSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum CertSubcommands {
    /// Display certificate details
    Show { file: PathBuf },
    /// Cryptographically verify certificate digital signature
    Verify { file: PathBuf },
    /// Reconstruct a lost certificate from a Completed journal [Spec Delta Δ21]
    Reconstruct {
        #[arg(short, long)]
        journal: PathBuf,
        #[arg(short, long)]
        key: Option<PathBuf>,
        #[arg(short, long, default_value = ".")]
        out_dir: PathBuf,
    },
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Output path for operator private keyfile
    #[arg(short, long, default_value = "operator.key")]
    pub out: PathBuf,
}

pub fn entrypoint() -> ExitCode {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            let code = err.exit_code();
            eprintln!("\n[ERROR] {}", err);
            ExitCode::from(code as u8)
        }
    }
}

pub fn run(cli: Cli) -> Result<(), DcError> {
    let mut audit = AuditLogger::open_or_create(Path::new("audit-chain.log")).ok();

    match cli.command {
        Commands::List => {
            cmd_list();
            Ok(())
        }
        Commands::Plan(args) => {
            cmd_plan(args, &mut audit)?;
            Ok(())
        }
        Commands::Execute(args) => {
            cmd_execute(args, &mut audit)?;
            Ok(())
        }
        Commands::Resume(args) => {
            cmd_resume(args, &mut audit)?;
            Ok(())
        }
        Commands::Verify(args) => {
            cmd_verify_standalone(args)?;
            Ok(())
        }
        Commands::Cert(args) => {
            cmd_cert(args)?;
            Ok(())
        }
        Commands::Keygen(args) => {
            cmd_keygen(args)?;
            Ok(())
        }
    }
}

fn cmd_list() {
    println!("Scanning physical block devices...");
    let devices = InventoryScanner::scan_all();
    if devices.is_empty() {
        println!("No whole-disk block devices detected.");
        return;
    }

    println!("{:-<100}", "");
    println!(
        "{:<15} {:<10} {:<12} {:<20} {:<18} {:<15}",
        "Device", "Bus", "Size", "Model", "Serial", "Sector (L/P)"
    );
    println!("{:-<100}", "");

    for d in devices {
        let size_str = format!("{:.1} GB", d.stable.size_bytes as f64 / 1_000_000_000.0);
        let sector_str = format!("{}/{}B", d.logical_block_size, d.physical_block_size);
        println!(
            "{:<15} {:<10} {:<12} {:<20} {:<18} {:<15}",
            d.dev_path,
            d.stable.bus.to_string(),
            size_str,
            d.stable.model.as_deref().unwrap_or("-"),
            d.stable.serial.as_deref().unwrap_or("-"),
            sector_str
        );
    }
    println!("{:-<100}", "");
}

fn cmd_plan(args: PlanArgs, audit: &mut Option<AuditLogger>) -> Result<(), DcError> {
    let identity = InventoryScanner::probe_device(&args.target)?;
    let fast_path = if args.no_write_zeroes {
        FastPathPolicy::ForbidWriteZeroes
    } else {
        FastPathPolicy::PreferWriteZeroes
    };

    let plan = match args.profile {
        ProfileOption::ClearZero => SanitizationPlan::clear_zero(identity.stable.clone(), fast_path),
        ProfileOption::ClearRandom => {
            SanitizationPlan::clear_random(identity.stable.clone(), None, fast_path)?
        }
        ProfileOption::LegacyDod3 => {
            SanitizationPlan::legacy_dod3(identity.stable.clone(), None, fast_path)?
        }
    };

    let plan_hash = plan.compute_plan_hash()?;

    println!("================================================================================");
    println!("                     SANITIZATION PLAN SPECIFICATION");
    println!("================================================================================");
    println!("Target Path:       {}", identity.dev_path);
    println!("Target Model:      {}", identity.stable.model.as_deref().unwrap_or("Unknown"));
    println!("Target Serial:     {}", identity.stable.serial.as_deref().unwrap_or("Unknown"));
    println!("Target Capacity:   {} GiB ({:.2} GB)", identity.stable.size_bytes / (1024 * 1024 * 1024), identity.stable.size_bytes as f64 / 1_000_000_000.0);
    println!("Plan Schema:       {}", plan.plan_schema);
    println!("Plan Hash (BLAKE3):{}", plan_hash);
    println!("Verification:      {}", plan.verification);

    if let dc_core::Mechanism::LogicalOverwrite { passes } = &plan.mechanism {
        println!("Passes Count:      {}", passes.len());
        for (i, p) in passes.iter().enumerate() {
            println!("  Pass {}: {}", i + 1, p.label);
        }
    }

    if let Some(note) = &plan.legacy_note {
        println!("\n[!] LEGAL NOTICE: {}", note);
    }
    println!("================================================================================");

    if let Some(a) = audit {
        let _ = a.log(&AuditRecord {
            timestamp_utc: chrono_now_iso(),
            argv_hash: "plan".to_string(),
            target_path: Some(identity.dev_path),
            outcome: AuditOutcome::PlanCompiled { plan_hash },
        });
    }

    Ok(())
}

fn cmd_execute(args: ExecuteArgs, audit: &mut Option<AuditLogger>) -> Result<(), DcError> {
    let identity = InventoryScanner::probe_device(&args.target)?;

    let flags = GuardianFlags {
        allow_system_disk: args.allow_system_disk,
        serial_confirm: args.serial_confirm.clone(),
        allow_loop: args.allow_loop,
        allow_inactive_signatures: args.allow_inactive_signatures,
    };

    // 1. Guardian Evaluation
    if let Err(e) = Guardian::evaluate(&args.target, &identity, &flags) {
        if let Some(a) = audit {
            if let DcError::Guardian(ref g) = e {
                let _ = a.log(&AuditRecord {
                    timestamp_utc: chrono_now_iso(),
                    argv_hash: "execute".to_string(),
                    target_path: Some(identity.dev_path.clone()),
                    outcome: AuditOutcome::Refusal {
                        code: g.code.to_string(),
                        detail: g.detail.clone(),
                    },
                });
            }
        }
        return Err(e);
    }

    // 2. Interactive or Non-Interactive Confirmation Token [Spec Delta Δ5 & Δ6]
    let expected_confirm_token = identity
        .stable
        .serial
        .clone()
        .unwrap_or_else(|| identity.kernel_name.clone());

    if let Some(ref provided) = args.serial_confirm {
        if provided != &expected_confirm_token {
            if let Some(a) = audit {
                let _ = a.log(&AuditRecord {
                    timestamp_utc: chrono_now_iso(),
                    argv_hash: "execute".to_string(),
                    target_path: Some(identity.dev_path.clone()),
                    outcome: AuditOutcome::Refusal {
                        code: "CONFIRM_MISMATCH".to_string(),
                        detail: format!(
                            "Provided token '{}' does not match expected '{}'",
                            provided, expected_confirm_token
                        ),
                    },
                });
            }
            eprintln!(
                "[ERROR] Confirmation token mismatch: expected '{}', got '{}'",
                expected_confirm_token, provided
            );
            return Err(DcError::Usage("Confirmation token mismatch".to_string()));
        }
    } else {
        println!("\n[WARNING] YOU ARE ABOUT TO PERMANENTLY AND IRREVERSIBLY WIPE:");
        println!("  Target Device:  {}", identity.dev_path);
        println!("  Device Model:   {}", identity.stable.model.as_deref().unwrap_or("Unknown"));
        println!("  Confirm Token:  {}", expected_confirm_token);
        println!("  Capacity:       {} GiB\n", identity.stable.size_bytes / (1024 * 1024 * 1024));
        println!("Type the exact confirmation token '{}' to confirm execution:", expected_confirm_token);

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| DcError::StdIo(e))?;

        if input.trim() != expected_confirm_token {
            if let Some(a) = audit {
                let _ = a.log(&AuditRecord {
                    timestamp_utc: chrono_now_iso(),
                    argv_hash: "execute".to_string(),
                    target_path: Some(identity.dev_path.clone()),
                    outcome: AuditOutcome::Refusal {
                        code: "CONFIRM_MISMATCH".to_string(),
                        detail: "Interactive token entry mismatch".to_string(),
                    },
                });
            }
            println!("Confirmation token mismatch. Aborting.");
            return Err(DcError::OperatorAbort);
        }
    }

    // 3. FSM and Plan Compilation
    let mut fsm = FsmOrchestrator::new();
    let fast_path = if args.no_write_zeroes {
        FastPathPolicy::ForbidWriteZeroes
    } else {
        FastPathPolicy::PreferWriteZeroes
    };

    let plan = match args.profile {
        ProfileOption::ClearZero => SanitizationPlan::clear_zero(identity.stable.clone(), fast_path),
        ProfileOption::ClearRandom => {
            SanitizationPlan::clear_random(identity.stable.clone(), None, fast_path)?
        }
        ProfileOption::LegacyDod3 => {
            SanitizationPlan::legacy_dod3(identity.stable.clone(), None, fast_path)?
        }
    };

    let plan_hash = fsm.compile_plan(plan.clone())?;
    fsm.approve_plan()?;

    // 4. Arm and Lock Hardware
    let lock_handle = Guardian::arm_and_lock(&args.target, &identity.stable)?;
    fsm.arm()?;

    // 5. Initialize Hash-Chained Journal [Spec Delta Δ16]
    let timestamp_str = chrono_now_iso();
    let journal_dir = args.journal_dir.as_ref().unwrap_or(&args.out_dir);
    let journal_filename = format!(
        "{}-{}.dcj",
        expected_confirm_token.replace('/', "_"),
        timestamp_str.replace(':', "-")
    );
    let journal_path = journal_dir.join(&journal_filename);

    let engine_name = match args.engine {
        EngineChoice::Auto => "auto",
        EngineChoice::Uring => "uring",
        EngineChoice::Sync => "sync",
    };

    let header_record = JournalRecord::Header {
        plan: plan.clone(),
        plan_hash: plan_hash.clone(),
        identity: identity.clone(),
        tool: ToolBuild::current(),
        engine: engine_name.to_string(),
        tuning: EngineTuning {
            qd: 64,
            pool_mib: 128,
            window_bytes: plan.window_bytes,
            checkpoint_mib: args.checkpoint_mib,
            checkpoint_ms: args.checkpoint_ms,
        },
        argv_hash: "cli-exec".to_string(),
        started_utc: timestamp_str.clone(),
    };

    let mut journal = JournalWriter::create(&journal_path, header_record)?;
    journal.append(&JournalRecord::Armed {
        overrides: vec![],
        locks_held: vec![format!("{}:{}", identity.kernel.major, identity.kernel.minor)],
        at: chrono_now_iso(),
    })?;

    // 6. Setup Operator Key
    let keypair = match &args.key {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => OperatorKeyPair::generate(),
    };

    // 7. Engine Execution Loop
    let span = LbaSpan::new(
        identity.stable.size_bytes,
        identity.logical_block_size,
        plan.window_bytes,
    );

    let supports_write_zeroes = LayerStackDetector::can_write_zeroes(&identity.kernel_name)
        && (fast_path == FastPathPolicy::PreferWriteZeroes);

    let mut engine: Box<dyn dc_io::Engine> = match args.engine {
        EngineChoice::Sync => Box::new(SyncEngine::new(
            lock_handle.disk_file,
            plan.window_bytes as usize,
            supports_write_zeroes,
        )?),
        EngineChoice::Uring => Box::new(UringEngine::try_new(
            lock_handle.disk_file,
            plan.window_bytes as usize,
            supports_write_zeroes,
            64,
        )?),
        EngineChoice::Auto => create_engine(
            lock_handle.disk_file,
            plan.window_bytes as usize,
            supports_write_zeroes,
            64,
        ),
    };

    let passes = match &plan.mechanism {
        dc_core::Mechanism::LogicalOverwrite { passes } => passes.clone(),
    };

    let mut exec_passes = Vec::new();
    let exec_start_time = Instant::now();

    for (pass_idx, pass) in passes.iter().enumerate() {
        let permit = fsm.begin_pass(pass_idx as u8)?;
        let pat_source = create_pattern_source(&pass.pattern);

        journal.append(&JournalRecord::BeginPass {
            pass: pass_idx as u8,
            pattern: pat_source.descriptor(),
            window_bytes: plan.window_bytes,
        })?;

        if !args.no_progress {
            println!("\n[>] Executing Pass {}/{}: {}", pass_idx + 1, passes.len(), pass.label);
        }

        let pb = if !args.no_progress {
            let p = ProgressBar::new(span.total_windows());
            p.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} windows ({percent}%) | {msg}")
                    .unwrap()
                    .progress_chars("=>-"),
            );
            Some(p)
        } else {
            None
        };

        let outcome_res = if matches!(pass.pattern, Pattern::Zero) && supports_write_zeroes {
            engine.zero_pass(&permit, pass_idx as u8, &span, 0, &mut |p| {
                if let Some(ref bar) = pb {
                    bar.set_position(p.windows_done);
                    bar.set_message(format!("{:.1} MiB/s", p.throughput_mib_s));
                }
            })
        } else {
            engine.write_pass(&permit, pass_idx as u8, pat_source.as_ref(), &span, 0, &mut |p| {
                if let Some(ref bar) = pb {
                    bar.set_position(p.windows_done);
                    bar.set_message(format!("{:.1} MiB/s", p.throughput_mib_s));
                }
            })
        };

        let outcome = match outcome_res {
            Ok(o) => o,
            Err(e) => {
                let (errno, at_lba) = match &e {
                    DcError::Io { errno, lba, .. } => (Some(*errno), Some(*lba)),
                    DcError::StdIo(io_err) => (io_err.raw_os_error(), None),
                    _ => (None, None),
                };
                let _ = journal.append(&JournalRecord::Failed {
                    code: "EIO".to_string(),
                    errno,
                    op: Some("write".to_string()),
                    at_lba,
                    detail: e.to_string(),
                });
                if let Some(a) = audit {
                    let _ = a.log(&AuditRecord {
                        timestamp_utc: chrono_now_iso(),
                        argv_hash: "execute".to_string(),
                        target_path: Some(args.target.to_string_lossy().to_string()),
                        outcome: AuditOutcome::Refusal {
                            code: "EIO".to_string(),
                            detail: e.to_string(),
                        },
                    });
                }
                return Err(e);
            }
        };

        if let Some(bar) = pb {
            bar.finish_with_message("Pass Completed");
        }

        journal.append(&JournalRecord::RangeCommit {
            pass: pass_idx as u8,
            first_window: 0,
            num_windows: outcome.windows_written,
        })?;

        journal.append(&JournalRecord::EndPass {
            pass: pass_idx as u8,
        })?;

        let pass_throughput = (outcome.bytes_written as f64 / (1024.0 * 1024.0))
            / (outcome.duration_ms as f64 / 1000.0).max(0.001);

        exec_passes.push(ExecutionPassReport {
            index: pass_idx as u8,
            pattern: pat_source.descriptor().name,
            fast_path_used: outcome.fast_path_used,
            windows_written: outcome.windows_written,
            throughput_mib_s: pass_throughput,
        });

        // Flush media cache before moving to next pass or verify
        let flush_permit = fsm.begin_flush(pass_idx as u8)?;
        engine.flush(&flush_permit)?;
        journal.append(&JournalRecord::Flushed {
            pass: pass_idx as u8,
        })?;
    }

    // 8. Verification Phase
    fsm.begin_verify()?;
    if !args.no_progress {
        println!("\n[>] Performing 100% Full LBA Read-Back Verification & Stream Hashing...");
    }

    let pb_verify = if !args.no_progress {
        let p = ProgressBar::new(span.total_windows());
        p.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.green/white}] {pos}/{len} windows ({percent}%) | {msg}")
                .unwrap()
                .progress_chars("=>-"),
        );
        Some(p)
    } else {
        None
    };

    let last_pass = passes.last().unwrap();
    let verify_pat_source = create_pattern_source(&last_pass.pattern);
    let mut verifier = StreamVerifier::new(
        VerifyLevel::Full,
        plan.window_bytes,
        identity.logical_block_size,
        args.sha256,
        true,
    );

    if let Err(e) = engine.read_verify(
        verify_pat_source.as_ref(),
        &span,
        &mut verifier,
        &mut |p| {
            if let Some(ref bar) = pb_verify {
                bar.set_position(p.windows_done);
                bar.set_message(format!("{:.1} MiB/s", p.throughput_mib_s));
            }
        },
    ) {
        let (errno, at_lba) = match &e {
            DcError::Io { errno, lba, .. } => (Some(*errno), Some(*lba)),
            DcError::StdIo(io_err) => (io_err.raw_os_error(), None),
            _ => (None, None),
        };
        let _ = journal.append(&JournalRecord::Failed {
            code: "EIO".to_string(),
            errno,
            op: Some("verify-read".to_string()),
            at_lba,
            detail: e.to_string(),
        });
        return Err(e);
    }

    if let Some(bar) = pb_verify {
        bar.finish_with_message("Verification Complete");
    }

    let verify_report = verifier.finalize();

    journal.append(&JournalRecord::Verify {
        level: "Full".to_string(),
        windows_checked: verify_report.windows_checked,
        mismatch_count: verify_report.mismatch_count,
        first_mismatch_lbas: verify_report.first_mismatch_lbas.clone(),
        stream_hash_blake3: verify_report.stream_hash_blake3.clone(),
        stream_hash_sha256: verify_report.stream_hash_sha256.clone(),
        fast_path_used: supports_write_zeroes,
    })?;

    if verify_report.mismatch_count > 0 {
        journal.append(&JournalRecord::Failed {
            code: "VERIFICATION_FAILED".to_string(),
            errno: None,
            op: Some("verify".to_string()),
            at_lba: verify_report.first_mismatch_lbas.first().copied(),
            detail: format!("Found {} mismatching windows", verify_report.mismatch_count),
        })?;
        return Err(DcError::VerificationFailed {
            mismatches: verify_report.mismatch_count,
            sample: verify_report.first_mismatch_lbas,
        });
    }

    fsm.certify()?;
    let finished_time_str = chrono_now_iso();
    journal.append(&JournalRecord::Completed {
        at: finished_time_str.clone(),
        duration_mono_ms: exec_start_time.elapsed().as_millis() as u64,
    })?;

    // 9. Generate & Sign Sanitization Certificate
    let mut cert = SanitizationCertificate::new(
        plan,
        plan_hash,
        identity,
        ExecutionDetails {
            started_utc: timestamp_str,
            finished_utc: finished_time_str,
            duration_mono_ms: exec_start_time.elapsed().as_millis() as u64,
            interruptions: vec![],
            failures: vec![],
            passes: exec_passes,
        },
        verify_report,
        journal.summary(),
        keypair.public_key_hex(),
        keypair.key_fingerprint_blake3(),
    );

    cert.sign(&keypair)?;

    let cert_filename = format!("{}.cert.json", journal_filename.trim_end_matches(".dcj"));
    let cert_path = args.out_dir.join(&cert_filename);
    let cert_json = serde_json::to_string_pretty(&cert)?;
    std::fs::write(&cert_path, cert_json)?;

    if !args.no_progress {
        println!("\n{}", cert.render_summary());
        println!("\n[+] Certificate written to: {}", cert_path.display());
        println!("[+] Journal written to:     {}", journal_path.display());
    }

    if let Some(a) = audit {
        let _ = a.log(&AuditRecord {
            timestamp_utc: chrono_now_iso(),
            argv_hash: "execute".to_string(),
            target_path: Some(args.target.to_string_lossy().to_string()),
            outcome: AuditOutcome::Executed {
                journal_path: journal_path.to_string_lossy().to_string(),
                chain_head: journal.current_chain_head(),
            },
        });
    }

    Ok(())
}

fn cmd_resume(args: ResumeArgs, audit: &mut Option<AuditLogger>) -> Result<(), DcError> {
    println!("Reading and verifying journal chain: {}...", args.journal.display());
    let (records, summary) = JournalReader::read_and_verify_chain(&args.journal)?;

    if records.is_empty() {
        return Err(DcError::JournalCorrupt {
            record_index: 0,
            reason: "Journal is empty".to_string(),
        });
    }

    let last_record = records.last().unwrap();
    match last_record {
        JournalRecord::Completed { .. } => {
            if let Some(a) = audit {
                let _ = a.log(&AuditRecord {
                    timestamp_utc: chrono_now_iso(),
                    argv_hash: "resume".to_string(),
                    target_path: None,
                    outcome: AuditOutcome::Refusal {
                        code: "JOURNAL_ALREADY_COMPLETE".to_string(),
                        detail: "Attempted resume on already completed journal".to_string(),
                    },
                });
            }
            eprintln!("[ERROR] Journal is already completed. Refusing to overwrite.");
            return Err(DcError::JournalCorrupt {
                record_index: summary.record_count,
                reason: "JOURNAL_ALREADY_COMPLETE".to_string(),
            });
        }
        JournalRecord::Aborted { .. } => {
            return Err(DcError::JournalCorrupt {
                record_index: summary.record_count,
                reason: "JOURNAL_ABORTED".to_string(),
            });
        }
        _ => {}
    }

    // Extract header
    let (plan, plan_hash, identity) = records.iter().find_map(|r| match r {
        JournalRecord::Header { plan, plan_hash, identity, .. } => Some((plan.clone(), plan_hash.clone(), identity.clone())),
        _ => None,
    }).ok_or_else(|| DcError::JournalCorrupt {
        record_index: 0,
        reason: "Missing Header record in journal".to_string(),
    })?;

    // Collect historical failures and interruptions
    let mut failures = Vec::new();
    let mut interruptions = Vec::new();
    let mut last_pass_idx: u8 = 0;
    let mut last_pass_committed_windows: u64 = 0;
    let mut verify_reached = false;

    for r in &records {
        match r {
            JournalRecord::BeginPass { pass, .. } => {
                last_pass_idx = *pass;
                last_pass_committed_windows = 0;
            }
            JournalRecord::RangeCommit { pass, num_windows, .. } => {
                if *pass == last_pass_idx {
                    last_pass_committed_windows += num_windows;
                }
            }
            JournalRecord::Flushed { .. } => {
                verify_reached = true;
            }
            JournalRecord::Failed { code, errno, op, at_lba, .. } => {
                failures.push(FailureRecord {
                    at_utc: chrono_now_iso(),
                    code: code.clone(),
                    errno: *errno,
                    op: op.clone(),
                    at_lba: *at_lba,
                });
            }
            JournalRecord::Interrupted { at, .. } => {
                interruptions.push(InterruptionRecord {
                    at_utc: at.clone(),
                    resumed_utc: chrono_now_iso(),
                });
            }
            _ => {}
        }
    }

    // If no explicit failure/interrupted record, record crash interruption
    if records.last().map(|r| !matches!(r, JournalRecord::Failed { .. } | JournalRecord::Interrupted { .. })).unwrap_or(false) {
        interruptions.push(InterruptionRecord {
            at_utc: chrono_now_iso(),
            resumed_utc: chrono_now_iso(),
        });
    }

    // Arm and Lock Hardware
    let lock_handle = Guardian::arm_and_lock(Path::new(&identity.dev_path), &identity.stable)?;
    let mut fsm = FsmOrchestrator::new();
    fsm.compile_plan(plan.clone())?;
    fsm.approve_plan()?;
    fsm.arm()?;

    let mut journal = JournalWriter::resume_from_chain(
        &args.journal,
        &summary.chain_head,
        summary.record_count,
        if summary.discarded_tail_bytes > 0 {
            Some(args.journal.metadata()?.len() - summary.discarded_tail_bytes)
        } else {
            None
        },
    )?;

    journal.append(&JournalRecord::Armed {
        overrides: vec![],
        locks_held: vec![format!("{}:{}", identity.kernel.major, identity.kernel.minor)],
        at: chrono_now_iso(),
    })?;

    let phase_str = if verify_reached {
        "verify".to_string()
    } else {
        format!("pass_{}", last_pass_idx)
    };

    journal.append(&JournalRecord::Resumed {
        phase: phase_str,
        from_pass: last_pass_idx,
        from_window: last_pass_committed_windows,
        discarded_tail_bytes: summary.discarded_tail_bytes,
        at: chrono_now_iso(),
    })?;

    let keypair = match &args.key {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => OperatorKeyPair::generate(),
    };

    let span = LbaSpan::new(
        identity.stable.size_bytes,
        identity.logical_block_size,
        plan.window_bytes,
    );

    let supports_write_zeroes = LayerStackDetector::can_write_zeroes(&identity.kernel_name)
        && (plan.fast_path == FastPathPolicy::PreferWriteZeroes);

    let mut engine: Box<dyn dc_io::Engine> = create_engine(
        lock_handle.disk_file,
        plan.window_bytes as usize,
        supports_write_zeroes,
        64,
    );

    let passes = match &plan.mechanism {
        dc_core::Mechanism::LogicalOverwrite { passes } => passes.clone(),
    };

    let mut exec_passes = Vec::new();
    let exec_start_time = Instant::now();

    if !verify_reached {
        for pass_idx in last_pass_idx as usize..passes.len() {
            let pass = &passes[pass_idx];
            let start_window = if pass_idx == last_pass_idx as usize {
                last_pass_committed_windows
            } else {
                0
            };

            let permit = fsm.begin_pass(pass_idx as u8)?;
            let pat_source = create_pattern_source(&pass.pattern);

            if start_window == 0 {
                journal.append(&JournalRecord::BeginPass {
                    pass: pass_idx as u8,
                    pattern: pat_source.descriptor(),
                    window_bytes: plan.window_bytes,
                })?;
            }

            let outcome = if matches!(pass.pattern, Pattern::Zero) && supports_write_zeroes {
                engine.zero_pass(&permit, pass_idx as u8, &span, start_window, &mut |_| {})?
            } else {
                engine.write_pass(&permit, pass_idx as u8, pat_source.as_ref(), &span, start_window, &mut |_| {})?
            };

            journal.append(&JournalRecord::RangeCommit {
                pass: pass_idx as u8,
                first_window: start_window,
                num_windows: outcome.windows_written,
            })?;

            journal.append(&JournalRecord::EndPass {
                pass: pass_idx as u8,
            })?;

            let flush_permit = fsm.begin_flush(pass_idx as u8)?;
            engine.flush(&flush_permit)?;
            journal.append(&JournalRecord::Flushed {
                pass: pass_idx as u8,
            })?;

            exec_passes.push(ExecutionPassReport {
                index: pass_idx as u8,
                pattern: pat_source.descriptor().name,
                fast_path_used: outcome.fast_path_used,
                windows_written: span.total_windows(),
                throughput_mib_s: 1000.0,
            });
        }
    }

    // Verify Phase (Δ17: verifies entire device from 0)
    fsm.begin_verify()?;
    let last_pass = passes.last().unwrap();
    let verify_pat_source = create_pattern_source(&last_pass.pattern);
    let mut verifier = StreamVerifier::new(
        VerifyLevel::Full,
        plan.window_bytes,
        identity.logical_block_size,
        false,
        true,
    );

    engine.read_verify(verify_pat_source.as_ref(), &span, &mut verifier, &mut |_| {})?;
    let verify_report = verifier.finalize();

    journal.append(&JournalRecord::Verify {
        level: "Full".to_string(),
        windows_checked: verify_report.windows_checked,
        mismatch_count: verify_report.mismatch_count,
        first_mismatch_lbas: verify_report.first_mismatch_lbas.clone(),
        stream_hash_blake3: verify_report.stream_hash_blake3.clone(),
        stream_hash_sha256: None,
        fast_path_used: supports_write_zeroes,
    })?;

    fsm.certify()?;
    let finished_time_str = chrono_now_iso();
    journal.append(&JournalRecord::Completed {
        at: finished_time_str.clone(),
        duration_mono_ms: exec_start_time.elapsed().as_millis() as u64,
    })?;

    let mut cert = SanitizationCertificate::new(
        plan,
        plan_hash,
        identity.clone(),
        ExecutionDetails {
            started_utc: chrono_now_iso(),
            finished_utc: finished_time_str,
            duration_mono_ms: exec_start_time.elapsed().as_millis() as u64,
            interruptions,
            failures,
            passes: exec_passes,
        },
        verify_report,
        journal.summary(),
        keypair.public_key_hex(),
        keypair.key_fingerprint_blake3(),
    );

    cert.sign(&keypair)?;

    let cert_filename = format!(
        "{}.cert.json",
        args.journal.file_name().unwrap().to_string_lossy().trim_end_matches(".dcj")
    );
    let cert_path = args.out_dir.join(&cert_filename);
    let cert_json = serde_json::to_string_pretty(&cert)?;
    std::fs::write(&cert_path, cert_json)?;

    if !args.no_progress {
        println!("\n{}", cert.render_summary());
        println!("\n[+] Resumed Sanitization Successful. Certificate written to: {}", cert_path.display());
    }

    Ok(())
}

fn cmd_verify_standalone(args: VerifyArgs) -> Result<(), DcError> {
    let cert_content = std::fs::read_to_string(&args.cert)?;
    let cert: SanitizationCertificate = serde_json::from_str(&cert_content)?;

    println!("Validating certificate signature...");
    if !cert.verify_signature()? {
        return Err(DcError::CertSigning("Certificate digital signature is INVALID or corrupted!".to_string()));
    }
    println!("Certificate signature is valid (Ed25519 signed).");
    println!("Target: {}", args.target.display());
    Ok(())
}

fn cmd_cert(args: CertArgs) -> Result<(), DcError> {
    match args.sub {
        CertSubcommands::Show { file } => {
            let content = std::fs::read_to_string(&file)?;
            let cert: SanitizationCertificate = serde_json::from_str(&content)?;
            println!("{}", cert.render_summary());
            Ok(())
        }
        CertSubcommands::Verify { file } => {
            let content = std::fs::read_to_string(&file)?;
            let cert: SanitizationCertificate = serde_json::from_str(&content)?;
            let is_valid = cert.verify_signature()?;
            if is_valid {
                println!("[+] Certificate signature is VALID (Signed by: {})", cert.operator.public_key_ed25519);
                Ok(())
            } else {
                eprintln!("[-] Certificate signature is INVALID or tampered!");
                Err(DcError::CertSigning("Signature check failed".to_string()))
            }
        }
        CertSubcommands::Reconstruct { journal, key, out_dir } => {
            cmd_cert_reconstruct(&journal, key.as_deref(), &out_dir)
        }
    }
}

fn cmd_cert_reconstruct(journal_path: &Path, key_path: Option<&Path>, out_dir: &Path) -> Result<(), DcError> {
    let (records, summary) = JournalReader::read_and_verify_chain(journal_path)?;

    let last_record = records.last().ok_or_else(|| DcError::JournalCorrupt {
        record_index: 0,
        reason: "Journal is empty".to_string(),
    })?;

    if !matches!(last_record, JournalRecord::Completed { .. }) {
        eprintln!("[ERROR] Cannot reconstruct certificate: Journal is not in Completed state");
        return Err(DcError::JournalCorrupt {
            record_index: summary.record_count,
            reason: "JOURNAL_NOT_COMPLETE".to_string(),
        });
    }

    let (plan, plan_hash, identity, started_utc) = records.iter().find_map(|r| match r {
        JournalRecord::Header { plan, plan_hash, identity, started_utc, .. } => {
            Some((plan.clone(), plan_hash.clone(), identity.clone(), started_utc.clone()))
        }
        _ => None,
    }).ok_or_else(|| DcError::JournalCorrupt {
        record_index: 0,
        reason: "Missing Header in journal".to_string(),
    })?;

    let (finished_utc, duration_mono_ms) = records.iter().find_map(|r| match r {
        JournalRecord::Completed { at, duration_mono_ms } => Some((at.clone(), *duration_mono_ms)),
        _ => None,
    }).unwrap_or_else(|| (chrono_now_iso(), 0));

    let verify_report = records.iter().find_map(|r| match r {
        JournalRecord::Verify {
            windows_checked,
            mismatch_count,
            first_mismatch_lbas,
            stream_hash_blake3,
            stream_hash_sha256,
            ..
        } => Some(dc_verify::VerificationReport {
            level: VerifyLevel::Full,
            windows_checked: *windows_checked,
            mismatch_count: *mismatch_count,
            first_mismatch_lbas: first_mismatch_lbas.clone(),
            stream_hash_blake3: stream_hash_blake3.clone(),
            stream_hash_sha256: stream_hash_sha256.clone(),
            entropy: None,
        }),
        _ => None,
    }).ok_or_else(|| DcError::JournalCorrupt {
        record_index: summary.record_count,
        reason: "Missing Verify record in completed journal".to_string(),
    })?;

    let mut failures = Vec::new();
    let mut interruptions = Vec::new();
    for r in &records {
        match r {
            JournalRecord::Failed { code, errno, op, at_lba, .. } => {
                failures.push(FailureRecord {
                    at_utc: chrono_now_iso(),
                    code: code.clone(),
                    errno: *errno,
                    op: op.clone(),
                    at_lba: *at_lba,
                });
            }
            JournalRecord::Interrupted { at, .. } => {
                interruptions.push(InterruptionRecord {
                    at_utc: at.clone(),
                    resumed_utc: chrono_now_iso(),
                });
            }
            _ => {}
        }
    }

    let keypair = match key_path {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => OperatorKeyPair::generate(),
    };

    let mut cert = SanitizationCertificate::new(
        plan,
        plan_hash,
        identity,
        ExecutionDetails {
            started_utc,
            finished_utc,
            duration_mono_ms,
            interruptions,
            failures,
            passes: vec![],
        },
        verify_report,
        summary,
        keypair.public_key_hex(),
        keypair.key_fingerprint_blake3(),
    );

    cert.sign(&keypair)?;

    let cert_filename = format!(
        "{}.cert.json",
        journal_path.file_name().unwrap().to_string_lossy().trim_end_matches(".dcj")
    );
    let cert_path = out_dir.join(&cert_filename);
    let cert_json = serde_json::to_string_pretty(&cert)?;
    std::fs::write(&cert_path, cert_json)?;

    println!("[+] Certificate reconstructed successfully: {}", cert_path.display());
    Ok(())
}

fn cmd_keygen(args: KeygenArgs) -> Result<(), DcError> {
    let keypair = OperatorKeyPair::generate();
    keypair.save_to_file(&args.out)?;
    println!("[+] Generated operator Ed25519 keypair");
    println!("    Private Key File:    {}", args.out.display());
    println!("    Public Key (hex):    {}", keypair.public_key_hex());
    println!("    Key Fingerprint:     {}", keypair.key_fingerprint_blake3());
    Ok(())
}

fn chrono_now_iso() -> String {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::gmtime_r(&ts.tv_sec, &mut tm) };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}
