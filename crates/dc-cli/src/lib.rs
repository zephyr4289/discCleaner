pub mod approve;
pub mod bench;
pub mod bootattest;
pub mod bootiso;
pub mod evidence;
pub mod execute;
pub mod fabrics;
pub mod fleet;
pub mod init;
pub mod key;
pub mod photon;
pub mod profiles;
pub mod purge;
pub mod quote;
pub mod stick_install;

pub use profiles::ProfileOption;

use clap::{Args, Parser, Subcommand, ValueEnum};
use dc_cert::{
    AuthorizationSet, ExecutionDetails, ExecutionPassReport, FailureRecord, InterruptionRecord,
    OperatorKeyPair, SanitizationCertificate,
};
use dc_core::{
    AuditLogger, AuditOutcome, AuditRecord, BusType, DcError, DeviceIdentity, EngineTuning,
    FastPathPolicy, FsmOrchestrator, JournalReader, JournalRecord, JournalWriter, KernelIdentity,
    Pattern, PatternDescriptor, SanitizationPlan, StableIdentity, ToolBuild, VerifyLevel,
    create_pattern_source,
};
use dc_io::{LbaSpan, create_engine, request_global_cancel};
// `request_global_cancel` is consumed by the signal handler below and must
// stay in the named-import list for async-signal-safety auditability.
use dc_probe::{Guardian, GuardianFlags, InventoryScanner, LayerStackDetector};
use dc_verify::StreamVerifier;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Signal handling (Δ87 / Δ83)
// ---------------------------------------------------------------------------

/// Set by the SIGINT/SIGTERM handler; consulted at every CLI boundary to
/// decide between drain-and-journal vs. immediate pre-arm exit.
static SIGNALS_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SIGNALS_RECEIVED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

extern "C" fn on_termination_signal(_sig: libc::c_int) {
    // Async-signal-safe only: two atomic stores, nothing else.
    SIGNALS_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
    SIGNALS_RECEIVED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    request_global_cancel();
}

fn install_signal_handlers() {
    unsafe {
        // Cast the handler through a raw pointer to satisfy the
        // fn-to-integer cast lint while keeping the same runtime behavior.
        let handler = on_termination_signal as *const () as libc::sighandler_t;
        let act = libc::sigaction {
            sa_sigaction: handler,
            sa_mask: std::mem::zeroed(),
            // SA_RESTART keeps pre-boundary syscalls transparently resumable;
            // the engines additionally retry EINTR as belt-and-braces.
            sa_flags: libc::SA_RESTART,
            #[cfg(target_os = "linux")]
            sa_restorer: None,
            #[cfg(not(target_os = "linux"))]
            sa_restorer: std::mem::zeroed(),
        };
        libc::sigaction(libc::SIGINT, &act, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &act, std::ptr::null_mut());
    }
}

fn signal_was_seen() -> bool {
    SIGNALS_SEEN.load(std::sync::atomic::Ordering::SeqCst)
}

/// Termination signals observed so far (batch workers journal this).
pub(crate) fn signals_received_count() -> u32 {
    SIGNALS_RECEIVED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Deterministic signal-injection hook for test rigs (DC_SIGNAL_AT).
///
/// SECURITY: compiled only for debug builds and explicit fault-injection
/// feature requests — release binaries contain no environment-variable-
/// driven signal path.
#[cfg(any(feature = "fault-injection", debug_assertions))]
fn cli_signal_injection(event: &str) {
    if let Ok(spec) = std::env::var("DC_SIGNAL_AT") {
        let target = spec.split(':').next().unwrap_or("");
        if target == event {
            eprintln!("[SIGNAL_HOOK] Raising SIGINT at boundary: {}", event);
            unsafe {
                libc::kill(libc::getpid(), libc::SIGINT);
            }
        }
    }
}

#[cfg(not(any(feature = "fault-injection", debug_assertions)))]
fn cli_signal_injection(_event: &str) {}

#[derive(Parser, Debug)]
#[command(
    name = "diskcleaner",
    author = "Forensic Systems Engineering Team",
    version = "0.8.0",
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

    /// Non-destructive pre-flight safety classification and try-lock probe [Spec Delta Δ23]
    Check(CheckArgs),

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

    /// Inspect, parse, and diagnose .dcj journal files [Spec Delta Δ92]
    Journal(JournalArgs),

    /// Generate an Ed25519 operator signing keypair
    Keygen(KeygenArgs),

    /// Hardware-attested sealing of operator keys into the platform TPM
    /// (PCR-policy bound: unseal only in the exact boot state that sealed)
    Key(KeyArgs),

    /// Two-officer Ed25519 countersignature approval of a compiled plan (2PI, Δ448)
    Approve(ApproveArgs),

    /// List the full sanitization standards profile catalog (procurement reference)
    Profiles,

    /// Benchmark the wipe engine throughput on a regular file (bake-off evidence)
    Bench(BenchArgs),

    /// Controller-attested hardware purge (NVMe Sanitize / Format NVM crypto erase)
    Purge(PurgeArgs),

    /// Standalone appliance lifecycle: PID-1 bootstrap, image packing and
    /// constituent attestation (v0.7.0, Vector 3)
    Boot(BootArgs),

    /// TPM 2.0 PCR remote attestation: generate/verify hardware-signed
    /// quotes proving the sanitization ran on an unmodified platform
    /// (v0.8.0, Vector 1)
    Quote(QuoteArgs),

    /// Bidirectional optical air-gap bridge: stream certificates and audit
    /// evidence out of a SCIF purely via photons — animated fountain-coded
    /// QR frames (v0.8.0, Vector 3)
    Photon(PhotonArgs),

    /// NVMe-oF fabric session management: connect, disconnect, list and
    /// discover remote subsystems over RDMA / RoCEv2 / TCP / FC
    /// (v0.8.0, Vector 4)
    Fabrics(FabricsArgs),
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EngineChoice {
    #[default]
    Auto,
    Uring,
    Sync,
}

#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Target device path (e.g. /dev/sda, /dev/nvme0n1, /dev/loop0)
    #[arg(short, long)]
    pub target: PathBuf,

    /// Override root / system disk protection
    #[arg(long)]
    pub allow_system_disk: bool,

    /// Allow targeting loopback virtual block devices
    #[arg(long)]
    pub allow_loop: bool,

    /// Allow overwriting disks with inactive storage signatures
    #[arg(long)]
    pub allow_inactive_signatures: bool,

    /// Allow overwriting retired LVM / RAID members [Spec Delta Δ32]
    #[arg(long)]
    pub allow_member: bool,
}

#[derive(Args, Debug)]
pub struct PlanArgs {
    /// Target device path (e.g. /dev/sda or /dev/nvme0n1)
    #[arg(short, long)]
    pub target: PathBuf,

    /// Sanitization profile (see `dc profiles`)
    #[arg(short, long, default_value = "nist-clear")]
    pub profile: ProfileOption,

    /// Post-wipe verification level to compile into the plan:
    /// full | none | sample:N (NIST SP 800-88 sampled verification)
    #[arg(long)]
    pub verify: Option<String>,

    /// Forbid kernel BLKZEROOUT offloading (force observable bus write traffic)
    #[arg(long)]
    pub no_write_zeroes: bool,

    /// Optional output file path for compiled Sanitization Plan JSON [Spec Delta Δ49]
    #[arg(short, long)]
    pub out: Option<PathBuf>,

    /// Explicit 32-byte CSPRNG seed in hex (64 chars) for deterministic PRNG passes [Spec Delta Δ56]
    #[arg(long)]
    pub seed: Option<String>,
}

#[derive(Args, Debug)]
pub struct ExecuteArgs {
    /// Target device path (repeat --target / list multiple paths to wipe a
    /// batch of devices in parallel: --target /dev/sda --target /dev/sdb)
    #[arg(short, long, required = true, num_args = 1..)]
    pub target: Vec<PathBuf>,

    /// Bind execution to a pre-compiled Sanitization Plan JSON file [Spec Delta Δ49]
    #[arg(long)]
    pub plan: Option<PathBuf>,

    /// Sanitization profile (see `dc profiles` for the full catalog)
    #[arg(short, long, default_value = "nist-clear")]
    pub profile: ProfileOption,

    /// Post-wipe verification level: full | none | sample:N (NIST SP 800-88
    /// sampled verification, 1-in-N windows) — cannot override a --plan
    #[arg(long)]
    pub verify: Option<String>,

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

    /// Allow overwriting retired LVM / RAID members [Spec Delta Δ32]
    #[arg(long)]
    pub allow_member: bool,

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

    /// Stop BEFORE any destructive step or confirmation prompt: compile the
    /// plan, run the Guardian, print exactly what WOULD be written, then exit
    /// 0 without touching the device or creating a journal (REG-DRYRUN-BOUNDARY).
    #[arg(long)]
    pub dry_run: bool,

    /// Explicit 32-byte CSPRNG seed in hex (64 chars) for deterministic PRNG
    /// passes (mirrors `dc plan --seed`)
    #[arg(long)]
    pub seed: Option<String>,

    /// Path to a two-officer AuthorizationSet JSON (see `dc approve`); when
    /// supplied, execution REQUIRES its countersignatures to verify before
    /// arming (Δ448)
    #[arg(long)]
    pub auth_set: Option<PathBuf>,

    /// Thermal throttle threshold in Celsius (default 55) for the
    /// overwrite pacing governor (v0.7.0, Vector 2).
    #[arg(long)]
    pub thermal_throttle_c: Option<i32>,

    /// Thermal abort threshold in Celsius (default 70): at or above it
    /// the run aborts before certification.
    #[arg(long)]
    pub thermal_critical_c: Option<i32>,

    /// Capture a TPM 2.0 remote-attestation quote over PCRs 0-11 into the
    /// certificate when a TPM is present (v0.8.0, Vector 1).
    #[arg(long)]
    pub tpm_quote: bool,

    /// Refuse to certify without a verified TPM quote (fail-closed).
    #[arg(long)]
    pub tpm_quote_required: bool,

    /// Execute the verification-critical path inside the micro-KVM vault
    /// enclave (v0.8.0, Vector 2). Requires /dev/kvm.
    #[arg(long)]
    pub vault: bool,

    /// Vault posture: require SEV/TDX memory encryption (implies --vault).
    #[arg(long)]
    pub vault_encrypted_required: bool,
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

    /// Drive serial confirmation for scripted resume [Spec Delta Δ5]
    #[arg(long)]
    pub serial_confirm: Option<String>,

    /// Allow targeting loopback virtual block devices on resume
    #[arg(long)]
    pub allow_loop: bool,

    /// Override root / system disk protection on resume
    #[arg(long)]
    pub allow_system_disk: bool,

    /// Allow overwriting disks with inactive filesystem/RAID signatures on resume
    #[arg(long)]
    pub allow_inactive_signatures: bool,

    /// Allow overwriting retired LVM / RAID members on resume [Spec Delta Δ32]
    #[arg(long)]
    pub allow_member: bool,

    /// Output directory for certificate files
    #[arg(short, long, default_value = ".")]
    pub out_dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct BenchArgs {
    /// Benchmark file path (MUST be a regular file, never a block device —
    /// bench uses the production engines; create one with `truncate -s`)
    #[arg(short, long)]
    pub file: PathBuf,

    /// Working set size in MiB
    #[arg(long, default_value_t = 512)]
    pub size_mib: u64,

    /// I/O engine to benchmark (auto, uring, sync)
    #[arg(long, value_enum, default_value_t = EngineChoice::Auto)]
    pub engine: EngineChoice,

    /// Reference device size in GiB for the per-profile ETA table
    #[arg(long, default_value_t = 1024)]
    pub ref_gib: u64,

    /// Wipe window size in MiB (engine tuning)
    #[arg(long, default_value_t = 2)]
    pub window_mib: u64,
}

#[derive(Args, Debug)]
pub struct PurgeArgs {
    /// Target block device on any purge-capable bus (NVMe namespace,
    /// SATA/SAT drive incl. USB docks, or SAS/SCSI LUN — e.g. /dev/nvme0n1,
    /// /dev/sda, /dev/sdb)
    #[arg(short, long)]
    pub target: PathBuf,

    /// Purge mechanism (bus-dispatched): auto (support-attested ladder) |
    /// sanitize-crypto | sanitize-block | format-crypto (NVMe) |
    /// security-erase-enhanced | security-erase-normal (ATA) |
    /// format-unit (SCSI)
    #[arg(long, default_value = "auto")]
    pub mechanism: String,

    /// Operator Ed25519 signing key path
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// Drive serial confirmation for scripted execution
    #[arg(long)]
    pub serial_confirm: Option<String>,

    /// Override root / system disk protection
    #[arg(long)]
    pub allow_system_disk: bool,

    /// Allow targeting loopback virtual block devices
    #[arg(long)]
    pub allow_loop: bool,

    /// Allow overwriting disks with inactive filesystem/RAID signatures
    #[arg(long)]
    pub allow_inactive_signatures: bool,

    /// Allow overwriting retired LVM / RAID members [Spec Delta Δ32]
    #[arg(long)]
    pub allow_member: bool,

    /// Suppress progress output (for testing/automation)
    #[arg(long)]
    pub no_progress: bool,

    /// Output directory for certificate and journal files
    #[arg(short, long, default_value = ".")]
    pub out_dir: PathBuf,

    /// Compile the purge ladder and exit WITHOUT touching the device
    #[arg(long)]
    pub dry_run: bool,

    /// Lights-out freeze remediation (v0.7.0, Vector 2): when the target
    /// is frozen, walk the cold-bus ladder (LUN delete + host rescan,
    /// ATA-port runtime-PM cycle) instead of refusing with a power-cycle
    /// advisory. Destructive-adjacent sysfs operations — the operator
    /// opts in for unattended racks.
    #[arg(long)]
    pub cold_unfreeze: bool,

    /// Thermal throttle threshold in Celsius (default 55): above it the
    /// run inserts adaptive pacing delays to protect the media.
    #[arg(long)]
    pub thermal_throttle_c: Option<i32>,

    /// Thermal abort threshold in Celsius (default 70): at or above it
    /// the run is refused certification (media health > completion).
    #[arg(long)]
    pub thermal_critical_c: Option<i32>,

    /// Disable the thermal guard entirely (NOT recommended; disclosed)
    #[arg(long)]
    pub no_thermal_guard: bool,

    /// Capture a TPM 2.0 remote-attestation quote over PCRs 0-11 into the
    /// certificate when a TPM is present (v0.8.0, Vector 1).
    #[arg(long)]
    pub tpm_quote: bool,

    /// Refuse to certify without a verified TPM quote (fail-closed
    /// hardware attestation).
    #[arg(long)]
    pub tpm_quote_required: bool,

    /// Execute the verification-critical path inside the micro-KVM vault
    /// enclave (v0.8.0, Vector 2). Requires /dev/kvm.
    #[arg(long)]
    pub vault: bool,

    /// Vault posture: require SEV/TDX memory encryption, refusing to run
    /// on hosts without it (implies --vault).
    #[arg(long)]
    pub vault_encrypted_required: bool,

    /// Runtime v0.8.0 evidence (TPM quote bundle, vault report, fabric
    /// session) captured by `cmd_purge` and consumed by the certificate
    /// assembly. Not a CLI flag.
    #[arg(skip)]
    pub v08_evidence: Option<std::sync::Arc<crate::purge::V08Evidence>>,
}

#[derive(Args, Debug)]
pub struct ApproveArgs {
    /// Path to the compiled Sanitization Plan JSON to countersign
    #[arg(short, long)]
    pub plan: PathBuf,

    /// First officer's Ed25519 private key path
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// Second officer's Ed25519 private key path (two-person integrity)
    #[arg(long)]
    pub key2: Option<PathBuf>,

    /// FIRST officer signs ON A HARDWARE TOKEN (PIV/CAC/YubiKey, USB
    /// CCID) instead of a keyfile: "auto" picks the first PIV reader on
    /// the bus, or pass the /dev/bus/usb/BBB/DDD node. The PIN is
    /// prompted on /dev/tty with echo disabled (v0.7.0, Vector 1).
    #[arg(long)]
    pub token: Option<String>,

    /// SECOND officer signs on a hardware token (same semantics)
    #[arg(long)]
    pub token2: Option<String>,

    /// Mark the FIRST officer's signature as originating from a hardware
    /// token (HSM/PIV) for custody-type derivation
    #[arg(long)]
    pub officer1_hardware: bool,

    /// Mark the SECOND officer's signature as originating from a hardware
    /// token (HSM/PIV) for custody-type derivation
    #[arg(long)]
    pub officer2_hardware: bool,

    /// Output path for the AuthorizationSet JSON
    #[arg(short, long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Target device path (if omitted, extracted from journal/cert)
    #[arg(short, long)]
    pub target: Option<PathBuf>,

    /// Path to .cert.json certificate to verify against
    #[arg(short, long)]
    pub cert: Option<PathBuf>,

    /// Path to .dcj journal file to re-verify against [Spec Delta Δ75]
    #[arg(long)]
    pub journal: Option<PathBuf>,
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
    /// Cryptographically verify certificate digital signature and authenticity
    Verify {
        file: PathBuf,
        /// Expected operator key fingerprint in hex (BLAKE3 of public key)
        #[arg(long)]
        fingerprint: Option<String>,
        /// Path to trusted public keys list file
        #[arg(long)]
        trusted_keys: Option<PathBuf>,
        /// Require verification to be anchored to a trusted fingerprint or key [Spec Delta Δ63]
        #[arg(long)]
        require_anchor: bool,
        /// Reconcile against corresponding .dcj journal file [Spec Delta Δ40]
        #[arg(long)]
        journal: Option<PathBuf>,
    },
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
pub struct JournalArgs {
    #[command(subcommand)]
    pub sub: JournalSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum JournalSubcommands {
    /// Inspect, parse, and diagnose a .dcj journal file in a strictly read-only manner [Spec Delta Δ92]
    Inspect { file: PathBuf },

    /// Generate format-authentic test journals for testing and verification [Spec Delta Δ119]
    SelftestSequence {
        /// Flavor to generate: clean | failed | interrupted | 2-epoch | dod3 | sealed
        #[arg(long, default_value = "clean")]
        flavor: String,
        /// Output path for generated .dcj file
        #[arg(short, long)]
        out: PathBuf,
        /// Optional Ed25519 signing key for sealed flavor
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Output path for operator private keyfile
    #[arg(short, long, default_value = "operator.key")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct BootArgs {
    #[command(subcommand)]
    pub sub: BootSubcommands,
}

// ---------------------------------------------------------------------------
// v0.8.0: Sovereign Air-Gap command surface
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct QuoteArgs {
    #[command(subcommand)]
    pub sub: QuoteSubcommands,
}

#[derive(Args, Debug)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub sub: KeySubcommands,
}

#[derive(Subcommand, Debug)]
pub enum KeySubcommands {
    /// Seal an operator keyfile into the machine's TPM 2.0, bound to the
    /// current PCR state (firmware + kernel + initramfs + dc binary)
    Seal {
        /// Plaintext operator keyfile (32-byte hex, mode 0600) to seal
        key: PathBuf,
        /// PCRs to bind the policy to (e.g. '0-11', '0,1,9'); default:
        /// the full quote bank 0-11
        #[arg(long)]
        pcrs: Option<String>,
        /// Output path for the sealed blob JSON (default: <key>.sealed.json)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Recover a sealed key — ONLY if the platform state still matches
    /// the sealing policy (writes the plaintext key to --out)
    Unseal {
        /// Sealed blob JSON produced by `dc key seal`
        blob: PathBuf,
        /// Output path for the recovered plaintext keyfile (created 0600)
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Inspect a sealed blob's policy WITHOUT touching the TPM
    Inspect { blob: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum QuoteSubcommands {
    /// Measure the appliance artifacts into PCRs 8-11 and produce a
    /// locally-verified TPM2_Quote over PCRs 0-11
    Generate {
        /// Kernel image to measure into PCR 8
        #[arg(long)]
        kernel: Option<PathBuf>,
        /// initramfs to measure into PCR 9
        #[arg(long)]
        initramfs: Option<PathBuf>,
        /// dc binary to measure into PCR 10
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Evidence tag extended into PCR 11 (default: run timestamp)
        #[arg(long)]
        evidence_tag: Option<String>,
        /// Freshness nonce in hex (default: run-bound BLAKE3)
        #[arg(long)]
        nonce: Option<String>,
        /// Output file for the quote bundle JSON (default: stdout)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Re-verify a saved quote bundle offline (the auditor's check)
    Verify { file: PathBuf },
}

#[derive(Args, Debug)]
pub struct PhotonArgs {
    #[command(subcommand)]
    pub sub: PhotonSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum PhotonSubcommands {
    /// Stream a file as an endless animated QR fountain (point the
    /// approved scanner at the screen)
    Stream {
        /// Evidence file to stream (certificate, journal, package…)
        file: PathBuf,
        /// Frames per second
        #[arg(long, default_value_t = 2.0)]
        fps: f64,
        /// Fountain block size in bytes
        #[arg(long, default_value_t = 48)]
        block_size: usize,
        /// Requested symbols per frame (clamped to QR capacity)
        #[arg(long, default_value_t = 4)]
        batch: u8,
        /// Quiet-zone modules around the QR
        #[arg(long, default_value_t = 2)]
        quiet_zone: usize,
        /// Experimental color-matrix mode (2 modules per character cell)
        #[arg(long, default_value_t = false)]
        color: bool,
        /// Stop after N frames (test rigs)
        #[arg(long)]
        limit: Option<u64>,
        /// Fountain stream seed (hex; receiver must match)
        #[arg(long, default_value = "0")]
        seed: String,
    },
    /// Reassemble a captured frame dump and verify the payload hash
    Decode {
        /// Frame dump file (one hex frame per line, from --dump-frames)
        frames: PathBuf,
        /// Fountain stream seed (hex)
        #[arg(long, default_value = "0")]
        seed: String,
        /// Write recovered payload here
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Print the stream manifest for the certificate
    Manifest {
        file: PathBuf,
        #[arg(long, default_value_t = 48)]
        block_size: usize,
        #[arg(long, default_value = "0")]
        seed: String,
    },
}

#[derive(Args, Debug)]
pub struct FabricsArgs {
    #[command(subcommand)]
    pub sub: FabricsSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum FabricsSubcommands {
    /// List connected fabric controllers
    List,
    /// Connect to a fabric target: nvme+tcp://addr[:port]/nqn…
    Connect {
        target: String,
        /// CONNECT netlink ACK deadline (ms)
        #[arg(long, default_value_t = 5000)]
        ack_ms: u64,
        /// Controller appearance deadline (ms)
        #[arg(long, default_value_t = 30000)]
        ctrl_appear_ms: u64,
        /// Disconnect immediately after a successful connect (probe)
        #[arg(long, default_value_t = false)]
        disconnect: bool,
    },
    /// Disconnect a controller by its fabric target
    Disconnect { target: String },
    /// Discover subsystems behind a discovery controller
    Discover {
        target: String,
        #[arg(long, default_value_t = 5000)]
        ack_ms: u64,
        #[arg(long, default_value_t = 30000)]
        ctrl_appear_ms: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum BootSubcommands {
    /// Run the real PID-1 bootstrap (mounts, entropy seeding, zombie
    /// reaper) — the /init entry of the RAM-resident appliance
    Init {
        /// Print the sequence record and exit (no destructive action
        /// follows the bootstrap in self-test mode)
        #[arg(long)]
        self_test: bool,
    },
    /// Pack the appliance initramfs (cpio newc) from a staged static dc
    /// binary and verify its constituents against the manifest
    Pack {
        /// Staged static musl dc binary to embed as /init
        #[arg(short, long)]
        dc_bin: PathBuf,
        /// Output path for the initramfs cpio
        #[arg(short, long, default_value = "dc-appliance-initramfs.cpio")]
        out: PathBuf,
        /// Optional kernel bzImage to hash into a new constituents
        /// manifest (writes <out>.manifest.json)
        #[arg(long)]
        kernel: Option<PathBuf>,
        /// Existing constituents manifest to verify against instead
        #[arg(long)]
        verify_against: Option<PathBuf>,
    },
}

pub fn entrypoint() -> ExitCode {
    tracing_subscriber::fmt::init();

    // Fresh process: no stale cancellation state, termination handlers armed.
    dc_io::reset_global_cancel();
    install_signal_handlers();

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
        Commands::Check(args) => {
            cmd_check(args, &mut audit)?;
            Ok(())
        }
        Commands::Plan(args) => {
            cmd_plan(args, &mut audit)?;
            Ok(())
        }
        Commands::Execute(args) => {
            execute::cmd_execute(args, &mut audit)?;
            Ok(())
        }
        Commands::Profiles => {
            print!("{}", profiles::render_catalog());
            Ok(())
        }
        Commands::Bench(args) => {
            bench::cmd_bench(args)?;
            Ok(())
        }
        Commands::Purge(args) => {
            purge::cmd_purge(args, &mut audit)?;
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
        Commands::Journal(args) => {
            cmd_journal(args)?;
            Ok(())
        }
        Commands::Keygen(args) => {
            cmd_keygen(args)?;
            Ok(())
        }
        Commands::Approve(args) => {
            cmd_approve(args)?;
            Ok(())
        }
        Commands::Boot(args) => {
            cmd_boot(args)?;
            Ok(())
        }
        Commands::Quote(args) => {
            quote::cmd_quote(args)?;
            Ok(())
        }
        Commands::Key(args) => {
            key::cmd_key(args)?;
            Ok(())
        }
        Commands::Photon(args) => {
            photon::cmd_photon(args)?;
            Ok(())
        }
        Commands::Fabrics(args) => {
            fabrics::cmd_fabrics(args)?;
            Ok(())
        }
    }
}

/// `dc boot` — appliance lifecycle verbs (v0.7.0, Vector 3).
fn cmd_boot(args: BootArgs) -> Result<(), DcError> {
    match args.sub {
        BootSubcommands::Init { self_test } => {
            use crate::init::LinuxInitBackend;
            let backend = LinuxInitBackend;
            let constituents = "appliance-self-test";
            let (state, record) = crate::init::run_pid1_init_real(&backend, true, constituents)
                .map_err(|e| {
                    eprintln!("[BOOT] PID-1 sequence refused: {}", e);
                    e
                })?;
            println!("[BOOT] PID-1 bootstrap sequence complete");
            for (source, target, fstype) in &record.mounted {
                println!("       mounted {} on {} ({})", source, target, fstype);
            }
            for target in &record.already_mounted {
                println!("       already mounted: {}", target);
            }
            println!(
                "       entropy credited: {} bytes, zombie reaper installed: {}",
                record.entropy_bytes_credited, record.zombie_reaper_installed
            );
            if self_test {
                println!(
                    "[BOOT] self-test: state fingerprint {}",
                    state.environment_fingerprint
                );
                return Ok(());
            }
            // Real appliance mode: hand over to the fleet wipe interface.
            println!(
                "[BOOT] appliance ready — every physical drive is unmounted; run `dc list` \
 then `dc execute --target <dev> --profile <profile>`"
            );
            Ok(())
        }
        BootSubcommands::Pack {
            dc_bin,
            out,
            kernel,
            verify_against,
        } => {
            let binary = crate::bootiso::read_file_bytes(&dc_bin)?;
            if let Some(manifest_path) = verify_against {
                let manifest: crate::bootattest::ConstituentsManifest = serde_json::from_str(
                    &std::fs::read_to_string(&manifest_path)?,
                )
                .map_err(|e| {
                    DcError::Usage(format!(
                        "invalid constituents manifest '{}': {}",
                        manifest_path.display(),
                        e
                    ))
                })?;
                // The kernel is mandatory when the manifest binds a real
                // kernel hash; a kernel-less (PXE userspace-only) manifest
                // carries the zero digest and verifies the binary + archive.
                let kernel_bytes = match &kernel {
                    Some(k) => crate::bootiso::read_file_bytes(k)?,
                    None => {
                        if manifest.kernel_hash != "0".repeat(64) {
                            return Err(DcError::Usage(
                                "--kernel is required with --verify-against (the manifest binds \
                                 a kernel image)"
                                    .to_string(),
                            ));
                        }
                        Vec::new()
                    }
                };
                let initramfs = crate::bootiso::build_appliance_initramfs(&binary, &manifest);
                crate::bootiso::verify_constituents(&manifest, &kernel_bytes, &binary, &initramfs)?;
                std::fs::write(&out, &initramfs)?;
                println!(
                    "[BOOT] constituents verified; initramfs written to {}",
                    out.display()
                );
                return Ok(());
            }
            // Build a fresh manifest (kernel optional: census hash used).
            // The embedded copy self-describes with a zeroed initramfs
            // digest (a hash cannot contain itself), so ONE build is
            // canonical and `--verify-against` reproduces it exactly.
            let kernel_bytes = kernel
                .as_ref()
                .map(|k| crate::bootiso::read_file_bytes(k))
                .transpose()?;
            let mut manifest = crate::bootattest::ConstituentsManifest {
                kernel_hash: kernel_bytes
                    .as_ref()
                    .map(|k| blake3::hash(k).to_hex().to_string())
                    .unwrap_or_else(|| "0".repeat(64)),
                initramfs_hash: "0".repeat(64), // zeroed in the embedded projection
                binary_hash: blake3::hash(&binary).to_hex().to_string(),
                census_manifest_hash: "0".repeat(64),
            };
            let initramfs = crate::bootiso::build_appliance_initramfs(&binary, &manifest);
            manifest.initramfs_hash = blake3::hash(&initramfs).to_hex().to_string();
            std::fs::write(&out, &initramfs)?;
            let manifest_path = out.with_extension("manifest.json");
            std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
            println!("[BOOT] appliance initramfs written to {}", out.display());
            println!("       constituents manifest: {}", manifest_path.display());
            println!(
                "       dc binary: {} bytes, sha256/blake3 manifest emitted",
                binary.len()
            );
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

fn cmd_check(args: CheckArgs, audit: &mut Option<AuditLogger>) -> Result<(), DcError> {
    // Guardian-classified probe: a missing target refuses with exit 2
    // (REG-CHECK-NONEXIST), not a raw I/O error.
    let identity = InventoryScanner::probe_device_or_refuse(&args.target)?;

    let flags = GuardianFlags {
        allow_system_disk: args.allow_system_disk,
        serial_confirm: None,
        allow_loop: args.allow_loop,
        allow_inactive_signatures: args.allow_inactive_signatures,
        allow_member: args.allow_member,
    };

    match Guardian::evaluate(&args.target, &identity, &flags) {
        Ok(()) => {
            println!(
                "================================================================================"
            );
            println!("                     GUARDIAN SAFETY PRE-FLIGHT CHECK");
            println!(
                "================================================================================"
            );
            println!("Target Device:     {}", identity.dev_path);
            println!(
                "Target Model:      {}",
                identity.stable.model.as_deref().unwrap_or("-")
            );
            println!(
                "Target Serial:     {}",
                identity.stable.serial.as_deref().unwrap_or("-")
            );
            println!(
                "Capacity:          {} GiB",
                identity.stable.size_bytes / (1024 * 1024 * 1024)
            );
            println!("VERDICT:           CLEAN (Target is safe for sanitization)");
            println!(
                "================================================================================"
            );
            Ok(())
        }
        Err(e) => {
            if let Some(a) = audit
                && let DcError::Guardian(ref g) = e
            {
                let _ = a.log(&AuditRecord {
                    timestamp_utc: chrono_now_iso(),
                    argv_hash: "check".to_string(),
                    target_path: Some(identity.dev_path.clone()),
                    outcome: AuditOutcome::Refusal {
                        code: g.code.to_string(),
                        detail: g.detail.clone(),
                    },
                });
            }
            if let DcError::Guardian(ref g) = e {
                eprintln!(
                    "================================================================================"
                );
                eprintln!("                     GUARDIAN REFUSAL: [{}]", g.code);
                eprintln!(
                    "================================================================================"
                );
                eprintln!("Target:  {}", identity.dev_path);
                eprintln!("Detail:  {}", g.detail);
                eprintln!("Hint:    {}", g.hint);
                eprintln!(
                    "================================================================================"
                );
            }
            Err(e)
        }
    }
}

impl ExecuteArgs {
    /// Human-readable engine name for plan/dry-run output.
    fn engine_default_name(&self) -> &'static str {
        match self.engine {
            EngineChoice::Auto => "auto (io_uring if available, else sync)",
            EngineChoice::Uring => "uring",
            EngineChoice::Sync => "sync",
        }
    }
}

fn cmd_plan(args: PlanArgs, audit: &mut Option<AuditLogger>) -> Result<(), DcError> {
    // Argument validation FIRST — a usage error (bad seed/profile combo)
    // must fail fast BEFORE any device is probed (fail-fast contract).
    let explicit_seed = match args.seed {
        Some(ref s) => profiles::parse_seed_hex(s, args.profile).map_err(DcError::Usage)?,
        None => None,
    };
    let verification = match args.verify.as_deref() {
        Some(spec) => {
            let level = profiles::parse_verify_flag(spec).map_err(DcError::Usage)?;
            // DEFENSE PROFILE ENFORCEMENT GATE (v0.6.0,
            // REG-DEFENSE-SAMPLING-REFUSED): a compiled plan for a defense
            // profile may never carry sampled/no verification.
            profiles::enforce_verification_policy(&args.profile.to_profile(), &level)
                .map_err(DcError::Usage)?;
            level
        }
        None => args.profile.to_profile().default_verification(),
    };

    // Guardian-classified probe (REG-CHECK-NONEXIST): a missing target is a
    // Guardian refusal (exit 2), not a raw I/O error.
    let identity = InventoryScanner::probe_device_or_refuse(&args.target)?;
    let fast_path = if args.no_write_zeroes {
        FastPathPolicy::ForbidWriteZeroes
    } else {
        FastPathPolicy::PreferWriteZeroes
    };

    let mut plan = SanitizationPlan::from_profile(
        args.profile.to_profile(),
        identity.stable.clone(),
        explicit_seed,
        fast_path,
        verification,
    )?;
    // If the device is NVMe and the controller char dev is readable, compile
    // the hardware purge strategy ladder into the plan for operator review.
    if let Some(ladder) = purge::compile_target_ladder(&identity) {
        plan.strategy_ladder = Some(ladder);
    }

    let plan_hash = plan.compute_plan_hash()?;

    println!("================================================================================");
    println!("                     SANITIZATION PLAN SPECIFICATION");
    println!("================================================================================");
    println!("Target Path:       {}", identity.dev_path);
    println!(
        "Target Model:      {}",
        identity.stable.model.as_deref().unwrap_or("Unknown")
    );
    println!(
        "Target Serial:     {}",
        identity.stable.serial.as_deref().unwrap_or("Unknown")
    );
    println!(
        "Target Capacity:   {} GiB ({:.2} GB)",
        identity.stable.size_bytes / (1024 * 1024 * 1024),
        identity.stable.size_bytes as f64 / 1_000_000_000.0
    );
    println!("Plan Schema:       {}", plan.plan_schema);
    println!("Plan Hash (BLAKE3):{}", plan_hash);
    println!("Verification:      {}", plan.verification);

    match &plan.mechanism {
        dc_core::Mechanism::LogicalOverwrite {
            passes: plan_passes,
        } => {
            if !plan_passes.is_empty() {
                println!("Passes Count:      {}", plan_passes.len());
                for (i, p) in plan_passes.iter().enumerate() {
                    println!("  Pass {}: {}", i + 1, p.label);
                }
            }
        }
        dc_core::Mechanism::HardwarePurge { .. } => {
            println!("Mechanism:         Hardware Purge (controller-attested)");
        }
    }

    if let Some(ladder) = &plan.strategy_ladder {
        println!("\nPurge Strategy Ladder (hardware paths this device attests):");
        for (i, step) in ladder.steps.iter().enumerate() {
            println!(
                "  {:>2}. {:<28} NIST class: {:<6} read-back: {}",
                i + 1,
                step.name,
                step.nist_class,
                step.readback_expectation
            );
        }
    }

    if let Some(note) = &plan.legacy_note {
        println!("\n[!] LEGAL NOTICE: {}", note);
    }
    println!("================================================================================");

    if let Some(ref out_path) = args.out {
        let plan_json = serde_json::to_string_pretty(&plan)?;
        std::fs::write(out_path, plan_json)?;
        println!("[+] Plan specification saved to: {}", out_path.display());
    }

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

fn cmd_resume(args: ResumeArgs, audit: &mut Option<AuditLogger>) -> Result<(), DcError> {
    println!(
        "Reading and verifying journal chain: {}...",
        args.journal.display()
    );
    let (records, summary) = JournalReader::read_and_verify_chain(&args.journal)?;

    if records.is_empty() {
        return Err(DcError::JournalCorrupt {
            record_index: 0,
            reason: "Journal is empty".to_string(),
        });
    }

    let last_record = records.last().unwrap();
    if let JournalRecord::Completed { .. } = last_record {
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

    // Extract header
    let (plan, plan_hash, identity) = records
        .iter()
        .find_map(|r| match r {
            JournalRecord::Header {
                plan,
                plan_hash,
                identity,
                ..
            } => Some((plan.clone(), plan_hash.clone(), identity.clone())),
            _ => None,
        })
        .ok_or_else(|| DcError::JournalCorrupt {
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
            JournalRecord::RangeCommit {
                pass, num_windows, ..
            } => {
                if *pass == last_pass_idx {
                    last_pass_committed_windows += num_windows;
                }
            }
            JournalRecord::Flushed { .. } => {
                verify_reached = true;
            }
            JournalRecord::Failed {
                code,
                errno,
                op,
                at_lba,
                ..
            } => {
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

    if records
        .last()
        .map(|r| {
            !matches!(
                r,
                JournalRecord::Failed { .. } | JournalRecord::Interrupted { .. }
            )
        })
        .unwrap_or(false)
    {
        interruptions.push(InterruptionRecord {
            at_utc: chrono_now_iso(),
            resumed_utc: chrono_now_iso(),
        });
    }

    // Re-run the Guardian on the LIVE device state before resuming: the
    // world may have changed since the interruption (a filesystem could
    // have been mounted, an md array assembled). Resume flags mirror the
    // execute flags so scripted resumes stay non-interactive.
    let live_identity = InventoryScanner::probe_device(Path::new(&identity.dev_path))?;
    let flags = GuardianFlags {
        allow_system_disk: args.allow_system_disk,
        serial_confirm: args.serial_confirm.clone(),
        allow_loop: args.allow_loop,
        allow_inactive_signatures: args.allow_inactive_signatures,
        allow_member: args.allow_member,
    };
    if let Err(e) = Guardian::evaluate(Path::new(&identity.dev_path), &live_identity, &flags) {
        if let Some(a) = audit
            && let DcError::Guardian(ref g) = e
        {
            let _ = a.log(&AuditRecord {
                timestamp_utc: chrono_now_iso(),
                argv_hash: "resume".to_string(),
                target_path: Some(identity.dev_path.clone()),
                outcome: AuditOutcome::Refusal {
                    code: g.code.to_string(),
                    detail: g.detail.clone(),
                },
            });
        }
        return Err(e);
    }

    // Arm and Lock Hardware
    let lock_handle = Guardian::arm_and_lock(Path::new(&identity.dev_path), &identity.stable)?;
    let mut fsm = FsmOrchestrator::new();
    fsm.compile_plan(plan.clone())?;
    fsm.approve_plan()?;
    fsm.arm()?;

    // Setup and validate operator key for sealed journals (Δ39)
    let keypair = match &args.key {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => {
            if summary.sealed {
                return Err(DcError::Usage(
                    "This journal is SEALED with digital signatures. You must provide '--key <OPERATOR_KEY>' to resume.".to_string()
                ));
            }
            OperatorKeyPair::generate()
        }
    };

    if summary.sealed
        && let Some(JournalRecord::Header {
            operator_pubkey: Some(expected_pk),
            ..
        }) = records.first()
        && &keypair.public_key_hex() != expected_pk
    {
        return Err(DcError::CertSigning(format!(
            "Key mismatch for sealed journal! Expected key: {}, Provided: {}",
            expected_pk,
            keypair.public_key_hex()
        )));
    }

    let signing_key = if summary.sealed {
        Some(keypair.signing_key.clone())
    } else {
        None
    };

    let mut journal = JournalWriter::open_for_resume(
        &args.journal,
        &summary.chain_head,
        summary.record_count,
        if summary.discarded_tail_bytes > 0 {
            Some(args.journal.metadata()?.len() - summary.discarded_tail_bytes)
        } else {
            None
        },
        summary.uuid.clone(),
        summary.sealed,
        signing_key,
    )?;

    journal.append(&JournalRecord::Armed {
        overrides: vec![],
        locks_held: vec![format!(
            "{}:{}",
            identity.kernel.major, identity.kernel.minor
        )],
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
    )?;

    let passes = match &plan.mechanism {
        dc_core::Mechanism::LogicalOverwrite { passes } => passes.clone(),
        dc_core::Mechanism::HardwarePurge { .. } => Vec::new(), // no logical passes on resume of purge journal
    };

    let mut exec_passes = Vec::new();
    let exec_start_time = Instant::now();

    if !verify_reached {
        for (offset, pass) in passes.iter().enumerate().skip(last_pass_idx as usize) {
            let pass_idx = last_pass_idx as usize + offset;
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

            let outcome = match if matches!(pass.pattern, Pattern::Zero) && supports_write_zeroes {
                engine.zero_pass(&permit, pass_idx as u8, &span, start_window, &mut |_| {})
            } else {
                engine.write_pass(
                    &permit,
                    pass_idx as u8,
                    pat_source.as_ref(),
                    &span,
                    start_window,
                    &mut |_| {},
                )
            } {
                Ok(o) => o,
                Err(DcError::Interrupted { completed_through }) => {
                    let (through_pass, through_window) = match completed_through {
                        Some((p, w)) => (Some(p), Some(w)),
                        None => (Some(pass_idx as u8), None),
                    };
                    let _ = journal.append(&JournalRecord::Interrupted {
                        at: chrono_now_iso(),
                        hint: "Graceful drain on termination signal during resume".to_string(),
                        completed_through_pass: through_pass,
                        completed_through_window: through_window,
                        signals_received: Some(
                            SIGNALS_RECEIVED.load(std::sync::atomic::Ordering::SeqCst),
                        ),
                    });
                    return Err(DcError::Interrupted { completed_through });
                }
                Err(e) => {
                    let (errno, at_lba) = match &e {
                        DcError::Io { errno, at_lba, .. } => (Some(*errno), *at_lba),
                        DcError::StdIo(io_err) => (io_err.raw_os_error(), None),
                        _ => (None, None),
                    };
                    let _ = journal.append(&JournalRecord::Failed {
                        code: "EIO".to_string(),
                        errno,
                        op: Some("resume-write".to_string()),
                        at_lba,
                        detail: e.to_string(),
                    });
                    return Err(e);
                }
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

            // Honest per-pass throughput (KiB/s) computed from the outcome.
            let elapsed_s = (outcome.duration_ms as f64 / 1000.0).max(0.001);
            let throughput_kib_s = ((outcome.bytes_written as f64 / 1024.0) / elapsed_s) as u64;

            exec_passes.push(ExecutionPassReport {
                index: pass_idx as u8,
                pattern: pat_source.descriptor().name,
                fast_path_used: outcome.fast_path_used,
                windows_written: outcome.windows_written,
                throughput_kib_s,
            });
        }
    }

    // Verify Phase (Δ17: verifies entire device from 0)
    fsm.begin_verify()?;
    let last_pass = passes.last().unwrap();
    let verify_pat_source = create_pattern_source(&last_pass.pattern);
    let mut verifier = StreamVerifier::new(
        plan.verification,
        plan.window_bytes,
        identity.logical_block_size,
        false,
        true,
    );

    if let Err(e) = engine.read_verify(
        verify_pat_source.as_ref(),
        &span,
        plan.verification.effective_stride(),
        &mut verifier,
        &mut |_| {},
    ) {
        match e {
            DcError::Interrupted { completed_through } => {
                let _ = journal.append(&JournalRecord::Interrupted {
                    at: chrono_now_iso(),
                    hint: "Graceful drain on termination signal during resume verification"
                        .to_string(),
                    completed_through_pass: completed_through.map(|(p, _)| p),
                    completed_through_window: completed_through.map(|(_, w)| w),
                    signals_received: Some(
                        SIGNALS_RECEIVED.load(std::sync::atomic::Ordering::SeqCst),
                    ),
                });
                return Err(DcError::Interrupted { completed_through });
            }
            e => {
                let (errno, at_lba) = match &e {
                    DcError::Io { errno, at_lba, .. } => (Some(*errno), *at_lba),
                    DcError::StdIo(io_err) => (io_err.raw_os_error(), None),
                    _ => (None, None),
                };
                let _ = journal.append(&JournalRecord::Failed {
                    code: "EIO".to_string(),
                    errno,
                    op: Some("resume-verify-read".to_string()),
                    at_lba,
                    detail: e.to_string(),
                });
                return Err(e);
            }
        }
    }
    let verify_report = verifier.finalize();

    journal.append(&JournalRecord::Verify {
        level: plan.verification.short_tag(),
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
        args.journal
            .file_name()
            .unwrap()
            .to_string_lossy()
            .trim_end_matches(".dcj")
    );
    let cert_path = args.out_dir.join(&cert_filename);
    let cert_json = serde_json::to_string_pretty(&cert)?;
    std::fs::write(&cert_path, cert_json)?;

    if !args.no_progress {
        println!("\n{}", cert.render_summary());
        println!(
            "\n[+] Resumed Sanitization Successful. Certificate written to: {}",
            cert_path.display()
        );
    }

    Ok(())
}

fn cmd_verify_standalone(args: VerifyArgs) -> Result<(), DcError> {
    if let Some(ref j_path) = args.journal {
        println!(
            "Re-verifying media directly from journal: {}",
            j_path.display()
        );
        let (records, _summary) = JournalReader::read_and_verify_chain(j_path)?;
        let (plan, identity) = records
            .iter()
            .find_map(|r| match r {
                JournalRecord::Header { plan, identity, .. } => {
                    Some((plan.clone(), identity.clone()))
                }
                _ => None,
            })
            .ok_or_else(|| DcError::JournalCorrupt {
                record_index: 0,
                reason: "Missing Header record in journal".to_string(),
            })?;

        let target_path = args
            .target
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or(identity.dev_path.clone());
        let target_file = OpenOptions::new().read(true).open(&target_path)?;

        let span = LbaSpan::new(
            identity.stable.size_bytes,
            identity.logical_block_size,
            plan.window_bytes,
        );

        let passes = match &plan.mechanism {
            dc_core::Mechanism::LogicalOverwrite { passes } => passes,
            dc_core::Mechanism::HardwarePurge {
                selected_mechanism, ..
            } => {
                return Err(DcError::Usage(format!(
                    "journal binds a hardware-purge plan ({}) — resume applies to \
                     logical overwrite journals; re-run `dc purge` instead",
                    selected_mechanism
                )));
            }
        };
        let last_pass = passes
            .last()
            .ok_or_else(|| DcError::Usage("No passes in plan".to_string()))?;
        let pat_source = create_pattern_source(&last_pass.pattern);

        let mut verifier = StreamVerifier::new(
            plan.verification,
            plan.window_bytes,
            identity.logical_block_size,
            false,
            true,
        );

        let mut engine: Box<dyn dc_io::Engine> =
            create_engine(target_file, plan.window_bytes as usize, false, 64)?;
        engine.read_verify(
            pat_source.as_ref(),
            &span,
            plan.verification.effective_stride(),
            &mut verifier,
            &mut |_| {},
        )?;

        let report = verifier.finalize();
        if report.mismatch_count > 0 {
            eprintln!(
                "[-] Verification FAILED with {} mismatching windows!",
                report.mismatch_count
            );
            return Err(DcError::VerificationFailed {
                mismatches: report.mismatch_count,
                sample: report.first_mismatch_lbas,
            });
        }

        println!(
            "[+] Verification SUCCESSFUL: Whole-media matches pattern bit-for-bit (BLAKE3: {})",
            report.stream_hash_blake3
        );
        return Ok(());
    }

    if let Some(ref cert_path) = args.cert {
        let cert_content = std::fs::read_to_string(cert_path)?;
        let cert: SanitizationCertificate = serde_json::from_str(&cert_content)?;

        println!("Validating certificate signature...");
        if !cert.verify_signature()? {
            return Err(DcError::CertSigning(
                "Certificate digital signature is INVALID or corrupted!".to_string(),
            ));
        }
        println!("Certificate signature is valid (Ed25519 signed).");
        return Ok(());
    }

    Err(DcError::Usage(
        "Must specify either --journal <PATH> or --cert <PATH> to verify".to_string(),
    ))
}

fn cmd_cert(args: CertArgs) -> Result<(), DcError> {
    match args.sub {
        CertSubcommands::Show { file } => {
            let content = std::fs::read_to_string(&file)?;
            let cert: SanitizationCertificate = serde_json::from_str(&content)?;
            println!("{}", cert.render_summary());
            Ok(())
        }
        CertSubcommands::Verify {
            file,
            fingerprint,
            trusted_keys,
            require_anchor,
            journal,
        } => {
            let raw_bytes = std::fs::read(&file)?;

            let trusted_list: Option<Vec<String>> = if let Some(ref tk_path) = trusted_keys {
                let content = std::fs::read_to_string(tk_path)?;
                Some(
                    content
                        .lines()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                )
            } else {
                None
            };

            let res = SanitizationCertificate::verify_raw_cert_file(
                &raw_bytes,
                fingerprint.as_deref(),
                trusted_list.as_deref(),
            );

            // Deterministic transcript (§5 / Δ69)
            println!("file_blake3: {}", res.file_blake3);
            println!("mode:        {}", res.mode);

            if !res.is_valid {
                let err_msg = res
                    .error_detail
                    .unwrap_or_else(|| "Signature or format invalid".to_string());
                eprintln!("verdict:     INVALID ({})", err_msg);
                return Err(DcError::CertInvalid(err_msg));
            }

            if require_anchor && !res.is_authenticated {
                eprintln!(
                    "verdict:     ANCHOR_REQUIRED (Certificate signature is valid but unauthenticated)"
                );
                return Err(DcError::CertInvalid(
                    "ANCHOR_REQUIRED: Verification must be anchored".to_string(),
                ));
            }

            // Journal Reconciliation (§5 / Δ40 / F6)
            if let Some(ref j_path) = journal {
                let (_records, j_summary) = JournalReader::read_and_verify_chain(j_path)?;
                let cert: SanitizationCertificate = serde_json::from_slice(&raw_bytes)?;

                if cert.journal.chain_head != j_summary.chain_head {
                    eprintln!("verdict:     RECONCILE_FAILED (Chain head mismatch with journal)");
                    return Err(DcError::CertInvalid(format!(
                        "Journal chain_head mismatch! Cert: {}, Journal: {}",
                        cert.journal.chain_head, j_summary.chain_head
                    )));
                }

                if cert.journal.uuid != j_summary.uuid {
                    eprintln!("verdict:     RECONCILE_FAILED (Journal UUID mismatch)");
                    return Err(DcError::CertInvalid("Journal UUID mismatch".to_string()));
                }

                println!("journal:     RECONCILED ({})", j_path.display());
            }

            println!(
                "verdict:     VALID ({})",
                if res.is_authenticated {
                    "AUTHENTICATED"
                } else {
                    "INTEGRITY-ONLY"
                }
            );
            Ok(())
        }
        CertSubcommands::Reconstruct {
            journal,
            key,
            out_dir,
        } => cmd_cert_reconstruct(&journal, key.as_deref(), &out_dir),
    }
}

fn cmd_cert_reconstruct(
    journal_path: &Path,
    key_path: Option<&Path>,
    out_dir: &Path,
) -> Result<(), DcError> {
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

    let (plan, plan_hash, identity, started_utc) = records
        .iter()
        .find_map(|r| match r {
            JournalRecord::Header {
                plan,
                plan_hash,
                identity,
                started_utc,
                ..
            } => Some((
                plan.clone(),
                plan_hash.clone(),
                identity.clone(),
                started_utc.clone(),
            )),
            _ => None,
        })
        .ok_or_else(|| DcError::JournalCorrupt {
            record_index: 0,
            reason: "Missing Header in journal".to_string(),
        })?;

    let (finished_utc, duration_mono_ms) = records
        .iter()
        .find_map(|r| match r {
            JournalRecord::Completed {
                at,
                duration_mono_ms,
            } => Some((at.clone(), *duration_mono_ms)),
            _ => None,
        })
        .unwrap_or_else(|| (chrono_now_iso(), 0));

    let verify_report = records
        .iter()
        .find_map(|r| match r {
            JournalRecord::Verify {
                level,
                windows_checked,
                mismatch_count,
                first_mismatch_lbas,
                stream_hash_blake3,
                stream_hash_sha256,
                ..
            } => Some(dc_verify::VerificationReport {
                level: parse_journal_verify_level(level),
                windows_checked: *windows_checked,
                mismatch_count: *mismatch_count,
                first_mismatch_lbas: first_mismatch_lbas.clone(),
                stream_hash_blake3: stream_hash_blake3.clone(),
                stream_hash_sha256: stream_hash_sha256.clone(),
                entropy: None,
            }),
            _ => None,
        })
        .ok_or_else(|| DcError::JournalCorrupt {
            record_index: summary.record_count,
            reason: "Missing Verify record in completed journal".to_string(),
        })?;

    let mut failures = Vec::new();
    let mut interruptions = Vec::new();
    for r in &records {
        match r {
            JournalRecord::Failed {
                code,
                errno,
                op,
                at_lba,
                ..
            } => {
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
        journal_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .trim_end_matches(".dcj")
    );
    let cert_path = out_dir.join(&cert_filename);
    let cert_json = serde_json::to_string_pretty(&cert)?;
    std::fs::write(&cert_path, cert_json)?;

    println!(
        "[+] Certificate reconstructed successfully: {}",
        cert_path.display()
    );
    Ok(())
}

fn cmd_keygen(args: KeygenArgs) -> Result<(), DcError> {
    let keypair = OperatorKeyPair::generate();
    keypair.save_to_file(&args.out)?;
    println!("[+] Generated operator Ed25519 keypair");
    println!("    Private Key File:    {}", args.out.display());
    println!("    Public Key (hex):    {}", keypair.public_key_hex());
    println!(
        "    Key Fingerprint:     {}",
        keypair.key_fingerprint_blake3()
    );
    Ok(())
}

/// Two-officer countersignature approval of a compiled plan (Δ448).
///
/// Produces an `AuthorizationSet` JSON containing REAL Ed25519
/// countersignatures over the plan hash (one per officer key), which
/// `dc execute --auth-set <file>` then REQUIRES to verify before arming.
fn cmd_approve(args: ApproveArgs) -> Result<(), DcError> {
    let plan_content = std::fs::read_to_string(&args.plan)?;
    let plan: SanitizationPlan = serde_json::from_str(&plan_content).map_err(|e| {
        DcError::Usage(format!(
            "Invalid plan JSON '{}': {}",
            args.plan.display(),
            e
        ))
    })?;
    let plan_hash = plan.compute_plan_hash()?;

    // Officer 1: hardware token (PIV/CCID) takes precedence over the
    // keyfile — the signature is computed inside the secure element and
    // carries a HardwareCustodyAttestation (v0.7.0, Vector 1).
    let mut auth_set = AuthorizationSet::new(&plan_hash);
    let mut token_attestations: Vec<String> = Vec::new();

    match &args.token {
        Some(spec) => {
            let (entry, attestation) =
                sign_plan_on_hardware_token(spec, &plan_hash, dc_cert::PLAN_APPROVAL_DOMAIN)?;
            token_attestations.push(attestation.summary_line());
            auth_set.add_signature(entry);
            // A token officer needs no software keyfile; if one was also
            // supplied it stays UNUSED for this signature (disclosed).
            if args.key.is_some() {
                eprintln!("[NOTE] --key is ignored for officer 1: the --token signature is used.");
            }
        }
        None => {
            let key_path = args.key.as_ref().ok_or_else(|| {
                DcError::Usage(
                    "officer 1 needs a signing source: pass --key <keyfile> or --token \
                     <usb-node|auto> (hardware PIV custody)"
                        .to_string(),
                )
            })?;
            let officer1 = OperatorKeyPair::load_from_file(key_path)?;
            auth_set.add_signature(approve::PlanApprover::countersign_plan(
                &plan_hash,
                &officer1,
                args.officer1_hardware,
            ));
        }
    }

    // Officer 2: token2 (hardware) or key2 (software keyfile).
    if let Some(spec) = &args.token2 {
        let (entry, attestation) =
            sign_plan_on_hardware_token(spec, &plan_hash, dc_cert::PLAN_APPROVAL_DOMAIN)?;
        token_attestations.push(attestation.summary_line());
        auth_set.add_signature(entry);
        if args.key2.is_some() {
            eprintln!("[NOTE] --key2 is ignored for officer 2: the --token2 signature is used.");
        }
    } else if let Some(ref key2_path) = args.key2 {
        let officer2 = OperatorKeyPair::load_from_file(key2_path)?;
        auth_set.add_signature(approve::PlanApprover::countersign_plan(
            &plan_hash,
            &officer2,
            args.officer2_hardware,
        ));
    } else {
        eprintln!("[WARNING] Only ONE officer key supplied: the authorization set will NOT");
        eprintln!("           satisfy the two-person-integrity gate of `dc execute --auth-set`.");
    }

    // Verify what we just built before writing it out: an approval file
    // that does not verify is worse than useless.
    let custody = auth_set
        .verify_pre_arm_authorization(&plan_hash, true)
        .map_err(|reason| {
            DcError::CertSigning(format!(
                "Generated authorization set failed self-verification: {}",
                reason
            ))
        })?;

    let out_path = args.out.clone().unwrap_or_else(|| {
        let stem = args
            .plan
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        PathBuf::from(format!("{}.auth.json", stem))
    });

    let json = serde_json::to_string_pretty(&auth_set)?;
    std::fs::write(&out_path, json)?;

    println!("[+] Plan approval recorded");
    println!("    Plan:            {}", args.plan.display());
    println!("    Plan Hash:       {}", plan_hash);
    println!("    Officers:         {}", auth_set.signatures.len());
    println!("    Distinct Keys:    {}", auth_set.distinct_key_count());
    println!("    Custody Type:     {:?}", custody);
    for line in &token_attestations {
        println!("    Hardware custody: {}", line);
    }
    println!("    Output:           {}", out_path.display());
    println!("\nUse with: dc execute --auth-set {}", out_path.display());
    Ok(())
}

/// Open a hardware token by CLI spec ("auto" = first PIV/CCID reader),
/// prompt the officer PIN on /dev/tty (echo off) and countersign the plan
/// inside the secure element (v0.7.0, Vector 1).
fn sign_plan_on_hardware_token(
    spec: &str,
    plan_hash: &str,
    domain: &[u8],
) -> Result<
    (
        dc_cert::AuthSignatureEntry,
        dc_cert::HardwareCustodyAttestation,
    ),
    DcError,
> {
    use dc_cert::ccid::{CcidCardTransport, CcidEndpoint, discover_ccid_interfaces};

    let endpoints = discover_ccid_interfaces();
    let endpoint: CcidEndpoint = if spec == "auto" {
        endpoints.into_iter().next().ok_or_else(|| {
            DcError::Usage(
                "no CCID/PIV token found on the USB bus (check lsusb; CAC/YubiKey \
                     readers enumerate as bInterfaceClass 0x0B)"
                    .to_string(),
            )
        })?
    } else {
        endpoints
            .into_iter()
            .find(|e| e.device_node.display().to_string() == spec)
            .ok_or_else(|| {
                DcError::Usage(format!(
                    "no CCID interface at '{}' (pass --token auto or a /dev/bus/usb node)",
                    spec
                ))
            })?
    };

    println!(
        "[TOKEN] Using PIV reader {} (usb {:04x}:{:04x}, serial {:?})",
        endpoint.device_node.display(),
        endpoint.id_vendor,
        endpoint.id_product,
        endpoint.serial
    );
    let mut transport = CcidCardTransport::open(&endpoint)
        .map_err(|e| DcError::Usage(format!("cannot open CCID transport: {} (root?)", e)))?;

    let pin = prompt_pin_no_echo("officer PIN").map_err(DcError::StdIo)?;
    let (entry, attestation) = dc_cert::token::countersign_ed25519_on_token(
        &mut transport,
        &endpoint,
        domain,
        plan_hash,
        &pin,
    )
    .map_err(|e| DcError::CertSigning(format!("hardware token signing failed: {}", e)))?;
    println!(
        "[TOKEN] Signed in slot {} via {} (PIN verified in-session)",
        attestation.slot, attestation.mechanism
    );
    Ok((entry, attestation))
}

/// Read a PIN from the controlling terminal with echo disabled
/// (termios ECHO off). The PIN never lands in shell history, environment,
/// or a file. Returns an error when there is no controlling TTY — a PIN
/// typed into a pipe is a PIN leaked to a log.
///
/// SECURITY (v0.9.0 Phase 1a): returns `Zeroizing<String>` — the heap copy
/// of the PIN is wiped with volatile stores when the caller drops it, and
/// the raw terminal line (including any leading/trailing whitespace the
/// trim removes) is wiped here before returning.
fn prompt_pin_no_echo(prompt: &str) -> std::io::Result<zeroize::Zeroizing<String>> {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let fd = tty.as_raw_fd();

    // Save termios, disable ECHO, restore on every path.
    let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let saved = unsafe { saved.assume_init() };
    let mut noecho = saved;
    noecho.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &noecho) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut read_tty = std::fs::File::open("/dev/tty")?;
    let result: std::io::Result<String> = (|| {
        let mut out = std::io::BufWriter::new(&tty);
        write!(out, "[TOKEN] {} (input hidden): ", prompt)?;
        out.flush()?;
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(&mut read_tty), &mut line)?;
        // Newline echo after hidden input.
        let mut out2 = std::io::BufWriter::new(&tty);
        let _ = writeln!(out2);
        // v0.9.0: the raw line can carry whitespace around the PIN — trim
        // into a fresh String, then wipe the raw line in place.
        let pin = line.trim().to_string();
        use zeroize::Zeroize;
        line.zeroize();
        Ok(pin)
    })();

    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &saved) };
    let pin = result?;
    if pin.is_empty() {
        return Err(std::io::Error::other(
            "empty PIN — hardware custody requires the officer PIN",
        ));
    }
    Ok(zeroize::Zeroizing::new(pin))
}

fn cmd_journal(args: JournalArgs) -> Result<(), DcError> {
    match args.sub {
        JournalSubcommands::Inspect { file } => cmd_journal_inspect(&file),
        JournalSubcommands::SelftestSequence { flavor, out, key } => {
            cmd_journal_selftest_sequence(&flavor, &out, key.as_deref())
        }
    }
}

fn cmd_journal_selftest_sequence(
    flavor: &str,
    out: &Path,
    key_path: Option<&Path>,
) -> Result<(), DcError> {
    let keypair = match key_path {
        Some(k) => Some(OperatorKeyPair::load_from_file(k)?),
        None => {
            if flavor == "sealed" {
                Some(OperatorKeyPair::generate())
            } else {
                None
            }
        }
    };

    let identity = DeviceIdentity {
        stable: StableIdentity {
            model: Some("FormatAuthenticNVMe".to_string()),
            serial: Some("SN-FORMAT-001".to_string()),
            wwn: None,
            size_bytes: 64 * 1024 * 1024,
            bus: BusType::Nvme,
            dm_name: None,
            dm_uuid: None,
        },
        kernel: KernelIdentity {
            major: 259,
            minor: 0,
        },
        kernel_name: "nvme0n1".to_string(),
        dev_path: "/dev/nvme0n1".to_string(),
        logical_block_size: 512,
        physical_block_size: 4096,
    };

    let plan = if flavor == "dod3" {
        SanitizationPlan::legacy_dod3(
            identity.stable.clone(),
            None,
            FastPathPolicy::PreferWriteZeroes,
        )?
    } else {
        SanitizationPlan::clear_zero(identity.stable.clone(), FastPathPolicy::PreferWriteZeroes)
    };

    let plan_hash = plan.compute_plan_hash()?;
    let is_sealed = keypair.is_some();
    let signing_key = keypair.as_ref().map(|k| k.signing_key.clone());

    let header = JournalRecord::Header {
        uuid: "format-authentic-uuid-001".to_string(),
        sealed: is_sealed,
        operator_pubkey: keypair.as_ref().map(|k| k.public_key_hex()),
        plan: plan.clone(),
        plan_hash,
        identity,
        tool: ToolBuild::current(),
        engine: "synthetic".to_string(),
        tuning: EngineTuning {
            qd: 64,
            pool_mib: 128,
            window_bytes: 2 * 1024 * 1024,
            checkpoint_mib: 512,
            checkpoint_ms: 5000,
        },
        argv_hash: "selftest".to_string(),
        started_utc: chrono_now_iso(),
    };

    let mut writer =
        JournalWriter::create_new(out, "format-authentic-uuid-001".to_string(), signing_key)?;
    writer.append(&header)?;
    writer.append(&JournalRecord::Armed {
        overrides: vec!["allow-loop".to_string()],
        locks_held: vec!["259:0".to_string()],
        at: chrono_now_iso(),
    })?;

    match flavor {
        "clean" | "sealed" => {
            writer.append(&JournalRecord::BeginPass {
                pass: 0,
                pattern: PatternDescriptor {
                    name: "Zero".to_string(),
                    pattern: Pattern::Zero,
                    description: "Zero".to_string(),
                },
                window_bytes: 2 * 1024 * 1024,
            })?;
            writer.append(&JournalRecord::RangeCommit {
                pass: 0,
                first_window: 0,
                num_windows: 32,
            })?;
            writer.append(&JournalRecord::EndPass { pass: 0 })?;
            writer.append(&JournalRecord::Flushed { pass: 0 })?;
            writer.append(&JournalRecord::Verify {
                level: "Full".to_string(),
                windows_checked: 32,
                mismatch_count: 0,
                first_mismatch_lbas: vec![],
                stream_hash_blake3:
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                stream_hash_sha256: None,
                fast_path_used: true,
            })?;
            writer.append(&JournalRecord::Completed {
                at: chrono_now_iso(),
                duration_mono_ms: 15000,
            })?;
        }
        "failed" => {
            writer.append(&JournalRecord::BeginPass {
                pass: 0,
                pattern: PatternDescriptor {
                    name: "Zero".to_string(),
                    pattern: Pattern::Zero,
                    description: "Zero".to_string(),
                },
                window_bytes: 2 * 1024 * 1024,
            })?;
            writer.append(&JournalRecord::RangeCommit {
                pass: 0,
                first_window: 0,
                num_windows: 16,
            })?;
            writer.append(&JournalRecord::Failed {
                code: "EIO".to_string(),
                errno: Some(5),
                op: Some("write".to_string()),
                at_lba: Some(32768),
                detail: "Synthetic I/O error".to_string(),
            })?;
        }
        "interrupted" => {
            writer.append(&JournalRecord::BeginPass {
                pass: 0,
                pattern: PatternDescriptor {
                    name: "Zero".to_string(),
                    pattern: Pattern::Zero,
                    description: "Zero".to_string(),
                },
                window_bytes: 2 * 1024 * 1024,
            })?;
            writer.append(&JournalRecord::RangeCommit {
                pass: 0,
                first_window: 0,
                num_windows: 16,
            })?;
            writer.append(&JournalRecord::Interrupted {
                at: chrono_now_iso(),
                hint: "Graceful drain".to_string(),
                completed_through_pass: Some(0),
                completed_through_window: Some(16),
                signals_received: Some(1),
            })?;
        }
        "dod3" => {
            for p in 0..3 {
                writer.append(&JournalRecord::BeginPass {
                    pass: p,
                    pattern: PatternDescriptor {
                        name: format!("DoD Pass {}", p),
                        pattern: Pattern::Zero,
                        description: "DoD".to_string(),
                    },
                    window_bytes: 2 * 1024 * 1024,
                })?;
                writer.append(&JournalRecord::RangeCommit {
                    pass: p,
                    first_window: 0,
                    num_windows: 32,
                })?;
                writer.append(&JournalRecord::EndPass { pass: p })?;
                writer.append(&JournalRecord::Flushed { pass: p })?;
            }
            writer.append(&JournalRecord::Verify {
                level: "Full".to_string(),
                windows_checked: 32,
                mismatch_count: 0,
                first_mismatch_lbas: vec![],
                stream_hash_blake3:
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                stream_hash_sha256: None,
                fast_path_used: false,
            })?;
            writer.append(&JournalRecord::Completed {
                at: chrono_now_iso(),
                duration_mono_ms: 45000,
            })?;
        }
        _ => {}
    }

    println!(
        "[+] Selftest sequence '{}' written to: {}",
        flavor,
        out.display()
    );
    Ok(())
}

fn cmd_journal_inspect(path: &Path) -> Result<(), DcError> {
    let (records, summary) = JournalReader::read_and_verify_chain(path)?;

    println!("================================================================================");
    println!("                         JOURNAL INSPECTION REPORT");
    println!("================================================================================");
    println!("File:               {}", path.display());
    println!(
        "Verdict:            {}",
        if summary.discarded_tail_bytes > 0 {
            "TORN_TAIL (Recoverable Prefix)"
        } else {
            "VALID (Complete Chain)"
        }
    );
    println!("Record Count:       {}", summary.record_count);
    println!("Chain Head:         {}", summary.chain_head);
    println!("Discarded Tail:     {} bytes", summary.discarded_tail_bytes);
    println!("Journal UUID:       {}", summary.uuid);
    println!("Sealed (Signed):    {}", summary.sealed);

    if let Some(first) = records.first()
        && let JournalRecord::Header {
            plan,
            identity,
            started_utc,
            ..
        } = first
    {
        println!("Target Device:      {}", identity.dev_path);
        println!(
            "Target Model:       {}",
            identity.stable.model.as_deref().unwrap_or("-")
        );
        println!(
            "Target Serial:      {}",
            identity.stable.serial.as_deref().unwrap_or("-")
        );
        println!("Started UTC:        {}", started_utc);
        println!(
            "Passes Planned:     {}",
            match &plan.mechanism {
                dc_core::Mechanism::LogicalOverwrite { passes } => passes.len(),
                dc_core::Mechanism::HardwarePurge { .. } => 0,
            }
        );
    }

    if let Some(last) = records.last() {
        println!(
            "Terminal State:     {}",
            match last {
                JournalRecord::Completed { .. } => "Completed",
                JournalRecord::Interrupted { .. } => "Interrupted",
                JournalRecord::Failed { .. } => "Failed",
                _ => "Incomplete",
            }
        );
    }

    println!("================================================================================");
    Ok(())
}

/// Parse the journal `Verify.level` string back into a VerifyLevel.
/// Unknown strings degrade to Full — the historical (and strictest) level.
fn parse_journal_verify_level(level: &str) -> VerifyLevel {
    VerifyLevel::from_short_tag(level).unwrap_or(VerifyLevel::Full)
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
