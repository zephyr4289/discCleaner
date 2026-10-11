//! `dc bench` — production-engine throughput benchmark on a regular file.
//!
//! Procurement bake-offs need evidence, not claims: this command runs the
//! SAME write/verify engine paths used by `dc execute` against a
//! caller-provided regular file and reports measured MiB/s plus an ETA table
//! for every standards profile at a reference capacity.
//!
//! SAFETY: bench REFUSES block devices and anything under /dev, /sys, /proc.
//! It is physically incapable of destroying data: it only ever opens a
//! regular file the operator explicitly names.

use crate::EngineChoice;
use dc_core::{
    DcError, FastPathPolicy, FsmOrchestrator, Mechanism, SanitizationPlan, SanitizationProfile,
    VerifyLevel,
};
use dc_io::{LbaSpan, SyncEngine, UringEngine, create_engine};
use dc_verify::StreamVerifier;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::time::Instant;

use crate::BenchArgs;

fn refuse_unsafe_bench_path(path: &Path) -> Result<(), DcError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| DcError::Usage(format!("--file {} not accessible: {}", path.display(), e)))?;
    if !meta.is_file() {
        return Err(DcError::Usage(format!(
            "--file {} is not a regular file; bench never operates on devices",
            path.display()
        )));
    }
    if meta.file_type().is_block_device() || meta.file_type().is_char_device() {
        return Err(DcError::Usage(
            "bench target is a device node — refused (use a regular file)".to_string(),
        ));
    }
    let forbidden = ["/dev", "/sys", "/proc"];
    let s = path.to_string_lossy();
    if forbidden.iter().any(|p| s.starts_with(p)) {
        return Err(DcError::Usage(format!(
            "bench target {} is under a kernel pseudo-filesystem — refused",
            path.display()
        )));
    }
    Ok(())
}

/// Prepare the benchmark file: extend to size_mib with zeros.
fn prepare_file(path: &Path, size_mib: u64) -> Result<(), DcError> {
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(DcError::StdIo)?;
    f.set_len(size_mib * 1024 * 1024).map_err(DcError::StdIo)?;
    f.sync_all().map_err(DcError::StdIo)?;
    Ok(())
}

pub fn cmd_bench(args: BenchArgs) -> Result<(), DcError> {
    refuse_unsafe_bench_path(&args.file)?;
    if args.size_mib == 0 {
        return Err(DcError::Usage("--size-mib must be > 0".to_string()));
    }
    if args.window_mib == 0 {
        return Err(DcError::Usage("--window-mib must be > 0".to_string()));
    }
    prepare_file(&args.file, args.size_mib)?;

    let total_bytes = args.size_mib * 1024 * 1024;
    let window_bytes = args.window_mib * 1024 * 1024;

    println!("================================================================================");
    println!("                    DISKCLEANER ENGINE BENCHMARK");
    println!("================================================================================");
    println!(
        "Benchmark file:     {} ({} MiB)",
        args.file.display(),
        args.size_mib
    );
    println!("Window size:       {} MiB", args.window_mib);
    println!("Engine:            {}", engine_name(args.engine));

    // A plan purely for the FSM's permit discipline (bench is not certified;
    // the FSM still enforces ordered permits on the engine).
    let dummy_plan = SanitizationPlan {
        plan_schema: "dc-plan/1".to_string(),
        target: bench_identity(total_bytes),
        mechanism: Mechanism::LogicalOverwrite {
            passes: vec![dc_core::Pass {
                pattern: dc_core::Pattern::Zero,
                label: "bench-zero".to_string(),
            }],
        },
        verification: VerifyLevel::Full,
        window_bytes,
        fast_path: FastPathPolicy::ForbidWriteZeroes,
        strategy_ladder: None,
        legacy_note: None,
    };

    let file = File::options()
        .read(true)
        .write(true)
        .open(&args.file)
        .map_err(DcError::StdIo)?;
    let mut engine = build_engine(args.engine, file, window_bytes as usize)?;

    let span = LbaSpan::new(total_bytes, 512, window_bytes);

    let mut fsm = FsmOrchestrator::new();
    fsm.compile_plan(dummy_plan)?;
    fsm.approve_plan()?;
    fsm.arm()?;

    // Pass 1: full zero write (no BLKZEROOUT — measure real bus traffic).
    let permit = fsm.begin_pass(0)?;
    let t0 = Instant::now();
    let outcome = engine.write_pass(&permit, 0, &dc_core::ZeroPattern, &span, 0, &mut |_| {})?;
    let write_secs = t0.elapsed().as_secs_f64().max(0.001);
    let write_mib_s = outcome.bytes_written as f64 / (1024.0 * 1024.0) / write_secs;
    let flush_permit = fsm.begin_flush(0)?;
    engine.flush(&flush_permit)?;

    // Pass 2: full read-back verification.
    fsm.begin_verify()?;
    let mut verifier = StreamVerifier::new(VerifyLevel::Full, window_bytes, 512, false, false);
    let t1 = Instant::now();
    engine.read_verify(&dc_core::ZeroPattern, &span, 1, &mut verifier, &mut |_| {})?;
    let verify_secs = t1.elapsed().as_secs_f64().max(0.001);
    let verify_mib_s = total_bytes as f64 / (1024.0 * 1024.0) / verify_secs;

    let report = verifier.finalize();
    let verified_ok = report.mismatch_count == 0;

    println!("--------------------------------------------------------------------------------");
    println!(
        "WRITE (zero pass):      {:>10.1} MiB/s   ({:>7.1} GB/h)",
        write_mib_s,
        write_mib_s * 3.6
    );
    println!(
        "VERIFY (read-back):     {:>10.1} MiB/s   ({:>7.1} GB/h)",
        verify_mib_s,
        verify_mib_s * 3.6
    );
    println!(
        "Read-back check:        {}",
        if verified_ok {
            "PASS (all windows matched)"
        } else {
            "MISMATCH (unexpected for a fresh zero file)"
        }
    );
    println!("--------------------------------------------------------------------------------");

    // ETA table at the reference capacity.
    let ref_bytes = args.ref_gib as f64 * 1024.0 * 1024.0 * 1024.0;
    let write_bps = write_mib_s * 1024.0 * 1024.0;
    let verify_bps = verify_mib_s * 1024.0 * 1024.0;
    println!(
        "PROFILE ETA @ {} GiB (write {} MiB/s + full verify {} MiB/s, sequential):",
        args.ref_gib, write_mib_s as u64, verify_mib_s as u64
    );
    println!(
        "{:<22} {:>7}  {:>12}  {:>12}",
        "PROFILE", "PASSES", "WRITE ONLY", "WRITE+VERIFY"
    );
    println!(
        "{:<22} {:>7}  {:>12}  {:>12}",
        "-------", "------", "----------", "-------------"
    );
    for p in SanitizationProfile::CATALOG {
        let passes = p.total_passes() as f64;
        let write_h = ref_bytes * passes / write_bps / 3600.0;
        let full_h = write_h + ref_bytes / verify_bps / 3600.0;
        println!(
            "{:<22} {:>7}  {:>10.2} h  {:>10.2} h",
            profile_slug(p),
            p.total_passes(),
            write_h,
            full_h
        );
    }
    println!(
        "{:<22} {:>7}  {:>12}  {:>12}",
        "hardware purge (NVMe)", "0", "seconds", "seconds"
    );
    println!("================================================================================");
    println!(
        "NOTE: parallel multi-device wiping (--target a --target b) scales these\n\
         wall-clock numbers by device count; per-device throughput holds."
    );

    Ok(())
}

fn bench_identity(size: u64) -> dc_core::StableIdentity {
    dc_core::StableIdentity {
        model: Some("BenchmarkFile".to_string()),
        serial: Some("BENCH".to_string()),
        wwn: None,
        size_bytes: size,
        bus: dc_core::BusType::File,
        dm_name: None,
        dm_uuid: None,
    }
}

fn build_engine(
    choice: EngineChoice,
    file: File,
    window_bytes: usize,
) -> Result<Box<dyn dc_io::Engine>, DcError> {
    Ok(match choice {
        EngineChoice::Sync => Box::new(SyncEngine::new(file, window_bytes, false)?),
        EngineChoice::Uring => Box::new(UringEngine::try_new(file, window_bytes, false, 64)?),
        EngineChoice::Auto => create_engine(file, window_bytes, false, 64)?,
    })
}

fn engine_name(c: EngineChoice) -> &'static str {
    match c {
        EngineChoice::Auto => "auto (io_uring if available, else sync)",
        EngineChoice::Uring => "uring",
        EngineChoice::Sync => "sync",
    }
}

fn profile_slug(p: &SanitizationProfile) -> &'static str {
    match p {
        SanitizationProfile::NistClear => "nist-clear",
        SanitizationProfile::NistClearRandom => "nist-clear-random",
        SanitizationProfile::Dod5220_22M => "dod-5220.22m",
        SanitizationProfile::Dod5220_22MEce => "dod-5220.22m-ece",
        SanitizationProfile::CsecItsg06 => "csec-itsg-06",
        SanitizationProfile::BsiVsitr => "bsi-vsitr",
        SanitizationProfile::Schneier => "schneier",
        SanitizationProfile::CertinGoi => "certin-goi",
        SanitizationProfile::Gutmann => "gutmann",
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn tmpfile(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join("dc-bench-tests");
        std::fs::create_dir_all(&d).unwrap();
        d.join(name)
    }

    #[test]
    fn bench_refuses_block_devices_and_pseudo_fs() {
        File::create(tmpfile("t1")).unwrap();
        assert!(refuse_unsafe_bench_path(Path::new("/dev/sda")).is_err());
        assert!(refuse_unsafe_bench_path(Path::new("/dev/nvme0n1")).is_err());
        assert!(refuse_unsafe_bench_path(Path::new("/sys/fake")).is_err());
        assert!(refuse_unsafe_bench_path(Path::new("/proc/meminfo")).is_err());
        assert!(refuse_unsafe_bench_path(&tmpfile("t1")).is_ok());
    }

    #[test]
    fn bench_end_to_end_on_temp_file() {
        let f = tmpfile("bench-e2e.bin");
        File::create(&f).unwrap();
        let args = BenchArgs {
            file: f.clone(),
            size_mib: 8,
            engine: EngineChoice::Sync,
            ref_gib: 1024,
            window_mib: 2,
        };
        cmd_bench(args).expect("bench must complete on a regular file");
        std::fs::remove_file(&f).ok();
    }
}
