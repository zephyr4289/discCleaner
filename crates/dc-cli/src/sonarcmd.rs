//! `dc sonar` — acoustic hardware fingerprinting (v0.12.0, Miracle 2).
//!
//! * `enroll` — challenge the physical drive with a seek micro-stepping
//!   score, capture K telemetry responses, and build a robust
//!   enrollment with public helper data (`sonar-enrollment.json`).
//! * `verify` — fresh challenge–response against an enrollment;
//!   match/mismatch verdict with per-pair scoring.
//! * `scan` — one-shot feature dump (diagnostics: which telemetry
//!   sources exist on this platform and what they hear).

use crate::{SonarArgs, SonarSubcommands};
use dc_core::DcError;
use dc_sonar::{
    Enrollment, FileIo, SpectrumFeatures, TelemetrySource, VerifyOutcome, extract_features,
    fresh_challenge, iio_accel, sysfs_hwmon,
};
use std::time::Duration;

pub fn cmd_sonar(args: SonarArgs) -> Result<(), DcError> {
    match &args.sub {
        SonarSubcommands::Enroll {
            target,
            out,
            captures,
            probe_steps,
            media_class,
            challenge,
        } => cmd_enroll(
            target,
            out,
            *captures,
            *probe_steps,
            media_class,
            challenge.as_deref(),
        ),
        SonarSubcommands::Verify {
            target,
            enrollment,
            media_class,
        } => cmd_verify(target, enrollment, media_class),
        SonarSubcommands::Scan {
            target,
            probe_steps,
            media_class,
        } => cmd_scan(target, *probe_steps, media_class),
    }
}

fn open_probe_io(target: &std::path::Path) -> Result<FileIo, DcError> {
    FileIo::open(target).map_err(|e| DcError::Usage(format!("open {}: {e}", target.display())))
}

/// Run one probe + capture cycle over all available telemetry sources.
///
/// The probe score (seek micro-stepping) runs on the caller's thread
/// while every telemetry source captures CONCURRENTLY from its own
/// thread — the excitation and the pickup overlap by construction.
fn probe_cycle(
    io: &mut FileIo,
    challenge: &[u8; 32],
    total_lbas: u64,
    media_class: &str,
    probe_steps: usize,
) -> Result<Vec<SpectrumFeatures>, DcError> {
    let score = dc_sonar::SeekScore::compose(challenge, total_lbas, media_class, probe_steps)
        .map_err(|e| DcError::Usage(format!("compose probe: {e}")))?;

    // Discover telemetry sources (accelerometers first — the actual
    // acoustic channel). The sysroot honors the debug-only
    // DC_SONAR_TELEMETRY_DIR seam (DC_SIGNAL_AT pattern).
    let sysroot = telemetry_sysroot();
    let mut sources: Vec<Box<dyn TelemetrySource + Send>> = Vec::new();
    for a in iio_accel(&sysroot) {
        sources.push(Box::new(a));
    }
    for h in sysfs_hwmon(&sysroot) {
        sources.push(Box::new(h));
    }
    if sources.is_empty() {
        return Err(no_telemetry_refusal());
    }

    let duration = Duration::from_millis(800);
    let mut features = Vec::new();
    for mut src in sources {
        let desc = src.describe();
        // Capture on a worker thread; the probe runs here, overlapped.
        let cap_duration = duration;
        let handle = std::thread::spawn(move || src.capture(cap_duration));
        let probe_result = dc_sonar::run_score(io, &score, |_| true);
        let cap_res = handle
            .join()
            .unwrap_or(Err(dc_sonar::telemetry::TelemetryError::NoSource));
        probe_result.map_err(|e| DcError::Usage(format!("probe failed: {e}")))?;
        match cap_res {
            Ok(cap) => {
                let f = extract_features(&cap, 6);
                if !f.is_empty() && f.iter().any(|x| !x.peaks.is_empty() || x.rms > 0.0) {
                    features.extend(f);
                    eprintln!(
                        "[sonar] captured: {} ({:.0} Hz, {} ch)",
                        desc,
                        cap.sample_hz,
                        cap.channels.len()
                    );
                }
            }
            Err(e) => {
                eprintln!("[sonar] source {desc} unusable: {e}");
            }
        }
    }
    Ok(features)
}

fn target_lbas(target: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(target)
        .map(|m| m.size() / 512)
        .unwrap_or(0)
}

fn parse_challenge(hex_str: &str) -> Result<[u8; 32], DcError> {
    let v = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| DcError::Usage(format!("challenge must be hex: {e}")))?;
    if v.len() != 32 {
        return Err(DcError::Usage(
            "challenge must be exactly 32 bytes (64 hex chars)".into(),
        ));
    }
    let mut c = [0u8; 32];
    c.copy_from_slice(&v);
    Ok(c)
}

fn cmd_enroll(
    target: &std::path::Path,
    out: &std::path::Path,
    captures: usize,
    probe_steps: usize,
    media_class: &str,
    challenge: Option<&str>,
) -> Result<(), DcError> {
    let captures = captures.clamp(2, 16);
    let mut io = open_probe_io(target)?;
    let total_lbas = target_lbas(target);
    let challenge = match challenge {
        Some(h) => parse_challenge(h)?,
        None => fresh_challenge().map_err(|e| DcError::Usage(format!("entropy: {e}")))?,
    };

    eprintln!(
        "[sonar] enrolling physical fingerprint of {} ({} capture cycles, media class '{}')…",
        target.display(),
        captures,
        media_class
    );
    let mut capture_features = Vec::new();
    for i in 0..captures {
        eprintln!("[sonar] capture {}/{}", i + 1, captures);
        let f = probe_cycle(&mut io, &challenge, total_lbas, media_class, probe_steps)?;
        if f.is_empty() {
            return Err(DcError::Usage(
                "no usable telemetry observed during the probe — cannot enroll".to_string(),
            ));
        }
        capture_features.push(f);
    }

    let enr = Enrollment::from_captures(&challenge, &capture_features)
        .map_err(|e| DcError::Usage(format!("enrollment failed: {e}")))?;
    let json = serde_json::to_string_pretty(&enr)
        .map_err(|e| DcError::Usage(format!("serialize: {e}")))?;
    std::fs::write(out, &json).map_err(|e| DcError::Usage(format!("I/O: {e}")))?;

    println!("Sonar enrollment: {}", out.display());
    println!("  scheme:        {}", enr.scheme);
    println!("  fingerprint:   {}", enr.digest_blake3);
    println!("  enrolled bits: {}", enr.bit_count);
    println!("  match tau:     {}", enr.match_threshold);
    println!("  telemetry:     {}", enr.telemetry_sources.join(", "));
    println!();
    println!("NEXT STEPS");
    println!(
        "  1. Guard a wipe: dc execute --target {} --puf-guard {}",
        target.display(),
        out.display()
    );
    println!(
        "  2. Verify later: dc sonar verify --target {} --enrollment {}",
        target.display(),
        out.display()
    );
    Ok(())
}

fn cmd_verify(
    target: &std::path::Path,
    enrollment: &std::path::Path,
    media_class: &str,
) -> Result<(), DcError> {
    let enr: Enrollment = {
        let data = std::fs::read_to_string(enrollment)
            .map_err(|e| DcError::Usage(format!("read {}: {e}", enrollment.display())))?;
        serde_json::from_str(&data)
            .map_err(|e| DcError::Usage(format!("malformed enrollment: {e}")))?
    };
    let mut io = open_probe_io(target)?;
    let total_lbas = target_lbas(target);
    let challenge = fresh_challenge().map_err(|e| DcError::Usage(format!("entropy: {e}")))?;

    eprintln!("[sonar] fresh challenge–response probe…");
    let features = probe_cycle(&mut io, &challenge, total_lbas, media_class, 48)?;
    let outcome = enr.verify(&features);
    print_outcome(&outcome, &enr);
    if !outcome.matches {
        return Err(DcError::Guardian(dc_core::GuardianRefusal {
            code: "PUF_MISMATCH",
            detail: format!(
                "acoustic fingerprint mismatch: {} of {} bits differ (threshold {}) — \
                 this is not the enrolled physical drive",
                outcome.hamming_distance, outcome.bit_count, outcome.match_threshold
            ),
            hint: "the chassis under the probe is not the one the enrollment describes — \
                   possible rogue swap or worn resonance"
                .to_string(),
        }));
    }
    Ok(())
}

fn print_outcome(o: &VerifyOutcome, _enr: &Enrollment) {
    println!(
        "verdict:        {}",
        if o.matches { "MATCH" } else { "MISMATCH" }
    );
    println!("hamming:        {}/{}", o.hamming_distance, o.bit_count);
    println!("threshold:      {}", o.match_threshold);
    println!("similarity:     {:.4}", o.similarity);
    println!("candidate fp:   {}", o.candidate_digest_blake3);
}

fn cmd_scan(
    target: &std::path::Path,
    probe_steps: usize,
    media_class: &str,
) -> Result<(), DcError> {
    let mut io = open_probe_io(target)?;
    let total_lbas = target_lbas(target);
    let challenge = fresh_challenge().map_err(|e| DcError::Usage(format!("entropy: {e}")))?;
    let features = probe_cycle(&mut io, &challenge, total_lbas, media_class, probe_steps)?;
    println!("observed {} feature set(s):", features.len());
    for f in &features {
        println!(
            "  {}#{}: {:.0} Hz sampled, centroid {:.1} Hz, flatness {:.4}, rms {:.3}, {} peak(s)",
            f.source,
            f.channel,
            f.sample_hz,
            f.centroid_hz,
            f.flatness,
            f.rms,
            f.peaks.len()
        );
        for (i, p) in f.peaks.iter().take(4).enumerate() {
            println!("    peak {i}: {:.1} Hz (rel {:.3})", p.hz, p.relative);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Executor integration (--puf-guard) — v0.12.0, Miracle 2
// ---------------------------------------------------------------------------

/// Telemetry sysroot. In debug/test builds, `DC_SONAR_TELEMETRY_DIR`
/// redirects discovery at a synthetic tree (the DC_SIGNAL_AT pattern:
/// release binaries carry no environment-driven behavior).
pub(crate) fn telemetry_sysroot() -> std::path::PathBuf {
    #[cfg(any(feature = "fault-injection", debug_assertions))]
    {
        if let Ok(dir) = std::env::var("DC_SONAR_TELEMETRY_DIR") {
            return std::path::PathBuf::from(dir);
        }
    }
    std::path::PathBuf::from("/sys")
}

/// Debug-only replay seam: `DC_SONAR_REPLAY_CAPTURE` points at a JSON
/// capture to replay as the sole telemetry source (CI + drills).
#[allow(dead_code)]
fn replay_capture_path() -> Option<std::path::PathBuf> {
    #[cfg(any(feature = "fault-injection", debug_assertions))]
    {
        std::env::var("DC_SONAR_REPLAY_CAPTURE")
            .ok()
            .map(std::path::PathBuf::from)
    }
    #[cfg(not(any(feature = "fault-injection", debug_assertions)))]
    {
        None
    }
}

/// One acoustic verification performed by the executor guard.
pub(crate) struct GuardVerdict {
    pub outcome: dc_sonar::VerifyOutcome,
    pub challenge: [u8; 32],
}

/// Executor-side guard: enroll (or load) then verify at run checkpoints.
pub(crate) enum GuardState {
    /// Enrollment loaded from a file (single-target mode).
    Loaded(Enrollment),
    /// Enrolled at run start (fresh; evidence carries the enrollment).
    Fresh(Enrollment),
}

/// Pre-wipe enrollment or verification (fail-closed on any failure —
/// a wipe that cannot establish the physical identity of its target
/// does not start).
pub(crate) fn guard_pre_wipe(
    target: &std::path::Path,
    enrollment_path: Option<&std::path::Path>,
) -> Result<GuardState, DcError> {
    let mut io = open_probe_io(target)?;
    let total_lbas = target_lbas(target);

    match enrollment_path {
        Some(path) => {
            let enr: Enrollment = {
                let data = std::fs::read_to_string(path)
                    .map_err(|e| DcError::Usage(format!("read {}: {e}", path.display())))?;
                serde_json::from_str(&data)
                    .map_err(|e| DcError::Usage(format!("malformed enrollment: {e}")))?
            };
            // Verify BEFORE the wipe starts (pre-phase check).
            let challenge =
                fresh_challenge().map_err(|e| DcError::Usage(format!("entropy: {e}")))?;
            let features = probe_features_for_guard(&mut io, &challenge, total_lbas)?;
            let outcome = enr.verify(&features);
            if !outcome.matches {
                return Err(puf_refusal("pre-wipe", &outcome));
            }
            eprintln!(
                "[sonar] pre-wipe verification: MATCH ({} of {} bits)",
                outcome.hamming_distance, outcome.bit_count
            );
            Ok(GuardState::Loaded(enr))
        }
        None => {
            eprintln!(
                "[sonar] enrolling physical fingerprint of {}…",
                target.display()
            );
            let challenge =
                fresh_challenge().map_err(|e| DcError::Usage(format!("entropy: {e}")))?;
            let mut capture_features = Vec::new();
            for i in 0..4 {
                eprintln!("[sonar] capture {}/4", i + 1);
                let f = probe_features_for_guard(&mut io, &challenge, total_lbas)?;
                capture_features.push(f);
            }
            let enr = Enrollment::from_captures(&challenge, &capture_features)
                .map_err(|e| DcError::Usage(format!("enrollment failed: {e}")))?;
            Ok(GuardState::Fresh(enr))
        }
    }
}

/// Mid/post-wipe verification against the guard enrollment.
pub(crate) fn guard_verify(
    state: &GuardState,
    target: &std::path::Path,
    _phase: &str,
) -> Result<GuardVerdict, DcError> {
    let enr = match state {
        GuardState::Loaded(e) | GuardState::Fresh(e) => e,
    };
    let mut io = open_probe_io(target)?;
    let total_lbas = target_lbas(target);
    let challenge = fresh_challenge().map_err(|e| DcError::Usage(format!("entropy: {e}")))?;
    let features = probe_features_for_guard(&mut io, &challenge, total_lbas)?;
    let outcome = enr.verify(&features);
    Ok(GuardVerdict { outcome, challenge })
}

fn probe_features_for_guard(
    io: &mut FileIo,
    challenge: &[u8; 32],
    total_lbas: u64,
) -> Result<Vec<SpectrumFeatures>, DcError> {
    if let Some(replay_path) = replay_capture_path() {
        let cap: dc_sonar::Capture = {
            let data = std::fs::read_to_string(&replay_path)
                .map_err(|e| DcError::Usage(format!("replay capture: {e}")))?;
            serde_json::from_str(&data)
                .map_err(|e| DcError::Usage(format!("replay capture malformed: {e}")))?
        };
        return Ok(extract_features(&cap, 6));
    }
    probe_cycle(io, challenge, total_lbas, "hdd", 32)
}

pub(crate) fn puf_refusal(phase: &str, o: &dc_sonar::VerifyOutcome) -> DcError {
    DcError::Guardian(dc_core::GuardianRefusal {
        code: "PUF_MISMATCH",
        detail: format!(
            "acoustic fingerprint mismatch at phase '{phase}': {} of {} bits differ \
             (threshold {}) — the chassis under the write head is not the enrolled \
             physical drive (rogue swap?)",
            o.hamming_distance, o.bit_count, o.match_threshold
        ),
        hint: "halt and inspect the bay: a drive swap may have occurred mid-wipe".to_string(),
    })
}

pub(crate) fn no_telemetry_refusal() -> DcError {
    DcError::Guardian(dc_core::GuardianRefusal {
        code: "PUF_NO_TELEMETRY",
        detail: "--puf-guard requested but this platform exposes no telemetry sources \
                 (IIO accelerometers / hwmon channels) and no replay capture was \
                 supplied — the physical identity of the target cannot be established"
            .to_string(),
        hint: "run on hardware with chassis telemetry, or (drills only) set \
               DC_SONAR_REPLAY_CAPTURE to a recorded capture file"
            .to_string(),
    })
}
