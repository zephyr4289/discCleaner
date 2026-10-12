//! `dc vdf` — cryptographic Proof-of-Erasure via Verifiable Delay
//! Functions (v0.12.0, Miracle 1).
//!
//! * `setup` — one-time parameter ceremony: generate a fresh RSA
//!   unknown-order modulus (safe-prime pair, factors zeroized
//!   in-process) or import one, calibrate `steps_per_pass` for a
//!   target per-pass duration, and write `vdf-params.json`.
//! * `bench` — measure this machine's Montgomery squaring rate for a
//!   published modulus (calibration evidence).
//! * `verify` — standalone audit of a woven certificate's time-lock
//!   timeline: every Wesolowski link checks in milliseconds and the
//!   math pins a wall-clock lower bound between the first and last
//!   woven writes.

use crate::{VdfArgs, VdfSubcommands};
use dc_core::DcError;
use dc_vdf::{
    ADVERSARY_SQUARINGS_PER_SECOND, CeremonyInfo, TimelineEvidence, VdfParams, verify_timeline,
};

pub fn cmd_vdf(args: VdfArgs) -> Result<(), DcError> {
    match &args.sub {
        VdfSubcommands::Setup {
            out,
            bits,
            modulus,
            steps_per_pass,
            passes,
            hours_per_pass_ms,
            seed,
        } => cmd_setup(
            out,
            *bits,
            modulus.as_deref(),
            *steps_per_pass,
            *passes,
            *hours_per_pass_ms,
            seed.as_deref(),
        ),
        VdfSubcommands::Bench { params, seconds } => cmd_bench(params, *seconds),
        VdfSubcommands::Verify {
            certificate,
            require_min_seconds,
        } => cmd_verify(certificate, *require_min_seconds),
    }
}

fn load_json_file<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T, DcError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| DcError::Usage(format!("cannot read {}: {}", path.display(), e)))?;
    serde_json::from_str(&data)
        .map_err(|e| DcError::Usage(format!("malformed JSON in {}: {}", path.display(), e)))
}

#[allow(clippy::too_many_arguments)]
fn cmd_setup(
    out: &std::path::Path,
    bits: u16,
    modulus: Option<&str>,
    steps_per_pass: u64,
    passes: u8,
    hours_per_pass_ms: u64,
    seed: Option<&str>,
) -> Result<(), DcError> {
    if steps_per_pass == 0 {
        return Err(DcError::Usage(
            "--steps-per-pass must be > 0 (or pass --hours-per-pass-ms for auto-calibration)"
                .to_string(),
        ));
    }

    let (n_hex, info) = match modulus {
        Some(m) => {
            dc_vdf::validate_modulus_hex(m)
                .map_err(|e| DcError::Usage(format!("--modulus: {e}")))?;
            eprintln!("[vdf] importing external modulus (ceremony performed elsewhere)");
            (
                m.trim_start_matches("0x").to_ascii_lowercase(),
                CeremonyInfo {
                    scheme: VdfParams::SCHEME.to_string(),
                    modulus_bits: (m.trim_start_matches("0x").len() as u16 * 4),
                    prime_class: "imported (external ceremony)".to_string(),
                    duration_ms: 0,
                    candidates_screened: 0,
                },
            )
        }
        None => {
            let seed_bytes: Option<Vec<u8>> = match seed {
                Some(h) => Some(
                    hex::decode(h)
                        .map_err(|e| DcError::Usage(format!("--seed must be hex: {e}")))?,
                ),
                None => None,
            };
            eprintln!(
                "[vdf] ceremony: generating {bits}-bit modulus (safe-prime pair; factors are \
                 zeroized in-process). This can take minutes on commodity hardware — run it on \
                 an OFFLINE machine with a witness."
            );
            let (n, info) = dc_vdf::generate_modulus(bits, seed_bytes.as_deref(), &mut |msg| {
                eprintln!("[vdf] {msg}")
            })
            .map_err(|e| DcError::Usage(format!("ceremony failed: {e}")))?;
            (n, info)
        }
    };

    // Calibrate: if hours_per_pass_ms given, measure the squaring rate
    // and compute steps_per_pass to hit the target duration.
    let steps = if hours_per_pass_ms > 0 {
        eprintln!(
            "[vdf] calibrating for a {} ms per-pass delay…",
            hours_per_pass_ms
        );
        let sps = measure_rate(&n_hex)?;
        ((hours_per_pass_ms as f64 / 1000.0) * sps) as u64
    } else {
        steps_per_pass
    };

    let params = VdfParams {
        scheme: VdfParams::SCHEME.to_string(),
        modulus_n: n_hex,
        steps_per_pass: steps,
        passes,
        beacon: None,
        ceremony_note: format!("{}; duration {} ms", info.prime_class, info.duration_ms),
    };
    let json = serde_json::to_string_pretty(&params)
        .map_err(|e| DcError::Usage(format!("serialize: {e}")))?;
    std::fs::write(out, &json).map_err(|e| DcError::Usage(format!("I/O: {e}")))?;

    let total_secs = params.total_steps() as f64 / ADVERSARY_SQUARINGS_PER_SECOND;
    println!("VDF parameters: {}", out.display());
    println!("  scheme:          {}", params.scheme);
    println!("  modulus bits:    {}", info.modulus_bits);
    println!("  steps per pass:  {}", params.steps_per_pass);
    println!("  passes:          {}", params.passes);
    println!(
        "  adversary floor: total {:.1} s (at {} squarings/s ASIC model)",
        total_secs, ADVERSARY_SQUARINGS_PER_SECOND as u64
    );
    println!();
    println!("NEXT STEPS");
    println!("  1. Distribute vdf-params.json to the wiping fleet (pin its hash out-of-band).");
    println!(
        "  2. Wipe: dc execute --target /dev/sda --profile nist-clear --vdf-lock {}",
        out.display()
    );
    println!("  3. Audit: dc vdf verify --certificate <cert.json>");
    Ok(())
}

fn measure_rate(n_hex: &str) -> Result<f64, DcError> {
    let ctx = VdfParams {
        scheme: VdfParams::SCHEME.to_string(),
        modulus_n: n_hex.to_string(),
        steps_per_pass: 1,
        passes: 1,
        beacon: None,
        ceremony_note: String::new(),
    }
    .context()
    .map_err(|e| DcError::Usage(format!("modulus: {e}")))?;
    let sps = dc_vdf::benchmark_squarings_per_second(&ctx, 1);
    println!("  measured rate: {:.0} squarings/s on this machine", sps);
    Ok(sps)
}

fn cmd_bench(params: &std::path::Path, seconds: u64) -> Result<(), DcError> {
    let p: VdfParams = load_json_file(params)?;
    let ctx = p
        .context()
        .map_err(|e| DcError::Usage(format!("params: {e}")))?;
    let sps = dc_vdf::benchmark_squarings_per_second(&ctx, seconds);
    println!("modulus bits:    {}", ctx.n.bits());
    println!("local rate:       {:.0} squarings/s", sps);
    println!(
        "adversary model: {} squarings/s (ASIC 10x margin)",
        ADVERSARY_SQUARINGS_PER_SECOND as u64
    );
    println!(
        "per-pass delay here:  {:.3} s",
        p.steps_per_pass as f64 / sps
    );
    println!(
        "adversary floor/pass: {:.3} s",
        p.steps_per_pass as f64 / ADVERSARY_SQUARINGS_PER_SECOND
    );
    Ok(())
}

fn cmd_verify(
    certificate: &std::path::Path,
    require_min_seconds: Option<f64>,
) -> Result<(), DcError> {
    let cert: dc_cert::SanitizationCertificate = load_json_file(certificate)?;
    let Some(ev) = cert.vdf.as_ref() else {
        return Err(DcError::Usage(
            "certificate carries no VDF timeline (not a woven run)".to_string(),
        ));
    };
    // Convert the certificate mirror into the dc-vdf structure (the
    // field layouts match by construction; kept separate so dc-cert
    // never depends on the proving engine).
    let engine_ev = TimelineEvidence {
        scheme: ev.scheme.clone(),
        modulus_n: ev.modulus_n.clone(),
        challenge_x: ev.challenge_x.clone(),
        steps_per_pass: ev.steps_per_pass,
        beacon: ev.beacon.clone(),
        passes: ev
            .passes
            .iter()
            .map(|p| dc_vdf::PassBinding {
                pass_index: p.pass_index,
                state: p.state.clone(),
                seed_fingerprint: p.seed_fingerprint.clone(),
                challenge_prime: p.challenge_prime.clone(),
                proof: p.proof.clone(),
                materialized_after_ms: p.materialized_after_ms,
            })
            .collect(),
        measured_squarings_per_second: ev.measured_squarings_per_second,
        squarings_done: ev.squarings_done,
    };
    eprintln!(
        "[vdf] verifying {} Wesolowski link(s)…",
        engine_ev.passes.len()
    );
    let verdict = verify_timeline(&engine_ev);

    println!("scheme:            {}", ev.scheme);
    println!(
        "passes verified:    {}/{}",
        verdict.passes_verified,
        ev.passes.len()
    );
    println!("total steps:        {}", verdict.total_steps);
    println!(
        "min elapsed claim:  {:.3} s (adversary model {} squarings/s)",
        verdict.min_elapsed_seconds_claim, ADVERSARY_SQUARINGS_PER_SECOND as u64
    );
    if let Some(m) = ev.measured_squarings_per_second {
        println!("executor rate note: {:.0} squarings/s (advisory)", m);
    }
    if !verdict.errors.is_empty() {
        println!("errors:");
        for e in &verdict.errors {
            println!("  - {e}");
        }
    }
    if let Some(min) = require_min_seconds {
        let ok = verdict.min_elapsed_seconds_claim >= min;
        println!(
            "required floor:     {min:.3} s — {}",
            if ok { "MET" } else { "NOT MET" }
        );
        if !ok {
            return Err(DcError::Usage(format!(
                "timeline proves only {:.3} s — below the required {min:.3} s floor",
                verdict.min_elapsed_seconds_claim
            )));
        }
    }
    if !verdict.verified {
        return Err(DcError::Usage(
            "VDF timeline INVALID — at least one weave link failed verification".to_string(),
        ));
    }
    println!();
    println!(
        "RESULT: VALID — {} non-parallelizable squarings separate the first and last",
        verdict.total_steps
    );
    println!("       woven writes, on ANY hardware, independent of system clocks.");
    Ok(())
}
