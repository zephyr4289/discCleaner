//! `dc remanence` — MFM Anti-Forensics & Remanence Annihilation
//! (v0.14.0, Breakthrough 1).
//!
//! * `simulate` — run the guard-band annihilation campaign
//!   (micro-step ladder + Curie-dither) on the deterministic
//!   platter simulation and assemble/judge the Remanence
//!   Annihilation Certificate (100% guard-band coverage, χ²
//!   omnibus SNR bound < −20 dB, detection horizon > supply).
//! * `verify` — offline verification of a certificate (digest
//!   binding + verdict arithmetic recomputation).
//! * `explain` — the physics, the models, and the threat model in
//!   operator terms.

use crate::{RemanenceArgs, RemanenceSubcommands};
use dc_core::DcError;

pub fn cmd_remanence(args: RemanenceArgs) -> Result<(), DcError> {
    match &args.sub {
        RemanenceSubcommands::Simulate {
            device_id,
            tracks,
            cells,
            resolution_nm,
            dither_passes,
            seed,
            out,
        } => cmd_simulate(
            device_id,
            *tracks,
            *cells,
            *resolution_nm,
            *dither_passes,
            *seed,
            out.as_deref(),
        ),
        RemanenceSubcommands::Verify { cert } => cmd_verify(cert),
        RemanenceSubcommands::Explain => cmd_explain(),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_simulate(
    device_id: &str,
    tracks: u32,
    cells: u32,
    resolution_nm: f64,
    dither_passes: u32,
    seed: u64,
    out: Option<&str>,
) -> Result<(), DcError> {
    if tracks == 0 || cells == 0 {
        return Err(DcError::Usage(
            "a remanence campaign needs at least one track and one cell".into(),
        ));
    }
    let geometry = dc_remanence::track::TrackGeometry::default();
    let plan = dc_remanence::proof::CampaignDefaults::plan(cells as usize);
    let dither = dc_remanence::curie::CurieDither {
        passes: dither_passes as usize,
        ..Default::default()
    };
    let front_end = dc_remanence::prml::ReadFrontEnd::default();

    println!("[REMANENCE] guard-band annihilation campaign: device {device_id}");
    println!(
        "[REMANENCE] {} tracks x {} cells, {:.1} nm lateral grid",
        tracks, cells, resolution_nm
    );
    println!(
        "[REMANENCE] track pitch {:.0} nm, write element {:.0} nm, guard band {:.1} nm/side",
        geometry.track_pitch_nm,
        geometry.write_width_nm,
        geometry.guard_band_nm()
    );
    println!(
        "[REMANENCE] ladder: {} steps (±15%, ±30% pitch at up to +55% current), Curie-dither {} passes",
        plan.ladder.len(),
        dither.passes
    );
    println!(
        "[REMANENCE] Johnson-Nyquist floor: {:.1} K, {:.0} ohm, {:.0} MHz → σ = {:.4} (normalized)",
        front_end.temperature_k,
        front_end.resistance_ohm,
        front_end.bandwidth_hz / 1e6,
        front_end.noise_sigma()
    );

    let cert = dc_remanence::proof::RemanenceCertificate::assemble(
        device_id,
        &geometry,
        &plan,
        &dither,
        &front_end,
        tracks as usize,
        cells as usize,
        resolution_nm,
        seed,
    )
    .map_err(|e| DcError::Internal(format!("campaign: {e}")))?;

    println!();
    println!(
        "trk | guard cols | cov | baseline ghost | residual UB | horizon vs supply | t-ghost | readback"
    );
    for v in &cert.tracks {
        println!(
            "{:3} | {:9} | {:3} | {:8.1} dB / {:4.0}b | {:7.1} dB | {:8.0} > {:6} | {:7.3} | {:7.2}",
            v.track,
            v.guard_columns,
            v.covered_columns,
            v.ghost_baseline_pooled_snr_db,
            v.ghost_baseline_horizon_bits,
            v.residual_snr_upper_db,
            v.detection_horizon_bits,
            v.available_bits,
            v.transition_ghost_corr,
            v.readback_mean,
        );
        for reason in &v.reasons {
            println!("     ! {reason}");
        }
    }
    println!();
    println!(
        "[REMANENCE] coverage: {}/{} tracks certified below the −20 dB adversary floor",
        cert.covered_tracks, cert.total_tracks
    );
    for note in &cert.notes {
        println!("[REMANENCE] NOTE: {note}");
    }
    if cert.verified {
        println!("[REMANENCE] REMANENCE ANNIHILATION CERTIFICATE: VERIFIED");
        println!("       guard-band sub-surface magnetization is below the thermal floor —");
        println!("       an MFM distinguisher cannot reach a decision within the platter");
    } else {
        println!("[REMANENCE] REMANENCE ANNIHILATION CERTIFICATE: REFUSED");
        println!("       at least one track retains MFM-readable structure");
    }

    if let Some(path) = out {
        let json = serde_json::to_string_pretty(&cert)
            .map_err(|e| DcError::Internal(format!("serialize certificate: {e}")))?;
        std::fs::write(path, json).map_err(|e| DcError::Internal(format!("write {path}: {e}")))?;
        println!(
            "[REMANENCE] certificate written to {path} (digest {})",
            &cert.digest[..16.min(cert.digest.len())]
        );
    }
    Ok(())
}

fn cmd_verify(cert_path: &str) -> Result<(), DcError> {
    let raw = std::fs::read_to_string(cert_path)
        .map_err(|e| DcError::Usage(format!("read {cert_path}: {e}")))?;
    let cert: dc_remanence::proof::RemanenceCertificate = serde_json::from_str(&raw)
        .map_err(|e| DcError::Usage(format!("parse remanence certificate: {e}")))?;
    println!("[REMANENCE] remanence annihilation certificate verification");
    println!("       device       : {}", cert.device_id);
    println!(
        "       digest       : {}",
        &cert.digest[..16.min(cert.digest.len())]
    );
    println!(
        "       tracks       : {}/{} certified",
        cert.covered_tracks, cert.total_tracks
    );
    cert.verify()
        .map_err(|e| DcError::Internal(format!("certificate verification: {e}")))?;
    if cert.verified {
        println!("[REMANENCE] VERIFIED — digest covers the body, verdicts recompute, floor holds");
    } else {
        println!("[REMANENCE] VERIFIED AS A DOCUMENT — but the run itself REFUSED (see notes)");
        for note in &cert.notes {
            println!("       NOTE: {note}");
        }
    }
    Ok(())
}

fn cmd_explain() -> Result<(), DcError> {
    println!("dc-remanence — MFM Anti-Forensics & Remanence Annihilation");
    println!();
    println!("THE MYTH: overwriting a sector with zeros destroys the data. In magnetic physics");
    println!("it does not: write-head fringing fields leave sub-track remnants a few nanometres");
    println!("wide in the guard bands — exactly what a Magnetic Force Microscope reads after a");
    println!("NIST-grade wipe of the track core.");
    println!();
    println!("dc-remanence annihilates the residual layer with three weapons:");
    println!("  * Off-track micro-stepping (microstep.rs): vendor-diagnostic head steps at");
    println!("    +15/-15/+30/-30 percent of track pitch with write-current overdrive — the");
    println!("    widened write bubble sweeps BOTH guard bands past the neighbor centerline.");
    println!("  * Curie-dither (curie.rs): a high-frequency alternating-flux pattern at");
    println!("    elevated current; each pass gives guard-band grains a Neel-Brown thermal");
    println!("    switch attempt toward the CURRENT polarity, so the old domain orientation");
    println!("    decays geometrically and ends re-randomized, decoupled from the recording.");
    println!("  * Statistical proof (prml.rs): multi-column known-plaintext adversary model");
    println!("    at the Johnson-Nyquist floor sqrt(4kTRB); a chi-square omnibus bounds the");
    println!("    per-bit aggregate SNR at 99% confidence, and the Neyman-Pearson detection");
    println!("    horizon counts the bits the adversary would need.");
    println!();
    println!("THE CERTIFICATE: every track must show 100% guard-band column coverage, a");
    println!("certified adversary SNR bound below -20 dB, and a detection horizon exceeding");
    println!("the bits the track physically contains. A naive zero-overwrite of the same");
    println!("recording pools its ghost ABOVE the floor and falls to the adversary in a");
    println!("handful of bits — the myth, quantified, then destroyed.");
    println!();
    println!("OPERATION:");
    println!("  dc remanence simulate --device-id SN-XYZ --tracks 4 --out remanence-cert.json");
    println!("  dc remanence verify --cert remanence-cert.json");
    println!();
    println!("MODEL CALIBRATION: the fringing falloff (6.5 nm), coercivity dispersion and");
    println!("read front end are textbook thin-film values; the per-drive micro-step command");
    println!("tables are vendor-proprietary — the SimStepTransport log is the integration");
    println!("point for real ATA/SCSI diagnostic backends.");
    Ok(())
}
