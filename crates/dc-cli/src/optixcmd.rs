//! `dc optix` — Sub-Surface Optical Disk Laser Photobleaching &
//! Phase-Change Destruction (v0.14.0, Breakthrough 3).
//!
//! * `simulate` — load a written WORM disc into the simulated
//!   drive, weaponize the pickup (disable OPC, overdrive the
//!   laser, park the CLV), run the full-spiral annihilation and
//!   assemble/judge the Photobleach Destruction Certificate.
//! * `verify` — offline verification of a certificate (digest
//!   binding + verdict arithmetic recomputation).
//! * `explain` — the media physics and the threat model in
//!   operator terms.

use crate::{OptixArgs, OptixMedia, OptixSubcommands};
use dc_core::DcError;
use dc_optix::layer::MediaType;

impl From<OptixMedia> for MediaType {
    fn from(m: OptixMedia) -> Self {
        match m {
            OptixMedia::OrganicDye => Self::OrganicDye,
            OptixMedia::PhaseChange => Self::PhaseChange,
            OptixMedia::GlassyCarbon => Self::GlassyCarbon,
        }
    }
}

pub fn cmd_optix(args: OptixArgs) -> Result<(), DcError> {
    match &args.sub {
        OptixSubcommands::Simulate {
            disc_id,
            media,
            passes,
            zones,
            sectors,
            cells,
            seed,
            out,
        } => cmd_simulate(
            disc_id,
            (*media).into(),
            *passes,
            *zones,
            *sectors,
            *cells,
            *seed,
            out.as_deref(),
        ),
        OptixSubcommands::Verify { cert } => cmd_verify(cert),
        OptixSubcommands::Explain => cmd_explain(),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_simulate(
    disc_id: &str,
    media: MediaType,
    passes: u32,
    zones: u32,
    sectors: u32,
    cells: u32,
    seed: u64,
    out: Option<&str>,
) -> Result<(), DcError> {
    if zones == 0 || sectors == 0 || cells == 0 {
        return Err(DcError::Usage(
            "the spiral grid needs zones, sectors and cells > 0".into(),
        ));
    }
    let config = dc_optix::anneal::AnnealConfig {
        passes,
        ..Default::default()
    };
    println!("[OPTIX] optical annihilation campaign: disc {disc_id}");
    println!(
        "[OPTIX] media: {} (destruction threshold {:.1} normalized dose)",
        media.name(),
        media.annihilate_dose()
    );
    println!(
        "[OPTIX] pickup : {:.1} mW CW at {:.2} m/s parked CLV, energy gain {:.1}x the write strategy",
        config.opu.effective_power_mw(),
        config.opu.clv_mps,
        config.opu.energy_gain()
    );
    println!(
        "[OPTIX] spiral : {zones} zones x {sectors} sectors x {cells} cells, {passes} write-long passes",
    );
    let cert = dc_optix::proof::OptixCertificate::assemble(
        disc_id,
        media,
        &config,
        zones as usize,
        sectors as usize,
        cells as usize,
        seed,
    )
    .map_err(|e| DcError::Internal(format!("campaign: {e}")))?;

    println!();
    println!("zone | min dose | mean dose | eye height | open |  dR/R  | verdict");
    for v in &cert.zones {
        println!(
            "{:4} | {:8.2} | {:9.2} | {:10.4} | {:>4} | {:6.4} | {}",
            v.zone,
            v.min_dose,
            v.mean_dose,
            v.eye_height,
            if v.eye_open { "YES" } else { "no" },
            v.modulation,
            if v.passed { "PASS" } else { "FAIL" }
        );
        for reason in &v.reasons {
            println!("     ! {reason}");
        }
    }
    println!();
    println!(
        "[OPTIX] coverage: {:.1}% of spiral cells over threshold",
        cert.coverage * 100.0
    );
    println!(
        "[OPTIX] readback: worst dR/R {:.4}, push-pull at {:.1}% of fresh, recovery {:.1}% (chance 50%)",
        cert.worst_modulation,
        cert.push_pull_ratio * 100.0,
        cert.read_recovery_rate * 100.0
    );
    for note in &cert.notes {
        println!("[OPTIX] NOTE: {note}");
    }
    if cert.verified {
        println!("[OPTIX] PHOTOBLEACH DESTRUCTION CERTIFICATE: VERIFIED");
        println!("       the recording layer is cooked into a uniform non-reflective state —");
        println!("       the drive tray was the incinerator");
    } else {
        println!("[OPTIX] PHOTOBLEACH DESTRUCTION CERTIFICATE: REFUSED");
        println!("       at least one zone retains readable structure");
    }

    if let Some(path) = out {
        let json = serde_json::to_string_pretty(&cert)
            .map_err(|e| DcError::Internal(format!("serialize certificate: {e}")))?;
        std::fs::write(path, json).map_err(|e| DcError::Internal(format!("write {path}: {e}")))?;
        println!(
            "[OPTIX] certificate written to {path} (digest {})",
            &cert.digest[..16.min(cert.digest.len())]
        );
    }
    Ok(())
}

fn cmd_verify(cert_path: &str) -> Result<(), DcError> {
    let raw = std::fs::read_to_string(cert_path)
        .map_err(|e| DcError::Usage(format!("read {cert_path}: {e}")))?;
    let cert: dc_optix::proof::OptixCertificate = serde_json::from_str(&raw)
        .map_err(|e| DcError::Usage(format!("parse optix certificate: {e}")))?;
    println!("[OPTIX] photobleach destruction certificate verification");
    println!("       disc         : {}", cert.disc_id);
    println!(
        "       digest       : {}",
        &cert.digest[..16.min(cert.digest.len())]
    );
    println!(
        "       zones        : {}/{} passed",
        cert.zones.iter().filter(|z| z.passed).count(),
        cert.zones.len()
    );
    cert.verify()
        .map_err(|e| DcError::Internal(format!("certificate verification: {e}")))?;
    if cert.verified {
        println!("[OPTIX] VERIFIED — digest covers the body, verdicts recompute, spiral is closed");
    } else {
        println!("[OPTIX] VERIFIED AS A DOCUMENT — but the run itself REFUSED (see notes)");
        for note in &cert.notes {
            println!("       NOTE: {note}");
        }
    }
    Ok(())
}

fn cmd_explain() -> Result<(), DcError> {
    println!("dc-optix — Sub-Surface Optical Disk Laser Photobleaching & Phase-Change Destruction");
    println!();
    println!("THE MYTH: WORM media (Archival Blu-Ray, M-DISC, CD-R, DVD-R) can only be");
    println!("destroyed by shredders or incinerators. The recording layer is chemically");
    println!("unmodifiable through standard OS writes — but it is a thin film sitting a few");
    println!("hundred microns from a precision laser: the drive's own pickup.");
    println!();
    println!("dc-optix weaponizes the drive firmware:");
    println!("  * MMC vendor diagnostics (mmc.rs): DISABLE_OPC stops the runtime power");
    println!("    calibration from clamping the diode; LASER_OVERDRIVE sets 100% PWM duty");
    println!("    at the absolute-maximum current; PARK_VELOCITY pins the CLV servo at the");
    println!("    spindle floor; WRITE_LONG burns the spiral zone by zone.");
    println!("  * The dose model (opu.rs): E/L = P/v — energy per unit track length is");
    println!("    maximized at LOW velocity and HIGH power, the inverse of the write");
    println!("    strategy. The default campaign runs ~11x the write-strategy energy.");
    println!("  * Media physics (layer.rs): organic dye photobleaches to saturation around");
    println!("    dose 1; phase-change alloy melts and quenches to amorphous around 2.5;");
    println!("    M-DISC glassy carbon needs ablation-class dose 6 — the media that");
    println!("    survives shredders, not the parked-CW overdrive.");
    println!("  * Readback proof (rfeeye.rs): the RF eye closes to the photodiode noise");
    println!("    floor, the push-pull tracking signal collapses with the slumped groove");
    println!("    walls, and the forensics read-recovery model lands at chance (50%).");
    println!();
    println!("THE CERTIFICATE: every zone must show minimum cell dose over the media");
    println!("threshold, a closed eye, and residual dR/R below the read threshold; the");
    println!("command-stream digest binds the exact weaponization sequence.");
    println!();
    println!("OPERATION:");
    println!("  dc optix simulate --disc-id MD-0001 --media glassy-carbon --out optix-cert.json");
    println!("  dc optix verify --cert optix-cert.json");
    println!();
    println!("SAFETY: this is the physics engine and command-protocol simulation. Physical");
    println!("hardware integration rides the vendor diagnostic tables through the");
    println!("MmcTransport trait — drive families differ and the interlocks are per-OEM.");
    Ok(())
}
