//! `dc wear` — Silicon-Level Analog Flash Degradation Analysis &
//! Charge Bleed (v0.13.0, Frontier 2).
//!
//! * `simulate` — run the deterministic SimNand P/E stress campaign
//!   and assemble/judge the Silicon Wear Certificate (100% channel
//!   coverage, F-N charge ledger, ΔVth estimates, RBER evidence).
//! * `verify` — offline verification of a wear certificate (digest
//!   binding + verdict arithmetic recomputation).
//! * `explain` — the physics constants, the models, and the
//!   threat model in operator terms.

use crate::{WearArgs, WearSubcommands};
use dc_core::DcError;

pub fn cmd_wear(args: WearArgs) -> Result<(), DcError> {
    match &args.sub {
        WearSubcommands::Simulate {
            device_id,
            cycles,
            channels,
            ces,
            luns,
            seed,
            out,
        } => cmd_simulate(
            device_id,
            *cycles,
            *channels,
            *ces,
            *luns,
            *seed,
            out.as_deref(),
        ),
        WearSubcommands::Verify { cert } => cmd_verify(cert),
        WearSubcommands::Explain => cmd_explain(),
    }
}

fn cmd_simulate(
    device_id: &str,
    cycles: u32,
    channels: u32,
    ces: u32,
    luns: u32,
    seed: u64,
    out: Option<&str>,
) -> Result<(), DcError> {
    if cycles == 0 {
        return Err(DcError::Usage(
            "a wear campaign needs at least one cycle (zero-cycle = no evidence)".into(),
        ));
    }
    let config = dc_wear::stress::CampaignConfig {
        topology: dc_wear::Topology {
            channels,
            ces_per_channel: ces,
            luns_per_ce: luns,
        },
        cycles,
        verify_reads_per_cycle: 2,
        pulse: dc_wear::stress::PulseShape::default(),
        c_fg_ff: 1.0,
        cells_per_channel: 1_000_000_000,
        seed,
    };
    println!("[WEAR] silicon stress campaign: device {device_id}");
    println!(
        "[WEAR] topology {}ch x {}ce x {}lun, {cycles} P/E cycles per die",
        config.topology.channels, config.topology.ces_per_channel, config.topology.luns_per_ce
    );
    println!(
        "[WEAR] erase pulses: {:.1} MV/cm, {:.0} µs (Fowler-Nordheim regime)",
        config.pulse.field_mv_cm, config.pulse.duration_us
    );

    let mut sim = dc_wear::stress::SimNand::new(&config);
    let rows = dc_wear::stress::run_campaign(&mut sim, &config)
        .map_err(|e| DcError::Internal(format!("campaign: {e}")))?;

    let cert = dc_wear::certificate::SiliconWearCertificate::assemble(device_id, &config, &rows)
        .map_err(|e| DcError::Internal(format!("certificate assembly: {e}")))?;

    println!();
    println!(
        "ch | dies | pulses | Q_inj min [C/cm2] | dVth max [V] | cons. min | t min | cycles | verdict"
    );
    for v in &cert.channels {
        println!(
            "{:2} | {:4} | {:6} | {:.3e} | {:>10.3} | {:>9.1} | {:>5.1} | {:6} | {}",
            v.channel,
            v.dies,
            v.erase_pulses,
            v.q_inj_c_cm2_min,
            v.vth_shift_v_max,
            v.charge_consistency_min,
            v.latency_t_min,
            v.implied_cycles_min,
            if v.passed { "PASS" } else { "FAIL" }
        );
        for reason in &v.reasons {
            println!("     ! {reason}");
        }
    }
    println!();
    println!(
        "[WEAR] coverage: {}/{} channels show full physical stress evidence",
        cert.covered_channels, cert.active_channels
    );
    for note in &cert.notes {
        println!("[WEAR] NOTE: {note}");
    }
    if cert.verified {
        println!("[WEAR] SILICON WEAR CERTIFICATE: VERIFIED");
        println!(
            "       the flash physically underwent high-voltage erasure on every active channel"
        );
    } else {
        println!("[WEAR] SILICON WEAR CERTIFICATE: REFUSED");
        println!("       at least one channel shows no physical erasure evidence");
    }

    if let Some(path) = out {
        let json = serde_json::to_string_pretty(&cert)
            .map_err(|e| DcError::Internal(format!("serialize certificate: {e}")))?;
        std::fs::write(path, json).map_err(|e| DcError::Internal(format!("write {path}: {e}")))?;
        println!(
            "[WEAR] certificate written to {path} (digest {})",
            &cert.digest[..16.min(cert.digest.len())]
        );
    }
    Ok(())
}

fn cmd_verify(cert_path: &str) -> Result<(), DcError> {
    let raw = std::fs::read_to_string(cert_path)
        .map_err(|e| DcError::Usage(format!("read {cert_path}: {e}")))?;
    let cert: dc_wear::certificate::SiliconWearCertificate = serde_json::from_str(&raw)
        .map_err(|e| DcError::Usage(format!("parse wear certificate: {e}")))?;
    println!("[WEAR] silicon wear certificate verification");
    println!("       device       : {}", cert.device_id);
    println!(
        "       digest       : {}",
        &cert.digest[..16.min(cert.digest.len())]
    );
    println!(
        "       channels     : {}/{} covered",
        cert.covered_channels, cert.active_channels
    );
    cert.verify()
        .map_err(|e| DcError::Internal(format!("certificate verification: {e}")))?;
    if cert.verified {
        println!("[WEAR] VERIFIED — digest covers the body, verdicts recompute, coverage closes");
    } else {
        println!("[WEAR] VERIFIED AS A DOCUMENT — but the run itself REFUSED (see notes)");
        for note in &cert.notes {
            println!("       NOTE: {note}");
        }
    }
    Ok(())
}

fn cmd_explain() -> Result<(), DcError> {
    println!("dc-wear — Silicon-Level Analog Flash Degradation Analysis & Charge Bleed");
    println!();
    println!("THE DOUBT: after a NIST 800-88 Clear, did the controller ACTUALLY erase the");
    println!("cells — or silently remap bad blocks, keep the charge, and tell the software");
    println!("what it wanted to hear? Software readback cannot tell: the FTL owns the mapping.");
    println!();
    println!("dc-wear measures the PHYSICS instead of the firmware:");
    println!("  * Fowler-Nordheim tunneling ledger (tunnel.rs): J = A*F^2*exp(-B/F)");
    println!("    with the canonical SiO2 constants A = 1.25e-6 A/cm^2/(MV/cm)^2,");
    println!("    B = 253 MV/cm. Every erase pulse injects charge THROUGH the tunnel");
    println!("    oxide; Q_inj = sum(J*t) is the quantity an FTL shortcut cannot fake.");
    println!("  * Threshold-voltage shift (vth.rs): dVth(N) = dV0 * N^alpha (alpha = 0.35),");
    println!("    estimated from the controller's own read-retry compensation.");
    println!("  * Program-latency statistics (latency.rs): worn cells need more ISPP");
    println!("    steps — sub-microsecond timing variance is a wear signature.");
    println!("  * RBER power law (ber.rs): r0 + a*(N/N_end)^b — fresh-looking RBER on a");
    println!("    supposedly cycled channel is FTL-shortcut evidence.");
    println!("  * Silicon Wear Certificate: 100% channel coverage required. A single");
    println!("    silently-retired die fails the whole certificate.");
    println!();
    println!("OPERATION:");
    println!("  dc wear simulate --device-id SN-XYZ --cycles 3000 --out wear-cert.json");
    println!("  dc wear verify wear-cert.json");
    println!();
    println!("MODEL CALIBRATION: the per-cell charge anchor is the textbook SLC erase");
    println!("window (~2.5e3 electrons per standard pulse) — the effective tunnel area is");
    println!("process-secret, so the per-cell conversion is calibrated, not first-principles.");
    println!("The area-side Q_inj ledger stays first-principles.");
    Ok(())
}
