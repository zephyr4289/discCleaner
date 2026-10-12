//! `dc iscsi` — native iSCSI target discovery and in-band remote SCSI
//! sanitization (v0.9.0, Phase 4).
//!
//! `discover`: SendTargets=All against a portal — the inventory answer
//! for SAN teams running iSCSI alongside (or instead of) NVMe-oF.
//! `purge`: operational login + SCSI SANITIZE passthrough with the
//! report-then-destroy discipline (identity first, `--execute` arms).

use crate::{IscsiArgs, IscsiSubcommands};
use dc_core::DcError;
use dc_hw::{ScsiCodec, ScsiSanitizeServiceAction};
use dc_iscsi::session::{IscsiSession, Portal};
use dc_iscsi::{IscsiTimeouts, ScsiIoParams};
use std::time::Duration;

pub fn cmd_iscsi(args: IscsiArgs) -> Result<(), DcError> {
    match args.sub {
        IscsiSubcommands::Discover { portal, login_ms } => cmd_discover(
            &portal,
            IscsiTimeouts {
                login_ms,
                scsi_ms: login_ms,
            },
        ),
        IscsiSubcommands::Purge {
            portal,
            target,
            lun,
            method,
            execute,
            scsi_ms,
        } => cmd_purge(&portal, &target, lun, &method, execute, scsi_ms),
    }
}

fn parse_portal(spec: &str) -> Result<Portal, DcError> {
    Portal::parse(spec).map_err(|e| DcError::Usage(format!("portal '{spec}': {e}")))
}

fn cmd_discover(portal_spec: &str, timeouts: IscsiTimeouts) -> Result<(), DcError> {
    let portal = parse_portal(portal_spec)?;
    println!("[ISCSI] Discovering targets at {} ...", portal);
    let targets = IscsiSession::discover(&portal, timeouts)
        .map_err(|e| DcError::Internal(format!("iSCSI discovery failed: {e}")))?;
    if targets.is_empty() {
        println!("[ISCSI] Portal advertised no targets.");
        return Ok(());
    }
    println!("{:<56} {:<28} {:<8}", "TargetName", "Address", "PGT");
    println!("{:-<96}", "");
    for t in &targets {
        if t.addresses.is_empty() {
            println!("{:<56} (no address advertised)", t.target_name);
            continue;
        }
        for (host, port, tag) in &t.addresses {
            let addr = format!("{host}:{port}");
            println!("{:<56} {:<28} {:<8}", t.target_name, addr, tag);
        }
    }
    println!("{:-<96}", "");
    println!("[ISCSI] {} target(s) discovered.", targets.len());
    Ok(())
}

fn parse_method(method: &str) -> Result<ScsiSanitizeServiceAction, DcError> {
    match method {
        "crypto-erase" => Ok(ScsiSanitizeServiceAction::CryptoErase),
        "block-erase" => Ok(ScsiSanitizeServiceAction::BlockErase),
        "overwrite" => Ok(ScsiSanitizeServiceAction::Overwrite),
        other => Err(DcError::Usage(format!(
            "unknown sanitize method '{other}' (expected crypto-erase | block-erase | overwrite)"
        ))),
    }
}

fn cmd_purge(
    portal_spec: &str,
    target: &str,
    lun: u16,
    method: &str,
    execute: bool,
    scsi_ms: u64,
) -> Result<(), DcError> {
    let action = parse_method(method)?;
    let portal = parse_portal(portal_spec)?;
    let timeouts = IscsiTimeouts {
        login_ms: 10_000,
        scsi_ms,
    };

    let mut session = IscsiSession::login_target(
        &portal,
        target,
        "iqn.2014-08.org.discleaner:initiator",
        timeouts,
    )
    .map_err(|e| DcError::Internal(format!("iSCSI login failed: {e}")))?;
    println!("[ISCSI] Logged into {} at {}", target, portal);

    // REPORT-then-destroy: identify the LUN before touching it.
    let mut inquiry_cdb = [0u8; 16];
    inquiry_cdb[..6].copy_from_slice(&ScsiCodec::encode_inquiry(36));
    let inquiry = ScsiIoParams::read(lun, inquiry_cdb, 6, 36, Duration::from_millis(scsi_ms));
    let identity = session
        .execute(&inquiry)
        .map_err(|e| DcError::Internal(format!("INQUIRY failed: {e}")))?;
    if !identity.is_good() {
        return Err(DcError::Internal(format!(
            "INQUIRY refused: status {:#04x}, sense {:?}",
            identity.status, identity.sense
        )));
    }
    let parsed_identity = ScsiCodec::decode_inquiry_identity(&identity.data_in)
        .map_err(|e| DcError::Internal(format!("INQUIRY decode: {e}")))?;
    println!(
        "[ISCSI] LUN {lun} identity: vendor '{}', product '{}', revision '{}'",
        parsed_identity.vendor.trim(),
        parsed_identity.product.trim(),
        parsed_identity.revision.trim()
    );

    // The destructive verb.
    let cdb = ScsiCodec::encode_sanitize(action, true); // IMMED: return at once
    let params = ScsiIoParams::write(lun, cdb, 16, Duration::from_millis(scsi_ms));

    if !execute {
        println!("[ISCSI] DRY: would issue SANITIZE ({method}, IMMED) to LUN {lun} of {target}.");
        println!("         Re-run with --execute to arm the purge.");
        let _ = session.logout();
        return Ok(());
    }

    println!("[ISCSI] ARMED: issuing SANITIZE ({method}, IMMED) to LUN {lun} ...");
    let outcome = session
        .execute(&params)
        .map_err(|e| DcError::Internal(format!("SANITIZE passthrough failed: {e}")))?;
    let _ = session.logout();

    if outcome.is_good() {
        println!("[ISCSI] SANITIZE accepted by the target (SCSI status GOOD).");
        println!("        Verify completion with the array's management plane or a");
        println!("        follow-up REQUEST SENSE poll (sense 2/04/1B = in progress).");
        Ok(())
    } else if outcome.is_sanitize_in_progress() {
        println!("[ISCSI] SANITIZE reported in progress (sense 2/04/1B).");
        Ok(())
    } else {
        Err(DcError::Internal(format!(
            "SANITIZE refused: response {:#04x}, status {:#04x}, sense {:?}",
            outcome.response, outcome.status, outcome.sense
        )))
    }
}
