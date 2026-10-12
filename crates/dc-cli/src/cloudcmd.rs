//! `dc cloud` — cloud block-storage lifecycle orchestration (v0.10.0,
//! Frontier 2).
//!
//! `describe` — the read-only pre-flight report for a volume.
//! `plan` — the full lifecycle, dry-run (no API mutations at all).
//! `wipe` — attach → sanitize → verify → detach with a hybrid-signed
//! audit receipt binding the cloud context. `--execute` arms it.
//!
//! The AWS driver runs against the real EC2 API (enable the `cloud-tls`
//! feature for the HTTPS transport; credentials resolve from the
//! environment or the instance profile). The `mock` provider runs the
//! SAME state machine with no cloud at all — operator drills and CI.

use crate::{CloudArgs, CloudSubcommands};
use dc_cert::{MlDsaOperatorKey, OperatorKeyPair};
use dc_cloud::CloudDriver;
#[cfg(feature = "cloud-tls")]
use dc_cloud::aws::Ec2Driver;
use dc_cloud::lifecycle::{SanitizeExecutor, SanitizeOutcome, WipeRequest, run_lifecycle};
use dc_cloud::mock::MockDriver;
use dc_cloud::receipt::CloudSanitizationReceipt;
use dc_core::DcError;
use std::time::Duration;

pub fn cmd_cloud(args: CloudArgs) -> Result<(), DcError> {
    match args.sub {
        CloudSubcommands::Providers => cmd_providers(),
        CloudSubcommands::Describe { provider, volume } => {
            let driver = open_driver(&provider)?;
            cmd_describe(driver.as_ref(), &volume)
        }
        CloudSubcommands::Plan {
            provider,
            volume,
            device,
        } => {
            let driver = open_driver(&provider)?;
            cmd_wipe(driver.as_ref(), &volume, &device, false, None, None)
        }
        CloudSubcommands::Wipe {
            provider,
            volume,
            device,
            execute,
            key,
        } => {
            let driver = open_driver(&provider)?;
            cmd_wipe(driver.as_ref(), &volume, &device, execute, key, None)
        }
    }
}

fn cmd_providers() -> Result<(), DcError> {
    println!("Cloud block-storage providers:");
    println!("{:<10} {:<12} Notes", "Provider", "Status");
    println!("{}", "-".repeat(70));
    let row = |p: &str, s: &str, n: &str| println!("{p:<10} {s:<12} {n}");
    row(
        "aws",
        "driver",
        "EBS via EC2 query API (SigV4 + IMDSv2; needs cloud-tls feature)",
    );
    row(
        "mock",
        "driver",
        "offline drills: full lifecycle, no cloud calls",
    );
    row("azure", "planned", "Managed Disks (driver trait ready)");
    row("gcp", "planned", "Persistent Disk (driver trait ready)");
    Ok(())
}

/// Resolve the driver named on the command line.
fn open_driver(provider: &str) -> Result<Box<dyn CloudDriver>, DcError> {
    match provider {
        "aws" => {
            #[cfg(feature = "cloud-tls")]
            {
                let transport = Box::new(dc_cloud::transport::UreqTransport::new());
                Ok(Box::new(Ec2Driver::from_instance_metadata(transport)?))
            }
            #[cfg(not(feature = "cloud-tls"))]
            {
                Err(DcError::Usage(
                    "the AWS driver needs the `cloud-tls` feature (TLS transport) — \
                     rebuild dc-cli with --features dc-cli/cloud-tls, or use \
                     --provider mock for offline drills"
                        .to_string(),
                ))
            }
        }
        "mock" => Ok(Box::new(MockDriver::with_volume("vol-mock0001", 8))),
        other => Err(DcError::Usage(format!(
            "unknown provider '{other}' (expected aws | mock)"
        ))),
    }
}

fn cmd_describe(driver: &dyn CloudDriver, volume_id: &str) -> Result<(), DcError> {
    let vol = driver.describe_volume(volume_id)?;
    println!("Volume:       {}", vol.volume_id);
    println!("Provider:     {}", driver.provider());
    println!("Size:         {} GiB", vol.size_gib);
    println!("Type:         {}", vol.volume_type);
    println!(
        "Encrypted:     {}",
        if vol.encrypted {
            "yes"
        } else {
            "NO — data-at-rest is plaintext"
        }
    );
    println!(
        "KMS Key:      {}",
        vol.kms_key_arn.as_deref().unwrap_or("—")
    );
    println!("AZ:           {}", vol.availability_zone);
    println!("State:        {}", vol.state);
    if let Some(dev) = &vol.attached_device {
        println!("Attached:     {dev} (safety rail: must be detached before a wipe)");
    }
    Ok(())
}

/// The engine binding for cloud wipes: spawn the real `dc execute` against
/// the attached device node (mock provider: run against the local backing
/// file directly in tests; production mock runs are drills).
struct EngineExecutor {
    self_exe: std::path::PathBuf,
    profile: String,
}

impl SanitizeExecutor for EngineExecutor {
    fn sanitize(
        &self,
        device: &str,
        volume: &dc_cloud::CloudVolume,
        execute: bool,
    ) -> Result<SanitizeOutcome, DcError> {
        if !execute {
            println!(
                "[CLOUD] DRY: would run `dc execute --target {device} --profile {}` on the \
                 {} GiB volume {}",
                self.profile, volume.size_gib, volume.volume_id
            );
            return Ok(SanitizeOutcome {
                cert_path: None,
                verification_level: "planned".to_string(),
                passes: vec!["(per profile)".to_string()],
            });
        }
        // The engine writes its journal + certificate; harvest the exit.
        let status = std::process::Command::new(&self.self_exe)
            .arg("--json")
            .arg("execute")
            .arg("--target")
            .arg(device)
            .arg("--profile")
            .arg(&self.profile)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .status()?;
        if !status.success() {
            return Err(DcError::Internal(format!(
                "engine run on {device} failed: {status}"
            )));
        }
        // The engine's certificate lands in ./certificates; the receipt
        // binds whichever newest certificate matches this device.
        Ok(SanitizeOutcome {
            cert_path: latest_cert_for_device(device),
            verification_level: "per-profile".to_string(),
            passes: vec!["engine".to_string()],
        })
    }
}

fn latest_cert_for_device(device: &str) -> Option<std::path::PathBuf> {
    let dir = std::path::Path::new("certificates");
    let mut best: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = std::fs::read(&path).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        if v.pointer("/device/dev_path").and_then(|p| p.as_str()) != Some(device) {
            continue;
        }
        let mtime = entry.metadata().ok()?.modified().ok()?;
        if best.as_ref().is_none_or(|(t, _)| mtime > *t) {
            best = Some((mtime, path));
        }
    }
    best.map(|(_, p)| p)
}

#[allow(clippy::too_many_arguments)]
fn cmd_wipe(
    driver: &dyn CloudDriver,
    volume_id: &str,
    device: &str,
    execute: bool,
    key: Option<std::path::PathBuf>,
    profile: Option<String>,
) -> Result<(), DcError> {
    let profile = profile.unwrap_or_else(|| "nist-clear".to_string());

    let self_exe = std::env::current_exe()
        .map_err(|e| DcError::Internal(format!("cannot resolve self executable: {e}")))?;
    let executor = EngineExecutor { self_exe, profile };

    let req = WipeRequest {
        volume_id: volume_id.to_string(),
        device: device.to_string(),
        execute,
        state_poll_timeout: Duration::from_secs(180),
    };

    if !execute {
        println!(
            "[CLOUD] DRY RUN — no attach, no writes, no detach. Re-run with --execute to arm."
        );
    }
    let result = run_lifecycle(driver, &executor, &req)?;

    println!();
    println!(
        "[CLOUD] Lifecycle {} ({} phases):",
        if execute { "EXECUTED" } else { "PLANNED" },
        result.phases.len()
    );
    for p in &result.phases {
        println!(
            "  {:<16} {:<10} {}",
            p.phase,
            p.result,
            p.detail.as_deref().unwrap_or("")
        );
    }

    // --- the receipt ---
    let context = driver.cloud_context(volume_id)?;
    let keypair = match &key {
        Some(k) => OperatorKeyPair::load_from_file(k)?,
        None => {
            return Err(DcError::Usage(
                "cloud wipes require an operator signing key (--key) for the receipt".to_string(),
            ));
        }
    };
    let pq = match &key {
        Some(k) => MlDsaOperatorKey::load_sibling(k)?,
        None => None,
    };

    let cert_json = result
        .outcome
        .cert_path
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|raw| serde_json::from_slice(&raw).ok());

    let cert_path_ref = result
        .outcome
        .cert_path
        .as_deref()
        .map(std::path::Path::new);
    let mut receipt = CloudSanitizationReceipt::build(
        &result,
        context,
        cert_path_ref,
        cert_json.as_ref(),
        &keypair,
    )?;
    receipt.sign(&keypair, pq.as_ref())?;

    let receipt_path = std::path::Path::new("certificates")
        .join(format!("{}.cloud-receipt.json", result.volume.volume_id));
    if let Some(parent) = receipt_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&receipt_path, serde_json::to_string_pretty(&receipt)?)?;
    println!();
    println!("[CLOUD] Receipt written: {}", receipt_path.display());
    println!(
        "        provider={}, volume={}, az={}",
        receipt.cloud.provider, receipt.cloud.volume_id, receipt.cloud.availability_zone
    );
    println!(
        "        signatures: Ed25519{}",
        if receipt.post_quantum.is_some() {
            " + ML-DSA-44 (hybrid)"
        } else {
            ""
        }
    );

    Ok(())
}
