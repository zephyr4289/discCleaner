//! The attach → sanitize → verify → detach state machine.

use crate::{CloudDriver, CloudVolume};
use dc_core::DcError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

/// What the wipe engine reports back to the lifecycle.
#[derive(Debug, Clone)]
pub struct SanitizeOutcome {
    /// Path of the SanitizationCertificate the engine wrote.
    pub cert_path: Option<PathBuf>,
    /// "full" | "sample:N" | "none"
    pub verification_level: String,
    pub passes: Vec<String>,
}

/// The engine binding: implemented by the CLI (spawns `dc execute` against
/// the attached device node) and by tests (wipes a temp file directly).
pub trait SanitizeExecutor {
    /// Sanitize `device` (the node the volume attached as). When `execute`
    /// is false, perform the pre-flight only and return the would-be plan.
    fn sanitize(
        &self,
        device: &str,
        volume: &CloudVolume,
        execute: bool,
    ) -> Result<SanitizeOutcome, DcError>;
}

/// One phase in the lifecycle timeline recorded in the receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseRecord {
    pub phase: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub result: String, // "ok" | "failed" | "skipped" | "rolled-back"
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleResult {
    pub volume: CloudVolume,
    pub phases: Vec<PhaseRecord>,
    pub outcome: SanitizeOutcomeReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizeOutcomeReport {
    pub executed: bool,
    pub cert_path: Option<String>,
    pub verification_level: Option<String>,
    pub passes: Vec<String>,
}

/// A pending volume lifecycle.
pub struct WipeRequest {
    pub volume_id: String,
    /// Device name to attach as (e.g. "/dev/sdf" — the cloud API's naming,
    /// not the local node).
    pub device: String,
    /// DRY-RUN without this flag.
    pub execute: bool,
    pub state_poll_timeout: Duration,
}

fn utc_now() -> String {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    // Reuse the epoch formatter for the IMDS-style date, then render the
    // audit-friendly RFC3339 shape.
    let compact = crate::aws::format_epoch(d.as_secs());
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &compact[0..4],
        &compact[4..6],
        &compact[6..8],
        &compact[9..11],
        &compact[11..13],
        &compact[13..15]
    )
}

struct PhaseTimer {
    phase: String,
    started: Instant,
    started_utc: String,
}

impl PhaseTimer {
    fn new(phase: &str) -> Self {
        PhaseTimer {
            phase: phase.to_string(),
            started: Instant::now(),
            started_utc: utc_now(),
        }
    }

    fn finish(self, records: &mut Vec<PhaseRecord>, result: &str, detail: Option<String>) {
        records.push(PhaseRecord {
            phase: self.phase,
            started_utc: self.started_utc,
            finished_utc: utc_now(),
            result: result.to_string(),
            detail: detail.or_else(|| {
                let elapsed = self.started.elapsed();
                if elapsed >= Duration::from_millis(1) {
                    Some(format!("{:.2}s", elapsed.as_secs_f64()))
                } else {
                    None
                }
            }),
        });
    }
}

/// Run the full lifecycle. The rollback rule: once `attach` succeeds, ANY
/// later failure still detaches (a failed wipe must not leave a foreign
/// volume hanging off the sanitizer instance).
pub fn run_lifecycle(
    driver: &dyn CloudDriver,
    executor: &dyn SanitizeExecutor,
    req: &WipeRequest,
) -> Result<LifecycleResult, DcError> {
    let mut phases: Vec<PhaseRecord> = Vec::new();

    // --- Phase 1: describe (read-only) ---
    let t = PhaseTimer::new("describe");
    let volume = driver.describe_volume(&req.volume_id)?;
    t.finish(
        &mut phases,
        "ok",
        Some(format!("{} GiB, {}", volume.size_gib, volume.state)),
    );

    // Safety rail: a volume attached elsewhere is refused (the operator
    // must detach it in the console first — an explicit, logged decision).
    if volume.state == "in-use" && volume.attached_device.is_some() {
        return Err(DcError::Usage(format!(
            "volume {} is currently attached (device {}) — detach it from \
             its compute host before running the sanitization lifecycle",
            req.volume_id,
            volume.attached_device.as_deref().unwrap_or("?")
        )));
    }

    // --- Phase 2: attach ---
    let mut attached = false;
    let t = PhaseTimer::new("attach");
    if req.execute {
        driver.attach_volume(&req.volume_id, &req.device)?;
        let vol = driver.wait_state(&req.volume_id, "in-use", req.state_poll_timeout)?;
        attached = true;
        t.finish(
            &mut phases,
            "ok",
            Some(format!("attached as {}", req.device)),
        );
        let _ = vol;
    } else {
        t.finish(
            &mut phases,
            "skipped",
            Some("dry-run: no API mutations".to_string()),
        );
    }

    // --- Phase 3: sanitize via the engine ---
    let sanitize_result: Result<SanitizeOutcome, DcError> = if req.execute {
        executor.sanitize(&req.device, &volume, true)
    } else {
        executor.sanitize(&req.device, &volume, false)
    };

    let t = PhaseTimer::new("sanitize");
    let outcome = match sanitize_result {
        Ok(o) => {
            t.finish(
                &mut phases,
                "ok",
                Some(format!(
                    "verification={}, passes={}",
                    o.verification_level,
                    o.passes.join("/")
                )),
            );
            o
        }
        Err(e) => {
            t.finish(&mut phases, "failed", Some(e.to_string()));
            if attached {
                let rb = PhaseTimer::new("rollback-detach");
                match driver.detach_volume(&req.volume_id, &req.device) {
                    Ok(()) => {
                        let _ =
                            driver.wait_state(&req.volume_id, "available", req.state_poll_timeout);
                        rb.finish(
                            &mut phases,
                            "ok",
                            Some("rolled back after failure".to_string()),
                        );
                    }
                    Err(rb_err) => {
                        rb.finish(&mut phases, "failed", Some(rb_err.to_string()));
                    }
                }
            }
            return Err(e);
        }
    };

    // --- Phase 4: detach ---
    let t = PhaseTimer::new("detach");
    if req.execute {
        match driver
            .detach_volume(&req.volume_id, &req.device)
            .and_then(|_| driver.wait_state(&req.volume_id, "available", req.state_poll_timeout))
        {
            Ok(_) => t.finish(&mut phases, "ok", None),
            Err(e) => {
                t.finish(&mut phases, "failed", Some(e.to_string()));
                return Err(DcError::Internal(format!(
                    "sanitize succeeded but detach failed — volume {} may \
                     still be attached: {e}",
                    req.volume_id
                )));
            }
        }
    } else {
        t.finish(&mut phases, "skipped", None);
    }

    Ok(LifecycleResult {
        volume,
        phases,
        outcome: SanitizeOutcomeReport {
            executed: req.execute,
            cert_path: outcome.cert_path.map(|p| p.display().to_string()),
            verification_level: Some(outcome.verification_level),
            passes: outcome.passes,
        },
    })
}
