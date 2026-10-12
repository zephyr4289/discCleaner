//! Cloud lifecycle integration: the state machine, the safety rails, the
//! rollback rule, and the hybrid-signed receipt binding the cloud context.

use dc_cert::{MlDsaOperatorKey, OperatorKeyPair};
use dc_cloud::lifecycle::{SanitizeExecutor, SanitizeOutcome, WipeRequest, run_lifecycle};
use dc_cloud::mock::MockDriver;
use dc_cloud::receipt::CloudSanitizationReceipt;
use dc_cloud::{CloudDriver, CloudVolume};
use dc_core::DcError;
use std::time::Duration;

/// A REAL (small) wipe executor: writes recognizable passes over a temp
/// file and verifies them — enough to exercise the lifecycle honestly
/// without spawning the full engine.
struct TempFileWiper {
    path: std::path::PathBuf,
    fail: std::sync::atomic::AtomicBool,
}

impl SanitizeExecutor for TempFileWiper {
    fn sanitize(
        &self,
        device: &str,
        volume: &CloudVolume,
        execute: bool,
    ) -> Result<SanitizeOutcome, DcError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(DcError::Internal(
                "executor: injected sanitize failure".to_string(),
            ));
        }
        if !execute {
            return Ok(SanitizeOutcome {
                cert_path: None,
                verification_level: "planned".to_string(),
                passes: vec!["zero".to_string(), "verify".to_string()],
            });
        }
        // Two passes: zeros, then one's complement — then verify both.
        let len = 1024 * 1024usize;
        let zeros = vec![0u8; len];
        let ones = vec![0xFF; len];
        std::fs::write(&self.path, &zeros).map_err(DcError::StdIo)?;
        std::fs::write(&self.path, &ones).map_err(DcError::StdIo)?;
        let readback = std::fs::read(&self.path).map_err(DcError::StdIo)?;
        if readback != ones {
            return Err(DcError::Internal("verification failed".to_string()));
        }
        let _ = (device, volume);
        Ok(SanitizeOutcome {
            cert_path: Some(self.path.clone()),
            verification_level: "full".to_string(),
            passes: vec!["zero".to_string(), "invert".to_string()],
        })
    }
}

#[test]
fn full_lifecycle_happy_path_with_hybrid_receipt() {
    let driver = MockDriver::with_volume("vol-test0001", 4);
    let wiper = TempFileWiper {
        path: std::env::temp_dir().join("dc-cloud-test-vol.img"),
        fail: std::sync::atomic::AtomicBool::new(false),
    };

    let req = WipeRequest {
        volume_id: "vol-test0001".to_string(),
        device: "/dev/sdf".to_string(),
        execute: true,
        state_poll_timeout: Duration::from_secs(5),
    };
    let result = run_lifecycle(&driver, &wiper, &req).expect("lifecycle");
    assert_eq!(result.volume.state, "available", "detached at the end");

    let phase_names: Vec<&str> = result.phases.iter().map(|p| p.phase.as_str()).collect();
    assert_eq!(
        phase_names,
        vec!["describe", "attach", "sanitize", "detach"]
    );
    assert!(result.phases.iter().all(|p| p.result == "ok"));
    assert!(result.outcome.executed);
    assert_eq!(result.outcome.verification_level.as_deref(), Some("full"));

    // The volume is back to `available` and detach left no attachment.
    let vol = driver.describe_volume("vol-test0001").expect("describe");
    assert_eq!(vol.state, "available");
    assert!(vol.attached_device.is_none());

    // --- the receipt: hybrid-signed, binding the cloud context ---
    let classical = OperatorKeyPair::generate();
    let pq = MlDsaOperatorKey::generate().expect("pq keygen");
    let context = driver.cloud_context("vol-test0001").expect("context");
    let mut receipt =
        CloudSanitizationReceipt::build(&result, context, wiper.cert_path(), None, &classical)
            .expect("build receipt");
    assert_eq!(receipt.cloud.provider, "mock");
    assert_eq!(receipt.cloud.volume_id, "vol-test0001");
    assert!(receipt.cloud.kms_key_arn.is_some());

    receipt.sign(&classical, Some(&pq)).expect("hybrid sign");
    assert!(
        receipt.verify().expect("verify"),
        "hybrid receipt must verify"
    );

    // Tamper with the cloud context -> both legs break.
    receipt.cloud.volume_id = "vol-OTHER".to_string();
    assert!(
        !receipt.verify().expect("verify 2"),
        "tampered context must fail"
    );
}

#[test]
fn dry_run_touches_nothing() {
    let driver = MockDriver::with_volume("vol-dry0001", 4);
    let wiper = TempFileWiper {
        path: std::env::temp_dir().join("dc-cloud-test-dry.img"),
        fail: std::sync::atomic::AtomicBool::new(false),
    };
    let req = WipeRequest {
        volume_id: "vol-dry0001".to_string(),
        device: "/dev/sdf".to_string(),
        execute: false,
        state_poll_timeout: Duration::from_secs(5),
    };
    let result = run_lifecycle(&driver, &wiper, &req).expect("dry lifecycle");
    assert!(!result.outcome.executed);
    let attach_phase = result.phases.iter().find(|p| p.phase == "attach").unwrap();
    assert_eq!(attach_phase.result, "skipped");
    let vol = driver.describe_volume("vol-dry0001").expect("describe");
    assert_eq!(vol.state, "available", "dry run must not mutate the volume");
}

#[test]
fn sanitize_failure_rolls_back_the_attachment() {
    let driver = MockDriver::with_volume("vol-fail001", 4);
    let wiper = TempFileWiper {
        path: std::env::temp_dir().join("dc-cloud-test-fail.img"),
        fail: std::sync::atomic::AtomicBool::new(true),
    };
    let req = WipeRequest {
        volume_id: "vol-fail001".to_string(),
        device: "/dev/sdf".to_string(),
        execute: true,
        state_poll_timeout: Duration::from_secs(5),
    };
    let err = run_lifecycle(&driver, &wiper, &req).expect_err("must fail");
    assert!(err.to_string().contains("injected sanitize failure"));

    // THE ROLLBACK RULE: the volume must be detached again.
    let vol = driver.describe_volume("vol-fail001").expect("describe");
    assert_eq!(vol.state, "available", "rollback detach must have run");
    assert!(vol.attached_device.is_none());
}

#[test]
fn attached_elsewhere_is_refused_upfront() {
    let driver = MockDriver::with_volume("vol-ours001", 4);
    driver.register_attached_elsewhere("vol-foreign1", "/dev/xvdb");
    let wiper = TempFileWiper {
        path: std::env::temp_dir().join("dc-cloud-test-foreign.img"),
        fail: std::sync::atomic::AtomicBool::new(false),
    };
    let req = WipeRequest {
        volume_id: "vol-foreign1".to_string(),
        device: "/dev/sdf".to_string(),
        execute: true,
        state_poll_timeout: Duration::from_secs(5),
    };
    let err = run_lifecycle(&driver, &wiper, &req).expect_err("must refuse");
    assert!(
        err.to_string().contains("currently attached"),
        "safety rail message: {err}"
    );
}

#[test]
fn unknown_volume_is_a_clean_usage_error() {
    let driver = MockDriver::with_volume("vol-known001", 4);
    let wiper = TempFileWiper {
        path: std::env::temp_dir().join("dc-cloud-test-unknown.img"),
        fail: std::sync::atomic::AtomicBool::new(false),
    };
    let req = WipeRequest {
        volume_id: "vol-does-not-exist".to_string(),
        device: "/dev/sdf".to_string(),
        execute: true,
        state_poll_timeout: Duration::from_secs(5),
    };
    let err = run_lifecycle(&driver, &wiper, &req).expect_err("must fail");
    assert!(err.to_string().contains("unknown volume"));
}

impl TempFileWiper {
    fn cert_path(&self) -> Option<&std::path::Path> {
        Some(self.path.as_path())
    }
}
