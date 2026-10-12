//! Mock cloud driver — offline drills and CI.
//!
//! `--provider mock` runs the REAL lifecycle state machine (and, when a
//! backing file is given, the REAL wipe engine against that file) without
//! touching any cloud API. This is both the test harness and the
//! training mode for operators rehearsing cloud workflows.

use crate::{CloudContext, CloudDriver, CloudVolume};
use dc_core::DcError;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub struct MockDriver {
    volumes: Mutex<HashMap<String, MockVolume>>,
    /// Fails the NEXT attach (failure-injection for rollback drills).
    pub fail_next_attach: AtomicBool,
    /// Fails the NEXT sanitize-phase poll (rollback drill).
    pub fail_next_detach: AtomicBool,
}

#[derive(Debug, Clone)]
struct MockVolume {
    spec: CloudVolume,
    attached_device: Option<String>,
}

impl MockDriver {
    /// A driver with one pre-registered volume.
    pub fn with_volume(volume_id: &str, size_gib: u64) -> Self {
        let mut volumes = HashMap::new();
        volumes.insert(
            volume_id.to_string(),
            MockVolume {
                spec: CloudVolume {
                    volume_id: volume_id.to_string(),
                    size_gib,
                    encrypted: true,
                    kms_key_arn: Some(format!(
                        "arn:aws:kms:eu-central-1:111122223333:key/mock-{volume_id}"
                    )),
                    availability_zone: "eu-central-1a".to_string(),
                    state: "available".to_string(),
                    attached_device: None,
                    iops: Some(3000),
                    volume_type: "gp3".to_string(),
                },
                attached_device: None,
            },
        );
        MockDriver {
            volumes: Mutex::new(volumes),
            fail_next_attach: AtomicBool::new(false),
            fail_next_detach: AtomicBool::new(false),
        }
    }

    /// Register an extra volume (e.g. one attached elsewhere, to exercise
    /// the safety rail).
    pub fn register_attached_elsewhere(&self, volume_id: &str, device: &str) {
        let mut vols = self.volumes.lock().expect("mock lock");
        vols.insert(
            volume_id.to_string(),
            MockVolume {
                spec: CloudVolume {
                    volume_id: volume_id.to_string(),
                    size_gib: 8,
                    encrypted: false,
                    kms_key_arn: None,
                    availability_zone: "eu-central-1b".to_string(),
                    state: "in-use".to_string(),
                    attached_device: Some(device.to_string()),
                    iops: None,
                    volume_type: "gp2".to_string(),
                },
                attached_device: Some(device.to_string()),
            },
        );
    }
}

impl Default for MockDriver {
    fn default() -> Self {
        MockDriver {
            volumes: Mutex::new(HashMap::new()),
            fail_next_attach: AtomicBool::new(false),
            fail_next_detach: AtomicBool::new(false),
        }
    }
}

impl CloudDriver for MockDriver {
    fn provider(&self) -> &'static str {
        "mock"
    }

    fn describe_volume(&self, volume_id: &str) -> Result<CloudVolume, DcError> {
        let vols = self.volumes.lock().expect("mock lock");
        let v = vols
            .get(volume_id)
            .ok_or_else(|| DcError::Usage(format!("mock driver: unknown volume '{volume_id}'")))?;
        Ok(v.spec.clone())
    }

    fn attach_volume(&self, volume_id: &str, device: &str) -> Result<(), DcError> {
        if self.fail_next_attach.swap(false, Ordering::SeqCst) {
            return Err(DcError::Internal(
                "mock: injected attach failure".to_string(),
            ));
        }
        let mut vols = self.volumes.lock().expect("mock lock");
        let v = vols
            .get_mut(volume_id)
            .ok_or_else(|| DcError::Usage(format!("mock driver: unknown volume '{volume_id}'")))?;
        v.spec.state = "in-use".to_string();
        v.spec.attached_device = Some(device.to_string());
        v.attached_device = Some(device.to_string());
        Ok(())
    }

    fn detach_volume(&self, volume_id: &str, device: &str) -> Result<(), DcError> {
        if self.fail_next_detach.swap(false, Ordering::SeqCst) {
            return Err(DcError::Internal(
                "mock: injected detach failure".to_string(),
            ));
        }
        let mut vols = self.volumes.lock().expect("mock lock");
        let v = vols
            .get_mut(volume_id)
            .ok_or_else(|| DcError::Usage(format!("mock driver: unknown volume '{volume_id}'")))?;
        v.spec.state = "available".to_string();
        v.spec.attached_device = None;
        v.attached_device = None;
        let _ = device;
        Ok(())
    }

    fn wait_state(
        &self,
        volume_id: &str,
        want: &str,
        timeout: Duration,
    ) -> Result<CloudVolume, DcError> {
        let deadline = Instant::now() + timeout;
        loop {
            let vol = self.describe_volume(volume_id)?;
            if vol.state == want {
                return Ok(vol);
            }
            if Instant::now() >= deadline {
                return Err(DcError::Internal(format!(
                    "mock driver: volume {volume_id} never reached state '{want}'"
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn cloud_context(&self, volume_id: &str) -> Result<CloudContext, DcError> {
        let vol = self.describe_volume(volume_id)?;
        Ok(CloudContext {
            provider: "mock".to_string(),
            account_id: Some("111122223333".to_string()),
            project_id: None,
            volume_id: vol.volume_id.clone(),
            kms_key_arn: vol.kms_key_arn.clone(),
            region: "eu-central-1".to_string(),
            availability_zone: vol.availability_zone.clone(),
            performed_by_instance: Some("i-mock000000000000".to_string()),
            attachment_device: vol.attached_device.clone(),
        })
    }
}
