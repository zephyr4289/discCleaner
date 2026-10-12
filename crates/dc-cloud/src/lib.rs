//! `dc-cloud` — cloud block-storage lifecycle orchestration (v0.10.0,
//! Frontier 2).
//!
//! Cloud-native enterprises retiring AWS EBS volumes (with Azure Managed
//! Disks and GCP Persistent Disk drivers planned behind the same trait)
//! need a **verified, automated attach → sanitize → verify → detach
//! lifecycle** with signed audit receipts that cryptographically bind the
//! cloud context: Provider, Account/Project ID, Volume ID, KMS Key ARN,
//! Region/AZ — alongside the usual write-pass verification evidence.
//!
//! # Architecture
//!
//! * [`CloudDriver`] — the provider abstraction: describe / attach /
//!   detach / wait-state. `Ec2Driver` (AWS) is the first implementation;
//!   `MockDriver` powers tests and offline drills.
//! * [`lifecycle::WipeLifecycle`] — the state machine. Destructive phases
//!   only run with `execute` armed; every failure after a successful
//!   attach triggers a rollback detach so the volume is never left
//!   dangling on an instance that failed mid-run.
//! * [`receipt::CloudSanitizationReceipt`] — the signed audit artifact:
//!   binds the engine's `SanitizationCertificate` (by file hash) + the
//!   cloud context + the full phase timeline, and is **hybrid-signed**
//!   (Ed25519 + ML-DSA-44) by default when a PQ key is present.
//!
//! # Safety rails
//!
//! 1. Volumes are only ever attached to the *instance the tool runs on*
//!    (identity via IMDSv2) — never cross-instance.
//! 2. A volume currently attached to ANOTHER instance is refused before
//!    any API call with side effects (detach-it-first is an explicit,
//!    logged decision the operator must make in the console, not here).
//! 3. The final receipt embeds the certificate's file hash: the cloud
//!    evidence chain cannot be spliced onto a different wipe's
//!    certificate.

pub mod aws;
pub mod hmac;
pub mod imds;
pub mod lifecycle;
pub mod mock;
pub mod receipt;
pub mod sigv4;
pub mod transport;

use dc_core::DcError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Provider-neutral volume description (what DescribeVolumes returns for
/// the volume we are about to sanitize).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudVolume {
    pub volume_id: String,
    pub size_gib: u64,
    pub encrypted: bool,
    pub kms_key_arn: Option<String>,
    pub availability_zone: String,
    /// "available" | "in-use" | ...
    pub state: String,
    /// Device name the volume is currently attached as, if any.
    pub attached_device: Option<String>,
    pub iops: Option<u64>,
    pub volume_type: String,
}

/// The cloud context a sanitization receipt cryptographically binds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudContext {
    /// "aws" | "azure" | "gcp" | "mock"
    pub provider: String,
    /// AWS account id (from the instance-identity document).
    pub account_id: Option<String>,
    /// GCP project id (future driver).
    pub project_id: Option<String>,
    pub volume_id: String,
    pub kms_key_arn: Option<String>,
    pub region: String,
    pub availability_zone: String,
    /// The instance that performed the attach→sanitize→detach.
    pub performed_by_instance: Option<String>,
    /// The device node the volume was attached as during the wipe.
    pub attachment_device: Option<String>,
}

/// The provider abstraction. Azure (Managed Disks) and GCP (Persistent
/// Disk) plug in behind this same surface.
pub trait CloudDriver {
    fn provider(&self) -> &'static str;

    /// Fetch volume metadata (the pre-flight report).
    fn describe_volume(&self, volume_id: &str) -> Result<CloudVolume, DcError>;

    /// Attach the volume to THIS machine under the given device name.
    fn attach_volume(&self, volume_id: &str, device: &str) -> Result<(), DcError>;

    /// Detach the volume from THIS machine.
    fn detach_volume(&self, volume_id: &str, device: &str) -> Result<(), DcError>;

    /// Poll until the volume reports the given state ("attached" is
    /// expressed as in-use + attached to us; drivers translate).
    fn wait_state(
        &self,
        volume_id: &str,
        want: &str,
        timeout: Duration,
    ) -> Result<CloudVolume, DcError>;

    /// The audit context for the receipt.
    fn cloud_context(&self, volume_id: &str) -> Result<CloudContext, DcError>;
}
