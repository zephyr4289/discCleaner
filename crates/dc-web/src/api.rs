//! REST control plane: the trait the CLI implements against the real
//! engine, plus the wire DTOs. `dc-web` deliberately owns none of the
//! engine types — the dashboard is a *view*, and the adapter lives in
//! `dc-cli` where the engine is.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub version: String,
    /// "appliance" | "server" | "workstation"
    pub mode: String,
    pub uptime_secs: u64,
    pub engine: String,
    pub guardian_locks_active: u32,
    pub post_quantum_ready: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceSnapshot {
    /// Stable node identifier (kernel name, e.g. "sda").
    pub id: String,
    pub node: String,
    pub dev_path: String,
    /// "ata" | "nvme" | "scsi" | "usb" | "file" | ...
    pub transport: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub capacity_bytes: u64,
    pub status: DeviceStatus,
    /// Sanitization profile ids valid for this device
    /// (see `dc profiles`).
    pub supported_profiles: Vec<String>,
    /// True when the Guardian classified this device as unsafe to wipe
    /// (root disk, mounted, DM-backed, ...).
    pub protected: bool,
    pub protection_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceStatus {
    Idle,
    Sanitizing { job_id: String },
    Locked,
    Error { message: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct JobSnapshot {
    pub id: String,
    pub device: String,
    pub dev_path: String,
    pub profile: String,
    pub started_utc: String,
    pub state: JobState,
    /// 0-100 or null while queued.
    pub progress_pct: Option<u8>,
    pub current_pass: Option<u32>,
    pub total_passes: Option<u32>,
    pub throughput_mib_s: Option<f64>,
    pub certificate: Option<String>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub log_lines: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateSummary {
    pub id: String,
    pub created_utc: String,
    pub device_serial: Option<String>,
    pub dev_path: String,
    pub profile: String,
    pub verified: Option<bool>,
    pub signature_algs: Vec<String>,
    /// "aws" | "azure" | "gcp" | "mock" for cloud-run certificates.
    pub cloud_provider: Option<String>,
    pub cloud_volume_id: Option<String>,
    pub file_blake3: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateDetail {
    pub id: String,
    pub json: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StartJobRequest {
    /// Device node to sanitize (kernel name, e.g. "sda").
    pub device: String,
    /// Sanitization profile id (validated against `dc profiles`).
    pub profile: String,
    /// Operator label recorded in the audit stream.
    #[serde(default)]
    pub label: Option<String>,
    /// Optional serial confirmation (same discipline as `--serial-confirm`).
    #[serde(default)]
    pub serial_confirm: Option<String>,
    /// The dashboard's typed confirmation phrase — the UI enforces it and
    /// the server re-checks it: no job starts without "ERASE".
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        ApiError {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn not_found(what: &str) -> Self {
        ApiError::new("NOT_FOUND", format!("{what} not found"))
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError::new("BAD_REQUEST", message)
    }

    pub fn unauthorized() -> Self {
        ApiError::new("UNAUTHORIZED", "missing or invalid bearer token")
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        ApiError::new("CONFLICT", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        ApiError::new("INTERNAL", message)
    }

    pub fn status(&self) -> u16 {
        match self.code.as_str() {
            "NOT_FOUND" => 404,
            "BAD_REQUEST" => 400,
            "UNAUTHORIZED" => 401,
            "CONFLICT" => 409,
            _ => 500,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "error": { "code": self.code, "message": self.message } })
    }
}

/// The dashboard's control plane — implemented by `dc-cli::serve` against
/// the real engine (inventory scanner, child-process job runner,
/// certificate registry).
pub trait ControlPlane: Send + Sync {
    fn system(&self) -> SystemInfo;
    fn devices(&self) -> Vec<DeviceSnapshot>;
    fn jobs(&self) -> Vec<JobSnapshot>;
    fn start_job(&self, req: StartJobRequest) -> Result<String, ApiError>;
    fn cancel_job(&self, job_id: &str) -> Result<(), ApiError>;
    fn certificates(&self) -> Vec<CertificateSummary>;
    /// Full certificate JSON by id.
    fn certificate(&self, cert_id: &str) -> Option<serde_json::Value>;
}
