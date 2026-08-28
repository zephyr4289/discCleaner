use crate::identity::StableIdentity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardianRefusal {
    pub code: &'static str,
    pub detail: String,
    pub hint: String,
}

#[derive(Error, Debug)]
pub enum DcError {
    #[error("Guardian refusal [{code}]: {detail}", code = .0.code, detail = .0.detail)]
    Guardian(GuardianRefusal),

    #[error("Identity drift detected! Expected serial/wwn: {expected:?}, observed: {observed:?}")]
    IdentityDrift {
        expected: StableIdentity,
        observed: StableIdentity,
    },

    #[error("I/O error during '{op}' (errno {errno})")]
    Io {
        op: &'static str,
        errno: i32,
        at_lba: Option<u64>,
    },

    #[error("Journal corruption at record #{record_index}: {reason}")]
    JournalCorrupt { record_index: u64, reason: String },

    #[error("Verification failed with {mismatches} mismatching windows! First mismatches at LBAs: {sample:?}")]
    VerificationFailed {
        mismatches: u64,
        sample: Vec<u64>,
    },

    #[error("Operation interrupted by signal or operator request")]
    Interrupted {
        completed_through: Option<(u8, u64)>, // (pass_index, last_completed_window)
    },

    #[error("Operator aborted the operation")]
    OperatorAbort,

    #[error("Certificate signing error: {0}")]
    CertSigning(String),

    #[error("Usage error: {0}")]
    Usage(String),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O OS error: {0}")]
    StdIo(#[from] std::io::Error),

    #[error("RNG error: {0}")]
    Rng(#[from] getrandom::Error),
}

impl DcError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Guardian(_) => 2,
            Self::Interrupted { .. } => 3,
            Self::VerificationFailed { .. } => 4,
            Self::Io { .. } => 5,
            Self::JournalCorrupt { .. } => 6,
            Self::IdentityDrift { .. } => 7,
            Self::Usage(_) => 8,
            Self::OperatorAbort => 8,
            _ => 1,
        }
    }
}
