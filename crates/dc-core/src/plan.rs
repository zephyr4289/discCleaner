use crate::identity::StableIdentity;
use crate::pattern::{ChaCha20Pattern, Pattern, PrngScheme};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerifyLevel {
    Full,
    None,
}

impl std::fmt::Display for VerifyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "Full (100% LBA verification)"),
            Self::None => write!(f, "None (No post-pass read verification)"),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FastPathPolicy {
    PreferWriteZeroes,
    ForbidWriteZeroes,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pass {
    pub pattern: Pattern,
    pub label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Mechanism {
    LogicalOverwrite { passes: Vec<Pass> },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizationPlan {
    pub plan_schema: String, // "dc-plan/1"
    pub target: StableIdentity,
    pub mechanism: Mechanism,
    pub verification: VerifyLevel,
    pub window_bytes: u64, // default 2 MiB (2097152)
    pub fast_path: FastPathPolicy,
    pub legacy_note: Option<String>,
}

impl SanitizationPlan {
    pub const DEFAULT_WINDOW_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB

    /// Create a "clear-zero" plan (NIST SP 800-88 Clear via logical zero overwrite).
    pub fn clear_zero(target: StableIdentity, fast_path: FastPathPolicy) -> Self {
        Self {
            plan_schema: "dc-plan/1".to_string(),
            target,
            mechanism: Mechanism::LogicalOverwrite {
                passes: vec![Pass {
                    pattern: Pattern::Zero,
                    label: "NIST SP 800-88 Clear (logical zero overwrite)".to_string(),
                }],
            },
            verification: VerifyLevel::Full,
            window_bytes: Self::DEFAULT_WINDOW_BYTES,
            fast_path,
            legacy_note: None,
        }
    }

    /// Create a "clear-random" plan (NIST SP 800-88 Clear via CSPRNG ChaCha20 overwrite).
    pub fn clear_random(
        target: StableIdentity,
        seed: Option<[u8; 32]>,
        fast_path: FastPathPolicy,
    ) -> Result<Self, getrandom::Error> {
        let seed = match seed {
            Some(s) => s,
            None => ChaCha20Pattern::generate_random_seed()?,
        };

        Ok(Self {
            plan_schema: "dc-plan/1".to_string(),
            target,
            mechanism: Mechanism::LogicalOverwrite {
                passes: vec![Pass {
                    pattern: Pattern::DeterministicRandom {
                        scheme: PrngScheme::ChaCha20WindowV1,
                        seed,
                    },
                    label: "NIST SP 800-88 Clear (logical CSPRNG overwrite)".to_string(),
                }],
            },
            verification: VerifyLevel::Full,
            window_bytes: Self::DEFAULT_WINDOW_BYTES,
            fast_path,
            legacy_note: None,
        })
    }

    /// Create a "legacy-dod3" plan (3-pass: 0xFF -> 0x00 -> CSPRNG).
    pub fn legacy_dod3(
        target: StableIdentity,
        seed: Option<[u8; 32]>,
        fast_path: FastPathPolicy,
    ) -> Result<Self, getrandom::Error> {
        let seed = match seed {
            Some(s) => s,
            None => ChaCha20Pattern::generate_random_seed()?,
        };

        Ok(Self {
            plan_schema: "dc-plan/1".to_string(),
            target,
            mechanism: Mechanism::LogicalOverwrite {
                passes: vec![
                    Pass {
                        pattern: Pattern::Fixed { byte: 0xFF },
                        label: "Pass 1/3: Fixed 0xFF".to_string(),
                    },
                    Pass {
                        pattern: Pattern::Fixed { byte: 0x00 },
                        label: "Pass 2/3: Fixed 0x00".to_string(),
                    },
                    Pass {
                        pattern: Pattern::DeterministicRandom {
                            scheme: PrngScheme::ChaCha20WindowV1,
                            seed,
                        },
                        label: "Pass 3/3: Deterministic CSPRNG".to_string(),
                    },
                ],
            },
            verification: VerifyLevel::Full,
            window_bytes: Self::DEFAULT_WINDOW_BYTES,
            fast_path,
            legacy_note: Some(
                "Legacy contractual pattern. Not recommended for flash media; NIST SP 800-88 §2.4 / DoD 5220.22-M superseded. Provided for contractual compliance only."
                    .to_string(),
            ),
        })
    }

    /// Compute the BLAKE3 hash of the canonical JCS (RFC 8785) representation of the plan.
    pub fn compute_plan_hash(&self) -> Result<String, serde_json::Error> {
        let canonical_bytes = serde_jcs::to_vec(self)?;
        let hash = blake3::hash(&canonical_bytes);
        Ok(hash.to_hex().to_string())
    }
}
