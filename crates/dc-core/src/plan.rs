use crate::identity::StableIdentity;
use crate::pattern::{ChaCha20Pattern, Pattern, PrngScheme};
use crate::strategy::StrategyLadder;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerifyLevel {
    /// 100% of user-addressable LBAs are read back and compared.
    Full,
    /// Deterministic 1-in-N window sampling (NIST SP 800-88 Rev.1 permits
    /// sampling-based verification of the final pass). `stride` = N: window
    /// indices divisible by `stride` are verified; every stride, coverage
    /// bounds and the sampling parameter are recorded in the certificate.
    Sampled {
        stride: u32,
    },
    None,
}

impl std::fmt::Display for VerifyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "Full (100% LBA verification)"),
            Self::Sampled { stride } => {
                write!(
                    f,
                    "Sampled (deterministic 1-in-{stride} window verification)"
                )
            }
            Self::None => write!(f, "None (No post-pass read verification)"),
        }
    }
}

impl VerifyLevel {
    /// Sampling stride actually applied (1 == every window == Full).
    pub fn effective_stride(&self) -> u64 {
        match self {
            Self::Full | Self::None => 1,
            Self::Sampled { stride } => (*stride).max(1) as u64,
        }
    }

    /// Machine-stable journal/record tag: "full" | "none" | "sample:N".
    /// Round-trips through `VerifyLevel::from_short_tag`.
    pub fn short_tag(&self) -> String {
        match self {
            Self::Full => "full".to_string(),
            Self::None => "none".to_string(),
            Self::Sampled { stride } => format!("sample:{}", stride),
        }
    }

    /// Parse a `short_tag` back; unknown strings return None (fail-closed).
    pub fn from_short_tag(tag: &str) -> Option<Self> {
        match tag {
            "full" => Some(Self::Full),
            "none" => Some(Self::None),
            _ => {
                let (kind, value) = tag.split_once(':')?;
                if kind != "sample" {
                    return None;
                }
                let stride: u32 = value.parse().ok()?;
                (2..=65536)
                    .contains(&stride)
                    .then_some(Self::Sampled { stride })
            }
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
    LogicalOverwrite {
        passes: Vec<Pass>,
    },
    /// Controller-attested hardware purge (NVMe Sanitize / Format NVM
    /// cryptographic erase). The ladder records the attested mechanism and
    /// its documented fallback; read-back expectations are
    /// controller-supplied (VendorRandom) unless the ladder states Zeros.
    HardwarePurge {
        ladder: StrategyLadder,
        selected_mechanism: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizationPlan {
    pub plan_schema: String, // "dc-plan/1"
    pub target: StableIdentity,
    pub mechanism: Mechanism,
    pub verification: VerifyLevel,
    pub window_bytes: u64, // default 2 MiB (2097152)
    pub fast_path: FastPathPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_ladder: Option<StrategyLadder>,
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
            strategy_ladder: None,
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
            strategy_ladder: None,
            legacy_note: None,
        })
    }

    /// Create a "legacy-dod3" plan (3-pass: 0xFF -> 0x00 -> CSPRNG).
    pub fn legacy_dod3(
        target: StableIdentity,
        seed: Option<[u8; 32]>,
        fast_path: FastPathPolicy,
    ) -> Result<Self, getrandom::Error> {
        Self::from_profile(
            SanitizationProfile::Dod5220_22M,
            target,
            seed,
            fast_path,
            VerifyLevel::Full,
        )
    }

    /// Compile a plan from any catalogued standards profile. This is the
    /// single source of truth for profile-to-passes translation; the CLI
    /// profile option and `dc profiles` both render from the same catalog.
    pub fn from_profile(
        profile: SanitizationProfile,
        target: StableIdentity,
        seed: Option<[u8; 32]>,
        fast_path: FastPathPolicy,
        verification: VerifyLevel,
    ) -> Result<Self, getrandom::Error> {
        let plan = Self::build_logical(
            SanitizationProfile::pass_matrix(&profile),
            target,
            seed,
            fast_path,
            verification,
        )?;
        Ok(Self {
            legacy_note: SanitizationProfile::legacy_note(&profile).map(str::to_string),
            ..plan
        })
    }

    /// Build a logical-overwrite plan from a raw pass matrix.
    fn build_logical(
        matrix: PassMatrix,
        target: StableIdentity,
        seed: Option<[u8; 32]>,
        fast_path: FastPathPolicy,
        verification: VerifyLevel,
    ) -> Result<Self, getrandom::Error> {
        let total_random = matrix.passes.iter().filter(|p| p.is_random).count();
        // One CSPRNG seed covers every random pass of the profile; either the
        // operator pinned it (deterministic replay) or it is drawn fresh.
        let default_seed = match seed {
            Some(s) => Some(s),
            None if total_random > 0 => Some(ChaCha20Pattern::generate_random_seed()?),
            None => None,
        };

        let passes = matrix
            .passes
            .into_iter()
            .enumerate()
            .map(|(i, spec)| Pass {
                pattern: match spec.pattern {
                    PatternSpec::Zero => Pattern::Zero,
                    PatternSpec::Fixed { byte } => Pattern::Fixed { byte },
                    PatternSpec::FixedWord { bytes } => Pattern::FixedWord { bytes },
                    PatternSpec::Random => Pattern::DeterministicRandom {
                        scheme: PrngScheme::ChaCha20WindowV1,
                        seed: default_seed.expect("seed allocated for random pass"),
                    },
                },
                label: format!("Pass {}/{}: {}", i + 1, matrix.total_passes, spec.label),
            })
            .collect();

        Ok(Self {
            plan_schema: "dc-plan/1".to_string(),
            target,
            mechanism: Mechanism::LogicalOverwrite { passes },
            verification,
            window_bytes: Self::DEFAULT_WINDOW_BYTES,
            fast_path,
            strategy_ladder: None,
            legacy_note: None,
        })
    }

    /// Compute the BLAKE3 hash of the canonical JCS (RFC 8785) representation of the plan.
    pub fn compute_plan_hash(&self) -> Result<String, serde_json::Error> {
        let canonical_bytes = serde_jcs::to_vec(self)?;
        let hash = blake3::hash(&canonical_bytes);
        Ok(hash.to_hex().to_string())
    }
}

// ---------------------------------------------------------------------------
// Standards compliance profile catalog
// ---------------------------------------------------------------------------

/// Catalogued sanitization profiles with the exact pass matrices procurement
/// documents reference. Each profile is pure data; `SanitizationPlan::
/// from_profile` is the only constructor path, so the catalog can never drift
/// from what actually executes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum SanitizationProfile {
    /// NIST SP 800-88 Rev.1 Clear: single zero overwrite + full verification.
    NistClear,
    /// NIST SP 800-88 Rev.1 Clear: single CSPRNG overwrite + full verification.
    NistClearRandom,
    /// DoD 5220.22-M: 0xFF -> 0x00 -> CSPRNG (3 passes).
    Dod5220_22M,
    /// DoD 5220.22-M ECE: 7-pass extended celebrity erase variant
    /// (0xFF, 0x00, CSPRNG, 0xFF, 0x00, CSPRNG, CSPRNG).
    Dod5220_22MEce,
    /// CSE ITSG-06 (Canada): 3-pass 0x00 -> CSPRNG -> CSPRNG w/ verification.
    CsecItsg06,
    /// BSI VSITR (Germany): 7-pass alternating 0x00/0xFF.
    BsiVsitr,
    /// Schneier (1996): 7-pass 0xFF, 0x00 + 5x CSPRNG.
    Schneier,
    /// CERT-In / GoI directions-aligned 3-pass overwrite (0x00, 0xFF, CSPRNG)
    /// for Indian government media sanitisation practice.
    CertinGoi,
    /// Gutmann (1996): 35-pass MFM/RLL sequence. LEGACY: 35 passes provide no
    /// benefit on modern PRML/EPRML and flash media; kept for contractual
    /// compliance with older Indian/UK tenders only.
    Gutmann,
}

impl SanitizationProfile {
    /// Total passes the profile writes (excluding verification reads).
    pub fn total_passes(&self) -> usize {
        self.pass_matrix().total_passes
    }

    /// Human-readable name used in `dc profiles` and certificates.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::NistClear => "NIST SP 800-88 Clear (zero)",
            Self::NistClearRandom => "NIST SP 800-88 Clear (CSPRNG)",
            Self::Dod5220_22M => "DoD 5220.22-M (3-pass)",
            Self::Dod5220_22MEce => "DoD 5220.22-M ECE (7-pass)",
            Self::CsecItsg06 => "CSE ITSG-06 (3-pass)",
            Self::BsiVsitr => "BSI VSITR (7-pass)",
            Self::Schneier => "Schneier (7-pass)",
            Self::CertinGoi => "CERT-In / GoI (3-pass)",
            Self::Gutmann => "Gutmann (35-pass, legacy)",
        }
    }

    /// Standards reference embedded into the plan label and `dc profiles`.
    pub fn standards_ref(&self) -> &'static str {
        match self {
            Self::NistClear | Self::NistClearRandom => "NIST SP 800-88 Rev.1 s4.3 (Clear)",
            Self::Dod5220_22M => "US DoD 5220.22-M (superseded; contractual use)",
            Self::Dod5220_22MEce => "US DoD 5220.22-M ECE (superseded; contractual use)",
            Self::CsecItsg06 => "CSE ITSG-06 (Canada)",
            Self::BsiVsitr => "BSI VSITR (Germany)",
            Self::Schneier => "B. Schneier, Applied Cryptography 2nd ed. (1996)",
            Self::CertinGoi => "CERT-In sanitisation directions / GoI media disposal practice",
            Self::Gutmann => "P. Gutmann, Secure Deletion of Data (1996)",
        }
    }

    /// Default verification level for the profile when the operator does not
    /// override it on the command line.
    pub fn default_verification(&self) -> VerifyLevel {
        VerifyLevel::Full
    }

    /// DEFENSE PROFILE ENFORCEMENT GATE (v0.6.0).
    ///
    /// Profiles mandated by defense/government authorities require 100%
    /// post-wipe read-back verification:
    /// - US DoD 5220.22-M / ECE (superseded pass matrices, but the 100%
    ///   verification mandate lives on in NSA/CSS Policy 9-12 practice),
    /// - CERT-In / GoI media disposal directions,
    /// - CSE ITSG-06 (Canada),
    /// - BSI VSITR (Germany).
    ///
    /// When this returns `true`, the CLI MUST refuse `--verify sample:N` and
    /// `--verify none` with a usage error (exit code 8) BEFORE any device is
    /// armed. Only commercial NIST SP 800-88 Clear profiles may lower the
    /// verification level. Sampling the final pass remains permissible for
    /// non-classified, commercial media under NIST SP 800-88 Rev.1 App. D.
    pub fn requires_full_verification(&self) -> bool {
        matches!(
            self,
            Self::Dod5220_22M
                | Self::Dod5220_22MEce
                | Self::CertinGoi
                | Self::CsecItsg06
                | Self::BsiVsitr
        )
    }

    /// Whether the profile is suitable for flash/SSD/NVMe media without the
    /// flash-aware caveats (wear, write amplification, FTL remapping).
    pub fn flash_suitable(&self) -> bool {
        !matches!(self, Self::Gutmann | Self::Dod5220_22MEce)
    }

    /// Non-None for profiles kept only for contractual/legacy compliance.
    pub fn legacy_note(&self) -> Option<&'static str> {
        match self {
            Self::Dod5220_22M | Self::Dod5220_22MEce => Some(
                "Legacy contractual pattern. NIST SP 800-88 s2.4 supersedes DoD 5220.22-M pass \
                 matrices; provided for contractual compliance only.",
            ),
            Self::Gutmann => Some(
                "MFM/RLL-era 35-pass sequence. No measurable benefit on PRML/EPRML or flash \
                 media; 35 passes consume drive endurance and wall-clock. Provided for \
                 contractual compliance with legacy tenders only.",
            ),
            _ => None,
        }
    }

    /// The full catalog, in stable display order for `dc profiles`.
    pub const CATALOG: &'static [SanitizationProfile] = &[
        SanitizationProfile::NistClear,
        SanitizationProfile::NistClearRandom,
        SanitizationProfile::CertinGoi,
        SanitizationProfile::Dod5220_22M,
        SanitizationProfile::Dod5220_22MEce,
        SanitizationProfile::CsecItsg06,
        SanitizationProfile::BsiVsitr,
        SanitizationProfile::Schneier,
        SanitizationProfile::Gutmann,
    ];

    /// Pass matrix for the profile (pure, deterministic given the catalog).
    pub fn pass_matrix(&self) -> PassMatrix {
        use PatternSpec::{Fixed, FixedWord, Random, Zero};
        let specs = match self {
            Self::NistClear => vec![Spec {
                pattern: Zero,
                label: "Zero overwrite".into(),
                is_random: false,
            }],
            Self::NistClearRandom => vec![Spec {
                pattern: Random,
                label: "CSPRNG overwrite".into(),
                is_random: true,
            }],
            Self::Dod5220_22M => vec![
                Spec {
                    pattern: Fixed { byte: 0xFF },
                    label: "Fixed 0xFF".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG".into(),
                    is_random: true,
                },
            ],
            Self::Dod5220_22MEce => vec![
                Spec {
                    pattern: Fixed { byte: 0xFF },
                    label: "Fixed 0xFF".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG".into(),
                    is_random: true,
                },
                Spec {
                    pattern: Fixed { byte: 0xFF },
                    label: "Fixed 0xFF (verify cycle)".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00 (verify cycle)".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG".into(),
                    is_random: true,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG (final)".into(),
                    is_random: true,
                },
            ],
            Self::CsecItsg06 => vec![
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG".into(),
                    is_random: true,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG (final)".into(),
                    is_random: true,
                },
            ],
            Self::BsiVsitr => vec![
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Fixed { byte: 0xFF },
                    label: "Fixed 0xFF".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Fixed { byte: 0xFF },
                    label: "Fixed 0xFF".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Fixed { byte: 0xFF },
                    label: "Fixed 0xFF".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00 (final)".into(),
                    is_random: false,
                },
            ],
            Self::Schneier => vec![
                Spec {
                    pattern: Fixed { byte: 0xFF },
                    label: "Fixed 0xFF".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG".into(),
                    is_random: true,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG".into(),
                    is_random: true,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG".into(),
                    is_random: true,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG".into(),
                    is_random: true,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG (final)".into(),
                    is_random: true,
                },
            ],
            Self::CertinGoi => vec![
                Spec {
                    pattern: Zero,
                    label: "Fixed 0x00".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Fixed { byte: 0xFF },
                    label: "Fixed 0xFF".into(),
                    is_random: false,
                },
                Spec {
                    pattern: Random,
                    label: "Deterministic CSPRNG".into(),
                    is_random: true,
                },
            ],
            Self::Gutmann => {
                // Gutmann 1996 Table 1 (35 passes). Passes 1-4 random, 5-31
                // MFM/RLL words, 32-35 random. Words encoded little-endian.
                const GUTMANN_WORDS: [[u8; 4]; 27] = [
                    [0x55, 0x55, 0x55, 0x55],
                    [0xAA, 0xAA, 0xAA, 0xAA],
                    [0x92, 0x49, 0x24, 0x92],
                    [0x49, 0x24, 0x92, 0x49],
                    [0x24, 0x92, 0x49, 0x24],
                    [0x00, 0x00, 0x00, 0x00],
                    [0x11, 0x11, 0x11, 0x11],
                    [0x22, 0x22, 0x22, 0x22],
                    [0x33, 0x33, 0x33, 0x33],
                    [0x44, 0x44, 0x44, 0x44],
                    [0x55, 0x55, 0x55, 0x55],
                    [0x66, 0x66, 0x66, 0x66],
                    [0x77, 0x77, 0x77, 0x77],
                    [0x88, 0x88, 0x88, 0x88],
                    [0x99, 0x99, 0x99, 0x99],
                    [0xAA, 0xAA, 0xAA, 0xAA],
                    [0xBB, 0xBB, 0xBB, 0xBB],
                    [0xCC, 0xCC, 0xCC, 0xCC],
                    [0xDD, 0xDD, 0xDD, 0xDD],
                    [0xEE, 0xEE, 0xEE, 0xEE],
                    [0xFF, 0xFF, 0xFF, 0xFF],
                    [0x92, 0x49, 0x24, 0x92],
                    [0x49, 0x24, 0x92, 0x49],
                    [0x24, 0x92, 0x49, 0x24],
                    [0x6D, 0xB6, 0xDB, 0x6D],
                    [0xB6, 0xDB, 0x6D, 0xB6],
                    [0xDB, 0x6D, 0xB6, 0xDB],
                ];
                let mut specs: Vec<Spec> = (0..4)
                    .map(|_| Spec {
                        pattern: Random,
                        label: "Random".into(),
                        is_random: true,
                    })
                    .collect();
                for w in GUTMANN_WORDS {
                    specs.push(Spec {
                        pattern: FixedWord { bytes: w },
                        label: format!("MFM word 0x{}", hex::encode(w)),
                        is_random: false,
                    });
                }
                specs.extend((0..4).map(|_| Spec {
                    pattern: Random,
                    label: "Random".into(),
                    is_random: true,
                }));
                specs
            }
        };
        let total = specs.len();
        PassMatrix {
            passes: specs,
            total_passes: total,
        }
    }
}

/// Construction spec for one pass of a profile.
pub struct Spec {
    /// Pass pattern specification.
    pub pattern: PatternSpec,
    /// Human label fragment used to build the pass label.
    pub label: String,
    /// Whether the pass is CSPRNG-driven (seed allocation relevant).
    pub is_random: bool,
}

/// Pass matrix for a catalogued profile (spec list + total count).
pub struct PassMatrix {
    passes: Vec<Spec>,
    total_passes: usize,
}

/// Pass pattern specification consumed by `SanitizationPlan::build_logical`.
pub enum PatternSpec {
    /// All zero bytes.
    Zero,
    /// Repeating single byte.
    Fixed { byte: u8 },
    /// Repeating 4-byte word.
    FixedWord { bytes: [u8; 4] },
    /// Deterministic CSPRNG (ChaCha20WindowV1).
    Random,
}

// ---------------------------------------------------------------------------
// Unit tests: standards profile catalog (PR2)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod profile_tests {
    use super::*;
    use crate::pattern::PatternSource;

    fn tid() -> StableIdentity {
        StableIdentity {
            model: Some("UnitSSD".to_string()),
            serial: Some("SN-P2".to_string()),
            wwn: None,
            size_bytes: 1024 * 1024 * 1024,
            bus: crate::identity::BusType::Nvme,
            dm_name: None,
            dm_uuid: None,
        }
    }

    #[test]
    fn catalog_pass_counts_match_matrix() {
        for p in SanitizationProfile::CATALOG {
            assert_eq!(
                p.total_passes(),
                p.pass_matrix().total_passes,
                "catalog pass count drifted for {}",
                p.display_name()
            );
        }
    }

    #[test]
    fn catalog_expected_totals() {
        let expect = [
            (SanitizationProfile::NistClear, 1),
            (SanitizationProfile::NistClearRandom, 1),
            (SanitizationProfile::CertinGoi, 3),
            (SanitizationProfile::Dod5220_22M, 3),
            (SanitizationProfile::Dod5220_22MEce, 7),
            (SanitizationProfile::CsecItsg06, 3),
            (SanitizationProfile::BsiVsitr, 7),
            (SanitizationProfile::Schneier, 7),
            (SanitizationProfile::Gutmann, 35),
        ];
        for (p, n) in expect {
            assert_eq!(p.total_passes(), n, "{}", p.display_name());
        }
    }

    #[test]
    fn profile_from_catalog_constructs_deterministically_with_seed() {
        let seed = [0xA7u8; 32];
        for p in SanitizationProfile::CATALOG {
            let a = SanitizationPlan::from_profile(
                *p,
                tid(),
                Some(seed),
                FastPathPolicy::ForbidWriteZeroes,
                VerifyLevel::Full,
            )
            .unwrap();
            let b = SanitizationPlan::from_profile(
                *p,
                tid(),
                Some(seed),
                FastPathPolicy::ForbidWriteZeroes,
                VerifyLevel::Full,
            )
            .unwrap();
            assert_eq!(
                a,
                b,
                "{}: pinned seed must reproduce identical plan",
                p.display_name()
            );
            let Mechanism::LogicalOverwrite { passes } = &a.mechanism else {
                panic!("logical profile must compile to LogicalOverwrite");
            };
            assert_eq!(passes.len(), p.total_passes());
            // Labels carry the pass counter.
            assert!(passes[0].label.starts_with("Pass 1/"));
        }
    }

    #[test]
    fn gutmann_word_sequence_is_representative() {
        let m = SanitizationProfile::Gutmann.pass_matrix();
        assert_eq!(m.passes.len(), 35);
        // 8 random passes (4 leading + 4 trailing), 27 word passes.
        assert_eq!(m.passes.iter().filter(|s| s.is_random).count(), 8);
        let Mechanism::LogicalOverwrite { passes } = SanitizationPlan::from_profile(
            SanitizationProfile::Gutmann,
            tid(),
            Some([1u8; 32]),
            FastPathPolicy::PreferWriteZeroes,
            VerifyLevel::Full,
        )
        .unwrap()
        .mechanism
        else {
            panic!("gutmann profile must compile to LogicalOverwrite");
        };
        // Pass 5 (index 4) is the first MFM word 0x55555555.
        assert!(matches!(passes[4].pattern, Pattern::FixedWord { .. }));
    }

    #[test]
    fn legacy_notes_only_on_superseded_profiles() {
        assert!(SanitizationProfile::Gutmann.legacy_note().is_some());
        assert!(SanitizationProfile::Dod5220_22M.legacy_note().is_some());
        assert!(SanitizationProfile::Dod5220_22MEce.legacy_note().is_some());
        assert!(SanitizationProfile::NistClear.legacy_note().is_none());
        assert!(SanitizationProfile::CertinGoi.legacy_note().is_none());
    }

    #[test]
    fn sampled_verify_level_display_and_stride() {
        let v = VerifyLevel::Sampled { stride: 64 };
        assert!(v.to_string().contains("1-in-64"));
        assert_eq!(v.effective_stride(), 64);
        assert_eq!(VerifyLevel::Full.effective_stride(), 1);
    }

    #[test]
    fn pre_v04_plan_json_deserializes_with_default_ladder() {
        // A v0.4 plan has no strategy_ladder field; it must deserialize
        // (serde default) and re-serialize losing nothing.
        let old = r#"{
            "plan_schema": "dc-plan/1",
            "target": {
                "model": "OldSSD", "serial": "SN-OLD", "wwn": null,
                "size_bytes": 1073741824, "bus": "nvme",
                "dm_name": null, "dm_uuid": null
            },
            "mechanism": { "type": "logical_overwrite", "passes": [
                { "pattern": { "type": "zero" }, "label": "NIST SP 800-88 Clear (logical zero overwrite)" }
            ]},
            "verification": "full",
            "window_bytes": 2097152,
            "fast_path": "prefer_write_zeroes",
            "legacy_note": null
        }"#;
        let plan: SanitizationPlan = serde_json::from_str(old)
            .expect("v0.4 plan JSON must remain loadable (backward compat)");
        assert!(plan.strategy_ladder.is_none());
        assert_eq!(plan.compute_plan_hash().unwrap().len(), 64);
    }

    #[test]
    fn fixed_word_pattern_fills_and_roundtrips() {
        let p = crate::pattern::FixedWordPattern {
            bytes: [0x92, 0x49, 0x24, 0x92],
        };
        let mut buf = [0u8; 10];
        p.fill(7, &mut buf);
        assert_eq!(&buf[..8], &[0x92, 0x49, 0x24, 0x92, 0x92, 0x49, 0x24, 0x92]);
        assert_eq!(&buf[8..], &[0x92, 0x49]);
        // Serde roundtrip through Pattern::FixedWord
        let pat = Pattern::FixedWord {
            bytes: [0x6D, 0xB6, 0xDB, 0x6D],
        };
        let j = serde_json::to_string(&pat).unwrap();
        let back: Pattern = serde_json::from_str(&j).unwrap();
        assert_eq!(pat, back);
    }

    #[test]
    fn defense_profiles_require_full_verification() {
        // REG-DEFENSE-SAMPLING-REFUSED (core invariant): every defense /
        // government-mandated profile mandates 100% verification.
        for defense in [
            SanitizationProfile::Dod5220_22M,
            SanitizationProfile::Dod5220_22MEce,
            SanitizationProfile::CertinGoi,
            SanitizationProfile::CsecItsg06,
            SanitizationProfile::BsiVsitr,
        ] {
            assert!(
                defense.requires_full_verification(),
                "{:?} must require full verification",
                defense
            );
        }
        // Commercial NIST SP 800-88 Clear profiles may sample.
        for commercial in [
            SanitizationProfile::NistClear,
            SanitizationProfile::NistClearRandom,
            SanitizationProfile::Schneier,
            SanitizationProfile::Gutmann,
        ] {
            assert!(
                !commercial.requires_full_verification(),
                "{:?} is not a defense profile and may lower verification",
                commercial
            );
        }
        // The gate is a superset check, not a total ordering: Schneier /
        // Gutmann are non-government practices and stay sampleable.
        assert!(
            !SanitizationProfile::CATALOG
                .iter()
                .all(|p| p.requires_full_verification())
        );
    }
}
