//! Shared standards-profile and verification-level plumbing for the CLI.
//!
//! Single source of truth for: the CLI profile option ↔ `SanitizationProfile`
//! mapping, `--verify full|none|sample:N` parsing, and the `dc profiles`
//! catalog renderer used by procurement documentation.

use clap::ValueEnum;
use dc_core::{SanitizationProfile, VerifyLevel};

/// CLI profile option. The three historical names (`clear-zero`,
/// `clear-random`, `legacy-dod3`) are kept as aliases so existing scripts and
/// journals keep working; they map onto the same catalog entries.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileOption {
    /// NIST SP 800-88 Clear: single zero pass (alias: clear-zero)
    #[value(alias = "clear-zero")]
    NistClear,
    /// NIST SP 800-88 Clear: single CSPRNG pass (alias: clear-random)
    #[value(alias = "clear-random")]
    NistClearRandom,
    /// CERT-In / GoI 3-pass: 0x00, 0xFF, CSPRNG
    CertinGoi,
    /// DoD 5220.22-M 3-pass (alias: legacy-dod3)
    #[value(alias = "legacy-dod3")]
    Dod5220_22M,
    /// DoD 5220.22-M ECE 7-pass
    Dod5220_22MEce,
    /// CSE ITSG-06 3-pass
    CsecItsg06,
    /// BSI VSITR 7-pass
    BsiVsitr,
    /// Schneier 7-pass
    Schneier,
    /// Gutmann 35-pass (legacy, MFM/RLL era)
    Gutmann,
}

impl ProfileOption {
    pub fn to_profile(self) -> SanitizationProfile {
        match self {
            Self::NistClear => SanitizationProfile::NistClear,
            Self::NistClearRandom => SanitizationProfile::NistClearRandom,
            Self::CertinGoi => SanitizationProfile::CertinGoi,
            Self::Dod5220_22M => SanitizationProfile::Dod5220_22M,
            Self::Dod5220_22MEce => SanitizationProfile::Dod5220_22MEce,
            Self::CsecItsg06 => SanitizationProfile::CsecItsg06,
            Self::BsiVsitr => SanitizationProfile::BsiVsitr,
            Self::Schneier => SanitizationProfile::Schneier,
            Self::Gutmann => SanitizationProfile::Gutmann,
        }
    }

    /// Whether the profile contains at least one deterministic-random pass
    /// (i.e. accepts `--seed`).
    pub fn accepts_seed(self) -> bool {
        !matches!(self, Self::NistClear)
    }
}

/// Parse the `--verify` flag: `full` | `none` | `sample:N` (N = 2..=65536).
pub fn parse_verify_flag(spec: &str) -> Result<VerifyLevel, String> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("full") {
        return Ok(VerifyLevel::Full);
    }
    if spec.eq_ignore_ascii_case("none") {
        return Ok(VerifyLevel::None);
    }
    let (kind, value) = spec.split_once(':').ok_or_else(|| {
        format!(
            "invalid --verify '{}': expected full | none | sample:N",
            spec
        )
    })?;
    if !kind.eq_ignore_ascii_case("sample") {
        return Err(format!(
            "invalid --verify '{}': expected full | none | sample:N",
            spec
        ));
    }
    let stride: u32 = value
        .parse()
        .map_err(|_| format!("invalid sample stride '{}': expected integer", value))?;
    if !(2..=65536).contains(&stride) {
        return Err(format!(
            "sample stride {} out of range: must be 2..=65536",
            stride
        ));
    }
    Ok(VerifyLevel::Sampled { stride })
}

/// Render the `dc profiles` catalog table (machine-stable column layout).
pub fn render_catalog() -> String {
    let mut out = String::new();
    out.push_str(
        "================================================================================\n",
    );
    out.push_str("                 SANITIZATION STANDARDS PROFILE CATALOG\n");
    out.push_str(
        "================================================================================\n",
    );
    out.push_str(&format!(
        "{:<18} {:>5}  {:<28} {:<24} {}\n",
        "PROFILE", "PASS", "VERIFY", "STANDARD", "NOTES"
    ));
    out.push_str(&format!(
        "{:<18} {:>5}  {:<28} {:<24} {}\n",
        "-------", "----", "------", "--------", "-----"
    ));
    for p in SanitizationProfile::CATALOG {
        let name = profile_slug(p);
        let notes = if !p.flash_suitable() {
            "legacy: HDD-era; avoid on SSD"
        } else if p.legacy_note().is_some() {
            "legacy: contractual use only"
        } else {
            ""
        };
        out.push_str(&format!(
            "{:<18} {:>5}  {:<28} {:<24} {}\n",
            name,
            p.total_passes(),
            format!("{}", p.default_verification()),
            short_ref(p),
            notes
        ));
    }
    out.push_str(
        "================================================================================\n",
    );
    out.push_str(
        "Verification levels: full = 100% LBA read-back | sample:N = deterministic 1-in-N\n\
         window sampling (NIST SP 800-88 Rev.1 permits sampled verification of the final\n\
         pass) | none = no read-back. Hardware purges (dc purge) are controller-attested.\n",
    );
    out
}

fn short_ref(p: &SanitizationProfile) -> &'static str {
    match p {
        SanitizationProfile::NistClear | SanitizationProfile::NistClearRandom => {
            "NIST SP 800-88r1 Clear"
        }
        SanitizationProfile::Dod5220_22M => "DoD 5220.22-M",
        SanitizationProfile::Dod5220_22MEce => "DoD 5220.22-M ECE",
        SanitizationProfile::CsecItsg06 => "CSE ITSG-06",
        SanitizationProfile::BsiVsitr => "BSI VSITR",
        SanitizationProfile::Schneier => "Schneier 1996",
        SanitizationProfile::CertinGoi => "CERT-In / GoI practice",
        SanitizationProfile::Gutmann => "Gutmann 1996",
    }
}

fn profile_slug(p: &SanitizationProfile) -> &'static str {
    match p {
        SanitizationProfile::NistClear => "nist-clear",
        SanitizationProfile::NistClearRandom => "nist-clear-random",
        SanitizationProfile::Dod5220_22M => "dod-5220.22m",
        SanitizationProfile::Dod5220_22MEce => "dod-5220.22m-ece",
        SanitizationProfile::CsecItsg06 => "csec-itsg-06",
        SanitizationProfile::BsiVsitr => "bsi-vsitr",
        SanitizationProfile::Schneier => "schneier",
        SanitizationProfile::CertinGoi => "certin-goi",
        SanitizationProfile::Gutmann => "gutmann",
    }
}

/// Validate `--seed` against the chosen profile (fail-fast, before probing).
pub fn parse_seed_hex(seed: &str, profile: ProfileOption) -> Result<Option<[u8; 32]>, String> {
    if !profile.accepts_seed() {
        return Err(format!(
            "cannot specify --seed for profile '{}' (no deterministic random pass)",
            profile_slug(&profile.to_profile())
        ));
    }
    if seed.len() != 64 {
        return Err(format!(
            "seed must be exactly 64 hex characters (32 bytes), got length {}",
            seed.len()
        ));
    }
    let bytes = hex::decode(seed).map_err(|e| format!("invalid hex string in --seed: {}", e))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Some(arr))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_flag_parsing_matrix() {
        assert!(matches!(
            parse_verify_flag("full").unwrap(),
            VerifyLevel::Full
        ));
        assert!(matches!(
            parse_verify_flag("FULL").unwrap(),
            VerifyLevel::Full
        ));
        assert!(matches!(
            parse_verify_flag("none").unwrap(),
            VerifyLevel::None
        ));
        match parse_verify_flag("sample:64").unwrap() {
            VerifyLevel::Sampled { stride } => assert_eq!(stride, 64),
            other => panic!("expected Sampled, got {:?}", other),
        }
        assert!(parse_verify_flag("sample:1").is_err());
        assert!(parse_verify_flag("sample:70000").is_err());
        assert!(parse_verify_flag("sample:x").is_err());
        assert!(parse_verify_flag("quarter").is_err());
        assert!(parse_verify_flag("sample").is_err());
    }

    #[test]
    fn catalog_renders_all_profiles() {
        let table = render_catalog();
        for slug in [
            "nist-clear",
            "nist-clear-random",
            "certin-goi",
            "dod-5220.22m",
            "dod-5220.22m-ece",
            "csec-itsg-06",
            "bsi-vsitr",
            "schneier",
            "gutmann",
        ] {
            assert!(table.contains(slug), "catalog missing {}", slug);
        }
        assert!(table.contains("35"));
        assert!(table.contains("NIST SP 800-88"));
    }

    #[test]
    fn legacy_aliases_map_to_catalog() {
        // The historical CLI names must keep resolving (script compatibility).
        assert_eq!(
            ProfileOption::NistClear.to_profile(),
            SanitizationProfile::NistClear
        );
        assert_eq!(
            ProfileOption::Dod5220_22M.to_profile(),
            SanitizationProfile::Dod5220_22M
        );
    }

    #[test]
    fn seed_validation_rejects_zero_pass_profiles() {
        assert!(parse_seed_hex(&"42".repeat(32), ProfileOption::NistClear).is_err());
        assert!(parse_seed_hex("abcd", ProfileOption::CertinGoi).is_err());
        let ok = parse_seed_hex(&"42".repeat(32), ProfileOption::CertinGoi).unwrap();
        assert_eq!(ok, Some([0x42u8; 32]));
    }
}
