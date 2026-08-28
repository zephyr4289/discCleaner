use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetArch {
    X86_64Musl,
    Aarch64Musl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchAgreementResult {
    pub corpus_name: String,
    pub x86_digest: String,
    pub arm_digest: String,
    pub matched: bool,
}

pub struct ArchAgreementDriver;

impl ArchAgreementDriver {
    /// Verify cross-architecture byte-level agreement across x86 and ARM (Δ484).
    pub fn verify_corpus_agreement(
        corpus_name: &str,
        x86_digest: &str,
        arm_digest: &str,
    ) -> ArchAgreementResult {
        ArchAgreementResult {
            corpus_name: corpus_name.to_string(),
            x86_digest: x86_digest.to_string(),
            arm_digest: arm_digest.to_string(),
            matched: x86_digest == arm_digest,
        }
    }

    /// Resolve architecture-aware serial console device (Δ486).
    pub fn resolve_console_device(arch: TargetArch) -> &'static str {
        match arch {
            TargetArch::X86_64Musl => "ttyS0",
            TargetArch::Aarch64Musl => "ttyAMA0",
        }
    }

    /// Return valid per-architecture boot matrix cells (Δ485).
    pub fn get_boot_matrix_cells(arch: TargetArch) -> Vec<&'static str> {
        match arch {
            TargetArch::X86_64Musl => vec![
                "SeaBIOS-dd",
                "SeaBIOS-installed",
                "OVMF-dd",
                "OVMF-installed",
            ],
            TargetArch::Aarch64Musl => vec![
                "edk2-AA64-dd",
                "edk2-AA64-installed",
            ],
        }
    }
}
