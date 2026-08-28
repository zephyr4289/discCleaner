use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceTransportClass {
    Nvme,
    SataSsd,
    SataHdd,
    ScsiSas,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedCapabilities {
    pub supports_sanitize_crypto: bool,
    pub supports_sanitize_block: bool,
    pub supports_format_nvm: bool,
    pub supports_ata_security_enhanced: bool,
    pub supports_dco_hpa: bool,
    pub supports_scsi_sanitize: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MechanismStep {
    pub name: String,
    pub grade: String,
    pub nist_class: String, // "Clear" or "Purge"
    pub readback_expectation: String,
    pub fallback_target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyLadder {
    pub steps: Vec<MechanismStep>,
}

pub struct StrategyCompiler;

impl StrategyCompiler {
    /// Pure, deterministic compiler translating device capabilities into a strategy ladder (Δ317, PLAN-EQUIV-HW).
    pub fn compile_strategy(
        class: DeviceTransportClass,
        caps: &AttestedCapabilities,
        request_purge: bool,
    ) -> Result<StrategyLadder, String> {
        let mut steps = Vec::new();

        match class {
            DeviceTransportClass::Nvme => {
                if caps.supports_sanitize_crypto && request_purge {
                    steps.push(MechanismStep {
                        name: "NvmeSanitizeCryptoErase".to_string(),
                        grade: "ControllerAttested".to_string(),
                        nist_class: "Purge".to_string(),
                        readback_expectation: "VendorRandom".to_string(),
                        fallback_target: Some("NvmeSanitizeBlockErase".to_string()),
                    });
                }
                if caps.supports_sanitize_block {
                    steps.push(MechanismStep {
                        name: "NvmeSanitizeBlockErase".to_string(),
                        grade: "ControllerAttested".to_string(),
                        nist_class: "Purge".to_string(),
                        readback_expectation: "VendorRandom".to_string(),
                        fallback_target: Some("NvmeFormatNvmCrypto".to_string()),
                    });
                }
                if caps.supports_format_nvm {
                    steps.push(MechanismStep {
                        name: "NvmeFormatNvmCrypto".to_string(),
                        grade: "ControllerAttested".to_string(),
                        nist_class: "Purge".to_string(),
                        readback_expectation: "Zeros".to_string(),
                        fallback_target: Some("LogicalOverwriteZero".to_string()),
                    });
                }
                // Final safety fallback
                steps.push(MechanismStep {
                    name: "LogicalOverwriteZero".to_string(),
                    grade: "ToolVerified".to_string(),
                    nist_class: "Clear".to_string(),
                    readback_expectation: "Zeros".to_string(),
                    fallback_target: None,
                });
            }
            DeviceTransportClass::SataSsd => {
                if caps.supports_ata_security_enhanced {
                    steps.push(MechanismStep {
                        name: "AtaSecurityEraseEnhanced".to_string(),
                        grade: "ControllerAttested".to_string(),
                        nist_class: "Purge".to_string(),
                        readback_expectation: "VendorRandom".to_string(),
                        fallback_target: Some("LogicalOverwriteZero".to_string()),
                    });
                }
                steps.push(MechanismStep {
                    name: "LogicalOverwriteZero".to_string(),
                    grade: "ToolVerified".to_string(),
                    nist_class: "Clear".to_string(),
                    readback_expectation: "Zeros".to_string(),
                    fallback_target: None,
                });
            }
            DeviceTransportClass::SataHdd => {
                if caps.supports_dco_hpa {
                    steps.push(MechanismStep {
                        name: "AtaGeometryRestoreDcoHpa".to_string(),
                        grade: "EffectVerified".to_string(),
                        nist_class: "Purge".to_string(),
                        readback_expectation: "None".to_string(),
                        fallback_target: None,
                    });
                }
                steps.push(MechanismStep {
                    name: "LogicalOverwritePattern".to_string(),
                    grade: "ToolVerified".to_string(),
                    nist_class: "Clear".to_string(),
                    readback_expectation: "Pattern".to_string(),
                    fallback_target: None,
                });
            }
            DeviceTransportClass::ScsiSas => {
                if caps.supports_scsi_sanitize {
                    steps.push(MechanismStep {
                        name: "ScsiSanitizeBlockErase".to_string(),
                        grade: "ControllerAttested".to_string(),
                        nist_class: "Purge".to_string(),
                        readback_expectation: "VendorRandom".to_string(),
                        fallback_target: Some("ScsiFormatUnit".to_string()),
                    });
                }
                steps.push(MechanismStep {
                    name: "ScsiFormatUnit".to_string(),
                    grade: "FormatUnitGrade".to_string(),
                    nist_class: "Clear".to_string(), // Capped per SBC-3
                    readback_expectation: "Zeros".to_string(),
                    fallback_target: None,
                });
            }
        }

        Ok(StrategyLadder { steps })
    }

    /// Enforce mutual exclusivity between hardware strategy and procedural overwrite profiles (Δ318).
    pub fn validate_plan_options(
        strategy_selected: bool,
        overwrite_profile_selected: bool,
    ) -> Result<(), &'static str> {
        if strategy_selected && overwrite_profile_selected {
            Err("CONFLICT_EXIT_8_CANNOT_MIX_STRATEGY_AND_PROFILE")
        } else {
            Ok(())
        }
    }
}
