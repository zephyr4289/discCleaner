use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaDeviceState {
    pub is_locked: bool,
    pub is_frozen: bool,
    pub password: Option<String>,
    pub enhanced_supported: bool,
    pub current_lba: u64,
    pub native_lba: u64,
    pub dco_lba: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtaSecurityResult {
    Success { erased_enhanced: bool },
    RefusedPreLocked,
    RefusedFrozen,
    EraseFailedRepaired { rescue_password: String },
    EraseFailedLocked { rescue_password: String },
}

pub struct AtaDev {
    pub state: AtaDeviceState,
    pub fail_erase_unit: bool,
    pub fail_disable_password: bool,
}

impl AtaDev {
    pub fn new(current_lba: u64, native_lba: u64, dco_lba: u64) -> Self {
        Self {
            state: AtaDeviceState {
                is_locked: false,
                is_frozen: false,
                password: None,
                enhanced_supported: true,
                current_lba,
                native_lba,
                dco_lba,
            },
            fail_erase_unit: false,
            fail_disable_password: false,
        }
    }

    /// Intake check: refuse immediately if drive arrives already locked.
    pub fn check_intake(&self) -> Result<(), &'static str> {
        if self.state.is_locked {
            Err("DRIVE_PRE_LOCKED_REFUSAL")
        } else {
            Ok(())
        }
    }

    /// Execute ATA Security Erase with No-Harm lifeline rule (Δ258).
    pub fn execute_security_erase(
        &mut self,
        password: &str,
        request_enhanced: bool,
    ) -> AtaSecurityResult {
        if self.state.is_locked {
            return AtaSecurityResult::RefusedPreLocked;
        }
        if self.state.is_frozen {
            return AtaSecurityResult::RefusedFrozen;
        }

        // Step 1: Set Security Password (enters locked state)
        self.state.password = Some(password.to_string());
        self.state.is_locked = true;

        // Step 2: Issue SECURITY ERASE UNIT
        if self.fail_erase_unit {
            // Erase failed! Apply No-Harm rule: attempt SECURITY DISABLE PASSWORD repair
            if !self.fail_disable_password {
                // Repair succeeded: lock is cleared
                self.state.is_locked = false;
                self.state.password = None;
                return AtaSecurityResult::EraseFailedRepaired {
                    rescue_password: password.to_string(),
                };
            } else {
                // Repair failed: drive remains locked, lifeline must be disclosed prominently!
                return AtaSecurityResult::EraseFailedLocked {
                    rescue_password: password.to_string(),
                };
            }
        }

        // Erase succeeded: controller automatically clears password and lock
        self.state.is_locked = false;
        self.state.password = None;
        let enhanced = request_enhanced && self.state.enhanced_supported;

        AtaSecurityResult::Success {
            erased_enhanced: enhanced,
        }
    }

    /// Restore DCO (Device Configuration Overlay) to maximum factory geometry.
    pub fn restore_dco(&mut self) -> u64 {
        // DCO restore unlocks hidden factory sectors and resets the device
        self.state.native_lba = self.state.dco_lba;
        self.state.native_lba
    }

    /// Unlock HPA (Host Protected Area) to native maximum.
    pub fn unlock_hpa(&mut self) -> u64 {
        self.state.current_lba = self.state.native_lba;
        self.state.current_lba
    }
}
