use dc_hw::AtaSecurityStatus;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaLifeline {
    pub id: String,
    pub password_hash: String,
    pub plaintext_password: Option<String>,
    pub voided: bool,
}

impl AtaLifeline {
    pub fn new(password: &str) -> Self {
        let password_hash = blake3::hash(password.as_bytes()).to_hex().to_string();
        Self {
            id: format!("life-{}", &password_hash[0..8]),
            password_hash,
            plaintext_password: Some(password.to_string()),
            voided: false,
        }
    }

    /// Void the lifeline structurally upon verified drive unlock (Δ276).
    pub fn void(&mut self) {
        self.plaintext_password = None;
        self.voided = true;
    }

    /// Revoke the lifeline by audited operator action (Δ276).
    pub fn revoke(&mut self) {
        self.plaintext_password = None;
        self.voided = true;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtaFsmOutcome {
    Clean { enhanced: bool },
    Repaired { rescue_password: String },
    LockedDisclosed { rescue_password: String },
    RefusedPreLocked,
    RefusedFrozen,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtaSecurityState {
    Intake,
    Armed { lifeline: AtaLifeline, enhanced: bool },
    Erasing,
    Repairing { lifeline: AtaLifeline },
    Terminal(AtaFsmOutcome),
}

pub struct AtaSecurityFsm {
    pub state: AtaSecurityState,
}

impl AtaSecurityFsm {
    pub fn new() -> Self {
        Self {
            state: AtaSecurityState::Intake,
        }
    }

    /// Transition 1: Intake check
    pub fn process_intake(&mut self, sec: &AtaSecurityStatus) -> Result<(), AtaFsmOutcome> {
        if sec.locked {
            self.state = AtaSecurityState::Terminal(AtaFsmOutcome::RefusedPreLocked);
            return Err(AtaFsmOutcome::RefusedPreLocked);
        }
        if sec.frozen {
            self.state = AtaSecurityState::Terminal(AtaFsmOutcome::RefusedFrozen);
            return Err(AtaFsmOutcome::RefusedFrozen);
        }
        Ok(())
    }

    /// Transition 2: Arm with random password lifeline
    pub fn arm(&mut self, password: &str, request_enhanced: bool) {
        let lifeline = AtaLifeline::new(password);
        self.state = AtaSecurityState::Armed {
            lifeline,
            enhanced: request_enhanced,
        };
    }

    /// Transition 3: Issue Security Erase Unit
    pub fn on_erase_success(&mut self, enhanced: bool) -> AtaFsmOutcome {
        if let AtaSecurityState::Armed { mut lifeline, .. } = self.state.clone() {
            lifeline.void(); // Structurally voided on unlock
        }
        let outcome = AtaFsmOutcome::Clean { enhanced };
        self.state = AtaSecurityState::Terminal(outcome.clone());
        outcome
    }

    /// Transition 4: Handle Erase Failure with No-Harm Repair
    pub fn on_erase_failure(&mut self, repair_succeeded: bool) -> AtaFsmOutcome {
        if let AtaSecurityState::Armed { lifeline, .. } = self.state.clone() {
            if repair_succeeded {
                let outcome = AtaFsmOutcome::Repaired {
                    rescue_password: lifeline.plaintext_password.clone().unwrap_or_default(),
                };
                self.state = AtaSecurityState::Terminal(outcome.clone());
                outcome
            } else {
                let outcome = AtaFsmOutcome::LockedDisclosed {
                    rescue_password: lifeline.plaintext_password.clone().unwrap_or_default(),
                };
                self.state = AtaSecurityState::Terminal(outcome.clone());
                outcome
            }
        } else {
            self.state = AtaSecurityState::Terminal(AtaFsmOutcome::RefusedPreLocked);
            AtaFsmOutcome::RefusedPreLocked
        }
    }
}
