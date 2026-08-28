use crate::error::DcError;
use crate::plan::SanitizationPlan;

/// Unforgeable token required by I/O engine to issue destructive writes.
/// Only minted when FSM is in `Executing` or `Flushing` state.
pub struct WritePermit {
    _private: (),
}

impl WritePermit {
    pub(crate) fn mint() -> Self {
        Self { _private: () }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum FsmState {
    Probed,
    PlanCompiled {
        plan: SanitizationPlan,
        plan_hash: String,
    },
    PlanApproved {
        plan: SanitizationPlan,
        plan_hash: String,
    },
    Armed,
    Executing {
        pass: u8,
        next_window: u64,
    },
    Flushing {
        pass: u8,
    },
    Verifying,
    Certified,
    Aborted,
    Failed {
        code: String,
        detail: String,
    },
    Interrupted {
        resumable: bool,
    },
}

pub struct FsmOrchestrator {
    state: FsmState,
}

impl FsmOrchestrator {
    pub fn new() -> Self {
        Self {
            state: FsmState::Probed,
        }
    }

    pub fn state(&self) -> &FsmState {
        &self.state
    }

    pub fn compile_plan(&mut self, plan: SanitizationPlan) -> Result<String, DcError> {
        match &self.state {
            FsmState::Probed => {
                let plan_hash = plan.compute_plan_hash()?;
                self.state = FsmState::PlanCompiled {
                    plan,
                    plan_hash: plan_hash.clone(),
                };
                Ok(plan_hash)
            }
            _ => Err(DcError::Usage(
                "Cannot compile plan: invalid state".to_string(),
            )),
        }
    }

    pub fn approve_plan(&mut self) -> Result<(), DcError> {
        match &self.state {
            FsmState::PlanCompiled { plan, plan_hash } => {
                self.state = FsmState::PlanApproved {
                    plan: plan.clone(),
                    plan_hash: plan_hash.clone(),
                };
                Ok(())
            }
            _ => Err(DcError::Usage(
                "Cannot approve plan: plan not compiled".to_string(),
            )),
        }
    }

    pub fn arm(&mut self) -> Result<(), DcError> {
        match &self.state {
            FsmState::PlanApproved { .. } => {
                self.state = FsmState::Armed;
                Ok(())
            }
            _ => Err(DcError::Usage(
                "Cannot arm: plan not approved".to_string(),
            )),
        }
    }

    pub fn begin_pass(&mut self, pass: u8) -> Result<WritePermit, DcError> {
        match &self.state {
            FsmState::Armed | FsmState::Flushing { .. } => {
                self.state = FsmState::Executing {
                    pass,
                    next_window: 0,
                };
                Ok(WritePermit::mint())
            }
            _ => Err(DcError::Usage(
                "Cannot begin pass: invalid state".to_string(),
            )),
        }
    }

    pub fn begin_flush(&mut self, pass: u8) -> Result<WritePermit, DcError> {
        match &self.state {
            FsmState::Executing { .. } => {
                self.state = FsmState::Flushing { pass };
                Ok(WritePermit::mint())
            }
            _ => Err(DcError::Usage(
                "Cannot begin flush: not executing".to_string(),
            )),
        }
    }

    pub fn begin_verify(&mut self) -> Result<(), DcError> {
        match &self.state {
            FsmState::Flushing { .. } => {
                self.state = FsmState::Verifying;
                Ok(())
            }
            _ => Err(DcError::Usage(
                "Cannot begin verification: media not flushed".to_string(),
            )),
        }
    }

    pub fn certify(&mut self) -> Result<(), DcError> {
        match &self.state {
            FsmState::Verifying => {
                self.state = FsmState::Certified;
                Ok(())
            }
            _ => Err(DcError::Usage(
                "Cannot certify: not verified".to_string(),
            )),
        }
    }

    pub fn fail(&mut self, code: String, detail: String) {
        self.state = FsmState::Failed { code, detail };
    }

    pub fn interrupt(&mut self) {
        self.state = FsmState::Interrupted { resumable: true };
    }

    pub fn abort(&mut self) {
        self.state = FsmState::Aborted;
    }
}
