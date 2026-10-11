use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrchestratorState {
    Initialized,
    Classified,
    Confirmed,
    Armed,
    ExecutingPass { pass_index: u8 },
    Flushed,
    Verifying,
    Completed,
    Interrupted,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrchestratorEffect {
    ClassifyDevice,
    PromptConfirmation,
    AcquireLocksAndArm,
    ExecutePass { pass: u8 },
    FlushDevice,
    VerifyMedia,
    WriteCertificate,
    AppendAuditRecord { outcome: String },
    Exit { code: i32 },
}

pub struct Orchestrator {
    state: OrchestratorState,
    total_passes: u8,
    is_confirmed: bool,
    /// Explicit index of the NEXT pass to execute. The transition
    /// `Confirmed -> Armed` already emits `ExecutePass { pass: 0 }` (the
    /// operator-armed first write), so this counter starts at 1. Without
    /// an explicit counter the `Armed` arm recomputes "next" from the
    /// state and used to execute pass 0 a second time.
    next_pass: u8,
}

impl Orchestrator {
    pub fn new(total_passes: u8) -> Self {
        Self {
            state: OrchestratorState::Initialized,
            total_passes,
            is_confirmed: false,
            next_pass: 0,
        }
    }

    pub fn current_state(&self) -> OrchestratorState {
        self.state
    }

    /// Step the FSM based on effect results (Δ175).
    pub fn step(&mut self, effect_success: bool) -> OrchestratorEffect {
        if !effect_success {
            self.state = OrchestratorState::Failed;
            return OrchestratorEffect::Exit { code: 1 };
        }

        match self.state {
            OrchestratorState::Initialized => {
                self.state = OrchestratorState::Classified;
                OrchestratorEffect::PromptConfirmation
            }
            OrchestratorState::Classified => {
                self.is_confirmed = true;
                self.state = OrchestratorState::Confirmed;
                OrchestratorEffect::AcquireLocksAndArm
            }
            OrchestratorState::Confirmed => {
                // The effect emitted here IS pass 0's execution (armed first
                // write). Record that pass 0 has been dispatched so the
                // `Armed`/`ExecutingPass` arm never re-dispatches it.
                self.next_pass = 1;
                self.state = OrchestratorState::Armed;
                OrchestratorEffect::ExecutePass { pass: 0 }
            }
            OrchestratorState::Armed | OrchestratorState::ExecutingPass { .. } => {
                let next = self.next_pass;
                if next < self.total_passes {
                    self.next_pass = next + 1;
                    self.state = OrchestratorState::ExecutingPass { pass_index: next };
                    OrchestratorEffect::ExecutePass { pass: next }
                } else {
                    self.state = OrchestratorState::Flushed;
                    OrchestratorEffect::FlushDevice
                }
            }
            OrchestratorState::Flushed => {
                self.state = OrchestratorState::Verifying;
                OrchestratorEffect::VerifyMedia
            }
            OrchestratorState::Verifying => {
                self.state = OrchestratorState::Completed;
                OrchestratorEffect::WriteCertificate
            }
            OrchestratorState::Completed => {
                OrchestratorEffect::Exit { code: 0 }
            }
            OrchestratorState::Interrupted => {
                OrchestratorEffect::Exit { code: 3 }
            }
            OrchestratorState::Failed => {
                OrchestratorEffect::Exit { code: 1 }
            }
        }
    }
}
