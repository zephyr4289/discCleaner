use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeLieClass {
    AcceptNoop,  // Returns SCSI GOOD (0), but command was never executed
    SilentDrop,  // Packet dropped on the wire; times out
    WrongSense,  // Sense data mangled or misreported
    TimeoutKill, // Bridge forcibly terminates connection mid-operation
    Mangle,      // Command executed with mangled sub-parameters
}

pub struct BridgeLieDetector;

impl BridgeLieDetector {
    /// Effect-verification law: No return code is trusted without observable consequence (Δ265).
    pub fn verify_state_change<T: PartialEq>(
        return_code_success: bool,
        before: &T,
        after: &T,
        lie_class: Option<BridgeLieClass>,
    ) -> Result<(), &'static str> {
        if let Some(BridgeLieClass::AcceptNoop) = lie_class {
            if return_code_success && before == after {
                return Err("BRIDGE_LIE_DETECTED_ACCEPT_NOOP");
            }
        }

        if return_code_success && before == after {
            return Err("EFFECT_VERIFICATION_FAILED_NO_OBSERVABLE_CHANGE");
        }

        Ok(())
    }
}
