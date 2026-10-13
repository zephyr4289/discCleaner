//! Failure taxonomy — why drives in decommissioning bins are actually
//! dead, and which resurrection route each cause implies.
//!
//! ```text
//! Class A  firmware corruption   SPI flash brownout-corrupted; the mask-ROM
//!                                 BROM is alive and strapped -> inject via
//!                                 UART BROM download. The happy path.
//! Class B  core fault             Cortex-R4 in a HardFault / lockup loop;
//!                                 BROM strap not asserted, but the ARM
//!                                 debug port answers -> halt over SWD,
//!                                 write payload to SRAM, release.
//! Class C  power path             blown TVS diode / dead rails; silicon is
//!                                 fine, the board just can't power itself
//!                                 -> rig applies bench power, then A or B.
//! Class D  debug lockdown         vendor debug bridges locked (SWD AP
//!                                 faults, JTAG-DP returns junk); the TAP
//!                                 and boundary cells still answer ->
//!                                 EXTEST pin-level NAND takeover. Slow,
//!                                 but it works on a corpse.
//! ```

use crate::hal::Transport;

/// Class labels are deliberately `A_`/`B_`/… — the taxonomy letters are
/// the operator-facing nomenclature.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    A_FirmwareCorruption,
    B_CoreFault,
    C_PowerPath,
    D_DebugLockdown,
    X_Unrecoverable,
}

impl FailureClass {
    pub fn name(&self) -> &'static str {
        match self {
            FailureClass::A_FirmwareCorruption => "A — firmware corruption (BROM alive)",
            FailureClass::B_CoreFault => "B — core fault / lockup (debug port alive)",
            FailureClass::C_PowerPath => "C — power path damage (bench power required)",
            FailureClass::D_DebugLockdown => "D — vendor debug lockdown (pin takeover)",
            FailureClass::X_Unrecoverable => "X — beyond debug silicon",
        }
    }

    pub fn route(&self) -> Transport {
        match self {
            FailureClass::A_FirmwareCorruption => Transport::UartBrom,
            FailureClass::B_CoreFault => Transport::Swd,
            FailureClass::C_PowerPath => Transport::UartBrom,
            FailureClass::D_DebugLockdown => Transport::Jtag,
            FailureClass::X_Unrecoverable => Transport::Jtag,
        }
    }
}

/// What the scan phase discovered about one dead board.
#[derive(Clone, Debug)]
pub struct TriageReport {
    pub class: FailureClass,
    pub evidence: Vec<String>,
    pub bench_power_applied: bool,
}

impl TriageReport {
    pub fn new(class: FailureClass) -> TriageReport {
        TriageReport {
            class,
            evidence: Vec::new(),
            bench_power_applied: false,
        }
    }

    pub fn evidence(&mut self, line: impl Into<String>) {
        self.evidence.push(line.into());
    }
}
