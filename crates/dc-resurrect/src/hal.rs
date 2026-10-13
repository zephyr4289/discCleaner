//! Debug-link HAL — the seam between the rig and dead silicon.
//!
//! Three physical transports, three traits:
//!
//! * [`JtagLink`] — IEEE 1149.1: every `tck()` is one Test Clock; the target
//!   samples TMS/TDI on the rising edge and returns TDO as driven during
//!   that cycle. (A real MPSSE driver folds the falling-edge TDO change into
//!   the same call; our simulator uses a single-edge model.)
//! * [`SwdLink`] — ARM Serial Wire Debug, ADIv5: the link exchanges
//!   *events*, not raw pins, because SWD is direction-switched. Each event
//!   consumes exactly one SWCLK: host-driven bit, target-driven bit, or a
//!   turnaround (ownership flip). Keeping turnarounds as first-class events
//!   is what makes the host engine and the simulated DP provably lock-step.
//! * [`UartLink`] — Boot-ROM UART at frame level (autobaud byte, then
//!   CRC16-XMODEM protected packets).
//!
//! `--transport ftdi` / `--transport gpio` map these traits onto an FT232H
//! class adapter in MPSSE mode or the gpiod character device. Those drivers
//! are intentionally not wired in this build (see README "Rig hardware");
//! everything in-tree runs against the bit-level simulator, which implements
//! the *device* side of each protocol — the same engine bits that would talk
//! to a real brick.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The selected physical transport is not compiled into this build.
    Unavailable(&'static str),
    /// Target did not answer on the wire within the deadline.
    NoAck,
    /// Target returned a protocol fault.
    Fault(&'static str),
    /// I/O failure on the host side.
    Io(String),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::Unavailable(w) => write!(f, "transport unavailable in this build: {w}"),
            LinkError::NoAck => write!(f, "no acknowledgment from target (silicon silent)"),
            LinkError::Fault(w) => write!(f, "target protocol fault: {w}"),
            LinkError::Io(e) => write!(f, "host i/o error: {e}"),
        }
    }
}

impl std::error::Error for LinkError {}

/// IEEE 1149.1 JTAG — one TCK cycle per call.
pub trait JtagLink {
    /// One Test Clock cycle: target samples TMS/TDI; returns TDO.
    fn tck(&mut self, tms: bool, tdi: bool) -> bool;
    /// Assert/deassert TRST if the rig has it (no-op otherwise).
    fn set_trst(&mut self, _assert: bool) {}
    /// Run `n` idle clocks in Run-Test/Idle.
    fn idle_clocks(&mut self, n: u32) {
        for _ in 0..n {
            self.tck(false, false);
        }
    }
    /// Rig-side service hook (drives simulated time forward).
    fn service(&mut self) {}
}

/// ARM SWD — one event per SWCLK cycle.
pub trait SwdLink {
    /// Host drives SWDIO=bit, one SWCLK.
    fn swd_host_bit(&mut self, bit: bool);
    /// Host clocks and samples the target-driven line.
    fn swd_target_bit(&mut self) -> bool;
    /// Turnaround: ownership flips, one SWCLK, no payload.
    fn swd_trn(&mut self);
    /// Idle clocks with SWDIO held at `level` (line reset uses high).
    fn swd_idle_clocks(&mut self, n: u32, level: bool) {
        for _ in 0..n {
            self.swd_host_bit(level);
        }
    }
    fn service(&mut self) {}
}

/// Boot-ROM UART — byte level with timeouts.
pub trait UartLink {
    fn write_byte(&mut self, b: u8) -> Result<(), LinkError>;
    fn read_byte_timeout(&mut self, ms: u32) -> Result<Option<u8>, LinkError>;
    fn write_all(&mut self, data: &[u8]) -> Result<(), LinkError> {
        for &b in data {
            self.write_byte(b)?;
        }
        Ok(())
    }
    /// Rig-side service hook (advances simulated time / core execution).
    fn service(&mut self) {}
}

/// Bench-power control for Class C boards (blown TVS diode, dead rails).
pub trait RigPower {
    /// Apply clean external power on the rig's current-limited supply.
    fn rig_apply_power(&mut self) -> Result<(), LinkError>;
    /// True once the board's rails are up through the rig.
    fn rig_power_good(&self) -> bool {
        true
    }
}

/// Which transport a mission should prefer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Vendor Boot-ROM over UART (fastest, needs live strap).
    UartBrom,
    /// ARM Debug Port over SWD (works when firmware faulted, strap absent).
    Swd,
    /// JTAG boundary-scan NAND bit-bang (works on locked / corpse silicon).
    Jtag,
}

impl Transport {
    pub fn parse(s: &str) -> Option<Transport> {
        match s.to_ascii_lowercase().as_str() {
            "uart" | "brom" | "uart-brom" => Some(Transport::UartBrom),
            "swd" => Some(Transport::Swd),
            "jtag" | "bsr" => Some(Transport::Jtag),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Transport::UartBrom => "UART Boot-ROM",
            Transport::Swd => "SWD (ARM ADIv5)",
            Transport::Jtag => "JTAG boundary-scan",
        }
    }
}
