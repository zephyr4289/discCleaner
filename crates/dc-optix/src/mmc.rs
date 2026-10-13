//! # MMC/ATAPI raw passthrough & vendor diagnostic commands.
//!
//! Optical drives speak the SCSI Multimedia Command set over
//! ATAPI, USB-BBB/UAS or SAT. Standard commands (READ/WRITE/FORMAT)
//! enforce the firmware's own laser safety and media-type rules —
//! which is exactly why WORM media "cannot be erased" through the
//! normal path.
//!
//! The weaponization path is the **vendor diagnostic block**: the
//! OEM maintenance command set service centers use to align pickup
//! optics, run OPC sweeps and stress the focus servo. dc-optix
//! uses a minimal slice of that surface:
//!
//! * `DISABLE_OPC` — stop run-time optimum power calibration
//!   from clamping the diode back to write-strategy levels.
//! * `LASER_OVERDRIVE` — PWM duty to 100% continuous wave, diode
//!   current to the vendor absolute-maximum shelf.
//! * `PARK_VELOCITY` — pin the CLV servo at minimum linear
//!   velocity (maximum dwell per unit track length).
//! * `FOCUS_OFFSET` — static focus offset into the protective
//!   substrate gap (the layer sits under the polycarbonate; the
//!   servo normally tracks the surface).
//! * `WRITE_LONG` — the burn pass over the spiral.
//!
//! [`MmcTransport`] abstracts the raw CDB channel (a real backend
//! implements it on SG_IO / dc-scsi); [`SimDrive`] records every
//! command for the certificate and simulates the media response.

use crate::OptixError;
use crate::layer::LayerStack;
/// Vendor diagnostic opcodes (the `0xDx` vendor-specific block).
pub mod opcodes {
    pub const DISABLE_OPC: u8 = 0xD1;
    pub const LASER_OVERDRIVE: u8 = 0xD2;
    pub const PARK_VELOCITY: u8 = 0xD3;
    pub const FOCUS_OFFSET: u8 = 0xD4;
    pub const WRITE_LONG: u8 = 0xD5;
}

/// One recorded vendor command (digest-bound in the certificate).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum VendorCommand {
    DisableOpc {
        opcode: u8,
    },
    LaserOverdrive {
        opcode: u8,
        /// PWM duty in per-mille (1000 = continuous wave).
        duty_pm: u16,
        /// Diode current in per-cent of nominal write current.
        current_pct: u16,
    },
    ParkVelocity {
        opcode: u8,
        /// Linear velocity in centi-m/s (e.g. 120 = 1.2 m/s).
        clv_centi_mps: u16,
    },
    FocusOffset {
        opcode: u8,
        /// Static focus offset in tenths of a micrometre.
        offset_tenth_um: i16,
    },
    WriteLong {
        opcode: u8,
        /// Start logical zone.
        zone: u32,
        /// Zone count covered by this pass.
        zones: u32,
    },
}

/// The raw CDB channel.
pub trait MmcTransport {
    /// Send one vendor diagnostic command.
    fn send(&mut self, cmd: VendorCommand) -> Result<(), OptixError>;

    /// The recorded stream (certificate digest input).
    fn command_log(&self) -> &[VendorCommand];

    /// Currently applied laser state, if any.
    fn laser_state(&self) -> Option<(u16, u16)>;

    /// Currently applied CLV, if any.
    fn velocity_cmps(&self) -> Option<u16>;
}

/// Hard safety envelope of the (simulated) pickup.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DriveLimits {
    /// Absolute-maximum diode current (per-cent of nominal).
    pub max_current_pct: u16,
    /// Spindle stall velocity (centi-m/s).
    pub stall_clv_centi_mps: u16,
    /// Focus actuator range (tenths of µm).
    pub focus_range_tenth_um: u16,
}

impl Default for DriveLimits {
    fn default() -> Self {
        Self {
            max_current_pct: 300,
            stall_clv_centi_mps: 100,
            focus_range_tenth_um: 30,
        }
    }
}

/// Simulated optical drive: records commands, holds the media.
pub struct SimDrive {
    limits: DriveLimits,
    log: Vec<VendorCommand>,
    laser: Option<(u16, u16)>,
    velocity: Option<u16>,
    focus_offset: i16,
    opc_disabled: bool,
    /// The loaded media (writable layers).
    pub media: LayerStack,
}

impl SimDrive {
    pub fn new(limits: DriveLimits, media: LayerStack) -> Self {
        Self {
            limits,
            log: Vec::new(),
            laser: None,
            velocity: None,
            focus_offset: 0,
            opc_disabled: false,
            media,
        }
    }

    /// Whether the full weaponization preconditions are armed.
    pub fn armed(&self) -> Result<(u16, u16, u16), OptixError> {
        if !self.opc_disabled {
            return Err(OptixError::Transport(
                "OPC still active — the drive would re-clamp the laser power mid-run".into(),
            ));
        }
        let (duty, current) = self
            .laser
            .ok_or_else(|| OptixError::Transport("laser not configured".into()))?;
        let v = self
            .velocity
            .ok_or_else(|| OptixError::Transport("CLV not parked".into()))?;
        Ok((duty, current, v))
    }
}

impl MmcTransport for SimDrive {
    fn send(&mut self, cmd: VendorCommand) -> Result<(), OptixError> {
        match &cmd {
            VendorCommand::DisableOpc { opcode } => {
                self.opc_disabled = true;
                let _ = opcode;
            }
            VendorCommand::LaserOverdrive {
                opcode,
                duty_pm,
                current_pct,
            } => {
                let _ = opcode;
                if *duty_pm == 0 || *duty_pm > 1000 {
                    return Err(OptixError::Transport(format!(
                        "PWM duty {duty_pm}‰ outside 1..=1000"
                    )));
                }
                if *current_pct == 0 || *current_pct > self.limits.max_current_pct {
                    return Err(OptixError::Transport(format!(
                        "diode current {current_pct}% outside the vendor envelope (max {}%)",
                        self.limits.max_current_pct
                    )));
                }
                self.laser = Some((*duty_pm, *current_pct));
            }
            VendorCommand::ParkVelocity {
                opcode,
                clv_centi_mps,
            } => {
                let _ = opcode;
                if *clv_centi_mps < self.limits.stall_clv_centi_mps || *clv_centi_mps > 2000 {
                    return Err(OptixError::Transport(format!(
                        "CLV {clv_centi_mps} c-m/s outside 1.0..20.0 m/s (spindle stall at {})",
                        self.limits.stall_clv_centi_mps
                    )));
                }
                self.velocity = Some(*clv_centi_mps);
            }
            VendorCommand::FocusOffset {
                opcode,
                offset_tenth_um,
            } => {
                let _ = opcode;
                if offset_tenth_um.unsigned_abs() > self.limits.focus_range_tenth_um {
                    return Err(OptixError::Transport(format!(
                        "focus offset {offset_tenth_um} exceeds the actuator range ±{}",
                        self.limits.focus_range_tenth_um
                    )));
                }
                self.focus_offset = *offset_tenth_um;
            }
            VendorCommand::WriteLong {
                opcode,
                zone,
                zones,
            } => {
                let _ = opcode;
                // The burn pass requires the full armed state.
                self.armed()?;
                if *zones == 0 || (*zone + *zones) as usize > self.media.zones() {
                    return Err(OptixError::Transport(format!(
                        "write-long zone window {zone}+{zones} exceeds the spiral"
                    )));
                }
            }
        }
        self.log.push(cmd);
        Ok(())
    }

    fn command_log(&self) -> &[VendorCommand] {
        &self.log
    }

    fn laser_state(&self) -> Option<(u16, u16)> {
        self.laser
    }

    fn velocity_cmps(&self) -> Option<u16> {
        self.velocity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{LayerStack, MediaType};

    fn drive() -> SimDrive {
        SimDrive::new(
            DriveLimits::default(),
            LayerStack::new(MediaType::PhaseChange, 12, 32, 16),
        )
    }

    #[test]
    fn command_envelope_is_enforced() {
        let mut d = drive();
        assert!(
            d.send(VendorCommand::LaserOverdrive {
                opcode: opcodes::LASER_OVERDRIVE,
                duty_pm: 1000,
                current_pct: 400, // beyond vendor max
            })
            .is_err()
        );
        assert!(
            d.send(VendorCommand::LaserOverdrive {
                opcode: opcodes::LASER_OVERDRIVE,
                duty_pm: 1000,
                current_pct: 280,
            })
            .is_ok()
        );
        assert!(
            d.send(VendorCommand::ParkVelocity {
                opcode: opcodes::PARK_VELOCITY,
                clv_centi_mps: 80, // below stall
            })
            .is_err()
        );
        assert!(
            d.send(VendorCommand::ParkVelocity {
                opcode: opcodes::PARK_VELOCITY,
                clv_centi_mps: 120,
            })
            .is_ok()
        );
        assert!(
            d.send(VendorCommand::FocusOffset {
                opcode: opcodes::FOCUS_OFFSET,
                offset_tenth_um: 40, // beyond actuator
            })
            .is_err()
        );
        assert!(
            d.send(VendorCommand::FocusOffset {
                opcode: opcodes::FOCUS_OFFSET,
                offset_tenth_um: -12,
            })
            .is_ok()
        );
    }

    #[test]
    fn write_long_requires_the_full_armed_state() {
        let mut d = drive();
        // Nothing configured: refuse.
        assert!(
            d.send(VendorCommand::WriteLong {
                opcode: opcodes::WRITE_LONG,
                zone: 0,
                zones: 4,
            })
            .is_err()
        );
        // OPC disabled but no laser/CLV: refuse.
        d.send(VendorCommand::DisableOpc {
            opcode: opcodes::DISABLE_OPC,
        })
        .unwrap();
        assert!(
            d.send(VendorCommand::WriteLong {
                opcode: opcodes::WRITE_LONG,
                zone: 0,
                zones: 4,
            })
            .is_err()
        );
        // Full arm: accept.
        d.send(VendorCommand::LaserOverdrive {
            opcode: opcodes::LASER_OVERDRIVE,
            duty_pm: 1000,
            current_pct: 280,
        })
        .unwrap();
        d.send(VendorCommand::ParkVelocity {
            opcode: opcodes::PARK_VELOCITY,
            clv_centi_mps: 120,
        })
        .unwrap();
        assert!(
            d.send(VendorCommand::WriteLong {
                opcode: opcodes::WRITE_LONG,
                zone: 0,
                zones: 4,
            })
            .is_ok()
        );
        // Out-of-spiral window: refuse.
        assert!(
            d.send(VendorCommand::WriteLong {
                opcode: opcodes::WRITE_LONG,
                zone: 10,
                zones: 5,
            })
            .is_err()
        );
        assert_eq!(d.command_log().len(), 4);
    }
}
