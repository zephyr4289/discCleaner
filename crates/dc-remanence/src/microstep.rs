//! # Off-track micro-stepping & write-current bias manipulation.
//!
//! The annihilation engine's first weapon: physically move the
//! read/write head off the track centerline in sub-track
//! increments, and overdrive the write current, so the write
//! bubble sweeps the guard bands on both sides of every track.
//!
//! ## The transport abstraction
//!
//! Real drives expose this via vendor-specific diagnostic command
//! sets (ATA task-file registers / SCSI CDBs on the OEM diagnostic
//! port — the same interfaces service centers use for head
//! alignment and RRO compensation). [`MicroStepTransport`] models
//! the minimal command surface we need:
//!
//! * `step_head(offset_frac)` — displace the servo target by a
//!   fraction of track pitch (micro-stepping the actuator, not
//!   seeking a different track),
//! * `set_write_current_bias(bias)` — scale the write driver
//!   current away from nominal,
//! * `write_track(cells)` — write one bit-cell burst at the current
//!   step/current settings.
//!
//! A hardware backend implements the trait on top of `dc-ata` /
//! `dc-scsi` passthrough; the simulation backend
//! ([`SimStepTransport`]) records the command stream so the
//! certificate can digest-bind the exact executed plan.
//!
//! ## The ladder
//!
//! The default plan is the mission ladder: **+15%, −15%, +30%,
//! −30%** of track pitch, each at elevated current, plus the
//! centerline zero-write. With a widened bubble each step covers a
//! guard-band slab; the union must cover 100% of the guard band on
//! both sides — [`plan_ladder`] verifies this against the geometry
//! and refuses plans that leave any column behind (a forensic
//! island).

use crate::RemanenceError;
use crate::track::TrackGeometry;
/// One step of the off-track write ladder.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StepSpec {
    /// Head offset from track centerline as a fraction of track
    /// pitch (may be negative).
    pub offset_frac: f64,
    /// Write-current bias (0 = nominal; > 0 = overdrive).
    pub bias: f64,
}

impl StepSpec {
    pub const fn new(offset_frac: f64, bias: f64) -> Self {
        Self { offset_frac, bias }
    }
}

/// A fully-specified annihilation write plan for one track.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WritePlan {
    /// Ordered ladder steps (executed top to bottom).
    pub ladder: Vec<StepSpec>,
    /// Number of data cells per track burst.
    pub cells: usize,
}

/// Default micro-step ladder from the breakthrough mission spec.
///
/// Centerline zero-write first, then symmetric off-track steps at
/// growing displacement with rising overdrive.
pub const DEFAULT_LADDER: &[StepSpec] = &[
    StepSpec::new(0.00, 0.30),
    StepSpec::new(0.15, 0.30),
    StepSpec::new(-0.15, 0.30),
    StepSpec::new(0.30, 0.55),
    StepSpec::new(-0.30, 0.55),
];

impl WritePlan {
    /// Build the plan for a geometry on the default ladder.
    pub fn default_plan(cells: usize) -> Self {
        Self {
            ladder: DEFAULT_LADDER.to_vec(),
            cells,
        }
    }

    /// Hard-switch half-width reached at a lateral position `y`
    /// (nm) by this plan: the maximum, over ladder steps, of the
    /// hard-switch margin. A column is hard-switch covered if any
    /// step's write field at that column exceeds its grain
    /// coercivity by [`crate::curie::HARD_SWITCH_MARGIN`].
    pub fn hard_switch_field_at(&self, geo: &TrackGeometry, y: f64) -> f64 {
        self.ladder
            .iter()
            .map(|s| {
                let c = s.offset_frac * geo.track_pitch_nm;
                geo.write_field_at(y, c, s.bias)
            })
            .fold(0.0_f64, f64::max)
    }

    /// Maximum switching-probability field exposure a column sees
    /// across the plan AND the dither passes that follow it.
    pub fn dither_exposure_at(&self, geo: &TrackGeometry, y: f64, dither_bias: f64) -> f64 {
        // Dither passes run at the ladder offsets too (the mission
        // schedule); the exposure of interest is the field from the
        // nearest step.
        self.ladder
            .iter()
            .map(|s| {
                let c = s.offset_frac * geo.track_pitch_nm;
                geo.write_field_at(y, c, dither_bias)
            })
            .fold(0.0_f64, f64::max)
    }
}

/// Verify a ladder covers the full guard band with hard-switch
/// fields (median-coercivity grain).
///
/// Returns the list of uncovered lateral positions (nm) — empty
/// when the plan is forensically closed.
pub fn ladder_coverage_gaps(geo: &TrackGeometry, plan: &WritePlan, resolution_nm: f64) -> Vec<f64> {
    let mut gaps = Vec::new();
    let core = geo.core_half_width_nm();
    let edge = core + geo.guard_band_nm();
    let hard_margin = crate::curie::HARD_SWITCH_MARGIN;
    // Walk both guard bands (and one fringe tail past the neighbor
    // centerline for the deepest forensic reach).
    for side in [-1.0_f64, 1.0_f64] {
        let mut y = core;
        while y <= edge + 2.0 * geo.lambda_fringe_nm {
            let pos = side * y;
            let field = plan.hard_switch_field_at(geo, pos);
            if field < geo.hc_median * (1.0 + hard_margin) {
                gaps.push(pos);
            }
            y += resolution_nm;
        }
    }
    gaps
}

/// Vendor-diagnostic command surface for off-track writes.
///
/// Implementations wrap raw ATA passthrough (`dc-ata`) or SCSI
/// direct-access CDBs (`dc-scsi`) against a specific drive family's
/// diagnostic protocol. The simulation records everything for the
/// certificate.
pub trait MicroStepTransport {
    /// Displace the write head by `offset_frac` of track pitch from
    /// the servo's current track centerline. Valid range ±0.5.
    fn step_head(&mut self, offset_frac: f64) -> Result<(), RemanenceError>;

    /// Set the write-current bias (0 = nominal, positive = overdrive).
    /// Valid range 0.0 ..= 1.0.
    fn set_write_current_bias(&mut self, bias: f64) -> Result<(), RemanenceError>;

    /// Write one bit-cell burst of `cells` cells (values supplied by
    /// the caller's pattern generator) at the current settings.
    fn write_burst(&mut self, cells: usize) -> Result<(), RemanenceError>;

    /// The recorded command stream (for digest binding).
    fn command_log(&self) -> &[VendorCommand];
}

/// One recorded vendor-diagnostic command.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum VendorCommand {
    /// Micro-step the head (opcode, offset in milli-pitch).
    StepHead { opcode: u8, offset_milli_pitch: i32 },
    /// Set write-current bias (opcode, bias in deci-percent).
    WriteCurrent { opcode: u8, bias_deci_pct: i32 },
    /// Burst-write at current settings (opcode, cell count).
    WriteBurst { opcode: u8, cells: u32 },
}

/// Opcodes of the (simulated) vendor diagnostic protocol.
///
/// The numbering follows the `0xDx` vendor-specific block reserved
/// by several ATA OEM diagnostic tables; a real backend maps these
/// to the drive family's documented protocol.
pub mod opcodes {
    pub const STEP_HEAD: u8 = 0xD1;
    pub const WRITE_CURRENT: u8 = 0xD2;
    pub const WRITE_BURST: u8 = 0xD3;
    pub const DITHER_ENABLE: u8 = 0xD4;
}

/// Simulation transport: records the vendor command stream.
#[derive(Debug, Clone, Default)]
pub struct SimStepTransport {
    log: Vec<VendorCommand>,
    current_offset: f64,
    current_bias: f64,
}

impl SimStepTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current applied head offset (fraction of pitch).
    pub fn applied_offset(&self) -> f64 {
        self.current_offset
    }

    /// Current applied write-current bias.
    pub fn applied_bias(&self) -> f64 {
        self.current_bias
    }
}

impl MicroStepTransport for SimStepTransport {
    fn step_head(&mut self, offset_frac: f64) -> Result<(), RemanenceError> {
        if !(-0.5..=0.5).contains(&offset_frac) {
            return Err(RemanenceError::Transport(format!(
                "head micro-step {offset_frac} outside servo envelope ±0.5 pitch"
            )));
        }
        self.current_offset = offset_frac;
        self.log.push(VendorCommand::StepHead {
            opcode: opcodes::STEP_HEAD,
            offset_milli_pitch: (offset_frac * 1000.0).round() as i32,
        });
        Ok(())
    }

    fn set_write_current_bias(&mut self, bias: f64) -> Result<(), RemanenceError> {
        if !(0.0..=1.0).contains(&bias) {
            return Err(RemanenceError::Transport(format!(
                "write-current bias {bias} outside driver range 0.0..=1.0"
            )));
        }
        self.current_bias = bias;
        self.log.push(VendorCommand::WriteCurrent {
            opcode: opcodes::WRITE_CURRENT,
            bias_deci_pct: (bias * 1000.0).round() as i32,
        });
        Ok(())
    }

    fn write_burst(&mut self, cells: usize) -> Result<(), RemanenceError> {
        if cells == 0 {
            return Err(RemanenceError::Transport(
                "empty write burst — nothing to record".into(),
            ));
        }
        self.log.push(VendorCommand::WriteBurst {
            opcode: opcodes::WRITE_BURST,
            cells: cells as u32,
        });
        Ok(())
    }

    fn command_log(&self) -> &[VendorCommand] {
        &self.log
    }
}

/// Execute a write plan against a transport: issue the vendor
/// commands for the ladder, one burst per step.
pub fn execute_plan(
    transport: &mut dyn MicroStepTransport,
    plan: &WritePlan,
) -> Result<(), RemanenceError> {
    for step in &plan.ladder {
        transport.step_head(step.offset_frac)?;
        transport.set_write_current_bias(step.bias)?;
        transport.write_burst(plan.cells)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ladder_covers_the_full_guard_band() {
        let geo = TrackGeometry::default();
        let plan = WritePlan::default_plan(256);
        let gaps = ladder_coverage_gaps(&geo, &plan, 1.0);
        assert!(
            gaps.is_empty(),
            "default ladder leaves forensic islands at {:?}",
            &gaps[..gaps.len().min(8)]
        );
    }

    #[test]
    fn anemic_ladder_leaves_gaps_and_gets_caught() {
        let geo = TrackGeometry::default();
        // Centerline-only zero write: no off-track steps, nominal
        // current — the classic "overwrite with zeros" myth.
        let plan = WritePlan {
            ladder: vec![StepSpec::new(0.0, 0.0)],
            cells: 256,
        };
        let gaps = ladder_coverage_gaps(&geo, &plan, 1.0);
        assert!(!gaps.is_empty(), "the myth must leave guard-band remnants");
        // Both guard bands violated.
        assert!(gaps.iter().any(|y| *y < 0.0) && gaps.iter().any(|y| *y > 0.0));
    }

    #[test]
    fn transport_rejects_out_of_envelope_steps() {
        let mut t = SimStepTransport::new();
        assert!(t.step_head(0.15).is_ok());
        assert!(t.step_head(0.51).is_err());
        assert!(t.step_head(-0.51).is_err());
        assert!(t.set_write_current_bias(0.3).is_ok());
        assert!(t.set_write_current_bias(1.5).is_err());
        assert!(t.set_write_current_bias(-0.1).is_err());
    }

    #[test]
    fn execute_plan_records_the_full_command_stream() {
        let mut t = SimStepTransport::new();
        let plan = WritePlan::default_plan(64);
        execute_plan(&mut t, &plan).expect("plan executes");
        // 5 steps x (step + current + burst) = 15 commands.
        assert_eq!(t.command_log().len(), 15);
        // First three: step to 0.0, bias 0.30, burst 64.
        assert_eq!(
            t.command_log()[0],
            VendorCommand::StepHead {
                opcode: 0xD1,
                offset_milli_pitch: 0
            }
        );
        assert_eq!(
            t.command_log()[1],
            VendorCommand::WriteCurrent {
                opcode: 0xD2,
                bias_deci_pct: 300
            }
        );
        assert_eq!(
            t.command_log()[2],
            VendorCommand::WriteBurst {
                opcode: 0xD3,
                cells: 64
            }
        );
    }

    #[test]
    fn step_offsets_reach_past_the_neighbor_centerline() {
        // ±30% of pitch + widened bubble must expose the neighbor's
        // near guard band — cross-track sterilization.
        let geo = TrackGeometry::default();
        let plan = WritePlan::default_plan(64);
        let far = 0.30 * geo.track_pitch_nm + geo.core_half_width_nm();
        let field_far = plan.hard_switch_field_at(&geo, far);
        assert!(
            field_far > geo.hc_median,
            "field {field_far} at {far} nm must still exceed coercivity"
        );
    }
}
