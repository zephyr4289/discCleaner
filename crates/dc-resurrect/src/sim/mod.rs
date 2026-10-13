//! The simulated dead drive: device-side protocols, reference core, and
//! the rig link that implements every transport.

pub mod core;
pub mod nand_ctrl;
pub mod scenarios;
pub mod target;

pub use scenarios::{SimLink, demo_geometry};
pub use target::ScenarioKind;
