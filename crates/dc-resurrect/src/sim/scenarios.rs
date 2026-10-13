//! Dead-drive builder and the sim link: the object the rig's engines
//! actually drive. One struct implements all three transports plus the
//! bench-power control, so a mission can migrate between transports the
//! way an operator would — UART first, SWD if the strap's missing, JTAG
//! pins when everything else is locked.

use super::target::{ScenarioKind, SimTarget};
use crate::hal::{JtagLink, LinkError, RigPower, SwdLink, UartLink};
use crate::nand::{NandDie, NandGeometry};
use crate::rng::XorShift;
use crate::vendors::ControllerProfile;

/// Default demo geometry: a small-but-real SATA SSD (256 MB class).
pub fn demo_geometry() -> NandGeometry {
    NandGeometry::new(2048, 64, 64, 512, 2)
}

/// The rig's connection to one dead drive.
pub struct SimLink {
    pub target: SimTarget,
    /// Scenario metadata the rig reports.
    pub label: String,
}

impl SimLink {
    /// Build a dead drive: scenario knobs, seeded NAND contents (with
    /// factory bad blocks and marginal erase blocks), optional injected
    /// stuck block for fault-path testing.
    pub fn build(
        scenario: ScenarioKind,
        profile: ControllerProfile,
        geometry: NandGeometry,
        seed: u64,
        stuck: Option<(usize, u32)>,
    ) -> SimLink {
        let mut rng = XorShift::new(seed);
        let dies: Vec<NandDie> = (0..geometry.luns)
            .map(|i| {
                // One package: every CE shares the same device READ-ID.
                let id = [0x98, 0xDE, 0x94, 0x32, 0x76];
                let mut die = NandDie::new(geometry, id, &mut rng);
                if let Some((sdie, sblock)) = stuck
                    && sdie == i as usize
                {
                    die.inject_stuck(sblock);
                }
                die
            })
            .collect();
        let target = SimTarget::new(profile, scenario, dies, rng);
        SimLink {
            target,
            label: format!("sim:{}", scenario.name()),
        }
    }
}

impl JtagLink for SimLink {
    fn tck(&mut self, tms: bool, tdi: bool) -> bool {
        self.target.jtag_tck(tms, tdi)
    }
    fn service(&mut self) {
        self.target.service();
    }
}

impl SwdLink for SimLink {
    fn swd_host_bit(&mut self, bit: bool) {
        self.target.swd_host_bit(bit);
    }
    fn swd_target_bit(&mut self) -> bool {
        self.target.swd_target_bit()
    }
    fn swd_trn(&mut self) {
        self.target.swd_trn();
    }
    fn service(&mut self) {
        self.target.service();
    }
}

impl UartLink for SimLink {
    fn write_byte(&mut self, b: u8) -> Result<(), LinkError> {
        self.target.uart_rx(b);
        Ok(())
    }
    fn read_byte_timeout(&mut self, _ms: u32) -> Result<Option<u8>, LinkError> {
        Ok(self.target.uart_read())
    }
    fn service(&mut self) {
        self.target.service();
    }
}

impl RigPower for SimLink {
    fn rig_apply_power(&mut self) -> Result<(), LinkError> {
        self.target.rig_apply_power();
        Ok(())
    }
    fn rig_power_good(&self) -> bool {
        self.target.rails_alive
    }
}
