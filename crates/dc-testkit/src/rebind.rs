use crate::dm::{DmDevice, TableLine};
use std::path::Path;

pub struct RebindChoreographer;

impl RebindChoreographer {
    /// Rebind DM device: remove existing dm mapping, and recreate with new UUID over new backing device.
    pub fn rebind_dm_device(
        name: &str,
        new_uuid: &str,
        new_backing_minor: u32,
        size_sectors: u64,
    ) -> Result<DmDevice, String> {
        let mut dm = DmDevice::create(name, new_uuid)?;
        let table = vec![TableLine::Linear {
            start_sector: 0,
            length_sectors: size_sectors,
            backing_major: 7, // Loop major
            backing_minor: new_backing_minor,
            backing_start_sector: 0,
        }];
        dm.swap_table(&table)?;
        Ok(dm)
    }
}
