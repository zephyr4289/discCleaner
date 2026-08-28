use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub struct UevFire;

impl UevFire {
    /// Fire a kernel KOBJ_CHANGE uevent on a block device by writing "change" to sysfs (Δ31, §5.2).
    /// Pure file write, zero external subprocesses.
    pub fn fire_change_event(kernel_name: &str) -> Result<(), String> {
        let uevent_path = format!("/sys/block/{}/uevent", kernel_name);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&uevent_path)
            .map_err(|e| format!("Failed to open {}: {}", uevent_path, e))?;

        file.write_all(b"change\n")
            .map_err(|e| format!("Failed to write change event to {}: {}", uevent_path, e))?;

        file.flush().map_err(|e| e.to_string())?;

        // Allow kernel & udev workers 200ms to process event
        std::thread::sleep(std::time::Duration::from_millis(200));

        Ok(())
    }
}
