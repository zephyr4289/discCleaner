use std::io::{self, Write};
use std::process::Command;

fn try_nvme_sanitize(device_path: &str) -> std::io::Result<bool> {
    let check = Command::new("nvme").args(["sanitize-log", device_path]).output()?;
    if !check.status.success() {
        println!("NVMe Sanitize not supported on this device, falling back to software wipe.");
        return Ok(false);
    }

    println!("Starting NVMe Sanitize (crypto erase)...");
    let status = Command::new("nvme")
        .args(["sanitize", device_path, "-a", "4"])
        .status()?;

    if !status.success() {
        println!("nvme sanitize command failed, falling back to software wipe.");
        return Ok(false);
    }

    loop {
        let log = Command::new("nvme").args(["sanitize-log", device_path]).output()?;
        let out = String::from_utf8_lossy(&log.stdout);
        if out.contains("Sanitize Completed") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
        print!(".");
        io::stdout().flush().ok();
    }
    println!("\nNVMe Sanitize complete.");
    Ok(true)
}

fn try_ata_secure_erase(device_path: &str) -> io::Result<bool> {
    let info = Command::new("hdparm").args(["-I", device_path]).output()?;
    let info_str = String::from_utf8_lossy(&info.stdout);

    if !info_str.contains("supported: enhanced erase") && !info_str.contains("Security:") {
        println!("ATA Secure Erase not supported, falling back to software wipe.");
        return Ok(false);
    }
    if info_str.contains("frozen") {
        println!("Drive is frozen (BIOS/kernel locked security state).");
        println!("Common fix: suspend and resume the machine, or hot-unplug/replug the drive, then retry.");
        return Ok(false);
    }

    let pass = "p";

    println!("Setting temporary security password...");
    let set_pass = Command::new("hdparm")
        .args(["--user-master", "u", "--security-set-pass", pass, device_path])
        .status()?;
    if !set_pass.success() {
        return Ok(false);
    }

    println!("Issuing security erase (this can take a while)...");
    let erase = Command::new("hdparm")
        .args(["--user-master", "u", "--security-erase", pass, device_path])
        .status()?;

    if !erase.success() {
        println!("hdparm secure erase failed, falling back to software wipe.");
        return Ok(false);
    }

    println!("ATA Secure Erase complete.");
    Ok(true)
}

pub fn try_secure_erase(device_path: &str) -> std::io::Result<bool> {
    if device_path.contains("nvme") {
        try_nvme_sanitize(device_path)
    }
    else {
        try_ata_secure_erase(device_path)
    }
}
