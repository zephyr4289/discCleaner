use std::env;
use std::fs::OpenOptions;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::io::Error;

mod erase_methods;
mod wipe_methods;

#[cfg(target_os = "linux")]
pub fn get_block_device_size(file: &File) -> std::io::Result<u64> {
    let mut size: u64 = 0;

    let fd = file.as_raw_fd();

    unsafe {
        if libc::ioctl(fd, 0x80081272, &mut size) == 0 {
            Ok(size)
        }
        else {
            Err(Error::last_os_error())
        }
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 || args[1] != "--wipe" {
        println!("Check lsblk to check drives available");
        println!("Usage:");
        println!("sudo {} --wipe /dev/sdX", args[0]);
        return Ok(());
    }

    let device_path = &args[2];
    
    println!("You have selected: {}", args[2]);
    println!("Are you sure you want to wipe selected drive? (y/n)");
    let mut confirm = String::new();
    std::io::stdin()
        .read_line(&mut confirm)
        .expect("failed to read line");

    if confirm.trim().to_lowercase() == "n" {
        return Ok(());
    }

    let mut options = OpenOptions::new();
    let drive = options.write(true).open(device_path).expect("failed to open device");

    println!("Drive size: {}", get_block_device_size(&drive).expect("failed to get size"));

    if erase_methods::try_secure_erase(device_path)? {
        println!("Drive sanitized at firmware level. Data is unrecoverable through normal or lab-grade means, where the drive's implementation is trustworthy.");
    }
    else {
        println!("Falling back to full logical overwrite...");
        wipe_methods::full_zero_wipe(device_path)?;
        println!("Drive overwritten. Data is unrecoverable through normal means.");
    }

    Ok(())
}
