use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};

pub fn full_zero_wipe(device_path: &str) -> std::io::Result<()> {
    let mut drive = OpenOptions::new().write(true).open(device_path)?;
    let size = super::get_block_device_size(&drive)?;

    const CHUNK_SIZE: usize = 1024 * 1024;
    let buf = vec![0u8; CHUNK_SIZE];

    drive.seek(SeekFrom::Start(0))?;
    let mut written: u64 = 0;

    while written < size {
        let remaining = size - written;
        let chunk = if remaining < buf.len() as u64 {
            &buf[..remaining as usize]
        }
        else {
            &buf[..]
        };

        drive.write_all(chunk)?;
        written += chunk.len() as u64;

        println!("\rWiped {} / {} bytes", written, size);
        std::io::stdout().flush().ok();
    }

    drive.sync_all()?;
    println!("\nZero-fill wipe complete.");
    Ok(())
}
