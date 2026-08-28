use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

pub struct SigCraft;

impl SigCraft {
    /// Write LVM2 physical volume label at sector 1 (offset 512).
    /// Citation: linux/drivers/md/dm-ioctl.h, LVM2 label header definition.
    pub fn craft_lvm2_label(target_path: &Path) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(target_path)
            .map_err(|e| e.to_string())?;

        file.seek(SeekFrom::Start(512)).map_err(|e| e.to_string())?;
        let mut block = vec![0u8; 512];
        block[0..8].copy_from_slice(b"LABELONE");
        block[24..32].copy_from_slice(b"LVM2 001");
        file.write_all(&block).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Write md v1.2 RAID superblock at offset 4096.
    /// Citation: linux/include/uapi/linux/raid/md_p.h (MD_SB_MAGIC = 0xa92b4efc).
    pub fn craft_md_superblock(target_path: &Path) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(target_path)
            .map_err(|e| e.to_string())?;

        file.seek(SeekFrom::Start(4096)).map_err(|e| e.to_string())?;
        let mut block = vec![0u8; 512];
        let magic: u32 = 0xa92b4efc;
        block[0..4].copy_from_slice(&magic.to_le_bytes());
        file.write_all(&block).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Write SWAPSPACE2 signature at offset 4086 (last 10 bytes of page 0).
    /// Citation: linux/include/linux/swap.h ("SWAPSPACE2").
    pub fn craft_swap_signature(target_path: &Path) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(target_path)
            .map_err(|e| e.to_string())?;

        file.seek(SeekFrom::Start(4086)).map_err(|e| e.to_string())?;
        file.write_all(b"SWAPSPACE2").map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Write LUKS cryptographic container magic at offset 0.
    /// Citation: cryptsetup/lib/luks1/luks.h ("LUKS\xba\xbe").
    pub fn craft_luks_magic(target_path: &Path) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(target_path)
            .map_err(|e| e.to_string())?;

        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut luks_hdr = vec![0u8; 512];
        luks_hdr[0..6].copy_from_slice(b"LUKS\xba\xbe");
        file.write_all(&luks_hdr).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Write ext4 superblock magic at offset 1080 (0x400 + 0x38).
    /// Citation: linux/fs/ext4/ext4.h (EXT4_SUPER_MAGIC = 0xEF53).
    pub fn craft_ext4_superblock(target_path: &Path) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(target_path)
            .map_err(|e| e.to_string())?;

        file.seek(SeekFrom::Start(1080)).map_err(|e| e.to_string())?;
        let magic: u16 = 0xef53;
        file.write_all(&magic.to_le_bytes()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    }
}
