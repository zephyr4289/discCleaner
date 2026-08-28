use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageSignature {
    LvmLabel { offset: u64 },
    Luks { version: u16 },
    Swap { version: u32 },
    MdRaid { version: String },
    GptMbr,
}

pub struct Sniffer;

impl Sniffer {
    /// Bounded sniff read plan (Δ124) reading <= 20 KiB total per device node.
    pub fn sniff_device(path: &Path) -> Option<StorageSignature> {
        let mut file = File::open(path).ok()?;
        let total_size = file.metadata().ok()?.len();

        if total_size < 4096 {
            return None;
        }

        // 1. Read first 4 KiB (LBA0 + LVM sectors 0..3 + LUKS header + Swap header)
        let mut head = [0u8; 4096];
        if file.read_exact(&mut head).is_err() {
            return None;
        }

        // Check LVM label (LABELONE in first 4 sectors)
        for s in 0..4 {
            let offset = s * 512;
            if &head[offset..offset + 8] == b"LABELONE" {
                return Some(StorageSignature::LvmLabel { offset: offset as u64 });
            }
        }

        // Check LUKS magic ("LUKS\xba\xbe")
        if &head[0..6] == b"LUKS\xba\xbe" {
            let ver = u16::from_be_bytes(head[6..8].try_into().unwrap_or([0, 1]));
            return Some(StorageSignature::Luks { version: ver });
        }

        // Check Swap magic ("SWAPSPACE2" at page offset 4086 or offset in 4K)
        if head.windows(10).any(|w| w == b"SWAPSPACE2") {
            return Some(StorageSignature::Swap { version: 2 });
        }

        // 2. Read tail 4 KiB if size > 8192 (for MD RAID v1.2 superblock)
        if total_size >= 8192 {
            if file.seek(SeekFrom::End(-4096)).is_ok() {
                let mut tail = [0u8; 4096];
                if file.read_exact(&mut tail).is_ok() {
                    // MD superblock magic: 0xa92b4efc in little-endian
                    if tail.windows(4).any(|w| w == &[0xfc, 0x4e, 0x2b, 0xa9]) {
                        return Some(StorageSignature::MdRaid { version: "1.2".to_string() });
                    }
                }
            }
        }

        // Check GPT protective MBR at LBA0
        if head[510] == 0x55 && head[511] == 0xAA {
            return Some(StorageSignature::GptMbr);
        }

        None
    }
}
