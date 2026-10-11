//! Real Linux NVMe admin-passthrough transport (`NVME_IOCTL_ADMIN_CMD`).
//!
//! This is the bridge between the codec layer's 64-byte CDW wire format
//! (`NvmeCodec::encode_*`) and the kernel ioctl on the controller character
//! device (`/dev/nvmeN`). It exists precisely so that `NvmePurgeClient` and
//! the health/identify probers run against real controllers, not only test
//! transports.
//!
//! Wire format (16 little-endian dwords), as emitted by dc-hw's `NvmeCodec`:
//! ```text
//!   bytes  0..4   dword 0:  [0]=opcode, [1]=flags, [2..4]=rsvd
//!   bytes  4..8   dword 1:  nsid
//!   bytes  8..16  dword 2-3: cdw2, cdw3 (unused by our codecs)
//!   bytes 40..44  dword 10:  cdw10
//!   bytes 44..64  dword 11-15: cdw11..cdw15
//! ```
//! Everything else is zero; the transport derives `data_len` from the opcode
//! (Get Log Page: NUMDL from CDW10[31:16]; Identify: 4096; Format/Sanitize: 0).

use crate::transport::{ErrnoClassifier, IoctlTaxonomy, NvmeAdminTransport};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// `struct nvme_passthru_cmd` from the kernel's `<linux/nvme.h>`, reproduced
/// field-for-field. Layout is part of the kernel UAPI and frozen.
#[repr(C)]
struct NvmePassthruCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

const _: () = assert!(std::mem::size_of::<NvmePassthruCmd>() == 72);

/// `NVME_IOCTL_ADMIN_CMD` = `_IOWR('N', 0x41, struct nvme_passthru_cmd)`
/// = (3 << 30) | (72 << 16) | ('N' << 8) | 0x41.
const NVME_IOCTL_ADMIN_CMD: libc::c_ulong = 0xC0484E41;

// Admin opcodes we know how to size (see module docs).
const OPC_GET_LOG_PAGE: u8 = 0x02;
const OPC_IDENTIFY: u8 = 0x06;
const OPC_FORMAT_NVM: u8 = 0x80;
const OPC_SANITIZE: u8 = 0x84;

/// Derive the data-phase length for a wire-format command from its opcode.
///
/// SECURITY: the length never comes from untrusted input; it is derived from
/// the opcode and the NUMDL the codec itself encoded.
pub fn data_len_for(cmd: &[u8; 64]) -> usize {
    match cmd[0] {
        OPC_GET_LOG_PAGE => {
            let cdw10 = u32::from_le_bytes([cmd[40], cmd[41], cmd[42], cmd[43]]);
            ((cdw10 >> 16) as usize + 1) * 4
        }
        OPC_IDENTIFY => 4096,
        _ => 0, // Format NVM / Sanitize carry no data phase
    }
}

/// Timeout class for the opcode: Format NVM without IMMED may legitimately
/// run for a long time; everything else gets a generous-but-bounded budget.
fn timeout_ms_for(opcode: u8) -> u32 {
    match opcode {
        OPC_FORMAT_NVM => 3_600_000, // 1 hour: crypto/user-data erase can take that long
        OPC_SANITIZE => 120_000,     // admin submission only; completion is polled via Log 0x81
        _ => 60_000,
    }
}

/// A real controller char-device handle (`/dev/nvme0`), O_RDWR.
#[derive(Debug)]
pub struct LinuxNvmeAdmin {
    dev: File,
    path: PathBuf,
}

impl LinuxNvmeAdmin {
    /// Open the controller character device (e.g. `/dev/nvme0`) with O_RDWR.
    pub fn open(controller_char_dev: &Path) -> Result<Self, IoctlTaxonomy> {
        let dev = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(controller_char_dev)
            .map_err(|e| ErrnoClassifier::classify(e.raw_os_error().unwrap_or(5)))?;
        Ok(Self {
            dev,
            path: controller_char_dev.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl NvmeAdminTransport for LinuxNvmeAdmin {
    fn admin_passthrough(&mut self, cmd: &[u8; 64]) -> Result<Vec<u8>, IoctlTaxonomy> {
        let data_len = data_len_for(cmd);
        let mut data = vec![0u8; data_len];

        let cdw10 = u32::from_le_bytes([cmd[40], cmd[41], cmd[42], cmd[43]]);
        let cdw11 = u32::from_le_bytes([cmd[44], cmd[45], cmd[46], cmd[47]]);
        let cdw12 = u32::from_le_bytes([cmd[48], cmd[49], cmd[50], cmd[51]]);
        let cdw13 = u32::from_le_bytes([cmd[52], cmd[53], cmd[54], cmd[55]]);
        let cdw14 = u32::from_le_bytes([cmd[56], cmd[57], cmd[58], cmd[59]]);
        let cdw15 = u32::from_le_bytes([cmd[60], cmd[61], cmd[62], cmd[63]]);

        let pt = NvmePassthruCmd {
            opcode: cmd[0],
            flags: cmd[1],
            rsvd1: 0,
            nsid: u32::from_le_bytes([cmd[4], cmd[5], cmd[6], cmd[7]]),
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            addr: data.as_mut_ptr() as u64,
            metadata_len: 0,
            data_len: data_len as u32,
            cdw10,
            cdw11,
            cdw12,
            cdw13,
            cdw14,
            cdw15,
            timeout_ms: timeout_ms_for(cmd[0]),
            result: 0,
        };

        let ret =
            unsafe { libc::ioctl(self.dev.as_raw_fd(), NVME_IOCTL_ADMIN_CMD, &pt as *const _) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            return Err(ErrnoClassifier::classify(errno));
        }
        Ok(data)
    }
}

/// Map a block namespace path (`/dev/nvme0n1`) to its controller char device
/// (`/dev/nvme0`). Pure string surgery; the caller still opens with O_EXCL
/// discipline on the block node separately.
pub fn controller_char_dev_for(block_ns: &Path) -> PathBuf {
    let s = block_ns.to_string_lossy();
    let s = s.trim_end_matches('/');
    // strip trailing "/n<digits>"
    if let Some(pos) = s.rfind("n") {
        if s[pos + 1..].chars().all(|c| c.is_ascii_digit()) && pos > s.rfind('/').unwrap_or(0) {
            return PathBuf::from(&s[..pos]);
        }
    }
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use dc_hw::NvmeCodec;

    #[test]
    fn passthru_struct_layout_is_kernel_frozen() {
        // Offset assertions pin the UAPI layout this transport depends on.
        assert_eq!(std::mem::offset_of!(NvmePassthruCmd, opcode), 0);
        assert_eq!(std::mem::offset_of!(NvmePassthruCmd, nsid), 4);
        assert_eq!(std::mem::offset_of!(NvmePassthruCmd, addr), 24);
        assert_eq!(std::mem::offset_of!(NvmePassthruCmd, data_len), 36);
        assert_eq!(std::mem::offset_of!(NvmePassthruCmd, cdw10), 40);
        assert_eq!(std::mem::offset_of!(NvmePassthruCmd, timeout_ms), 64);
        assert_eq!(std::mem::size_of::<NvmePassthruCmd>(), 72);
        assert_eq!(NVME_IOCTL_ADMIN_CMD, 0xC0484E41);
    }

    #[test]
    fn data_len_derivation_matches_codec_encoding() {
        let log = NvmeCodec::encode_get_sanitize_status_log();
        assert_eq!(data_len_for(&log), 512);
        let health = NvmeCodec::encode_get_health_log();
        assert_eq!(data_len_for(&health), 512);
        let idc = NvmeCodec::encode_identify_controller();
        assert_eq!(data_len_for(&idc), 4096);
        let idn = NvmeCodec::encode_identify_namespace(3);
        assert_eq!(data_len_for(&idn), 4096);
        let fmt = NvmeCodec::encode_format_nvm(3, dc_hw::NvmeSecureEraseSetting::CryptoErase, 0);
        assert_eq!(data_len_for(&fmt), 0);
        let san = NvmeCodec::encode_sanitize(dc_hw::NvmeSanitizeAction::CryptoErase, false);
        assert_eq!(data_len_for(&san), 0);
    }

    #[test]
    fn timeout_class_per_opcode() {
        assert_eq!(timeout_ms_for(OPC_FORMAT_NVM), 3_600_000);
        assert_eq!(timeout_ms_for(OPC_SANITIZE), 120_000);
        assert_eq!(timeout_ms_for(OPC_GET_LOG_PAGE), 60_000);
    }

    #[test]
    fn controller_char_dev_mapping() {
        assert_eq!(
            controller_char_dev_for(Path::new("/dev/nvme0n3")),
            PathBuf::from("/dev/nvme0")
        );
        assert_eq!(
            controller_char_dev_for(Path::new("/dev/nvme12n1")),
            PathBuf::from("/dev/nvme12")
        );
        // No namespace suffix: unchanged (caller passed a char dev already).
        assert_eq!(
            controller_char_dev_for(Path::new("/dev/nvme0")),
            PathBuf::from("/dev/nvme0")
        );
        // Non-NVMe path: unchanged.
        assert_eq!(
            controller_char_dev_for(Path::new("/dev/sda")),
            PathBuf::from("/dev/sda")
        );
    }

    #[test]
    fn open_missing_device_fails_with_transport_fault() {
        let res = LinuxNvmeAdmin::open(Path::new("/definitely/not/a/chardev/nvme999"));
        match res {
            Err(IoctlTaxonomy::TransportFault { .. } | IoctlTaxonomy::UnmappedLoud { .. }) => {}
            other => panic!("expected failure for missing device, got {:?}", other),
        }
    }
}
