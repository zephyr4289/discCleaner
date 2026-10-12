//! Production MMIO backend: maps the CXL device register block from a
//! PCI BAR resource file and serves the mailbox register view.
//!
//! Safety model: `/sys/bus/pci/devices/<bdf>/resource<N>` is mmap(2)'d
//! read/write for exactly the register-block window (page-aligned,
//! length-clamped). All access is through volatile reads/writes to
//! prevent the compiler from tearing or eliding MMIO side effects.

use crate::mailbox::{MailboxBackend, MailboxError};
use crate::regs;
use std::fs::OpenOptions;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicU64, Ordering};

/// Volatile MMIO window over one BAR resource file.
pub struct MmioWindow {
    mapping: *mut u8,
    len: usize,
    /// base offset inside the mapping where the device register block
    /// starts (BAR-relative).
    block_base: usize,
}

// SAFETY: the mapping is owned exclusively by this object (created in
// `MmioWindow::open`, never aliased); cross-thread use is behind &mut
// via the mailbox engine which owns the window.
unsafe impl Send for MmioWindow {}

impl MmioWindow {
    /// Map `len` bytes at `offset` of `resource_path`.
    ///
    /// # Safety contract (caller)
    /// * `resource_path` must be the sysfs resource file of the target
    ///   PCI function, and the process must hold permission to mmap it
    ///   read/write (root or appropriate udev group).
    pub fn open(
        resource_path: &std::path::Path,
        offset: u64,
        len: u64,
    ) -> Result<Self, MailboxError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(resource_path)
            .map_err(|e| {
                MailboxError::Backend(format!("open {}: {}", resource_path.display(), e))
            })?;
        let page = 4096u64;
        let map_off = (offset / page) * page;
        let delta = (offset % page) as usize;
        let map_len = ((offset % page) + len).div_ceil(page) * page;
        let map_len = map_len as usize;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_fd().as_raw_fd(),
                map_off as libc::off_t,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(MailboxError::Backend("mmap failed".into()));
        }
        Ok(Self {
            mapping: ptr as *mut u8,
            len: map_len,
            block_base: delta,
        })
    }

    fn read_u64(&self, off: u64) -> Result<u64, MailboxError> {
        let idx = self.block_base + off as usize;
        if idx + 8 > self.len {
            return Err(MailboxError::Backend(format!(
                "MMIO read out of window: {:#x}",
                off
            )));
        }
        let cell = unsafe { &*(self.mapping.add(idx) as *const AtomicU64) };
        Ok(cell.load(Ordering::Relaxed))
    }

    fn write_u64(&mut self, off: u64, v: u64) -> Result<(), MailboxError> {
        let idx = self.block_base + off as usize;
        if idx + 8 > self.len {
            return Err(MailboxError::Backend(format!(
                "MMIO write out of window: {:#x}",
                off
            )));
        }
        let cell = unsafe { &*(self.mapping.add(idx) as *const AtomicU64) };
        cell.store(v, Ordering::Relaxed);
        Ok(())
    }

    fn read_bytes(&self, off: u64, buf: &mut [u8]) -> Result<(), MailboxError> {
        let base = self.block_base + off as usize;
        if base + buf.len() > self.len {
            return Err(MailboxError::Backend("payload read out of window".into()));
        }
        for (i, slot) in buf.iter_mut().enumerate() {
            let cell = unsafe { &*(self.mapping.add(base + i) as *const AtomicU64) };
            let b = (cell.load(Ordering::Relaxed) & 0xff) as u8;
            *slot = b;
        }
        Ok(())
    }

    fn write_bytes(&mut self, off: u64, data: &[u8]) -> Result<(), MailboxError> {
        let base = self.block_base + off as usize;
        if base + data.len() > self.len {
            return Err(MailboxError::Backend("payload write out of window".into()));
        }
        for (i, byte) in data.iter().enumerate() {
            let cell = unsafe { &*(self.mapping.add(base + i) as *const AtomicU64) };
            cell.store(u64::from(*byte), Ordering::Relaxed);
        }
        Ok(())
    }
}

impl Drop for MmioWindow {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mapping as *mut libc::c_void, self.len);
        }
    }
}

/// Mailbox backend over a real MMIO window.
pub struct MmioBackend {
    window: MmioWindow,
    base: u64,
}

impl std::fmt::Debug for MmioBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MmioBackend(base={:#x})", self.base)
    }
}

impl MmioBackend {
    /// Build the backend for a device register block mapped at `window`
    /// (already positioned at the register block base); `base` is the
    /// mailbox offset inside it (normally [`regs::MBOX_OFFSET`]).
    pub fn new(window: MmioWindow, base: u64) -> Self {
        Self { window, base }
    }
}

impl MailboxBackend for MmioBackend {
    fn read_reg(&mut self, reg_off: u64) -> Result<u64, MailboxError> {
        self.window.read_u64(self.base + reg_off)
    }

    fn write_reg(&mut self, reg_off: u64, value: u64) -> Result<(), MailboxError> {
        self.window.write_u64(self.base + reg_off, value)
    }

    fn read_payload(&mut self, off: usize, buf: &mut [u8]) -> Result<(), MailboxError> {
        self.window
            .read_bytes(self.base + regs::MBOX_PAYLOAD + off as u64, buf)
    }

    fn write_payload(&mut self, off: usize, data: &[u8]) -> Result<(), MailboxError> {
        self.window
            .write_bytes(self.base + regs::MBOX_PAYLOAD + off as u64, data)
    }
}
