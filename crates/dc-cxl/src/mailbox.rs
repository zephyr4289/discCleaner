//! CXL Memory Device Mailbox protocol engine.
//!
//! The engine drives the mailbox state machine defined by CXL 2.0
//! §8.2.8.4: write payload → write command register (opcode + length)
//! → poll status.busy until clear → read return code → read response
//! payload. Background commands (Sanitize) additionally poll the
//! Background Command Status register until percent-complete reaches
//! 100 and the return code lands.
//!
//! All MMIO access goes through the [`MailboxBackend`] trait — the
//! production backend maps the device register block via
//! [`crate::mmio`], while [`MockCxlDevice`] simulates a full Type 3
//! device (including the background sanitize progress telemetry) for
//! tests and drills.

use crate::regs;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MailboxError {
    #[error("device returned {0:#06x} ({1})")]
    ReturnCode(u16, &'static str),
    #[error("mailbox still busy after {0:?} (command {1:#06x})")]
    Timeout(Duration, u16),
    #[error("background command {0:#06x} failed: {1:#06x} ({2})")]
    BackgroundFailed(u16, u16, &'static str),
    #[error("payload too large: {0} > {1} bytes")]
    PayloadTooLarge(usize, usize),
    #[error("response payload length {0} exceeds mailbox size {1}")]
    ResponseTooLarge(usize, usize),
    #[error("backend I/O error: {0}")]
    Backend(String),
    #[error("sanitize already in progress (retry after completion)")]
    SanitizeInProgress,
}

/// Result of one completed mailbox command.
#[derive(Debug, Clone)]
pub struct MailboxReply {
    pub opcode: u16,
    pub return_code: u16,
    pub payload: Vec<u8>,
}

/// MMIO view of one mailbox register (read/write u64).
pub trait MailboxBackend: std::fmt::Debug {
    fn read_reg(&mut self, reg_off: u64) -> Result<u64, MailboxError>;
    fn write_reg(&mut self, reg_off: u64, value: u64) -> Result<(), MailboxError>;
    fn read_payload(&mut self, off: usize, buf: &mut [u8]) -> Result<(), MailboxError>;
    fn write_payload(&mut self, off: usize, data: &[u8]) -> Result<(), MailboxError>;
    fn payload_capacity(&self) -> usize {
        regs::MBOX_PAYLOAD_SIZE
    }
    /// Poll cadence override for the mock (tests want speed).
    fn poll_interval(&self) -> Duration {
        Duration::from_millis(50)
    }
}

/// The protocol engine. `D` is the backend.
pub struct Mailbox<D: MailboxBackend> {
    backend: D,
    /// Hard ceiling for foreground polls.
    pub command_timeout: Duration,
    /// Hard ceiling for background operations (sanitize can run for
    /// tens of minutes on large media).
    pub background_timeout: Duration,
}

impl<D: MailboxBackend> Mailbox<D> {
    pub fn new(backend: D) -> Self {
        Self {
            backend,
            command_timeout: Duration::from_secs(10),
            background_timeout: Duration::from_secs(24 * 3600),
        }
    }

    pub fn backend(&self) -> &D {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut D {
        &mut self.backend
    }

    /// Issue one foreground command.
    pub fn execute(&mut self, opcode: u16, payload: &[u8]) -> Result<MailboxReply, MailboxError> {
        if payload.len() > self.backend.payload_capacity() {
            return Err(MailboxError::PayloadTooLarge(
                payload.len(),
                self.backend.payload_capacity(),
            ));
        }
        // 1. payload in
        self.backend.write_payload(0, payload)?;
        // 2. command register: opcode | (len << 32)
        let cmd = u64::from(opcode) | (u64::from(payload.len() as u32) << 32);
        self.backend.write_reg(regs::MBOX_COMMAND, cmd)?;
        // 3. poll busy
        let started = Instant::now();
        loop {
            let status = self.backend.read_reg(regs::MBOX_STATUS)?;
            if status & 0x1 == 0 {
                // Return code lives at [31:16]; bit 0 is the busy flag
                // (keeps odd return codes like 0x0b unambiguous).
                let rc = ((status >> 16) & 0xffff) as u16;
                if rc == regs::RC_SANITIZE_IN_PROGRESS {
                    return Err(MailboxError::SanitizeInProgress);
                }
                if rc != regs::RC_SUCCESS {
                    return Err(MailboxError::ReturnCode(rc, regs::return_code_name(rc)));
                }
                // 4. read response payload (identify etc.)
                // We cannot know the response length from the status
                // register (the spec reports it in the command register's
                // length field post-completion); read the full mailbox.
                let cap = self.backend.payload_capacity();
                let mut buf = vec![0u8; cap];
                self.backend.read_payload(0, &mut buf)?;
                return Ok(MailboxReply {
                    opcode,
                    return_code: rc,
                    payload: buf,
                });
            }
            if started.elapsed() > self.command_timeout {
                return Err(MailboxError::Timeout(self.command_timeout, opcode));
            }
            std::thread::sleep(self.backend.poll_interval());
        }
    }

    /// Issue a background command (Sanitize) and poll until completion.
    /// Returns the final background return code and the completion
    /// telemetry collected along the way.
    pub fn execute_background(
        &mut self,
        opcode: u16,
        payload: &[u8],
    ) -> Result<BackgroundReport, MailboxError> {
        if payload.len() > self.backend.payload_capacity() {
            return Err(MailboxError::PayloadTooLarge(
                payload.len(),
                self.backend.payload_capacity(),
            ));
        }
        self.backend.write_payload(0, payload)?;
        let cmd = u64::from(opcode) | (u64::from(payload.len() as u32) << 32);
        self.backend.write_reg(regs::MBOX_COMMAND, cmd)?;
        let started = Instant::now();
        let mut samples: Vec<(u64, u8)> = Vec::new(); // (elapsed_ms, percent)
        loop {
            let status = self.backend.read_reg(regs::MBOX_STATUS)?;
            let busy = status & 0x1 != 0;
            let rc = ((status >> 16) & 0xffff) as u16;
            if !busy {
                // Foreground-style completion (device may finish small
                // sanitizes without ever reporting "background started").
                if rc == regs::RC_SUCCESS {
                    return Ok(BackgroundReport {
                        opcode,
                        return_code: rc,
                        samples,
                        completed_in: started.elapsed(),
                    });
                }
                if rc == regs::RC_SANITIZE_IN_PROGRESS {
                    // Busy in the background; keep polling.
                    let bg = self.poll_background(opcode, started, &mut samples)?;
                    return Ok(bg);
                }
                return Err(MailboxError::ReturnCode(rc, regs::return_code_name(rc)));
            }
            // Busy: poll the background status register for progress.
            let bg = self.backend.read_reg(regs::MBOX_BG_STATUS)?;
            let percent = ((bg >> 16) & 0xff) as u8;
            samples.push((started.elapsed().as_millis() as u64, percent));
            if started.elapsed() > self.background_timeout {
                return Err(MailboxError::Timeout(self.background_timeout, opcode));
            }
            std::thread::sleep(self.backend.poll_interval());
        }
    }

    fn poll_background(
        &mut self,
        opcode: u16,
        started: Instant,
        samples: &mut Vec<(u64, u8)>,
    ) -> Result<BackgroundReport, MailboxError> {
        loop {
            let bg = self.backend.read_reg(regs::MBOX_BG_STATUS)?;
            let percent = ((bg >> 16) & 0xff) as u8;
            samples.push((started.elapsed().as_millis() as u64, percent));
            if percent >= 100 {
                // Final return code from the status register [31:16].
                let status = self.backend.read_reg(regs::MBOX_STATUS)?;
                let effective = ((status >> 16) & 0xffff) as u16;
                if effective != regs::RC_SUCCESS {
                    return Err(MailboxError::BackgroundFailed(
                        opcode,
                        effective,
                        regs::return_code_name(effective),
                    ));
                }
                return Ok(BackgroundReport {
                    opcode,
                    return_code: effective,
                    samples: std::mem::take(samples),
                    completed_in: started.elapsed(),
                });
            }
            if started.elapsed() > self.background_timeout {
                return Err(MailboxError::Timeout(self.background_timeout, opcode));
            }
            std::thread::sleep(self.backend.poll_interval());
        }
    }
}

/// Telemetry from a background (sanitize) command: progress samples of
/// (elapsed milliseconds, percent complete) plus the final result.
#[derive(Debug, Clone)]
pub struct BackgroundReport {
    pub opcode: u16,
    pub return_code: u16,
    pub samples: Vec<(u64, u8)>,
    pub completed_in: Duration,
}

// ---------------------------------------------------------------------------
// Mock device: a full in-memory CXL Type 3 mailbox simulator
// ---------------------------------------------------------------------------

/// Simulated Type 3 memory device for tests and offline drills. The media
/// model is a byte array; sanitize fills it with 0x00 (the real spec
/// mandates an implementation-defined overwrite pattern — we model the
/// observable post-condition: all bytes zeroed and the sanitize state
/// machine returning success).
#[derive(Debug)]
pub struct MockCxlDevice {
    /// Device register block (MMIO view) — index 0 = offset 0.
    regs: Vec<u64>,
    /// Mailbox payload RAM.
    payload: Vec<u8>,
    /// Simulated media.
    pub media: Vec<u8>,
    /// Whether the NEXT command should be treated as background.
    sanitize_percent: u8,
    sanitize_running: bool,
    /// Progress the mock advances per poll.
    progress_step: u8,
    /// Injected return codes (canned failure testing).
    pub force_return_code: Option<u16>,
    /// Identify payload the device serves.
    pub identify_payload: Vec<u8>,
    /// Fault injection: sanitize completes "successfully" but leaves the
    /// media untouched (verification must catch this).
    pub sanitize_leaves_media: bool,
    /// Records of every command executed (audit trail).
    pub command_log: Vec<(u16, Vec<u8>)>,
}

impl MockCxlDevice {
    pub fn new(media_len: usize) -> Self {
        let mut identify = vec![0u8; regs::IDENTIFY_PAYLOAD_LEN];
        identify[regs::IDENTIFY_SERIAL_OFF..regs::IDENTIFY_SERIAL_OFF + 8]
            .copy_from_slice(b"MOCKCXL1");
        identify[regs::IDENTIFY_CAPACITY_OFF..regs::IDENTIFY_CAPACITY_OFF + 8]
            .copy_from_slice(&(media_len as u64).to_le_bytes());
        Self {
            regs: vec![0u64; 64],
            payload: vec![0u8; regs::MBOX_PAYLOAD_SIZE],
            media: vec![0xa5u8; media_len],
            sanitize_percent: 0,
            sanitize_running: false,
            progress_step: 25,
            force_return_code: None,
            identify_payload: identify,
            sanitize_leaves_media: false,
            command_log: Vec::new(),
        }
    }

    pub fn with_progress_step(mut self, step: u8) -> Self {
        self.progress_step = step.max(1);
        self
    }

    /// Read back a slice of the (post-sanitize) media for verification.
    pub fn media_slice(&self, off: usize, len: usize) -> &[u8] {
        let end = (off + len).min(self.media.len());
        &self.media[off.min(self.media.len())..end]
    }
}

impl MailboxBackend for MockCxlDevice {
    fn read_reg(&mut self, reg_off: u64) -> Result<u64, MailboxError> {
        let idx = (reg_off / 8) as usize;
        if idx >= self.regs.len() {
            return Err(MailboxError::Backend(format!(
                "register {:#x} out of range",
                reg_off
            )));
        }
        // Simulated background progress: advance sanitize on each BG poll.
        let val = self.regs[idx];
        if reg_off == regs::MBOX_BG_STATUS && self.sanitize_running {
            self.sanitize_percent = (self.sanitize_percent + self.progress_step).min(100);
            if self.sanitize_percent >= 100 {
                // finish: zero the media, clear busy (unless fault-injected)
                if !self.sanitize_leaves_media {
                    for b in self.media.iter_mut() {
                        *b = 0;
                    }
                }
                self.sanitize_running = false;
                self.regs[(regs::MBOX_STATUS / 8) as usize] = u64::from(regs::RC_SUCCESS) << 16;
            }
            return Ok(u64::from(self.sanitize_percent) << 16);
        }
        if reg_off == regs::MBOX_STATUS && self.sanitize_running {
            // busy + RC_SANITIZE_IN_PROGRESS at [31:16]
            return Ok(0x1 | (u64::from(regs::RC_SANITIZE_IN_PROGRESS) << 16));
        }
        Ok(val)
    }

    fn write_reg(&mut self, reg_off: u64, value: u64) -> Result<(), MailboxError> {
        let idx = (reg_off / 8) as usize;
        if idx >= self.regs.len() {
            return Err(MailboxError::Backend(format!(
                "register {:#x} out of range",
                reg_off
            )));
        }
        if reg_off == regs::MBOX_COMMAND {
            let opcode = (value & 0xffff) as u16;
            let plen = ((value >> 32) & 0x1ff) as usize;
            self.command_log
                .push((opcode, self.payload[..plen].to_vec()));
            // Decode and execute.
            if let Some(rc) = self.force_return_code {
                self.regs[(regs::MBOX_STATUS / 8) as usize] = u64::from(rc) << 16;
                return Ok(());
            }
            match opcode {
                regs::OP_IDENTIFY => {
                    self.payload[..self.identify_payload.len()]
                        .copy_from_slice(&self.identify_payload);
                    self.regs[(regs::MBOX_STATUS / 8) as usize] = u64::from(regs::RC_SUCCESS) << 16;
                }
                regs::OP_GET_SECURITY_STATE => {
                    self.payload[0] = 0x01; // security enabled, no locks
                    self.regs[(regs::MBOX_STATUS / 8) as usize] = u64::from(regs::RC_SUCCESS) << 16;
                }
                regs::OP_SECURE_ERASE => {
                    // Foreground: instant cryptographic erase in the mock.
                    for b in self.media.iter_mut() {
                        *b = 0;
                    }
                    self.regs[(regs::MBOX_STATUS / 8) as usize] = u64::from(regs::RC_SUCCESS) << 16;
                }
                regs::OP_SANITIZE => {
                    // Background: start the progress machinery (busy flag
                    // set; final rc arrives on completion).
                    self.sanitize_running = true;
                    self.sanitize_percent = 0;
                    self.regs[(regs::MBOX_STATUS / 8) as usize] =
                        0x1 | (u64::from(regs::RC_SANITIZE_IN_PROGRESS) << 16);
                }
                _ => {
                    self.regs[(regs::MBOX_STATUS / 8) as usize] =
                        u64::from(regs::RC_UNSUPPORTED) << 16;
                }
            }
            return Ok(());
        }
        self.regs[idx] = value;
        Ok(())
    }

    fn read_payload(&mut self, off: usize, buf: &mut [u8]) -> Result<(), MailboxError> {
        if off + buf.len() > self.payload.len() {
            return Err(MailboxError::ResponseTooLarge(
                off + buf.len(),
                self.payload.len(),
            ));
        }
        buf.copy_from_slice(&self.payload[off..off + buf.len()]);
        Ok(())
    }

    fn write_payload(&mut self, off: usize, data: &[u8]) -> Result<(), MailboxError> {
        if off + data.len() > self.payload.len() {
            return Err(MailboxError::PayloadTooLarge(
                off + data.len(),
                self.payload.len(),
            ));
        }
        self.payload[off..off + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn poll_interval(&self) -> Duration {
        Duration::from_millis(1) // tests run fast
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_round_trip() {
        let mut mbox = Mailbox::new(MockCxlDevice::new(1024));
        let reply = mbox.execute(regs::OP_IDENTIFY, &[]).unwrap();
        assert_eq!(reply.return_code, regs::RC_SUCCESS);
        assert_eq!(&reply.payload[..8], b"MOCKCXL1");
    }

    #[test]
    fn sanitize_background_completes_and_zeroes_media() {
        let dev = MockCxlDevice::new(4096);
        let mut mbox = Mailbox::new(dev);
        let report = mbox.execute_background(regs::OP_SANITIZE, &[]).unwrap();
        assert_eq!(report.return_code, regs::RC_SUCCESS);
        assert!(
            report.samples.iter().any(|(_, p)| *p < 100),
            "progress telemetry must be non-trivial: {:?}",
            report.samples
        );
        assert!(
            report.samples.iter().any(|(_, p)| *p == 100),
            "must reach 100 percent"
        );
        let dev = mbox.backend();
        assert!(
            dev.media.iter().all(|&b| b == 0),
            "sanitize must zero the media"
        );
    }

    #[test]
    fn secure_erase_foreground_zeroes_media() {
        let dev = MockCxlDevice::new(256);
        let mut mbox = Mailbox::new(dev);
        let reply = mbox.execute(regs::OP_SECURE_ERASE, &[]).unwrap();
        assert_eq!(reply.return_code, regs::RC_SUCCESS);
        assert!(mbox.backend().media.iter().all(|&b| b == 0));
    }

    #[test]
    fn forced_failure_surfaces_return_code() {
        let mut dev = MockCxlDevice::new(64);
        dev.force_return_code = Some(regs::RC_UNSUPPORTED);
        let mut mbox = Mailbox::new(dev);
        assert!(matches!(
            mbox.execute(regs::OP_IDENTIFY, &[]),
            Err(MailboxError::ReturnCode(rc, _)) if rc == regs::RC_UNSUPPORTED
        ));
    }

    #[test]
    fn unsupported_opcode_rejected() {
        let mut mbox = Mailbox::new(MockCxlDevice::new(64));
        assert!(matches!(
            mbox.execute(0xffff, &[]),
            Err(MailboxError::ReturnCode(rc, _)) if rc == regs::RC_UNSUPPORTED
        ));
    }

    #[test]
    fn command_log_records_audit_trail() {
        let mut mbox = Mailbox::new(MockCxlDevice::new(64));
        mbox.execute(regs::OP_IDENTIFY, &[]).unwrap();
        mbox.execute(regs::OP_GET_SECURITY_STATE, &[]).unwrap();
        let log = &mbox.backend().command_log;
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].0, regs::OP_IDENTIFY);
        assert_eq!(log[1].0, regs::OP_GET_SECURITY_STATE);
    }
}
