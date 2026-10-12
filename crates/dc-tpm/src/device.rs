//! TPM device transport (`/dev/tpmrm0`, the kernel TPM Resource Manager).
//!
//! The RM multiplexes concurrent callers and flushes transient handles; the
//! command/response framing over the char device is: write the full command
//! buffer, then read the full response (the RM guarantees a bounded,
//! single-shot reply per write). Reads are deadline-guarded with `poll(2)`
//! so a wedged TPM fails the purge path in seconds instead of hanging a
//! lights-out run forever.

use crate::structures::parse_response_header;
use crate::wire::WireResult;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Errors surfaced by the TPM stack (transport, protocol, policy).
#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error(
        "TPM device unavailable: {0} (expected /dev/tpmrm0 — is the TPM 2.0 driver bound and the tpmrm udev rule installed?)"
    )]
    DeviceUnavailable(String),
    #[error("TPM I/O error: {0}")]
    Io(String),
    #[error("TPM command timed out after {0:?} — device wedged or resource manager stalled")]
    Timeout(Duration),
    #[error("TPM returned error response code {code:#010x}")]
    ResponseCode { code: u32 },
    #[error("TPM wire protocol violation: {0}")]
    Wire(String),
    #[error("TPM attestation verification FAILED: {0}")]
    Verification(String),
    #[error("TPM policy refusal: {0}")]
    Policy(String),
}

impl TpmError {
    pub fn wire(e: crate::wire::WireError) -> Self {
        Self::Wire(e.to_string())
    }
}

/// Transport abstraction: the real RM char device, or the synthetic
/// in-process TPM used by the regression matrices (no hardware in CI).
pub trait TpmTransport {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmError>;
    fn describe(&self) -> String;
}

/// Kernel resource-manager transport.
pub struct TpmRmTransport {
    dev: File,
    path: PathBuf,
    /// Deadline per command (default 10 s; quotes can be slow on some
    /// firmware but never minutes).
    timeout: Duration,
}

impl TpmRmTransport {
    pub fn open() -> Result<Self, TpmError> {
        Self::open_path(Path::new("/dev/tpmrm0"), Duration::from_secs(10))
    }

    pub fn open_path(path: &Path, timeout: Duration) -> Result<Self, TpmError> {
        let dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| TpmError::DeviceUnavailable(format!("{}: {e}", path.display())))?;
        Ok(Self {
            dev,
            path: path.to_path_buf(),
            timeout,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn poll_readable(&self, deadline: Instant) -> Result<(), TpmError> {
        let mut remaining = deadline.saturating_duration_since(Instant::now());
        loop {
            let mut pfd = libc::pollfd {
                fd: self.dev.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe {
                libc::poll(
                    &mut pfd as *mut libc::pollfd,
                    1,
                    remaining.as_millis() as i32,
                )
            };
            if rc < 0 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                if errno == libc::EINTR {
                    remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(TpmError::Timeout(self.timeout));
                    }
                    continue;
                }
                return Err(TpmError::Io(format!(
                    "poll({}): errno {errno}",
                    self.path.display()
                )));
            }
            if rc == 0 {
                return Err(TpmError::Timeout(self.timeout));
            }
            return Ok(());
        }
    }
}

impl TpmTransport for TpmRmTransport {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmError> {
        // Write the complete command.
        self.dev
            .write_all(command)
            .map_err(|e| TpmError::Io(format!("write: {e}")))?;
        // Read the bounded response (RM caps at the spec limit 4096).
        let mut response = vec![0u8; 4096];
        let deadline = Instant::now() + self.timeout;
        let mut filled = 0usize;
        loop {
            self.poll_readable(deadline)?;
            let n = self
                .dev
                .read(&mut response[filled..])
                .map_err(|e| TpmError::Io(format!("read: {e}")))?;
            if n == 0 {
                return Err(TpmError::Io("TPM closed mid-response".into()));
            }
            filled += n;
            // Complete when the header's declared size is satisfied.
            if filled >= 10 {
                let declared =
                    u32::from_be_bytes([response[2], response[3], response[4], response[5]])
                        as usize;
                if declared >= 10 && filled >= declared {
                    response.truncate(declared);
                    return Ok(response);
                }
                if declared > 4096 {
                    return Err(TpmError::Wire(format!(
                        "declared response size {declared} exceeds spec limit"
                    )));
                }
            }
        }
    }

    fn describe(&self) -> String {
        format!("tpmrm:{}", self.path.display())
    }
}

/// Classify a raw response buffer into Ok(params-slice) or Err(rc).
pub fn classify_response(buf: &[u8]) -> Result<&[u8], TpmError> {
    match parse_response_header(buf).map_err(TpmError::wire)? {
        Ok((_hdr, params)) => Ok(params),
        Err(code) => Err(TpmError::ResponseCode { code }),
    }
}

/// Run one command against any transport and return just the parameter area.
pub fn transact<'a, T: TpmTransport>(
    tpm: &mut T,
    command: &[u8],
    scratch: &'a mut Vec<u8>,
) -> Result<&'a [u8], TpmError> {
    let response = tpm.transact(command)?;
    scratch.clear();
    scratch.extend_from_slice(&response);
    classify_response(scratch)
}

/// Convenience wrapper that allocates per call (CLI paths).
pub fn transact_owned<T: TpmTransport>(tpm: &mut T, command: &[u8]) -> Result<Vec<u8>, TpmError> {
    let response = tpm.transact(command)?;
    let offset = match parse_response_header(&response).map_err(TpmError::wire)? {
        Ok((hdr, _)) => hdr.params_offset,
        Err(code) => return Err(TpmError::ResponseCode { code }),
    };
    Ok(response[offset..].to_vec())
}
/// Serialize a wire result into a transport-level error (call sites).
pub fn wire_result<T>(r: WireResult<T>) -> Result<T, TpmError> {
    r.map_err(TpmError::wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_device_fails_clean() {
        let res =
            TpmRmTransport::open_path(Path::new("/definitely/no/tpmrm"), Duration::from_secs(1));
        assert!(matches!(res, Err(TpmError::DeviceUnavailable(_))));
    }

    #[test]
    fn response_classification_success_and_error() {
        // success, no sessions: tag, size, code=0, params
        let ok = [
            0x80u8, 0x01, 0, 0, 0, 14, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        assert_eq!(classify_response(&ok).unwrap(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        // success with sessions: parameterSize word present
        let ok2 = [
            0x80u8, 0x02, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 4, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        assert_eq!(classify_response(&ok2).unwrap(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        // error: TPM_RC_INITIALIZE (startup twice)
        let err = [0x80u8, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x00];
        assert!(matches!(
            classify_response(&err),
            Err(TpmError::ResponseCode { code: 0x100 })
        ));
        // truncated header
        assert!(matches!(
            classify_response(&[0x80, 0x01, 0]),
            Err(TpmError::Wire(_))
        ));
    }
}
