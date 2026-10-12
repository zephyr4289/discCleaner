//! cargo-fuzz target: the CXL mailbox protocol engine against arbitrary
//! register/payload mutations.
//!
//! Real CXL devices (or a hostile hypervisor presenting a virtual one)
//! can return arbitrary status/register combinations; the engine must
//! surface errors, never panic.

#![no_main]

use dc_cxl::mailbox::{Mailbox, MailboxBackend, MailboxError};
use dc_cxl::regs;
use libfuzzer_sys::fuzz_target;

/// Byte-addressable "registers" with arbitrary contents.
#[derive(Debug)]
struct FuzzRegs {
    mem: Vec<u8>,
}

impl FuzzRegs {
    fn rd(&self, off: u64) -> u64 {
        let mut v = [0u8; 8];
        for (i, slot) in v.iter_mut().enumerate() {
            let idx = (off as usize + i).min(self.mem.len().saturating_sub(1));
            *slot = self.mem.get(idx).copied().unwrap_or(0);
        }
        u64::from_le_bytes(v)
    }
}

impl MailboxBackend for FuzzRegs {
    fn read_reg(&mut self, reg_off: u64) -> Result<u64, MailboxError> {
        Ok(self.rd(reg_off))
    }
    fn write_reg(&mut self, _reg_off: u64, _value: u64) -> Result<(), MailboxError> {
        Ok(())
    }
    fn read_payload(&mut self, _off: usize, _buf: &mut [u8]) -> Result<(), MailboxError> {
        Ok(())
    }
    fn write_payload(&mut self, _off: usize, _data: &[u8]) -> Result<(), MailboxError> {
        Ok(())
    }
    fn poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(0)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mut mbox = Mailbox::new(FuzzRegs { mem: data.to_vec() });
    // cap the poll budget so the fuzzer does not spin on always-busy
    mbox.command_timeout = std::time::Duration::from_millis(1);
    mbox.background_timeout = std::time::Duration::from_millis(1);
    let _ = mbox.execute(regs::OP_IDENTIFY, &[]);
    let _ = mbox.execute(regs::OP_GET_SECURITY_STATE, &[]);
    let _ = mbox.execute_background(regs::OP_SANITIZE, &[]);
});
