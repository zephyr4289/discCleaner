//! ARM Serial Wire Debug (SWD) — ADIv5 packet engine.
//!
//! Bit-exact host-side protocol:
//!
//! * Request (8 bits, LSB first): START=1, APnDP, RnW, A[2], A[3], PARITY,
//!   STOP=0, PARK=1. Parity covers the four meaningful bits.
//! * ACK (3 bits, target driven): OK=0b001, WAIT=0b010, FAULT=0b100.
//! * Data (32 bits LSB first) + odd parity.
//! * Turnarounds (ownership flips, one SWCLK each):
//!   read  = request(8) [host] · trn · ack(3) · data+par(33) [target] · trn
//!   write = request(8) [host] · trn · ack(3) [target] · trn · data+par(33) [host]
//!   On WAIT/FAULT the packet terminates after the ACK phase (see README
//!   "modeling gaps" — the bench driver completes write data on WAIT per the
//!   DP spec).
//!
//! AP reads are posted (RDBUFF semantics); [`DpPort`] resolves that for
//! callers. A line reset is >=50 SWCLK with SWDIO high; the JTAG-to-SWD
//! switch magic 0xE79E is clocked MSB-first, per the ADIv5 appendix.

use crate::dp::{DpPort, dp_reg};
use crate::hal::{LinkError, SwdLink};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ack {
    Ok,
    Wait,
    Fault,
    NoAck,
}

impl Ack {
    fn from_bits(ack: u32) -> Ack {
        match ack {
            0b001 => Ack::Ok,
            0b010 => Ack::Wait,
            0b100 => Ack::Fault,
            _ => Ack::NoAck,
        }
    }
}

/// Build the 8-bit request word (LSB-first bit order at transmission time).
fn request_word(ap: bool, rnw: bool, addr: u8) -> [bool; 8] {
    let apn = ap as u8;
    let rnw_b = rnw as u8;
    let a2 = (addr >> 2) & 1;
    let a3 = (addr >> 3) & 1;
    let parity = (apn ^ rnw_b ^ a2 ^ a3) & 1;
    [
        true,        // START
        apn == 1,    // APnDP
        rnw_b == 1,  // RnW
        a2 == 1,     // A[2]
        a3 == 1,     // A[3]
        parity == 1, // PAR
        false,       // STOP
        true,        // PARK
    ]
}

fn odd_parity32(v: u32) -> bool {
    (v.count_ones() & 1) == 1
}

pub struct SwdEngine<L: SwdLink> {
    link: L,
    /// Full-request retries on WAIT before giving up.
    pub max_wait_retries: u32,
    /// Whether FAULT triggers a sticky-clear + single retry.
    pub fault_retry: bool,
}

impl<L: SwdLink> SwdEngine<L> {
    pub fn new(link: L) -> Self {
        SwdEngine {
            link,
            max_wait_retries: 64,
            fault_retry: true,
        }
    }

    pub fn into_inner(self) -> L {
        self.link
    }

    /// >=50 SWCLK with SWDIO high, then two low idle clocks — resets the
    /// > wire protocol layer and cleanly re-arms the DP (a request START bit
    /// > is never mistaken for more reset clocks).
    pub fn line_reset(&mut self) {
        self.link.swd_idle_clocks(56, true);
        self.link.swd_idle_clocks(2, false);
    }

    /// 16-bit switch magic, MSB-first, then a line reset.
    pub fn jtag_to_swd_switch(&mut self) {
        const MAGIC: u32 = 0xE79E;
        for i in (0..16).rev() {
            let bit = (MAGIC >> i) & 1 == 1;
            self.link.swd_host_bit(bit);
        }
    }

    /// Bring the wire up: line reset, JTAG->SWD switch if needed, DPIDR read.
    pub fn connect(&mut self) -> Result<u32, LinkError> {
        self.line_reset();
        self.jtag_to_swd_switch();
        self.line_reset();
        self.dp_read(dp_reg::DPIDR_OR_ABORT)
    }

    fn transaction_once(
        &mut self,
        ap: bool,
        rnw: bool,
        addr: u8,
        wdata: u32,
    ) -> Result<(Ack, Option<u32>), LinkError> {
        let req = request_word(ap, rnw, addr);
        for &b in req.iter() {
            self.link.swd_host_bit(b);
        }
        self.link.swd_trn(); // host releases; target drives ACK
        let mut ack_val: u32 = 0;
        for k in 0..3 {
            if self.link.swd_target_bit() {
                ack_val |= 1 << k;
            }
        }
        let ack = Ack::from_bits(ack_val);
        match ack {
            Ack::Ok if rnw => {
                let mut data: u32 = 0;
                for k in 0..32 {
                    if self.link.swd_target_bit() {
                        data |= 1 << k;
                    }
                }
                let parity_bit = self.link.swd_target_bit();
                self.link.swd_trn(); // target releases back to host
                if parity_bit != odd_parity32(data) {
                    return Err(LinkError::Fault("SWD data parity error"));
                }
                Ok((Ack::Ok, Some(data)))
            }
            Ack::Ok => {
                self.link.swd_trn(); // target releases; host takes data phase
                for k in 0..32 {
                    self.link.swd_host_bit((wdata >> k) & 1 == 1);
                }
                self.link.swd_host_bit(odd_parity32(wdata));
                Ok((Ack::Ok, None))
            }
            _ => {
                // WAIT / FAULT / NoAck: terminate packet after ACK.
                self.link.swd_trn(); // reacquire the line
                Ok((ack, None))
            }
        }
    }

    /// One SWD transaction with WAIT retry and FAULT clear-and-retry.
    pub fn transaction(
        &mut self,
        ap: bool,
        rnw: bool,
        addr: u8,
        wdata: u32,
    ) -> Result<Option<u32>, LinkError> {
        let mut waits = 0;
        loop {
            let (ack, data) = self.transaction_once(ap, rnw, addr, wdata)?;
            match ack {
                Ack::Ok => return Ok(data),
                Ack::Wait => {
                    waits += 1;
                    if waits > self.max_wait_retries {
                        return Err(LinkError::Fault("SWD WAIT storm"));
                    }
                }
                Ack::Fault => {
                    if !self.fault_retry {
                        return Err(LinkError::Fault("SWD FAULT"));
                    }
                    self.fault_retry = false;
                    // Clear sticky error / overrun and retry once.
                    self.raw_write_abort(1 << 1 | 1 << 3)?;
                    let (ack2, data2) = self.transaction_once(ap, rnw, addr, wdata)?;
                    self.fault_retry = true;
                    match ack2 {
                        Ack::Ok => return Ok(data2),
                        Ack::Wait => continue,
                        _ => return Err(LinkError::Fault("SWD FAULT persists — AP locked?")),
                    }
                }
                Ack::NoAck => {
                    return Err(LinkError::NoAck);
                }
            }
        }
    }

    /// ABORT write is special: it is a DP write that must succeed even in a
    /// wedged state, so it bypasses the retry machinery.
    fn raw_write_abort(&mut self, bits: u32) -> Result<(), LinkError> {
        let req = request_word(false, false, dp_reg::DPIDR_OR_ABORT);
        for &b in req.iter() {
            self.link.swd_host_bit(b);
        }
        self.link.swd_trn();
        let mut ack_val: u32 = 0;
        for k in 0..3 {
            if self.link.swd_target_bit() {
                ack_val |= 1 << k;
            }
        }
        let ack = Ack::from_bits(ack_val);
        if matches!(ack, Ack::NoAck) {
            return Err(LinkError::NoAck);
        }
        if matches!(ack, Ack::Ok) {
            self.link.swd_trn();
            for k in 0..32 {
                self.link.swd_host_bit((bits >> k) & 1 == 1);
            }
            self.link.swd_host_bit(odd_parity32(bits));
            Ok(())
        } else {
            self.link.swd_trn();
            Ok(())
        }
    }
}

impl<L: SwdLink> DpPort for SwdEngine<L> {
    fn dp_read(&mut self, addr: u8) -> Result<u32, LinkError> {
        match self.transaction(false, true, addr, 0)? {
            Some(v) => Ok(v),
            None => Err(LinkError::Fault("DP read returned no data")),
        }
    }

    fn dp_write(&mut self, addr: u8, value: u32) -> Result<(), LinkError> {
        self.transaction(false, false, addr, value).map(|_| ())
    }

    fn ap_read(&mut self, addr: u8) -> Result<u32, LinkError> {
        // AP reads are posted: issue the request, then pull RDBUFF.
        self.transaction(true, true, addr, 0)?;
        match self.transaction(false, true, dp_reg::RDBUFF, 0)? {
            Some(v) => Ok(v),
            None => Err(LinkError::Fault("AP read returned no data")),
        }
    }

    fn ap_write(&mut self, addr: u8, value: u32) -> Result<(), LinkError> {
        self.transaction(true, false, addr, value).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_word_layout_and_parity() {
        // DP read of DPIDR (0x00): APnDP=0 RnW=1 A2=0 A3=0 -> parity 1.
        let r = request_word(false, true, 0x00);
        assert_eq!(r, [true, false, true, false, false, true, false, true]);
        // MEM-AP DRW write (0x0C): AP=1 RnW=0 A2=1 A3=1 -> parity 1^0^1^1 = 1.
        let r = request_word(true, false, 0x0C);
        assert_eq!(r, [true, true, false, true, true, true, false, true]);
        // CTRL/STAT read (0x04): AP=0 RnW=1 A2=1 A3=0 -> parity 0.
        let r = request_word(false, true, 0x04);
        assert_eq!(&r[..5], &[true, false, true, true, false]);
    }

    #[test]
    fn ack_decode() {
        assert_eq!(Ack::from_bits(0b001), Ack::Ok);
        assert_eq!(Ack::from_bits(0b010), Ack::Wait);
        assert_eq!(Ack::from_bits(0b100), Ack::Fault);
        assert_eq!(Ack::from_bits(0b111), Ack::NoAck);
        assert_eq!(Ack::from_bits(0b000), Ack::NoAck);
    }

    #[test]
    fn parity_bit_formula() {
        // parity = ones(data) mod 2 — host and device use the same rule.
        assert!(!odd_parity32(0));
        assert!(odd_parity32(1));
        assert!(!odd_parity32(0xFFFF_FFFF)); // 32 ones -> 0
        assert!(odd_parity32(0x8000_0000));
    }
}
