//! ISO 7816-4 APDU codec — the smart-card command framing layer of the
//! hardware custody stack (v0.7.0, Vector 1).
//!
//! Pure encode/decode with zero side effects: the same APDU builder serves
//! the production USB-CCID transport (`ccid.rs`) and the scripted test
//! transports (`token.rs` tests). PIV commands (SP 800-73-4) are layered on
//! top of these primitives in `token.rs`.
//!
//! Wire formats pinned here:
//! - Short APDU: `CLA INS P1 P2 [Lc] [CommandData] [Le]`, Lc/Le <= 255.
//! - Extended APDU: 3-byte Lc/Le fields (`00 LcH LcL`), payload <= 65 535.
//!   PIV cards (YubiKey 5.7+, most CACs) accept extended APDUs for
//!   GENERAL AUTHENTICATE with large Ed25519 payloads.
//! - Response: `ResponseData || SW1 SW2` (status word 0x9000 = success).

/// Command APDU (case 1/2/3/4 in the short and extended forms).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    /// Command data (empty for case 1/2).
    pub data: Vec<u8>,
    /// Expected response length; `None` = no response expected (case 1/3).
    pub ne: Option<usize>,
    /// Force the extended-length encoding even for small payloads (some
    /// PIV applets reject 0x00-padded short Lc on signed operations).
    pub extended: bool,
}

impl CommandApdu {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            ne: None,
            extended: false,
        }
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn with_ne(mut self, ne: usize) -> Self {
        self.ne = Some(ne);
        self
    }

    pub fn extended(mut self) -> Self {
        self.extended = true;
        self
    }

    /// Serialize to the on-wire byte form.
    ///
    /// SECURITY NOTE: lengths are derived from the payload, never taken
    /// from untrusted input, so a mis-sized Lc/Le field cannot be smuggled
    /// through this encoder.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 5 + self.data.len() + 3);
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        let big = self.extended || self.data.len() > 255 || self.ne.unwrap_or(0) > 256;
        if !self.data.is_empty() {
            if big {
                out.push(0x00);
                out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
            } else {
                out.push(self.data.len() as u8);
            }
            out.extend_from_slice(&self.data);
        } else if big && self.ne.is_some() {
            // Case 2E without command data still needs the 0x00 marker so
            // the card parses Le (not Lc) correctly.
            out.push(0x00);
        }
        if let Some(ne) = self.ne {
            if big {
                // Extended Le: two bytes, 0x0000 means 65 536.
                let le = ne.min(65_536);
                let le_val = if le == 65_536 { 0u16 } else { le as u16 };
                out.extend_from_slice(&le_val.to_be_bytes());
            } else {
                let le = ne.min(256);
                out.push(if le == 256 { 0 } else { le as u8 });
            }
        }
        out
    }
}

/// Response APDU: payload plus the two-byte status word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseApdu {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ResponseApdu {
    pub const SW_OK: (u8, u8) = (0x90, 0x00);
    pub const SW_PIN_RETRIES: (u8, u8) = (0x63, 0xC0); // SW2 = 0xC0..0xCF retries

    /// Parse a raw card response. Malformed (short) buffers are an error,
    /// never a silent truncation.
    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 2 {
            return Err(format!(
                "APDU response too short for a status word ({} bytes)",
                raw.len()
            ));
        }
        let (data, sw) = raw.split_at(raw.len() - 2);
        Ok(Self {
            data: data.to_vec(),
            sw1: sw[0],
            sw2: sw[1],
        })
    }

    pub fn is_ok(&self) -> bool {
        (self.sw1, self.sw2) == Self::SW_OK
    }

    /// 63 Cx: remaining PIN retries before lockout.
    pub fn pin_retries_left(&self) -> Option<u8> {
        if self.sw1 == 0x63 && (0xC0..=0xCF).contains(&self.sw2) {
            Some(self.sw2 & 0x0F)
        } else {
            None
        }
    }

    /// Human-readable status classification for operator disclosure.
    pub fn status_name(&self) -> &'static str {
        match (self.sw1, self.sw2) {
            (0x90, 0x00) => "success",
            (0x63, c) if (0xC0..=0xCF).contains(&c) => "wrong PIN (retries remain)",
            (0x69, 0x83) => "authentication method blocked (PIN locked)",
            (0x6A, 0x82) => "file/application not found",
            (0x6A, 0x86) => "incorrect P1/P2 parameters",
            (0x6D, 0x00) => "instruction not supported",
            (0x67, 0x00) => "wrong length",
            _ => "card-specific status",
        }
    }
}

/// Transport abstraction: one exchange = one APDU command/response cycle.
/// Production rides [`crate::ccid::CcidCardTransport`]; tests script it.
pub trait Iso7816Transport {
    fn exchange(&mut self, command: &CommandApdu) -> Result<ResponseApdu, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_1_no_data_no_response() {
        let apdu = CommandApdu::new(0x00, 0xA4, 0x04, 0x00);
        assert_eq!(apdu.encode(), vec![0x00, 0xA4, 0x04, 0x00]);
    }

    #[test]
    fn case_3_short_with_data() {
        let apdu = CommandApdu::new(0x00, 0x20, 0x00, 0x80).with_data(vec![0x31, 0x32, 0x33, 0x34]);
        assert_eq!(
            apdu.encode(),
            vec![0x00, 0x20, 0x00, 0x80, 0x04, 0x31, 0x32, 0x33, 0x34]
        );
    }

    #[test]
    fn case_4_short_with_le() {
        let apdu = CommandApdu::new(0x00, 0x47, 0x00, 0x00)
            .with_data(vec![0xAA; 16])
            .with_ne(0x100);
        let raw = apdu.encode();
        // Lc=16, data, Le=256 encoded as 0x00.
        assert_eq!(raw[4], 16);
        assert_eq!(raw[5 + 16], 0x00);
        assert_eq!(raw.len(), 5 + 16 + 1);
    }

    #[test]
    fn extended_length_for_large_payloads() {
        let apdu = CommandApdu::new(0x00, 0x87, 0xE0, 0x9C)
            .with_data(vec![0x42; 64])
            .with_ne(256)
            .extended();
        let raw = apdu.encode();
        // 0x00 marker + 2-byte Lc.
        assert_eq!(&raw[4..7], &[0x00, 0x00, 0x40]);
        assert_eq!(raw[7 + 64], 0x01);
        assert_eq!(raw[7 + 65], 0x00); // Le 256 -> 0x0100? no: 0x0100 == 256
        // Le field: 256 encoded as 0x0100 big-endian.
        let le = u16::from_be_bytes([raw[7 + 64], raw[7 + 65]]);
        assert_eq!(le, 256);
    }

    #[test]
    fn response_decode_and_status_words() {
        let ok = ResponseApdu::decode(&[0x01, 0x02, 0x90, 0x00]).unwrap();
        assert!(ok.is_ok());
        assert_eq!(ok.data, vec![0x01, 0x02]);

        let retries = ResponseApdu::decode(&[0x63, 0xC2]).unwrap();
        assert_eq!(retries.pin_retries_left(), Some(2));

        let blocked = ResponseApdu::decode(&[0x69, 0x83]).unwrap();
        assert_eq!(
            blocked.status_name(),
            "authentication method blocked (PIN locked)"
        );

        assert!(ResponseApdu::decode(&[0x90]).is_err());
    }
}
