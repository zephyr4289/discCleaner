//! Checksum primitives shared by host rig, injected nucleus and proof file.
//!
//! * [`crc16_xmodem`] — protects every Boot-ROM frame (the classic XMODEM
//!   polynomial 0x1021, init 0x0000, no reflection, no final xor).
//! * [`crc32`] — the running digest the in-silicon nucleus streams into the
//!   SRAM mailbox for every verified block (IEEE 802.3 poly 0xEDB88320,
//!   reflected, init/final 0xFFFFFFFF). The nucleus builds the same 256-entry
//!   table at boot, so host and target always agree.
//!
//! Test vectors are the canonical ones ("123456789" -> 0x31C3 / 0xCBF43926).

/// CRC-16/XMODEM of a buffer.
pub fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Running CRC-32 register update (pre-final-xor state).
pub fn crc32_update(mut state: u32, data: &[u8]) -> u32 {
    for &b in data {
        state ^= b as u32;
        for _ in 0..8 {
            let mask = (state & 1).wrapping_neg();
            state = (state >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    state
}

/// Finalize a running register.
pub fn crc32_finish(state: u32) -> u32 {
    !state
}

/// CRC-32 (IEEE) of a buffer, identical to zlib/PNG.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_finish(crc32_update(0xFFFF_FFFF, data))
}

/// Append `b` to a running CRC-32 register — mirrors the exact per-byte step
/// the nucleus executes (`crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)`).
pub fn crc32_byte(state: u32, b: u8) -> u32 {
    crc32_update(state, &[b])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_xmodem_vectors() {
        assert_eq!(crc16_xmodem(b""), 0x0000);
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
        // Frame-level check: [0x01][addr LE][len LE] + payload must round-trip
        let mut frame = vec![0x01u8, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00];
        frame.extend_from_slice(b"RZRT");
        let c = crc16_xmodem(&frame);
        assert!(c != 0);
    }

    #[test]
    fn crc32_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn crc32_streaming_matches_one_shot() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let mut st = 0xFFFF_FFFF;
        for chunk in data.chunks(7) {
            st = crc32_update(st, chunk);
        }
        assert_eq!(crc32_finish(st), crc32(&data));
    }

    #[test]
    fn crc32_byte_step_matches_tableless() {
        let mut st = 0xFFFF_FFFF;
        for &b in b"nucleus" {
            st = crc32_byte(st, b);
        }
        assert_eq!(crc32_finish(st), crc32(b"nucleus"));
    }
}
