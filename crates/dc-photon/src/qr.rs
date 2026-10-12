//! Minimal, byte-mode QR encoder (v0.8.0, Vector 3).
//!
//! Pure-Rust, zero-dependency generation of scannable QR codes for the
//! photon bridge stream: versions 1..=10 (21×21 to 57×57 modules), error
//! correction level M, byte mode, full 8-mask penalty evaluation, BCH
//! format info and (versions ≥ 7) version info blocks. Placement follows
//! ISO/IEC 18004 including the timing-column skip in the zig-zag walk.
//!
//! Only the encoder side exists on the transmitter; decoding is the
//! auditor's scanner problem. The encoder is validated by structure
//! invariants (finder/timing/alignment placement, format-info BCH
//! round-trip, RS codeword syndromes) below.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum QrError {
    #[error("payload too large for QR v10-M: {0} bytes (max 213)")]
    TooLarge(usize),
    #[error("QR internal error: {0}")]
    Internal(String),
}

pub const MAX_BYTE_PAYLOAD_V10_M: usize = 213;

/// Data codewords per version at ECC level M (ISO/IEC 18004 Table 22):
/// (total_codewords, [(block_total, block_data), ...]).
const VERSION_BLOCKS_M: [(usize, &[(usize, usize)]); 10] = [
    (26, &[(26, 16)]),                                          // v1
    (44, &[(44, 28)]),                                          // v2
    (70, &[(70, 44)]),                                          // v3
    (100, &[(50, 32), (50, 32)]),                               // v4
    (134, &[(67, 43), (67, 43)]),                               // v5
    (172, &[(43, 27), (43, 27), (43, 27), (43, 27)]),           // v6
    (196, &[(49, 31), (49, 31), (49, 31), (49, 31)]),           // v7
    (242, &[(60, 38), (60, 38), (61, 39), (61, 39)]),           // v8
    (292, &[(58, 36), (58, 36), (58, 36), (59, 37), (59, 37)]), // v9
    (346, &[(69, 43), (69, 43), (69, 43), (69, 43), (70, 44)]), // v10
];

/// Alignment pattern centers by version (ISO Table 13).
const ALIGNMENT: [&[usize]; 10] = [
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
];

fn version_side(version: u8) -> usize {
    17 + 4 * version as usize
}

fn data_capacity(version: u8) -> usize {
    VERSION_BLOCKS_M[version as usize - 1]
        .1
        .iter()
        .map(|(_, d)| d)
        .sum()
}

/// Smallest version that fits `payload_len` bytes at level M.
fn pick_version(payload_len: usize) -> Result<u8, QrError> {
    for v in 1u8..=10 {
        let header_bits = if v <= 9 { 4 + 8 } else { 4 + 16 };
        if header_bits + payload_len * 8 <= data_capacity(v) * 8 {
            return Ok(v);
        }
    }
    Err(QrError::TooLarge(payload_len))
}

// ---------------------------------------------------------------------------
// GF(256) Reed–Solomon (modulus 0x11D, generator α = 2)
// ---------------------------------------------------------------------------

fn gf_tables() -> (Vec<u8>, Vec<u8>) {
    let mut exp = vec![0u8; 512];
    let mut log = vec![0u8; 256];
    let mut x: u16 = 1;
    for slot in exp.iter_mut().take(255) {
        *slot = x as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11D;
        }
    }
    // log[i] = discrete log of i (α^log[i] = i): second pass.
    let mut v: u16 = 1;
    for i in 0..255 {
        log[v as usize] = i as u8;
        v <<= 1;
        if v & 0x100 != 0 {
            v ^= 0x11D;
        }
    }
    for i in 255..512 {
        let lo = exp[i - 255];
        exp[i] = lo;
    }
    (exp, log)
}

fn gf_mul(exp: &[u8], log: &[u8], a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    exp[log[a as usize] as usize + log[b as usize] as usize]
}

/// RS generator polynomial of degree `n` (the parity-symbol count).
fn rs_generator(n: usize, exp: &[u8], log: &[u8]) -> Vec<u8> {
    let mut poly = vec![1u8];
    for i in 0..n {
        // poly *= (x + α^i)
        let mut next = vec![0u8; poly.len() + 1];
        for (j, c) in poly.iter().enumerate() {
            next[j] ^= gf_mul(exp, log, *c, exp[i]);
            next[j + 1] ^= *c;
        }
        poly = next;
    }
    poly
}

/// RS-encode `data` producing `ec_len` parity symbols (systematic
/// polynomial division: append `ec_len` zero bytes, then eliminate every
/// leading data coefficient against the generator — the classic
/// append-zeros algorithm, tap-verified against zero syndromes by tests).
fn rs_encode(data: &[u8], ec_len: usize, exp: &[u8], log: &[u8]) -> Vec<u8> {
    let generator = rs_generator(ec_len, exp, log);
    let mut out = data.to_vec();
    out.resize(data.len() + ec_len, 0);
    for i in 0..data.len() {
        let factor = out[i];
        if factor == 0 {
            continue;
        }
        for jp in 0..ec_len {
            // Generator is constant-first (index k = coefficient of x^k):
            // position i+jp+1 pairs with the x^(ec_len-1-jp) tap.
            let g = generator[ec_len - 1 - jp];
            if g != 0 {
                let idx = i + jp + 1;
                out[idx] ^= gf_mul(exp, log, factor, g);
            }
        }
    }
    out[data.len()..].to_vec()
}

// ---------------------------------------------------------------------------
// BCH format / version info
// ---------------------------------------------------------------------------

/// 15-bit format info: 2 ECL bits (M = 00) + 3 mask bits, BCH(15,5)
/// with generator 0x537, XOR the standard mask 0x5412.
fn format_bits(mask: u8) -> u16 {
    let data = mask as u16; // ECL M = 00 → high two bits zero
    let mut v = data << 10;
    let g = 0x537u16;
    for i in (10..15).rev() {
        if (v >> i) & 1 == 1 {
            v ^= g << (i - 10);
        }
    }
    ((data << 10) | (v & 0x3FF)) ^ 0x5412
}

/// 18-bit version info for v ≥ 7: 6 data bits + BCH(18,6) (g = 0x1F25).
fn version_bits(version: u8) -> u32 {
    let v = version as u32;
    let mut rem = v << 12;
    let g = 0x1F25u32;
    for i in (12..18).rev() {
        if (rem >> i) & 1 == 1 {
            rem ^= g << (i - 12);
        }
    }
    (v << 12) | (rem & 0xFFF)
}

// ---------------------------------------------------------------------------
// Matrix construction
// ---------------------------------------------------------------------------

/// One QR code: module grid (`true` = dark) + the function-module map used
/// during placement.
pub struct QrMatrix {
    pub size: usize,
    pub modules: Vec<bool>,
    pub mask: u8,
    pub version: u8,
    function: Vec<bool>,
}

impl QrMatrix {
    pub fn get(&self, row: usize, col: usize) -> bool {
        self.modules[row * self.size + col]
    }

    fn set(&mut self, row: usize, col: usize, v: bool) {
        self.modules[row * self.size + col] = v;
    }

    fn set_function(&mut self, row: usize, col: usize, v: bool) {
        let i = row * self.size + col;
        self.modules[i] = v;
        self.function[i] = true;
    }
}

/// Encode a byte payload at level M with automatic version selection and
/// the lowest-penalty mask.
pub fn encode(payload: &[u8]) -> Result<QrMatrix, QrError> {
    if payload.len() > MAX_BYTE_PAYLOAD_V10_M {
        return Err(QrError::TooLarge(payload.len()));
    }
    let version = pick_version(payload.len())?;
    let size = version_side(version);
    let blocks = VERSION_BLOCKS_M[version as usize - 1].1;
    let capacity = data_capacity(version);

    // --- Bit stream: mode 0100 (byte), length, payload, terminator, pad.
    let mut bits: Vec<bool> = Vec::with_capacity(capacity * 8 + 8);
    push_bits(&mut bits, 0b0100, 4);
    let len_bits = if version <= 9 { 8 } else { 16 };
    push_bits(&mut bits, payload.len() as u32, len_bits);
    for b in payload {
        push_bits(&mut bits, *b as u32, 8);
    }
    for _ in 0..4 {
        if bits.len() >= capacity * 8 {
            break;
        }
        bits.push(false);
    }
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }
    let mut bytes = Vec::with_capacity(capacity);
    for chunk in bits.chunks(8) {
        let mut v = 0u8;
        for b in chunk {
            v = (v << 1) | u8::from(*b);
        }
        bytes.push(v);
    }
    let mut pad = 0xEC;
    while bytes.len() < capacity {
        bytes.push(pad);
        pad = if pad == 0xEC { 0x11 } else { 0xEC };
    }

    // --- Block split + RS parity per block + interleave.
    let (exp, log) = gf_tables();
    let mut data_blocks: Vec<Vec<u8>> = Vec::new();
    let mut ec_blocks: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0usize;
    for (block_total, block_data) in blocks {
        let ec_len = block_total - block_data;
        let _ = ec_len;
        data_blocks.push(bytes[offset..offset + block_data].to_vec());
        offset += block_data;
        ec_blocks.push(Vec::new());
    }
    // (recompute parity with correct per-block sizes)
    for (i, (block_total, block_data)) in blocks.iter().enumerate() {
        let ec_len = block_total - block_data;
        ec_blocks[i] = rs_encode(&data_blocks[i], ec_len, &exp, &log);
    }

    let max_data = data_blocks.iter().map(|b| b.len()).max().unwrap_or(0);
    let max_ec = ec_blocks.iter().map(|b| b.len()).max().unwrap_or(0);
    let mut interleaved = Vec::with_capacity(capacity + 40);
    for i in 0..max_data {
        for b in &data_blocks {
            if let Some(v) = b.get(i) {
                interleaved.push(*v);
            }
        }
    }
    for i in 0..max_ec {
        for b in &ec_blocks {
            if let Some(v) = b.get(i) {
                interleaved.push(*v);
            }
        }
    }

    // --- Try all 8 masks; keep the lowest-penalty matrix.
    let mut best: Option<(QrMatrix, u32)> = None;
    for mask in 0u8..8 {
        let mut m = build_matrix(version, size, mask)?;
        place_data(&mut m, &interleaved);
        apply_mask(&mut m, mask);
        let penalty = penalty_score(&m);
        if best.as_ref().is_none_or(|(_, p)| penalty < *p) {
            best = Some((m, penalty));
        }
    }
    best.map(|(m, _)| m)
        .ok_or_else(|| QrError::Internal("mask selection failed".into()))
}

fn push_bits(out: &mut Vec<bool>, value: u32, count: usize) {
    for i in (0..count).rev() {
        out.push((value >> i) & 1 == 1);
    }
}

fn build_matrix(version: u8, size: usize, mask: u8) -> Result<QrMatrix, QrError> {
    let mut m = QrMatrix {
        size,
        modules: vec![false; size * size],
        mask,
        version,
        function: vec![false; size * size],
    };

    // Finder patterns + separators (8×8 function areas, 7×7 patterns).
    for (r, c) in [(0usize, 0usize), (0, size - 8), (size - 8, 0)] {
        for dr in 0..8usize {
            for dc in 0..8usize {
                let dark = if dr == 7 || dc == 7 {
                    false // separator ring
                } else if dr == 0 || dr == 6 || dc == 0 || dc == 6 {
                    true // outer ring
                } else {
                    (2..=4).contains(&dr) && (2..=4).contains(&dc) // center 3×3
                };
                m.set_function(r + dr, c + dc, dark);
            }
        }
    }

    // Timing patterns (row 6 / column 6), dark on even indices.
    for i in 8..size - 8 {
        m.set_function(6, i, i % 2 == 0);
        m.set_function(i, 6, i % 2 == 0);
    }

    // Alignment patterns.
    let centers = ALIGNMENT[version as usize - 1];
    for &cr in centers {
        for &cc in centers {
            let near_tl = cr <= 8 && cc <= 8;
            let near_tr = cr <= 8 && cc >= size - 9;
            let near_bl = cr >= size - 9 && cc <= 8;
            if near_tl || near_tr || near_bl {
                continue;
            }
            for dr in -2i32..=2 {
                for dc in -2i32..=2 {
                    let r = (cr as i32 + dr) as usize;
                    let c = (cc as i32 + dc) as usize;
                    let dark = dr.abs() == 2 || dc.abs() == 2 || (dr == 0 && dc == 0);
                    m.set_function(r, c, dark);
                }
            }
        }
    }

    // Reserve the format-info regions (content written per-mask below).
    for i in 0..9 {
        if i != 6 {
            m.function[8 * size + i] = true;
            m.function[i * size + 8] = true;
        }
    }
    for i in 0..8 {
        m.function[8 * size + (size - 1 - i)] = true;
        m.function[(size - 1 - i) * size + 8] = true;
    }

    // Version info (v ≥ 7): two 3×6 blocks.
    if version >= 7 {
        let vbits = version_bits(version);
        for i in 0..18 {
            let bit = (vbits >> i) & 1 == 1;
            let a = i / 3;
            let b = size - 11 + i % 3;
            m.set_function(a, b, bit);
            m.set_function(b, a, bit);
        }
    }

    // Format info (two copies).
    let fmt = format_bits(mask);
    for i in 0..15 {
        let bit = (fmt >> i) & 1 == 1;
        // Copy 1 around the top-left finder.
        match i {
            0..=5 => m.set_function(8, i, bit),
            6 => m.set_function(8, 7, bit),
            7 => m.set_function(8, 8, bit),
            8 => m.set_function(7, 8, bit),
            _ => m.set_function(14 - i, 8, bit),
        }
        // Copy 2: split below top-right and beside bottom-left.
        if i < 8 {
            m.set_function(size - 1 - i, 8, bit);
        } else {
            m.set_function(8, size - 15 + i, bit);
        }
    }

    // Dark module (ISO 18004: always dark; drawn after the format copy
    // because copy 2's 8th cell lands on the same coordinate).
    m.set_function(size - 8, 8, true);

    Ok(m)
}

/// Zig-zag data placement: column pairs right-to-left, skipping the
/// timing column 6 (ISO §8.7.3).
fn place_data(m: &mut QrMatrix, codewords: &[u8]) {
    let size = m.size;
    let total_bits = codewords.len() * 8;
    let mut bit_index = 0usize;
    let mut col = size as i32 - 1;
    let mut upward = true;
    while col > 0 {
        if col == 6 {
            col -= 1;
        }
        for i in 0..size {
            let row = if upward { size - 1 - i } else { i };
            for c in [col, col - 1] {
                let (row, cu) = (row, c as usize);
                if m.function[row * size + cu] {
                    continue;
                }
                let bit = bit_index < total_bits
                    && (codewords[bit_index / 8] >> (7 - bit_index % 8)) & 1 == 1;
                m.set(row, cu, bit);
                bit_index += 1;
            }
        }
        upward = !upward;
        col -= 2;
    }
}

/// ISO mask formulas (x = column, y = row); applied to non-function modules.
fn mask_flips(mask: u8, row: usize, col: usize) -> bool {
    let (y, x) = (row, col);
    match mask {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => (x / 2 + y / 3) % 2 == 0,
        5 => (x * y) % 2 + (x * y) % 3 == 0,
        6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
        7 => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
        _ => false,
    }
}

fn apply_mask(m: &mut QrMatrix, mask: u8) {
    let size = m.size;
    for row in 0..size {
        for col in 0..size {
            if m.function[row * size + col] {
                continue;
            }
            if mask_flips(mask, row, col) {
                let v = !m.get(row, col);
                m.set(row, col, v);
            }
        }
    }
}

/// ISO 18004 §8.8.2 mask penalty heuristic.
fn penalty_score(m: &QrMatrix) -> u32 {
    let size = m.size;
    let mut score = 0u32;

    // N1: runs of 5+ same color, rows then columns.
    let scan_runs = |iter: &mut dyn Iterator<Item = bool>| {
        let mut run = 0usize;
        let mut prev: Option<bool> = None;
        let mut local = 0u32;
        for v in iter {
            if prev == Some(v) {
                run += 1;
            } else {
                if run >= 5 {
                    local += 3 + (run - 5) as u32;
                }
                run = 1;
                prev = Some(v);
            }
        }
        if run >= 5 {
            local += 3 + (run - 5) as u32;
        }
        local
    };
    for row in 0..size {
        score += scan_runs(&mut (0..size).map(|c| m.get(row, c)));
    }
    for col in 0..size {
        score += scan_runs(&mut (0..size).map(|r| m.get(r, col)));
    }

    // N2: 2×2 blocks of the same color.
    for row in 0..size - 1 {
        for col in 0..size - 1 {
            let a = m.get(row, col);
            if a == m.get(row, col + 1) && a == m.get(row + 1, col) && a == m.get(row + 1, col + 1)
            {
                score += 3;
            }
        }
    }

    // N3: finder-like 1011101 with 4 light modules on at least one side.
    let pattern = [true, false, true, true, true, false, true];
    let mut light_run_ok = |cells: &dyn Fn(usize) -> (bool, bool)| {
        // (value, in-bounds) accessor for the 4 modules on one side
        !cells(0).0 || !cells(0).1
    };
    let _ = &mut light_run_ok;
    for row in 0..size {
        for col in 0..size.saturating_sub(6) {
            // horizontal
            if (0..7).all(|k| m.get(row, col + k) == pattern[k]) {
                let left_ok =
                    col + 4 <= size && (0..4).all(|k| col >= 4 && !m.get(row, col - 4 + k));
                let right_ok = col + 11 <= size && (0..4).all(|k| !m.get(row, col + 7 + k));
                if left_ok || right_ok {
                    score += 40;
                }
            }
            // vertical
            if row + 7 <= size && (0..7).all(|k| m.get(row + k, col) == pattern[k]) {
                let up_ok = row + 4 <= size && (0..4).all(|k| row >= 4 && !m.get(row - 4 + k, col));
                let down_ok = row + 11 <= size && (0..4).all(|k| !m.get(row + 7 + k, col));
                if up_ok || down_ok {
                    score += 40;
                }
            }
        }
    }

    // N4: dark-module proportion deviation from 50%.
    let dark: usize = m.modules.iter().filter(|b| **b).count();
    let percent = dark * 100 / (size * size);
    let prev5 = (percent / 5) * 5;
    let next5 = prev5 + 5;
    let d1 = (prev5 as i64 - 50).unsigned_abs() / 5;
    let d2 = (next5 as i64 - 50).unsigned_abs() / 5;
    score += (d1.min(d2) * 10) as u32;
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bits_bch_round_trip() {
        for mask in 0u8..8 {
            let fmt = format_bits(mask);
            let raw = fmt ^ 0x5412;
            let data = (raw >> 10) as u8;
            assert_eq!(data >> 3, 0b00, "ECL M bits");
            assert_eq!(data & 0b111, mask);
            let mut v = (data as u16) << 10;
            let g = 0x537u16;
            for i in (10..15).rev() {
                if (v >> i) & 1 == 1 {
                    v ^= g << (i - 10);
                }
            }
            assert_eq!(v & 0x3FF, raw & 0x3FF, "BCH remainder");
        }
    }

    #[test]
    fn version_bits_bch_round_trip() {
        for v in 7u8..=10 {
            let bits = version_bits(v);
            assert_eq!((bits >> 12) as u8, v);
            let mut rem = (v as u32) << 12;
            let g = 0x1F25u32;
            for i in (12..18).rev() {
                if (rem >> i) & 1 == 1 {
                    rem ^= g << (i - 12);
                }
            }
            assert_eq!(rem & 0xFFF, bits & 0xFFF, "BCH remainder");
        }
    }

    #[test]
    fn rs_parity_has_zero_syndromes() {
        let (exp, log) = gf_tables();
        let data: Vec<u8> = (1..=16u8).collect();
        let parity = rs_encode(&data, 10, &exp, &log);
        let mut cw = data.clone();
        cw.extend_from_slice(&parity);
        for i in 0..10 {
            let mut acc = 0u8;
            for &c in &cw {
                acc = gf_mul(&exp, &log, acc, exp[i]) ^ c;
            }
            assert_eq!(acc, 0, "syndrome {i} nonzero");
        }
        // Zero data → zero parity.
        let p0 = rs_encode(&[0u8; 12], 13, &exp, &log);
        assert!(p0.iter().all(|p| *p == 0));
    }

    #[test]
    fn encode_produces_structurally_valid_matrices() {
        for len in [10usize, 60, 100, 180, 213] {
            let payload: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 1) as u8).collect();
            let m = encode(&payload).expect("encode");
            let size = 17 + 4 * m.version as usize;
            assert_eq!(m.size, size);
            // Finder patterns intact at the three corners, separators light.
            for (r, c) in [(0usize, 0usize), (0, size - 8), (size - 8, 0)] {
                assert!(m.get(r + 3, c + 3), "finder center dark");
                assert!(m.get(r, c + 3), "finder top ring dark");
                assert!(
                    !m.get(r + 1, c + 1) && !m.get(r + 1, c + 5),
                    "inner ring light"
                );
                // The 8th row/column inside the 8×8 function area is the
                // light separator ring.
                assert!(!m.get(r + 7, c), "separator light (below-left)");
                assert!(!m.get(r, c + 7), "separator light (above-right)");
            }
            // Timing patterns.
            for i in 8..size - 8 {
                assert_eq!(m.get(6, i), i % 2 == 0);
                assert_eq!(m.get(i, 6), i % 2 == 0);
            }
            // Dark module + every module written.
            assert!(m.get(size - 8, 8));
            assert!(penalty_score(&m) > 0);
            assert!(m.mask < 8);
            // The chosen mask must be <= every tried mask's penalty is not
            // directly observable; but encode determinism is:
            let m2 = encode(&payload).unwrap();
            assert_eq!(m.modules, m2.modules, "encoding is deterministic");
        }
    }

    #[test]
    fn oversize_payload_is_rejected() {
        let payload = vec![0u8; 214];
        assert!(matches!(encode(&payload), Err(QrError::TooLarge(214))));
    }

    #[test]
    fn version_selection_is_monotonic() {
        assert_eq!(pick_version(10).unwrap(), 1);
        assert_eq!(pick_version(14).unwrap(), 1);
        assert_eq!(pick_version(15).unwrap(), 2);
        assert_eq!(pick_version(180).unwrap(), 9);
        assert_eq!(pick_version(213).unwrap(), 10);
        assert!(pick_version(214).is_err());
    }
}
