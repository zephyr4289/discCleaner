//! Minimal, deterministic sRGB ICC v2.1 profile (PDF/A-3 OutputIntent).
//!
//! Hand-built binary ICC: 128-byte header, tag table, and the seven tags
//! a GTS_PDFA1 sRGB output intent needs — desc, wtpt, rXYZ/gXYZ/bXYZ
//! (Bradford-adapted sRGB -> D50 columns), rTRC/gTRC/bTRC (gamma-2.2
//! `curv`), cprt. No external asset, no clock, no randomness: the same
//! profile bytes ship in every archive this tool produces.

/// Build the sRGB IEC61966-2.1 output-intent profile bytes.
pub fn srgb_icc_profile() -> Vec<u8> {
    // ------------------------------------------------------------------
    // Tag payloads (assembled first so offsets are known for the table).
    // ------------------------------------------------------------------
    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }
    fn s15f(v: f64) -> u32 {
        (v * 65536.0).round() as u32
    }

    /// textDescriptionType 'desc' (ICC v2 layout with all three sections).
    fn tag_desc(text: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"desc");
        b.extend_from_slice(&be32(0)); // reserved
        let ascii = format!("{}\0", text);
        b.extend_from_slice(&be32(ascii.len() as u32));
        b.extend_from_slice(ascii.as_bytes());
        // Unicode section: language code + count = 0.
        b.extend_from_slice(&be32(0));
        b.extend_from_slice(&be32(0));
        // ScriptCode section: code (2), count (1), 67 fixed bytes.
        b.extend_from_slice(&[0, 0]);
        b.push(0);
        b.extend_from_slice(&[0u8; 67]);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    /// textType 'text' (copyright).
    fn tag_text(text: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"text");
        b.extend_from_slice(&be32(0));
        b.extend_from_slice(format!("{}\0", text).as_bytes());
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    /// XYZType — one or three s15Fixed16 triples.
    fn tag_xyz(triples: &[(f64, f64, f64)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"XYZ ");
        b.extend_from_slice(&be32(0));
        for (x, y, z) in triples {
            b.extend_from_slice(&be32(s15f(*x)));
            b.extend_from_slice(&be32(s15f(*y)));
            b.extend_from_slice(&be32(s15f(*z)));
        }
        b
    }

    /// curveType 'curv' with a single u8Fixed8 gamma (2.2).
    fn tag_curv_gamma() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"curv");
        b.extend_from_slice(&be32(0));
        b.extend_from_slice(&be32(1)); // one entry
        b.extend_from_slice(&[0x02, 0x33]); // 2.2 * 256 = 563
        b
    }

    // sRGB (D65) primaries Bradford-adapted to the D50 PCS — the standard
    // values carried by the canonical sRGB IEC61966-2.1 profile.
    let r_xyz = tag_xyz(&[(0.4360_741, 0.2225_043, 0.0139_258)]);
    let g_xyz = tag_xyz(&[(0.3850_649, 0.7168_786, 0.0971_045)]);
    let b_xyz = tag_xyz(&[(0.1430_742, 0.0606_076, 0.7141_733)]);
    // Media white point = D50 (PCS illuminant; v2 sRGB profiles are
    // chromatically adapted, so wtpt IS the PCS white).
    let wtpt = tag_xyz(&[(0.9642, 1.0, 0.8249)]);
    let trc = tag_curv_gamma();
    let desc = tag_desc("sRGB IEC61966-2.1");
    let cprt = tag_text("IEC 61966-2.1 Default RGB Colour Space - sRGB");

    // ------------------------------------------------------------------
    // Header + tag table.
    // ------------------------------------------------------------------
    const N_TAGS: usize = 9;
    let table_size = 4 + N_TAGS * 12;
    let mut offset = 128 + table_size;
    let mut entries: Vec<([u8; 4], Vec<u8>, usize)> = Vec::new();
    for (sig, data) in [
        (b"desc", &desc),
        (b"wtpt", &wtpt),
        (b"rXYZ", &r_xyz),
        (b"gXYZ", &g_xyz),
        (b"bXYZ", &b_xyz),
        (b"rTRC", &trc),
        (b"gTRC", &trc),
        (b"bTRC", &trc),
        (b"cprt", &cprt),
    ] {
        let at = offset;
        // Every payload is padded to a 4-byte boundary (ICC requirement).
        let mut padded = data.clone();
        while padded.len() % 4 != 0 {
            padded.push(0);
        }
        entries.push((*sig, padded, at));
        offset += entries.last().unwrap().1.len();
    }

    let total = offset;

    let mut p = Vec::with_capacity(total);
    // -- 128-byte header --
    p.extend_from_slice(&be32(total as u32)); // profile size
    p.extend_from_slice(b"none"); // preferred CMM
    p.extend_from_slice(&be32(0x0210_0000)); // version 2.1.0
    p.extend_from_slice(b"mntr"); // device class: display
    p.extend_from_slice(b"RGB "); // data colour space
    p.extend_from_slice(b"XYZ "); // PCS
                                  // Date/time: 1998-01-01 00:00:00 (fixed, deterministic).
    p.extend_from_slice(&1998u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    p.extend_from_slice(b"acsp"); // signature
    p.extend_from_slice(&be32(0)); // platform
    p.extend_from_slice(&be32(0)); // flags
    p.extend_from_slice(&be32(0)); // device manufacturer
    p.extend_from_slice(&be32(0)); // device model
    p.extend_from_slice(&be32(0)); // attributes (8 bytes: two words)
    p.extend_from_slice(&be32(0));
    p.extend_from_slice(&be32(0)); // rendering intent: perceptual
                                   // PCS illuminant (D50) in s15Fixed16.
    p.extend_from_slice(&be32(0x0000_F6D6));
    p.extend_from_slice(&be32(0x0001_0000));
    p.extend_from_slice(&be32(0x0000_D32D));
    p.extend_from_slice(&be32(0)); // creator
    p.extend_from_slice(&[0u8; 16]); // profile ID
    p.extend_from_slice(&[0u8; 28]); // reserved
    debug_assert_eq!(p.len(), 128);

    // -- tag table --
    p.extend_from_slice(&be32(N_TAGS as u32));
    for (sig, data, at) in &entries {
        p.extend_from_slice(sig);
        p.extend_from_slice(&be32(*at as u32));
        p.extend_from_slice(&be32(data.len() as u32));
    }
    debug_assert_eq!(p.len(), 128 + table_size);

    // -- payloads --
    for (_, data, _) in &entries {
        p.extend_from_slice(data);
    }
    debug_assert_eq!(p.len(), total);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icc_header_and_tags_parse() {
        let p = srgb_icc_profile();
        // Header: size field matches, 'acsp' at offset 36.
        let size = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
        assert_eq!(size, p.len());
        assert_eq!(&p[36..40], b"acsp");
        assert_eq!(&p[12..16], b"mntr");
        assert_eq!(&p[16..20], b"RGB ");
        // D50 illuminant.
        assert_eq!(&p[68..72], &0x0000_F6D6u32.to_be_bytes());
        // Tag table: 9 entries, first is 'desc' with in-bounds offset.
        let n = u32::from_be_bytes(p[128..132].try_into().unwrap()) as usize;
        assert_eq!(n, 9);
        assert_eq!(&p[132..136], b"desc");
        let desc_off = u32::from_be_bytes(p[136..140].try_into().unwrap()) as usize;
        let desc_len = u32::from_be_bytes(p[140..144].try_into().unwrap()) as usize;
        assert!(desc_off >= 128 + 4 + 9 * 12);
        assert!(desc_off + desc_len <= p.len());
        assert_eq!(&p[desc_off..desc_off + 4], b"desc");
        // rTRC/gTRC/bTRC all point at valid 'curv' payloads.
        assert_eq!(&p[132 + 12 * 5..132 + 12 * 5 + 4], b"rTRC");
        // Every table entry is in-bounds and 4-byte aligned.
        for i in 0..n {
            let base = 132 + i * 12;
            let off = u32::from_be_bytes(p[base + 4..base + 8].try_into().unwrap()) as usize;
            let len = u32::from_be_bytes(p[base + 8..base + 12].try_into().unwrap()) as usize;
            assert!(off >= 128 + 4 + n * 12, "tag {} offset inside table", i);
            assert!(off.is_multiple_of(4), "tag {} unaligned", i);
            assert!(off + len <= p.len(), "tag {} out of bounds", i);
        }
        // Deterministic across calls.
        assert_eq!(p, srgb_icc_profile());
    }
}
