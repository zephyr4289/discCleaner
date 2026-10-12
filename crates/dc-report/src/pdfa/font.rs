//! Minimal TrueType parser + PDF CIDFontType2 embedder.
//!
//! Parses exactly what PDF/A-3b font embedding needs from the bundled
//! Tinos face — `head` (units per em, bbox), `hhea`/`hmtx` (advances,
//! ascender/descender), `maxp` (glyph count), `cmap` (format-4 Unicode ->
//! GID), `OS/2` (cap height) — and emits the Type0/Identity-H font
//! object graph with correct `/W` widths and a full ToUnicode CMap.
//!
//! The face is embedded WHOLE (no subsetting): a missing glyph in a
//! subset would be a silent text-loss defect in an evidentiary document,
//! and the whole face is only ~300 KiB.

use super::pdfw::{ObjRef, PdfBuilder};

/// The bundled serif face (Liberation Serif, SIL OFL 1.1; see assets/fonts/NOTICE).
pub const EMBEDDED_FONT: &[u8] = include_bytes!("../../assets/fonts/LiberationSerif-Regular.ttf");

const M_E: f64 = 1000.0; // PDF font units per em

struct Table<'a> {
    data: &'a [u8],
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be16s(b: &[u8], off: usize) -> i16 {
    i16::from_be_bytes([b[off], b[off + 1]])
}

/// Parsed font metrics used by both the embedder and the layout engine.
pub struct PdfFont {
    pub units_per_em: u16,
    pub ascender: i16,
    pub descender: i16,
    pub cap_height: i16,
    pub bbox: (i16, i16, i16, i16),
    /// Glyph advance widths (PDF units, 1000/em), indexed by GID.
    widths: Vec<u16>,
    /// Unicode scalar -> GID.
    cmap: std::collections::BTreeMap<char, u16>,
}

impl PdfFont {
    /// Parse the bundled font (or an equivalent TrueType face).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 {
            return Err("font too small".to_string());
        }
        let num_tables = be16(bytes, 4) as usize;
        let dir_len = 12 + num_tables * 16;
        if bytes.len() < dir_len {
            return Err("font table directory truncated".to_string());
        }
        let mut tables = std::collections::BTreeMap::new();
        for i in 0..num_tables {
            let e = 12 + i * 16;
            let tag: [u8; 4] = [bytes[e], bytes[e + 1], bytes[e + 2], bytes[e + 3]];
            let off = u32::from_be_bytes([bytes[e + 8], bytes[e + 9], bytes[e + 10], bytes[e + 11]])
                as usize;
            let len =
                u32::from_be_bytes([bytes[e + 12], bytes[e + 13], bytes[e + 14], bytes[e + 15]])
                    as usize;
            if off.checked_add(len).map(|end| end <= bytes.len()) != Some(true) {
                return Err(format!("table {:?} out of bounds", tag));
            }
            tables.insert(tag, (off, len));
        }

        let head = tables
            .get(b"head")
            .ok_or("missing head table")
            .map(|(o, l)| Table {
                data: &bytes[*o..*o + *l],
            })?;
        let hhea = tables
            .get(b"hhea")
            .ok_or("missing hhea table")
            .map(|(o, l)| Table {
                data: &bytes[*o..*o + *l],
            })?;
        let hmtx = tables
            .get(b"hmtx")
            .ok_or("missing hmtx table")
            .map(|(o, l)| Table {
                data: &bytes[*o..*o + *l],
            })?;
        let maxp = tables
            .get(b"maxp")
            .ok_or("missing maxp table")
            .map(|(o, l)| Table {
                data: &bytes[*o..*o + *l],
            })?;
        let cmap = tables
            .get(b"cmap")
            .ok_or("missing cmap table")
            .map(|(o, l)| Table {
                data: &bytes[*o..*o + *l],
            })?;
        let os2 = tables
            .get(b"OS/2")
            .ok_or("missing OS/2 table")
            .map(|(o, l)| Table {
                data: &bytes[*o..*o + *l],
            })
            .ok();

        let units_per_em = be16(head.data, 18);
        if units_per_em == 0 {
            return Err("unitsPerEm == 0".to_string());
        }
        let bbox = (
            be16s(head.data, 36),
            be16s(head.data, 38),
            be16s(head.data, 40),
            be16s(head.data, 42),
        );

        let ascender = be16s(hhea.data, 4);
        let descender = be16s(hhea.data, 6);
        let num_hmetrics = be16(hhea.data, 34) as usize;
        let num_glyphs = be16(maxp.data, 4) as usize;
        if num_glyphs == 0 || num_hmetrics == 0 || num_hmetrics > num_glyphs {
            return Err("degenerate metrics".to_string());
        }

        let cap_height = os2
            .map(|t| {
                let v = be16s(t.data, 87); // sCapHeight, OS/2 v2+ at offset 87
                if t.data.len() >= 90 && v != 0 {
                    v
                } else {
                    ascender
                }
            })
            .unwrap_or(ascender);

        // Advances: `num_hmetrics` explicit pairs, then the last advance
        // repeats for the remaining glyphs.
        let mut widths = Vec::with_capacity(num_glyphs);
        let scale = M_E / units_per_em as f64;
        let mut last = 0u16;
        for g in 0..num_glyphs {
            if g < num_hmetrics {
                last = be16(hmtx.data, g * 4);
            }
            widths.push((last as f64 * scale).round() as u16);
        }

        let cmap_map = parse_cmap(cmap.data)?;

        Ok(Self {
            units_per_em,
            ascender,
            descender,
            cap_height,
            bbox,
            widths,
            cmap: cmap_map,
        })
    }

    /// GID for a character (0 = .notdef fallback).
    pub fn gid(&self, c: char) -> u16 {
        self.cmap.get(&c).copied().unwrap_or(0)
    }

    /// Advance width of a glyph in PDF units (1000/em).
    pub fn width(&self, gid: u16) -> u16 {
        self.widths.get(gid as usize).copied().unwrap_or(0)
    }

    /// Rendered width of a text run at `size` pt (for layout).
    pub fn measure(&self, text: &str, size: f64) -> f64 {
        let mut units = 0u64;
        for c in text.chars() {
            units += self.width(self.gid(c)) as u64;
        }
        units as f64 * size / M_E
    }

    /// Encode a text run as a PDF hex string of Identity-H GIDs.
    pub fn encode_hex(&self, text: &str) -> String {
        let mut bytes = Vec::with_capacity(text.len() * 2);
        for c in text.chars() {
            bytes.extend_from_slice(&self.gid(c).to_be_bytes());
        }
        hex::encode(bytes)
    }
    /// The set of GIDs used by `text` (for /W and ToUnicode).
    pub fn used_gids(&self, text: &str) -> Vec<(u16, char)> {
        let mut seen = std::collections::BTreeMap::new();
        for c in text.chars() {
            let g = self.gid(c);
            if g != 0 {
                seen.insert(g, c);
            }
        }
        seen.into_iter().collect()
    }
}

/// Parse a `cmap` table for a Unicode mapping (format 4 subtable,
/// platform 3 encoding 1 preferred, 0/x accepted).
fn parse_cmap(data: &[u8]) -> Result<std::collections::BTreeMap<char, u16>, String> {
    let n = be16(data, 2) as usize;
    let mut best: Option<(usize, usize)> = None; // (offset, score)
    for i in 0..n {
        let e = 4 + i * 8;
        if e + 8 > data.len() {
            break;
        }
        let platform = be16(data, e);
        let encoding = be16(data, e + 2);
        let offset =
            u32::from_be_bytes([data[e + 4], data[e + 5], data[e + 6], data[e + 7]]) as usize;
        if offset >= data.len() {
            continue;
        }
        let score = match (platform, encoding) {
            (3, 1) => 4, // Windows Unicode BMP
            (0, _) => 3, // Unicode
            (3, 10) => 2,
            _ => 0,
        };
        if score > 0 && best.map(|(_, s)| score > s).unwrap_or(true) {
            best = Some((offset, score));
        }
    }
    let (off, _) = best.ok_or("no Unicode cmap subtable")?;
    let sub = &data[off..];
    let format = be16(sub, 0);
    let mut map = std::collections::BTreeMap::new();
    match format {
        4 => {
            let seg_x2 = be16(sub, 6) as usize;
            let seg_count = seg_x2 / 2;
            let end_off = 14;
            let start_off = end_off + seg_x2 + 2;
            let delta_off = start_off + seg_x2;
            let range_off = delta_off + seg_x2;
            for i in 0..seg_count {
                let end = be16(sub, end_off + i * 2);
                let start = be16(sub, start_off + i * 2);
                let delta = be16(sub, delta_off + i * 2);
                let range = be16(sub, range_off + i * 2);
                if range == 0 {
                    let d = delta as i32;
                    for c in start..=end {
                        let gid = (((c as i32 + d) & 0xFFFF) & 0xFFFF) as u16;
                        if gid != 0 {
                            map.insert(char::from_u32(c as u32).unwrap_or('\u{FFFD}'), gid);
                        }
                    }
                } else {
                    let glyph_off_base = range_off + i * 2 + range as usize;
                    for (k, c) in (start..=end).enumerate() {
                        let idx = glyph_off_base + k * 2;
                        if idx + 2 > sub.len() {
                            break;
                        }
                        let gid = be16(sub, idx);
                        if gid != 0 {
                            map.insert(char::from_u32(c as u32).unwrap_or('\u{FFFD}'), gid);
                        }
                    }
                }
            }
        }
        12 => {
            let n_groups = u32::from_be_bytes(sub[12..16].try_into().unwrap()) as usize;
            for g in 0..n_groups {
                let e = 16 + g * 12;
                if e + 12 > sub.len() {
                    break;
                }
                let start = u32::from_be_bytes(sub[e..e + 4].try_into().unwrap());
                let end = u32::from_be_bytes(sub[e + 4..e + 8].try_into().unwrap());
                let start_gid = u32::from_be_bytes(sub[e + 8..e + 12].try_into().unwrap());
                for (k, c) in (start..=end).enumerate() {
                    if let Some(ch) = char::from_u32(c) {
                        map.insert(ch, (start_gid + k as u32) as u16);
                    }
                }
            }
        }
        other => return Err(format!("unsupported cmap subtable format {}", other)),
    }
    if map.is_empty() {
        return Err("Unicode cmap resolved to nothing".to_string());
    }
    Ok(map)
}

/// UTF-16BE encoding of a single scalar (with surrogate pairs for
/// astral characters).
fn char_to_utf16(c: char) -> Vec<u16> {
    let cp = c as u32;
    if cp <= 0xFFFF {
        vec![cp as u16]
    } else {
        let v = cp - 0x10000;
        vec![0xD800 | (v >> 10) as u16, 0xDC00 | (v & 0x3FF) as u16]
    }
}

/// The object graph of the embedded font.
pub struct FontObjects {
    pub font: ObjRef,
}

/// Write the full Type0/CIDFontType2 font graph into the builder.
/// `used` carries the (GID, char) pairs actually drawn, so /W and
/// ToUnicode cover exactly the drawn glyphs (the whole face is still
/// embedded in FontFile2).
///
/// Object layout:
/// - F:  `/Type /Font /Subtype /Type0 /Encoding /Identity-H`
/// - FD: FontDescriptor with `/FontFile2` (raw TrueType stream)
/// - D:  CIDFontType2 with `/CIDToGIDMap /Identity` and `/W` widths
/// - TU: ToUnicode CMap (UTF-16BE targets for text extraction)
pub fn write_cid_font(b: &mut PdfBuilder, font: &PdfFont, used: &[(u16, char)]) -> FontObjects {
    let scale = M_E / font.units_per_em as f64;
    let asc = font.ascender as f64 * scale;
    let desc = font.descender as f64 * scale;
    let ch = font.cap_height as f64 * scale;
    let bbox = font.bbox;
    let bbox_str = format!(
        "[{} {} {} {}]",
        (bbox.0 as f64 * scale).round() as i32,
        (bbox.1 as f64 * scale).round() as i32,
        (bbox.2 as f64 * scale).round() as i32,
        (bbox.3 as f64 * scale).round() as i32
    );

    // --- FontFile2: the raw TrueType program, unfiltered ---
    let fontfile2 = b.reserve();
    b.write_stream(fontfile2, "", EMBEDDED_FONT);

    // --- ToUnicode CMap (drawn glyphs -> UTF-16BE) ---
    let tounicode = b.reserve();
    let mut tu = String::new();
    tu.push_str("/CIDInit /ProcSet findresource begin\n");
    tu.push_str("12 dict begin\n");
    tu.push_str("begincmap\n");
    tu.push_str("/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n");
    tu.push_str("/CMapName /Adobe-Identity-UCS def\n");
    tu.push_str("/CMapType 2 def\n");
    tu.push_str("1 begincodespacerange\n");
    tu.push_str("<0000> <FFFF>\n");
    tu.push_str("endcodespacerange\n");
    // bfchar blocks of up to 100 entries each.
    let mut chunk: Vec<String> = Vec::new();
    for (gid, c) in used {
        let utf16 = char_to_utf16(*c);
        let hexbytes: Vec<u8> = utf16.iter().flat_map(|u| u.to_be_bytes()).collect();
        chunk.push(format!("<{:04X}> <{}>", gid, hex::encode(hexbytes)));
        if chunk.len() == 100 {
            tu.push_str(&format!("{} beginbfchar\n", chunk.len()));
            for entry in chunk.drain(..) {
                tu.push_str(&entry);
                tu.push('\n');
            }
            tu.push_str("endbfchar\n");
        }
    }
    if !chunk.is_empty() {
        tu.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for entry in chunk.drain(..) {
            tu.push_str(&entry);
            tu.push('\n');
        }
        tu.push_str("endbfchar\n");
    }
    tu.push_str("endcmap\n");
    tu.push_str("CMapName currentdict /CMap defineresource pop\n");
    tu.push_str("end\n");
    tu.push_str("end\n");
    b.write_stream(tounicode, "", tu.as_bytes());

    // --- FontDescriptor ---
    let descriptor = b.reserve();
    b.write(descriptor, |out| {
        out.extend_from_slice(
            format!(
                "<< /Type /FontDescriptor /FontName /LiberationSerif /Flags 4 /FontBBox {} /ItalicAngle 0 \
                 /Ascent {} /Descent {} /CapHeight {} /StemV 80 /FontFile2 {} 0 R >>",
                bbox_str,
                asc.round() as i32,
                desc.round() as i32,
                ch.round() as i32,
                fontfile2.0
            )
            .as_bytes(),
        );
    });

    // --- CIDFontType2 descendant with /W widths for drawn glyphs ---
    let descendant = b.reserve();
    b.write(descendant, |out| {
        let mut w = String::from("[");
        for (gid, _) in used {
            w.push_str(&format!("{} [{}] ", gid, font.width(*gid)));
        }
        w.push(']');
        out.extend_from_slice(
            format!(
                "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /LiberationSerif \
                 /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> \
                 /FontDescriptor {} 0 R /DW 1000 /W {} /CIDToGIDMap /Identity >>",
                descriptor.0, w
            )
            .as_bytes(),
        );
    });

    // --- Type0 root ---
    let root = b.reserve();
    b.write(root, |out| {
        out.extend_from_slice(
            format!(
                "<< /Type /Font /Subtype /Type0 /BaseFont /LiberationSerif /Encoding /Identity-H \
                 /DescendantFonts [{} 0 R] /ToUnicode {} 0 R >>",
                descendant.0, tounicode.0
            )
            .as_bytes(),
        );
    });

    FontObjects { font: root }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_font_parses_and_maps() {
        let font = PdfFont::parse(EMBEDDED_FONT).expect("bundled Tinos must parse");
        assert_eq!(font.units_per_em, 2048, "Tinos unitsPerEm");
        // ASCII coverage through format-4 cmap.
        assert!(font.gid('A') != 0, "'A' must map to a real glyph");
        assert!(font.gid('z') != 0);
        assert!(font.width(font.gid('A')) > 0, "'A' has an advance");
        // Measure sanity: 100 characters at 10pt have positive width.
        let w = font.measure(&"x".repeat(100), 10.0);
        assert!(w > 100.0 && w < 1000.0, "width 100 x's at 10pt: {}", w);
        // Non-Latin chars fall back to glyph 0 without panicking.
        assert_eq!(
            font.gid('\u{9F8E}'),
            0,
            "unmapped CJK falls back to .notdef"
        );
    }

    #[test]
    fn cid_font_graph_is_wellformed() {
        let font = PdfFont::parse(EMBEDDED_FONT).unwrap();
        let used = font.used_gids("Certificate");
        let mut b = PdfBuilder::new();
        let fo = write_cid_font(&mut b, &font, &used);
        let info = b.reserve();
        b.write(info, |out| out.extend_from_slice(b"<< >>"));
        let bytes = b.finish(fo.font, info, &[0u8; 16]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("/Subtype /Type0"));
        assert!(s.contains("/Subtype /CIDFontType2"));
        assert!(s.contains("/CIDToGIDMap /Identity"));
        assert!(s.contains("/FontFile2"));
        assert!(s.contains("beginbfchar"));
        // The raw TTF program is embedded verbatim.
        let head = &EMBEDDED_FONT[..64];
        assert!(bytes.windows(64).any(|w| w == head));
    }
}
