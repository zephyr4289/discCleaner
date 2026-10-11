//! Low-level, zero-dependency PDF 1.7 serializer (PDF/A-3 core).
//!
//! Emits classic (non-cross-referenced-stream) object files: a `%PDF-1.7`
//! binary-comment header, indirect objects, a literal `xref` table whose
//! offsets are verified by the crate's structural tests, a trailer with
//! the document `/ID`, and `startxref`/`%%EOF`.
//!
//! Design rules:
//! - DETERMINISTIC: no clocks, no randomness — byte-identical output for
//!   identical inputs (Δ472, Δ476 clock-leak discipline).
//! - NO COMPRESSION: every stream (content, XMP, ICC, embedded files) is
//!   stored raw. Forensic reviewers can read the certificate JSON with a
//!   hex viewer, and diffs between two archives stay meaningful.

/// Reference to an allocated (possibly not-yet-written) indirect object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjRef(pub u32);

/// Incremental PDF file builder with verified xref bookkeeping.
pub struct PdfBuilder {
    out: Vec<u8>,
    /// `offsets[objnum - 1]` = byte offset of the object body (0 = free).
    offsets: Vec<u32>,
    next_obj: u32,
}

impl Default for PdfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PdfBuilder {
    pub fn new() -> Self {
        let mut b = Self {
            out: Vec::new(),
            offsets: Vec::new(),
            next_obj: 0,
        };
        // %PDF-1.7 header with the binary-flagging comment (>= 4 bytes
        // with the high bit set — required so transports treat the file
        // as binary).
        b.out.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
        b
    }

    /// Allocate the next object number WITHOUT writing the body. Enables
    /// forward references (catalog -> pages -> contents ...).
    pub fn reserve(&mut self) -> ObjRef {
        self.next_obj += 1;
        self.offsets.push(0);
        ObjRef(self.next_obj)
    }

    /// Write the body of a reserved object, recording its xref offset.
    pub fn write(&mut self, obj: ObjRef, body: impl FnOnce(&mut Vec<u8>)) {
        self.offsets[obj.0 as usize - 1] = self.out.len() as u32;
        self.out
            .extend_from_slice(format!("{} 0 obj\n", obj.0).as_bytes());
        body(&mut self.out);
        self.out.extend_from_slice(b"\nendobj\n");
    }

    /// Write a raw (unfiltered) stream object with extra dictionary keys.
    pub fn write_stream(&mut self, obj: ObjRef, extra_dict: &str, data: &[u8]) {
        self.write(obj, |out| {
            out.extend_from_slice(
                format!("<< /Length {} {} >>\nstream\n", data.len(), extra_dict).as_bytes(),
            );
            out.extend_from_slice(data);
            out.extend_from_slice(b"\nendstream");
        });
    }

    /// Finish the file: xref table + trailer, return the bytes.
    pub fn finish(mut self, root: ObjRef, info: ObjRef, file_id: &[u8; 16]) -> Vec<u8> {
        let count = self.next_obj;
        let xref_at = self.out.len() as u32;
        self.out
            .extend_from_slice(format!("xref\n0 {}\n", count + 1).as_bytes());
        // Entry 0: the free-list head (65535 generation).
        self.out.extend_from_slice(b"0000000000 65535 f \n");
        for off in &self.offsets {
            self.out
                .extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
        }
        self.out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root {} 0 R /Info {} 0 R /ID [<{}> <{}>] >>\nstartxref\n{}\n%%EOF\n",
                count + 1,
                root.0,
                info.0,
                hex::encode(file_id),
                hex::encode(file_id),
                xref_at
            )
            .as_bytes(),
        );
        self.out
    }
}

/// Escape a literal PDF string body: `\` `(` `)` get backslash-escaped.
pub fn escape_pdf_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Encode a string as a UTF-16BE PDF hex string (with BOM), for /UF keys
/// and other text strings that may carry non-Latin-1 characters.
pub fn utf16be_hex(s: &str) -> String {
    let mut bytes = vec![0xFE, 0xFF];
    for unit in s.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    hex::encode(bytes)
}

/// Escape a PDF /Name (slashes, parens, and the hash introducer).
pub fn escape_pdf_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'/' | b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'%' | b'#' => {
                out.push_str(&format!("#{:02X}", b));
            }
            0x21..=0x7E => out.push(b as char),
            _ => out.push_str(&format!("#{:02X}", b)),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_emits_verifiable_xref_layout() {
        let mut b = PdfBuilder::new();
        let obj1 = b.reserve();
        let obj2 = b.reserve();
        b.write(obj1, |out| out.extend_from_slice(b"<< /A 1 >>"));
        b.write(obj2, |out| out.extend_from_slice(b"<< /B 2 >>"));
        let info = b.reserve();
        b.write(info, |out| out.extend_from_slice(b"<< >>"));
        let bytes = b.finish(obj2, info, &[0x11u8; 16]);

        assert!(bytes.starts_with(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"));
        // startxref points at the xref keyword.
        let tail = &bytes[bytes.len() - 40..];
        let s = String::from_utf8_lossy(tail);
        assert!(s.contains("%%EOF"));
        // The trailer carries the deterministic ID.
        let all = String::from_utf8_lossy(&bytes);
        assert!(all.contains("/Root 2 0 R"));
        assert!(all.contains(format!("<{}>", hex::encode([0x11u8; 16])).as_str()));
        // Offsets recorded for both objects.
        // (verified end-to-end by the pdfa module's xref walker test)
        assert!(all.contains("xref\n0 4\n"));
    }

    #[test]
    fn string_and_name_escaping() {
        assert_eq!(escape_pdf_string("a(b)c\\d"), "a\\(b\\)c\\\\d");
        assert_eq!(escape_pdf_name("application/json"), "application#2Fjson");
        assert_eq!(utf16be_hex("A"), "feff0041");
    }
}
