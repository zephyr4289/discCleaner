//! PDF/A-3 (ISO 19005-3) document assembly — the public facade.
//!
//! `render_pdfa` builds a complete, standards-targeted PDF/A-3b file:
//! - `%PDF-1.7` binary header, classic xref, trailer `/ID`
//! - catalog with `/Metadata` (XMP: pdfaid part 3, conformance B),
//!   `/OutputIntents` (sRGB ICC), `/Names /EmbeddedFiles`, and `/AF`
//!   (associated files — the PDF/A-3 embedded-evidence mechanism)
//! - every embedded attachment stored UNFILTERED so auditors can carve
//!   `certificate.json` out of the archive with a hex viewer and verify
//!   its Ed25519 signature as-is
//! - one Type0/CIDFontType2 font, fully embedded (PDF/A requires it)
//! - human-readable pages drawn by `crate::template`
//!
//! DETERMINISM CONTRACT: identical inputs produce byte-identical output;
//! every date comes in through `creation_utc_iso` (Δ472, Δ476).

pub mod font;
pub mod icc;
pub mod pdfw;
pub mod xmp;

use pdfw::{ObjRef, PdfBuilder};

/// One attachment embedded into the archive.
#[derive(Clone, Debug)]
pub struct ArchiveAttachment<'a> {
    /// File name as it appears in the /EmbeddedFiles tree and to the
    /// auditor when extracted (e.g. "certificate.json").
    pub filename: &'a str,
    pub bytes: &'a [u8],
    /// MIME subtype stored as `/Subtype` (e.g. "application/json").
    pub mime: &'a str,
    /// PDF/A-3 /AFRelationship: Source | Data | Alternative | Supplement.
    pub relationship: &'a str,
}

/// Layout interface consumed from `template.rs`: pages of vector ops.
pub struct VisualPage {
    /// Raw content stream bytes (already emitted drawing operators).
    pub content: Vec<u8>,
}

/// Render a complete PDF/A-3b archive.
///
/// `pages` carry the pre-rendered content streams (see `template.rs`);
/// `drawn_text` is the exact union of text drawn across all pages (it
/// drives the /W widths and ToUnicode mappings); `attachments` are
/// embedded, listed in /Names, and associated via catalog /AF.
pub fn render_pdfa(
    title: &str,
    subtitle: &str,
    creation_utc_iso: &str,
    pages: &[VisualPage],
    drawn_text: &str,
    attachments: &[ArchiveAttachment<'_>],
) -> Vec<u8> {
    let font = font::PdfFont::parse(font::EMBEDDED_FONT).expect("bundled font must parse");
    let used = font.used_gids(drawn_text);

    let mut b = PdfBuilder::new();

    // --- reserve the object graph (numbers are stable references) ---
    let catalog = b.reserve();
    let pages_obj = b.reserve();
    let info = b.reserve();
    let metadata = b.reserve();
    let fonts = [font::write_cid_font(&mut b, &font, &used)];

    // Page objects + content streams.
    let mut page_refs: Vec<ObjRef> = Vec::with_capacity(pages.len());
    let mut content_refs: Vec<ObjRef> = Vec::with_capacity(pages.len());
    for _ in pages {
        page_refs.push(b.reserve());
        content_refs.push(b.reserve());
    }

    let output_intent = b.reserve();
    let iccp = b.reserve();
    let names = b.reserve();

    // Embedded files: filespec + embedded stream per attachment.
    let mut filespecs: Vec<ObjRef> = Vec::with_capacity(attachments.len());
    let mut embedded_streams: Vec<ObjRef> = Vec::with_capacity(attachments.len());
    for _ in attachments {
        filespecs.push(b.reserve());
        embedded_streams.push(b.reserve());
    }

    // --- Info dictionary (must mirror the XMP packet) ---
    let (pdf_date, _) = pdf_dates(creation_utc_iso);
    let producer = "diskcleaner dc-report (PDF/A-3b, ISO 19005-3)";
    b.write(info, |out| {
        out.extend_from_slice(
            format!(
                "<< /Title ({}) /Producer ({}) /CreationDate ({}) /ModDate ({}) >>",
                pdfw::escape_pdf_string(title),
                pdfw::escape_pdf_string(producer),
                pdf_date,
                pdf_date
            )
            .as_bytes(),
        );
    });

    // --- XMP metadata stream (unfiltered, /Type /Metadata) ---
    let xmp_bytes = xmp::build_xmp(
        title,
        subtitle,
        producer,
        creation_utc_iso,
        &attachments
            .iter()
            .map(|a| (a.filename, a.bytes.len() as u64, a.mime))
            .collect::<Vec<_>>(),
    );
    b.write_stream(metadata, "/Type /Metadata", &xmp_bytes);

    // --- ICC profile + OutputIntent ---
    let icc_bytes = icc::srgb_icc_profile();
    b.write_stream(iccp, "/N 3", &icc_bytes);
    b.write(output_intent, |out| {
        out.extend_from_slice(
            b"<< /Type /OutputIntent /S /GTS_PDFA1 /OutputConditionIdentifier (sRGB IEC61966-2.1) \
             /Info (sRGB IEC61966-2.1) /RegistryName (http://www.color.org) /DestOutputProfile ",
        );
        out.extend_from_slice(format!("{} 0 R >>", iccp.0).as_bytes());
    });

    // --- Page content streams + page objects ---
    for (i, page) in pages.iter().enumerate() {
        b.write_stream(content_refs[i], "", &page.content);
    }
    for (i, _) in pages.iter().enumerate() {
        b.write(page_refs[i], |out| {
            out.extend_from_slice(
                format!(
                    "<< /Type /Page /Parent {} 0 R /MediaBox [0 0 595 842] \
                     /Resources << /Font << /F1 {} 0 R >> >> /Contents {} 0 R >>",
                    pages_obj.0, fonts[0].font.0, content_refs[i].0
                )
                .as_bytes(),
            );
        });
    }

    // --- Page tree ---
    let kids: Vec<String> = page_refs.iter().map(|r| format!("{} 0 R", r.0)).collect();
    b.write(pages_obj, |out| {
        out.extend_from_slice(
            format!(
                "<< /Type /Pages /Kids [{}] /Count {} >>",
                kids.join(" "),
                pages.len()
            )
            .as_bytes(),
        );
    });

    // --- Embedded files ---
    let mod_date = pdf_date.clone();
    for (idx, att) in attachments.iter().enumerate() {
        let ef = embedded_streams[idx];
        b.write_stream(
            ef,
            &format!(
                "/Type /EmbeddedFile /Subtype /{} /Params << /Size {} /ModDate ({}) >>",
                pdfw::escape_pdf_name(att.mime),
                att.bytes.len(),
                mod_date
            ),
            att.bytes,
        );
        let fs = filespecs[idx];
        b.write(fs, |out| {
            out.extend_from_slice(
                format!(
                    "<< /Type /Filespec /F ({}) /UF <{}> /Desc (diskcleaner evidence attachment) \
                     /AFRelationship /{} /EF << /F {} 0 R >> >>",
                    pdfw::escape_pdf_string(att.filename),
                    pdfw::utf16be_hex(att.filename),
                    att.relationship,
                    ef.0
                )
                .as_bytes(),
            );
        });
    }

    // --- /Names EmbeddedFiles tree (sorted by filename) ---
    let mut sorted: Vec<(String, ObjRef)> = attachments
        .iter()
        .enumerate()
        .map(|(i, a)| (a.filename.to_string(), filespecs[i]))
        .collect();
    sorted.sort_by(|a, c| a.0.cmp(&c.0));
    let names_entries: Vec<String> = sorted
        .iter()
        .map(|(name, r)| format!("({}) {} 0 R", pdfw::escape_pdf_string(name), r.0))
        .collect();
    b.write(names, |out| {
        out.extend_from_slice(
            format!(
                "<< /EmbeddedFiles << /Names [{}] >> >>",
                names_entries.join(" ")
            )
            .as_bytes(),
        );
    });

    // --- Catalog ---
    let af: Vec<String> = filespecs.iter().map(|r| format!("{} 0 R", r.0)).collect();
    b.write(catalog, |out| {
        out.extend_from_slice(
            format!(
                "<< /Type /Catalog /Pages {} 0 R /Metadata {} 0 R /Lang (en) \
                 /PageMode /UseAttachments /OutputIntents [{} 0 R] /Names {} 0 R /AF [{}] >>",
                pages_obj.0,
                metadata.0,
                output_intent.0,
                names.0,
                af.join(" ")
            )
            .as_bytes(),
        );
    });

    // --- Deterministic file ID: hash of title + attachment bytes ---
    let mut id_input = title.as_bytes().to_vec();
    id_input.extend_from_slice(subtitle.as_bytes());
    for a in attachments {
        id_input.extend_from_slice(a.filename.as_bytes());
        id_input.extend_from_slice(blake3::hash(a.bytes).as_bytes());
    }
    let id: [u8; 16] = blake3::hash(&id_input).as_bytes()[..16]
        .try_into()
        .expect("blake3 output is 32 bytes");

    b.finish(catalog, info, &id)
}

/// ISO-8601 UTC instant ("2026-10-12T07:33:00Z") ->
/// (PDF "D:20261012073300Z", XMP keeps the ISO form).
fn pdf_dates(iso: &str) -> (String, String) {
    let mut digits: Vec<char> = iso.chars().filter(|c| c.is_ascii_digit()).collect();
    let mut fields = [0u32; 6]; // Y M D h m s
    for (i, slot) in fields.iter_mut().enumerate() {
        let take = [4, 2, 2, 2, 2, 2][i];
        if digits.len() >= take {
            let s: String = digits[..take].iter().collect();
            *slot = s.parse().unwrap_or(0);
        }
        let drain = take.min(digits.len());
        digits.drain(..drain);
    }
    let (y, mo, d, h, mi, s) = (
        fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
    );
    (
        format!("D:{:04}{:02}{:02}{:02}{:02}{:02}Z", y, mo, d, h, mi, s),
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s),
    )
}

// ---------------------------------------------------------------------------
// Legacy document-level API (compatibility surface kept since v0.4.0)
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

/// One embedded evidence attachment (legacy API).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedAttachment {
    pub filename: String,
    pub content: Vec<u8>,
    pub mime: String,
}

/// Simple single-page archival document: title, header, body lines, and
/// embedded attachments — rendered through the REAL PDF/A-3 engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfaDocument {
    pub title: String,
    pub header: String,
    pub body_lines: Vec<String>,
    pub footer: String,
    pub attachments: Vec<EmbeddedAttachment>,
}

impl PdfaDocument {
    pub fn new(title: &str, header: &str) -> Self {
        Self {
            title: title.to_string(),
            header: header.to_string(),
            body_lines: Vec::new(),
            footer: "This document is a rendering. The authoritative record is embedded within and governs over this text.".to_string(),
            attachments: Vec::new(),
        }
    }

    pub fn add_line(&mut self, line: &str) {
        self.body_lines.push(line.to_string());
    }

    pub fn embed_file(&mut self, filename: &str, content: Vec<u8>, mime: &str) {
        self.attachments.push(EmbeddedAttachment {
            filename: filename.to_string(),
            content,
            mime: mime.to_string(),
        });
    }

    pub fn extract_attachment(&self, filename: &str) -> Option<&[u8]> {
        self.attachments
            .iter()
            .find(|a| a.filename == filename)
            .map(|a| a.content.as_slice())
    }

    /// Render deterministic PDF/A-3 bytes without clock leaks (Δ472, Δ476):
    /// the date derives from the document's header timestamp if it carries
    /// one, else a fixed epoch (the caller's evidence carries the real time).
    pub fn render_pdf_bytes(&self) -> Vec<u8> {
        let font = font::PdfFont::parse(font::EMBEDDED_FONT).expect("bundled font must parse");
        let mut c = crate::template::Canvas::new(font);

        // Simple one-page layout: header, lines, footer.
        c.rect_fill(0.0, 0.0, 595.0, 86.0, (0.070, 0.129, 0.278));
        c.text(56.0, 26.0, 18.0, (1.0, 1.0, 1.0), true, &self.title);
        for (i, l) in c
            .wrap(&self.header, 10.0, 595.0 - 2.0 * 56.0)
            .iter()
            .enumerate()
        {
            c.text(
                56.0,
                56.0 + (i as f64) * 13.0,
                10.0,
                (0.75, 0.79, 0.87),
                false,
                l,
            );
        }
        let mut y = 120.0;
        for line in &self.body_lines {
            for l in c.wrap(line, 10.0, 595.0 - 2.0 * 56.0) {
                c.text(56.0, y, 10.0, (0.1, 0.1, 0.1), false, &l);
                y += 14.0;
            }
            y += 4.0;
        }
        c.text(56.0, 790.0, 8.5, (0.39, 0.41, 0.44), false, &self.footer);

        let (page, drawn) = c.finish();
        let atts: Vec<ArchiveAttachment> = self
            .attachments
            .iter()
            .map(|a| ArchiveAttachment {
                filename: &a.filename,
                bytes: &a.content,
                mime: &a.mime,
                relationship: "Source",
            })
            .collect();
        render_pdfa(
            &self.title,
            &self.header,
            "1970-01-01T00:00:00Z",
            std::slice::from_ref(&page),
            &drawn,
            &atts,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_page(text: &str) -> VisualPage {
        let font = font::PdfFont::parse(font::EMBEDDED_FONT).unwrap();
        let mut content = Vec::new();
        content.extend_from_slice(b"BT /F1 12 Tf 72 770 Td <");
        content.extend_from_slice(font.encode_hex(text).as_bytes());
        content.extend_from_slice(b"> Tj ET");
        VisualPage { content }
    }

    #[test]
    fn pdf_dates_conversion() {
        let (pdf, xmp) = pdf_dates("2026-10-12T07:33:00Z");
        assert_eq!(pdf, "D:20261012073300Z");
        assert_eq!(xmp, "2026-10-12T07:33:00Z");
        // Fractional seconds are tolerated.
        let (pdf2, _) = pdf_dates("2026-10-12T07:33:00.123456Z");
        assert_eq!(pdf2, "D:20261012073300Z");
    }

    #[test]
    fn renders_structurally_valid_pdfa3() {
        let page = sample_page("Certificate");
        let att = ArchiveAttachment {
            filename: "certificate.json",
            bytes: b"{\"signed\": true}".as_slice(),
            mime: "application/json",
            relationship: "Source",
        };
        let bytes = render_pdfa(
            "Certificate of Sanitization",
            "SN-TEST",
            "2026-10-12T07:33:00Z",
            &[page],
            "Certificate",
            std::slice::from_ref(&att),
        );
        assert!(bytes.starts_with(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"));
        let s = String::from_utf8_lossy(&bytes);
        for marker in [
            "/Type /Catalog",
            "/OutputIntents",
            "/GTS_PDFA1",
            "/DestOutputProfile",
            "/EmbeddedFiles",
            "/Type /Filespec",
            "/AFRelationship /Source",
            "/Type /EmbeddedFile",
            "pdfaid:part>3<",
            "pdfaid:conformance>B<",
            "/Subtype /Type0",
            "/CIDToGIDMap /Identity",
            "startxref",
            "%%EOF",
        ] {
            assert!(s.contains(marker), "missing {}", marker);
        }
        // The embedded attachment bytes appear VERBATIM (unfiltered).
        let needle = b"{\"signed\": true}";
        assert!(bytes.windows(needle.len()).any(|w| w == needle));
        // Determinism.
        let page2 = sample_page("Certificate");
        let att2 = ArchiveAttachment {
            filename: "certificate.json",
            bytes: b"{\"signed\": true}".as_slice(),
            mime: "application/json",
            relationship: "Source",
        };
        let bytes2 = render_pdfa(
            "Certificate of Sanitization",
            "SN-TEST",
            "2026-10-12T07:33:00Z",
            &[page2],
            "Certificate",
            std::slice::from_ref(&att2),
        );
        assert_eq!(bytes, bytes2, "identical inputs must be byte-identical");
    }

    #[test]
    fn xref_offsets_walk_clean() {
        let page = sample_page("xref");
        let bytes = render_pdfa("T", "S", "2026-10-12T07:33:00Z", &[page], "xref", &[]);
        // Find "startxref" in the raw bytes, read its value, land on the
        // xref keyword, then verify EVERY table entry points at its
        // "<num> 0 obj" header — all in byte space (the file contains
        // binary font/ICC streams that are not valid UTF-8).
        let startxref_pos = {
            let mut found = None;
            for i in 0..bytes.len().saturating_sub(9) {
                if &bytes[i..i + 9] == b"startxref" {
                    found = Some(i);
                }
            }
            found.expect("startxref present")
        };
        let num_start = startxref_pos + 10; // skip "startxref\n"
        let num_end = bytes[num_start..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|e| num_start + e)
            .expect("startxref value terminated");
        let xref_off: usize = std::str::from_utf8(&bytes[num_start..num_end])
            .expect("startxref is ASCII")
            .trim()
            .parse()
            .expect("startxref value");
        assert_eq!(&bytes[xref_off..xref_off + 4], b"xref");

        // Walk the table in byte space.
        let mut pos = xref_off;
        pos += b"xref\n".len();
        // Header: "0 <count>\n"
        let hdr_end = pos + bytes[pos..].iter().position(|b| *b == b'\n').unwrap();
        let hdr = std::str::from_utf8(&bytes[pos..hdr_end]).unwrap();
        let count: usize = hdr.split_whitespace().nth(1).unwrap().parse().unwrap();
        pos = hdr_end + 1;
        for objnum in 0..count {
            let row_end = pos + bytes[pos..].iter().position(|b| *b == b'\n').unwrap();
            let row = std::str::from_utf8(&bytes[pos..row_end]).unwrap();
            if objnum == 0 {
                assert!(row.starts_with("0000000000 65535 f"), "free-list head");
            } else {
                let off: usize = row[..10].parse().unwrap();
                let expect = format!("{} 0 obj", objnum);
                assert_eq!(
                    &bytes[off..off + expect.len()],
                    expect.as_bytes(),
                    "xref entry {} must point at its object header",
                    objnum
                );
            }
            pos = row_end + 1;
        }
    }
}
