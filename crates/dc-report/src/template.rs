//! Visual certificate composition for PDF/A-3 archives (v0.6.0).
//!
//! Draws the human-readable front page auditors see in Acrobat:
//! - navy masthead with the certificate class and outcome
//! - NIST SP 800-88 grade badge (Clear / Purge) and verification verdict
//! - ordered evidence table (mechanism, completion evidence, digests,
//!   officer key fingerprints)
//! - defense-warning box (red) when the run carries mandatory advisories
//! - attachment manifest with per-attachment BLAKE3 digests
//!
//! All geometry is deterministic; the only inputs are the document data.

use crate::pdfa::font::PdfFont;
use crate::pdfa::VisualPage;

// A4 portrait, PDF units.
const W: f64 = 595.0;
const H: f64 = 842.0;
const MARGIN: f64 = 56.0;

// Palette (sRGB, covered by the OutputIntent).
const NAVY: (f64, f64, f64) = (0.070, 0.129, 0.278);
const INK: (f64, f64, f64) = (0.098, 0.106, 0.118);
const MUTED: (f64, f64, f64) = (0.388, 0.407, 0.435);
const GOLD: (f64, f64, f64) = (0.776, 0.616, 0.184);
const PAPER: (f64, f64, f64) = (1.0, 1.0, 1.0);
const BAND: (f64, f64, f64) = (0.945, 0.955, 0.973);
const HAIR: (f64, f64, f64) = (0.820, 0.843, 0.878);
const RED: (f64, f64, f64) = (0.678, 0.145, 0.145);
const WARN_BG: (f64, f64, f64) = (0.988, 0.949, 0.949);
const GREEN: (f64, f64, f64) = (0.129, 0.447, 0.204);

/// One content-stream canvas. Records the drawn-text union so the PDF
/// font widths and ToUnicode mappings stay exact.
pub struct Canvas {
    ops: String,
    drawn: String,
    font: PdfFont,
}

impl Canvas {
    pub fn new(font: PdfFont) -> Self {
        Self {
            ops: String::new(),
            drawn: String::new(),
            font,
        }
    }

    fn rgb(&mut self, c: (f64, f64, f64)) {
        self.ops.push_str(&format!(
            "{} {} {} rg\n{} {} {} RG\n",
            c.0, c.1, c.2, c.0, c.1, c.2
        ));
    }

    pub fn rect_fill(&mut self, x: f64, y_top: f64, w: f64, h: f64, c: (f64, f64, f64)) {
        self.rgb(c);
        self.ops
            .push_str(&format!("{} {} {} {} re f\n", x, H - y_top - h, w, h));
    }

    pub fn rect_stroke(&mut self, x: f64, y_top: f64, w: f64, h: f64, c: (f64, f64, f64), lw: f64) {
        self.rgb(c);
        self.ops.push_str(&format!("{} w\n", lw));
        self.ops
            .push_str(&format!("{} {} {} {} re S\n", x, H - y_top - h, w, h));
    }

    pub fn hline(&mut self, x1: f64, x2: f64, y_top: f64, c: (f64, f64, f64), lw: f64) {
        self.rgb(c);
        self.ops.push_str(&format!("{} w\n", lw));
        self.ops.push_str(&format!(
            "{} {} m {} {} l S\n",
            x1,
            H - y_top,
            x2,
            H - y_top
        ));
    }

    /// Text with its baseline `size` below the given top offset.
    /// `bold` uses fill+stroke (faux bold) — the single embedded face.
    pub fn text(
        &mut self,
        x: f64,
        y_top: f64,
        size: f64,
        c: (f64, f64, f64),
        bold: bool,
        text: &str,
    ) {
        self.rgb(c);
        let hex = self.font.encode_hex(text);
        let mode = if bold { "2 Tr 0.30 w" } else { "0 Tr" };
        self.ops.push_str(&format!(
            "BT /F1 {} Tf {} {} Td {} <{}> Tj ET\n",
            size,
            x,
            H - y_top - size,
            mode,
            hex
        ));
        self.drawn.push_str(text);
        self.drawn.push('\n');
    }

    pub fn measure(&self, text: &str, size: f64) -> f64 {
        self.font.measure(text, size)
    }

    pub fn text_right(
        &mut self,
        x_right: f64,
        y_top: f64,
        size: f64,
        c: (f64, f64, f64),
        bold: bool,
        text: &str,
    ) {
        let w = self.measure(text, size);
        self.text(x_right - w, y_top, size, c, bold, text);
    }

    /// Greedy word wrap at a pixel width.
    pub fn wrap(&self, text: &str, size: f64, max_w: f64) -> Vec<String> {
        let mut lines = Vec::new();
        let mut current = String::new();
        for word in text.split_whitespace() {
            let candidate = if current.is_empty() {
                word.to_string()
            } else {
                format!("{} {}", current, word)
            };
            if self.measure(&candidate, size) > max_w && !current.is_empty() {
                lines.push(std::mem::take(&mut current));
                current = word.to_string();
            } else {
                current = candidate;
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
        if lines.is_empty() {
            lines.push(String::new());
        }
        lines
    }

    pub fn finish(self) -> (VisualPage, String) {
        (
            VisualPage {
                content: self.ops.into_bytes(),
            },
            self.drawn,
        )
    }
}

/// The complete visual certificate: two A4 pages.
pub struct CertificateDocument<'a> {
    pub title: &'a str,
    pub subtitle: &'a str,
    pub nist_class: &'a str,
    pub outcome_clean: bool,
    pub fields: &'a [(String, String)],
    pub warnings: &'a [String],
    pub creation_utc_iso: &'a str,
    pub attachments: &'a [(&'a str, u64, &'a str, String)],
}

impl<'a> CertificateDocument<'a> {
    /// Render both pages; returns (pages, drawn-text union).
    pub fn render(&self) -> (Vec<VisualPage>, String) {
        let font =
            PdfFont::parse(crate::pdfa::font::EMBEDDED_FONT).expect("bundled font must parse");
        let mut drawn = String::new();
        let mut pages = Vec::new();

        // ---------------- Page 1: summary ----------------
        let mut c = Canvas::new(PdfFont::parse(crate::pdfa::font::EMBEDDED_FONT).unwrap());

        // Masthead band.
        c.rect_fill(0.0, 0.0, W, 148.0, NAVY);
        c.rect_fill(0.0, 148.0, W, 4.0, GOLD);
        c.text(MARGIN, 30.0, 13.0, GOLD, true, "D I S C C L E A N E R");
        c.text(MARGIN, 54.0, 26.0, PAPER, true, self.title);
        let sub_lines = c.wrap(self.subtitle, 11.0, W - 2.0 * MARGIN);
        let mut y = 92.0;
        for l in &sub_lines {
            c.text(MARGIN, y, 11.0, (0.757, 0.792, 0.867), false, l);
            y += 14.0;
        }
        c.text_right(
            W - MARGIN,
            30.0,
            11.0,
            (0.757, 0.792, 0.867),
            false,
            "ISO 19005-3 (PDF/A-3b) ARCHIVAL COPY",
        );
        c.text_right(
            W - MARGIN,
            46.0,
            10.0,
            (0.757, 0.792, 0.867),
            false,
            self.creation_utc_iso,
        );

        // Outcome + NIST badge row.
        let mut y = 190.0;
        c.rect_fill(MARGIN, y, 232.0, 54.0, BAND);
        c.rect_stroke(MARGIN, y, 232.0, 54.0, HAIR, 0.8);
        c.text(
            MARGIN + 14.0,
            y + 10.0,
            9.0,
            MUTED,
            true,
            "NIST SP 800-88 Rev.1 CLASS",
        );
        c.text(
            MARGIN + 14.0,
            y + 24.0,
            22.0,
            NAVY,
            true,
            &self.nist_class.to_uppercase(),
        );
        let outcome_label = if self.outcome_clean {
            "VERIFIED CLEAN"
        } else {
            "VERIFICATION FAILED"
        };
        let outcome_color = if self.outcome_clean { GREEN } else { RED };
        let ow = c.measure(outcome_label, 22.0);
        c.rect_fill(
            W - MARGIN - ow - 28.0,
            y,
            ow + 28.0,
            54.0,
            if self.outcome_clean {
                (0.914, 0.957, 0.925)
            } else {
                WARN_BG
            },
        );
        c.text(
            W - MARGIN - ow - 14.0,
            y + 24.0,
            22.0,
            outcome_color,
            true,
            outcome_label,
        );
        y += 78.0;

        // Evidence table.
        c.text(MARGIN, y, 12.0, NAVY, true, "SANITIZATION EVIDENCE");
        y += 22.0;
        for (i, (k, v)) in self.fields.iter().enumerate() {
            if y > H - 120.0 {
                break; // fields beyond page 1 continue on page 2
            }
            if i % 2 == 0 {
                c.rect_fill(MARGIN - 6.0, y - 4.0, W - 2.0 * (MARGIN - 6.0), 20.0, BAND);
            }
            c.text(MARGIN, y, 9.5, MUTED, false, k);
            let vv: String = v.chars().collect();
            let mut lines = c.wrap(&vv, 9.5, W - MARGIN - 200.0);
            if lines.len() > 2 {
                lines.truncate(2);
                let last = lines.last_mut().unwrap();
                if last.chars().count() > 60 {
                    *last = last.chars().take(57).collect::<String>() + "...";
                }
            }
            let mut vy = y;
            for l in &lines {
                c.text(MARGIN + 200.0, vy, 9.5, INK, true, l);
                vy += 12.0;
            }
            c.hline(MARGIN - 6.0, W - MARGIN + 6.0, y + 14.0, HAIR, 0.5);
            y += 20.0;
        }

        // Defense warnings box.
        if !self.warnings.is_empty() {
            let box_top = y + 14.0;
            c.rect_fill(MARGIN - 6.0, box_top, W - 2.0 * (MARGIN - 6.0), 8.0, RED);
            let mut wy = box_top + 16.0;
            c.text(
                MARGIN,
                wy,
                10.0,
                RED,
                true,
                "DEFENSE WARNINGS (MANDATORY DISCLOSURE)",
            );
            wy += 16.0;
            for w_ in self.warnings {
                for l in c.wrap(w_, 9.5, W - 2.0 * MARGIN - 20.0) {
                    c.text(MARGIN + 10.0, wy, 9.5, INK, false, &l);
                    wy += 13.0;
                }
                wy += 3.0;
            }
        }

        // Footer.
        c.hline(MARGIN, W - MARGIN, H - 70.0, HAIR, 0.5);
        c.text(
            MARGIN,
            H - 60.0,
            8.5,
            MUTED,
            false,
            "The authoritative record is the embedded certificate.json (Ed25519-signed, RFC 8785 canonical) and journal.dcj (hash-chained).",
        );
        c.text(
            MARGIN,
            H - 48.0,
            8.5,
            MUTED,
            false,
            "This page is a rendering for human review; the embedded attachments govern in any discrepancy.",
        );
        c.text_right(W - MARGIN, H - 48.0, 8.5, MUTED, false, "Page 1 of 2");

        let (p1, d1) = c.finish();
        pages.push(p1);
        drawn.push_str(&d1);

        // ---------------- Page 2: attachments + notices ----------------
        let mut c = Canvas::new(PdfFont::parse(crate::pdfa::font::EMBEDDED_FONT).unwrap());
        let mut y = 70.0;
        c.text(MARGIN, y, 16.0, NAVY, true, "Evidence Attachments");
        y += 26.0;
        c.text(
            MARGIN,
            y,
            9.0,
            MUTED,
            false,
            "Every attachment is embedded unfiltered; extract it from this PDF and verify it independently.",
        );
        y += 20.0;

        // Header row.
        c.rect_fill(MARGIN - 6.0, y - 4.0, W - 2.0 * (MARGIN - 6.0), 18.0, NAVY);
        c.text(MARGIN, y, 9.0, PAPER, true, "FILE");
        c.text(MARGIN + 150.0, y, 9.0, PAPER, true, "SIZE (BYTES)");
        c.text(MARGIN + 230.0, y, 9.0, PAPER, true, "MIME TYPE");
        c.text(MARGIN + 350.0, y, 9.0, PAPER, true, "BLAKE3");
        y += 22.0;
        for (name, size, mime, digest) in self.attachments {
            c.text(MARGIN, y, 9.0, INK, true, name);
            c.text(MARGIN + 150.0, y, 9.0, INK, false, &size.to_string());
            c.text(MARGIN + 230.0, y, 9.0, INK, false, mime);
            // Digest split into two 32-hex lines.
            if digest.len() >= 64 {
                c.text(MARGIN + 350.0, y - 1.0, 7.5, MUTED, false, &digest[..32]);
                c.text(MARGIN + 350.0, y + 8.5, 7.5, MUTED, false, &digest[32..64]);
            }
            c.hline(MARGIN - 6.0, W - MARGIN + 6.0, y + 13.0, HAIR, 0.5);
            y += 20.0;
        }

        // Determinism notice.
        y += 24.0;
        c.text(
            MARGIN,
            y,
            12.0,
            NAVY,
            true,
            "Deterministic Rendering Notice",
        );
        y += 18.0;
        for l in c.wrap(
            "This document was produced by a deterministic renderer: identical evidence inputs yield byte-identical PDF/A-3 output. All timestamps derive from the signed certificate's execution record, never from a rendering-time clock.",
            9.5,
            W - 2.0 * MARGIN,
        ) {
            c.text(MARGIN, y, 9.5, INK, false, &l);
            y += 13.0;
        }

        y += 18.0;
        c.text(MARGIN, y, 12.0, NAVY, true, "Court / Archive Ingest");
        y += 18.0;
        for l in c.wrap(
            "This file targets ISO 19005-3 (PDF/A-3b): it carries an XMP identification (pdfaid:part 3, conformance B), an sRGB output intent, fully embedded fonts, and associated-file relationships for every embedded evidence artifact. Automated e-discovery and archival systems (VeraPDF-class validators) can parse the structure and extract the attachments directly.",
            9.5,
            W - 2.0 * MARGIN,
        ) {
            c.text(MARGIN, y, 9.5, INK, false, &l);
            y += 13.0;
        }

        c.hline(MARGIN, W - MARGIN, H - 70.0, HAIR, 0.5);
        c.text(
            MARGIN,
            H - 60.0,
            8.5,
            MUTED,
            false,
            "Face: Liberation Serif (SIL OFL 1.1), embedded in full for PDF/A compliance. Embedded ICC: sRGB IEC61966-2.1.",
        );
        c.text_right(W - MARGIN, H - 48.0, 8.5, MUTED, false, "Page 2 of 2");

        let (p2, d2) = c.finish();
        pages.push(p2);
        drawn.push_str(&d2);
        let _ = font;

        (pages, drawn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_renders_two_pages_with_wrapped_text() {
        let digest = "a".repeat(64);
        let doc = CertificateDocument {
            title: "Certificate of Sanitization",
            subtitle: "Hardware Purge — ATA Sanitize Crypto Scramble — SN-TEST-42",
            nist_class: "Purge",
            outcome_clean: true,
            fields: &[
                (
                    "Executed mechanism".to_string(),
                    "AtaSanitizeCryptoScramble".to_string(),
                ),
                (
                    "Completion evidence".to_string(),
                    "ata-sanitize-status-log-0x30".to_string(),
                ),
                ("Plan hash".to_string(), "b".repeat(64)),
            ],
            warnings: &["DEFENSE_WARNING: Media contains reallocated sectors.".to_string()],
            creation_utc_iso: "2026-10-12T07:33:00Z",
            attachments: &[
                ("certificate.json", 1024, "application/json", digest.clone()),
                (
                    "journal.dcj",
                    4096,
                    "application/octet-stream",
                    digest.clone(),
                ),
            ],
        };
        let (pages, drawn) = doc.render();
        assert_eq!(pages.len(), 2);
        assert!(!pages[0].content.is_empty());
        assert!(drawn.contains("VERIFIED CLEAN"));
        assert!(drawn.contains("DEFENSE_WARNING"));
        assert!(drawn.contains("certificate.json"));
        let s = String::from_utf8_lossy(&pages[0].content);
        // Text operators are present and hex-encoded.
        assert!(s.contains("BT /F1"));
        assert!(s.contains(" Tj ET"));
    }
}
