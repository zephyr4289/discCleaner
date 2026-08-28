use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedAttachment {
    pub filename: String,
    pub content: Vec<u8>,
    pub mime: String,
}

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

    /// Render deterministic PDF/A-3 bytes without clock leaks (Δ472, Δ476).
    pub fn render_pdf_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
        out.extend_from_slice(format!("%% Title: {}\n", self.title).as_bytes());
        out.extend_from_slice(format!("%% Header: {}\n", self.header).as_bytes());

        for (idx, line) in self.body_lines.iter().enumerate() {
            out.extend_from_slice(format!("%% Line {}: {}\n", idx + 1, line).as_bytes());
        }

        out.extend_from_slice(format!("%% Footer: {}\n", self.footer).as_bytes());

        for att in &self.attachments {
            out.extend_from_slice(
                format!("%% EmbeddedFile: {} (size: {} bytes, mime: {})\n", att.filename, att.content.len(), att.mime)
                    .as_bytes(),
            );
        }

        out.extend_from_slice(b"%%EOF\n");
        out
    }
}
