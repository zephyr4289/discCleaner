use crate::pdfa::PdfaDocument;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportModel {
    pub target_serial: String,
    pub mechanism_name: String,
    pub outcome_clean: bool,
    pub evidence_timestamp_utc: u64,
    pub embedded_cert_json: String,
}

impl ReportModel {
    /// Derive front-page title strictly based on sanitization outcome (Δ474).
    pub fn derive_title(&self) -> &'static str {
        if self.outcome_clean {
            "Certificate of Sanitization"
        } else {
            "Sanitization Report — VERIFICATION FAILED"
        }
    }

    /// Project ReportModel into deterministic archival PDF/A document (Δ471, Δ473, Δ476).
    pub fn generate_pdfa(&self) -> PdfaDocument {
        let title = self.derive_title();
        let header = format!(
            "Target: SN:{} | Mechanism: {} | Timestamp: {}",
            self.target_serial, self.mechanism_name, self.evidence_timestamp_utc
        );

        let mut doc = PdfaDocument::new(title, &header);

        doc.add_line(&format!("Execution Status: {}", if self.outcome_clean { "VERIFIED_CLEAN" } else { "VERIFICATION_FAILURE" }));
        doc.add_line(&format!("Evidence Time (UTC): {}", self.evidence_timestamp_utc));
        doc.add_line(&format!("Sanitization Mechanism: {}", self.mechanism_name));

        // Embed verifiable signed certificate JSON as document attachment (Δ473)
        doc.embed_file(
            "certificate.json",
            self.embedded_cert_json.as_bytes().to_vec(),
            "application/json",
        );

        doc
    }
}
