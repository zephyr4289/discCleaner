//! dc-report — evidence rendering for diskcleaner.
//!
//! v0.6.0 ships a REAL ISO 19005-3 (PDF/A-3b) archival engine (zero
//! external dependencies, no supply-chain surface): every sanitization
//! run can emit a court-ingestible PDF whose embedded, unfiltered
//! `certificate.json` and `journal.dcj` remain independently verifiable
//! (Ed25519 signature, hash chain) after extraction.

pub mod batch;
pub mod pdfa;
pub mod project;
pub mod template;

pub use batch::{BatchVerifier, BatchVerifyResult};
pub use pdfa::{EmbeddedAttachment, PdfaDocument};
pub use project::ReportModel;
pub use template::CertificateDocument;

/// One attachment embedded into an archival PDF/A-3 document.
pub use pdfa::ArchiveAttachment;

/// Render the archival PDF/A-3 copy of a sanitization run: a visual
/// certificate front page + attachment manifest, with every evidence
/// artifact embedded unfiltered and associated per ISO 19005-3.
///
/// Determinism: identical inputs produce byte-identical PDFs; the only
/// time source is `creation_utc_iso` (the signed certificate's own
/// timestamp).
pub fn render_sanitization_archive(
    title: &str,
    subtitle: &str,
    nist_class: &str,
    outcome_clean: bool,
    fields: &[(String, String)],
    warnings: &[String],
    creation_utc_iso: &str,
    attachments: &[ArchiveAttachment<'_>],
) -> Vec<u8> {
    let manifest: Vec<(&str, u64, &str, String)> = attachments
        .iter()
        .map(|a| {
            (
                a.filename,
                a.bytes.len() as u64,
                a.mime,
                blake3::hash(a.bytes).to_hex().to_string(),
            )
        })
        .collect();

    let doc = CertificateDocument {
        title,
        subtitle,
        nist_class,
        outcome_clean,
        fields,
        warnings,
        creation_utc_iso,
        attachments: &manifest,
    };
    let (pages, drawn) = doc.render();
    pdfa::render_pdfa(
        title,
        subtitle,
        creation_utc_iso,
        &pages,
        &drawn,
        attachments,
    )
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn batch_verification_is_exhaustive_without_short_circuit() {
        // Δ477: every artifact gets a verdict, even after the first failure.
        let result = BatchVerifier::verify_directory(&[
            ("a.cert.json", true),
            ("b.cert.json", false),
            ("c.cert.json", true),
            ("d.cert.json", false),
        ]);
        assert_eq!(result.total_examined, 4);
        assert_eq!(result.passed_count, 2);
        assert_eq!(result.failed_count, 2);
        assert_eq!(result.verdicts.len(), 4);
        assert_eq!(result.aggregate_exit_code(), 1);
        assert!(result.verdicts[1].1.is_err());
        assert!(result.verdicts[3].1.is_err());
    }

    #[test]
    fn clean_batch_aggregates_to_zero() {
        let result = BatchVerifier::verify_directory(&[("x.cert.json", true)]);
        assert_eq!(result.aggregate_exit_code(), 0);
        assert_eq!(result.failed_count, 0);
    }

    #[test]
    fn archival_pdf_passes_structural_pdfa3_checks() {
        // REG-PDFA3-COMPLIANT-STRUCTURE (library half).
        let cert_bytes = br#"{"schema":"diskcleaner-cert/1","signed":true}"#.to_vec();
        let journal_bytes = b"DCJ1-journal-bytes".to_vec();
        let atts = [
            ArchiveAttachment {
                filename: "certificate.json",
                bytes: &cert_bytes,
                mime: "application/json",
                relationship: "Source",
            },
            ArchiveAttachment {
                filename: "journal.dcj",
                bytes: &journal_bytes,
                mime: "application/octet-stream",
                relationship: "Supplement",
            },
        ];
        let pdf = render_sanitization_archive(
            "Certificate of Sanitization",
            "Hardware Purge — ATA Sanitize Crypto Scramble — SN-42",
            "Purge",
            true,
            &[
                (
                    "Executed mechanism".to_string(),
                    "AtaSanitizeCryptoScramble".to_string(),
                ),
                ("Plan hash".to_string(), "f".repeat(64)),
            ],
            &["DEFENSE_WARNING: reallocated sectors present".to_string()],
            "2026-10-12T07:33:00Z",
            &atts,
        );

        let s = String::from_utf8_lossy(&pdf);
        for marker in [
            "%PDF-1.7",
            "xref",
            "/Type /Catalog",
            "/OutputIntents",
            "/EmbeddedFiles",
            "/Type /Filespec",
            "pdfaid:part>3<",
            "pdfaid:conformance>B<",
            "/Subtype /Type0",
        ] {
            assert!(s.contains(marker), "missing {}", marker);
        }
        // Attachments embedded verbatim (unfiltered streams).
        let needle1 = cert_bytes.as_slice();
        assert!(pdf.windows(needle1.len()).any(|w| w == needle1));
        let needle2 = journal_bytes.as_slice();
        assert!(pdf.windows(needle2.len()).any(|w| w == needle2));
        // Defense warning rendered on the visual page.
        let page_text = String::from_utf8_lossy(&pdf);
        // (warning text is hex-encoded as GIDs; the drawn warning string
        // appears in the template's own unit test — here we check the
        // attachment-level evidence instead.)
        assert!(page_text.contains("/AFRelationship /Source"));
        // Determinism: same inputs, same bytes.
        let pdf2 = render_sanitization_archive(
            "Certificate of Sanitization",
            "Hardware Purge — ATA Sanitize Crypto Scramble — SN-42",
            "Purge",
            true,
            &[
                (
                    "Executed mechanism".to_string(),
                    "AtaSanitizeCryptoScramble".to_string(),
                ),
                ("Plan hash".to_string(), "f".repeat(64)),
            ],
            &["DEFENSE_WARNING: reallocated sectors present".to_string()],
            "2026-10-12T07:33:00Z",
            &atts,
        );
        assert_eq!(pdf, pdf2);
    }

    #[test]
    fn legacy_pdfa_document_uses_the_real_engine() {
        let mut doc = PdfaDocument::new("Certificate of Sanitization", "Target: SN:X | NIST Clear");
        doc.add_line("Execution Status: VERIFIED_CLEAN");
        doc.embed_file(
            "certificate.json",
            b"{\"ok\":true}".to_vec(),
            "application/json",
        );
        let bytes = doc.render_pdf_bytes();
        assert!(bytes.starts_with(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"));
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("/Type /Catalog"));
        assert!(s.contains("pdfaid:part>3<"));
        // Attachment round-trip through the raw bytes.
        let needle = b"{\"ok\":true}";
        assert!(bytes.windows(needle.len()).any(|w| w == needle));
    }
}
