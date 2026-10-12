//! XMP metadata packet (PDF/A-3 identification).
//!
//! Declares `pdfaid:part = 3`, `pdfaid:conformance = B` — the ISO
//! 19005-3 conformance level — and carries the dc / xmp / pdf properties
//! veraPDF cross-checks against the document information dictionary
//! (title, producer, creation date).

use super::pdfw::escape_pdf_string;

/// Build the XMP packet bytes for one archival document.
///
/// `creation_utc_iso` is the same instant the Info dictionary's
/// `/CreationDate` carries (e.g. "2026-10-12T07:33:00Z"); the clock never
/// runs inside this module.
pub fn build_xmp(
    title: &str,
    subtitle: &str,
    producer: &str,
    creation_utc_iso: &str,
    attachments: &[(&str, u64, &str)],
) -> Vec<u8> {
    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
    let _ = escape_pdf_string; // (dict strings escape in pdfw; XMP escapes here)

    let mut xmp = String::new();
    xmp.push_str("<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n");
    xmp.push_str("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"diskcleaner-dc-report\">\n");
    xmp.push_str(" <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n");
    xmp.push_str("  <rdf:Description rdf:about=\"\"\n");
    xmp.push_str("    xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n");
    xmp.push_str("    xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"\n");
    xmp.push_str("    xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\"\n");
    xmp.push_str("    xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\">\n");
    xmp.push_str(&format!(
        "   <dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">{}</rdf:li></rdf:Alt></dc:title>\n",
        xml_escape(title)
    ));
    xmp.push_str(&format!(
        "   <dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\">{}</rdf:li></rdf:Alt></dc:description>\n",
        xml_escape(subtitle)
    ));
    xmp.push_str("   <dc:format>application/pdf</dc:format>\n");
    xmp.push_str(&format!(
        "   <xmp:CreateDate>{}</xmp:CreateDate>\n",
        xml_escape(creation_utc_iso)
    ));
    xmp.push_str(&format!(
        "   <xmp:ModifyDate>{}</xmp:ModifyDate>\n",
        xml_escape(creation_utc_iso)
    ));
    xmp.push_str(&format!(
        "   <pdf:Producer>{}</pdf:Producer>\n",
        xml_escape(producer)
    ));
    xmp.push_str("   <pdfaid:part>3</pdfaid:part>\n");
    xmp.push_str("   <pdfaid:conformance>B</pdfaid:conformance>\n");
    xmp.push_str("  </rdf:Description>\n");

    // One description per embedded attachment, mirroring the /EmbeddedFiles
    // tree so archival harvesters see the manifest in metadata too.
    xmp.push_str("  <rdf:Description rdf:about=\"\"\n");
    xmp.push_str("    xmlns:dcir=\"http://www.aiim.org/pdfa/ns/extension/\">\n");
    xmp.push_str("   <dcir:embeddedfiles>\n");
    xmp.push_str("    <rdf:Bag>\n");
    for (name, size, mime) in attachments {
        xmp.push_str(&format!(
            "     <rdf:li rdf:parseType=\"Resource\"><dcir:name>{}</dcir:name><dcir:mime>{}</dcir:mime><dcir:size>{}</dcir:size></rdf:li>\n",
            xml_escape(name),
            xml_escape(mime),
            size
        ));
    }
    xmp.push_str("    </rdf:Bag>\n");
    xmp.push_str("   </dcir:embeddedfiles>\n");
    xmp.push_str("  </rdf:Description>\n");
    xmp.push_str(" </rdf:RDF>\n");
    xmp.push_str("</x:xmpmeta>\n");
    xmp.push_str("<?xpacket end=\"w\"?>\n");
    xmp.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xmp_declares_pdfa3b_and_matches_inputs() {
        let x = build_xmp(
            "Certificate of Sanitization",
            "Hardware Purge — SN-1",
            "diskcleaner dc-report/0.6.0",
            "2026-10-12T07:33:00Z",
            &[("certificate.json", 512, "application/json")],
        );
        let s = String::from_utf8(x).unwrap();
        assert!(s.contains("pdfaid:part>3<"), "part 3: {}", s);
        assert!(s.contains("pdfaid:conformance>B<"));
        assert!(s.contains("Certificate of Sanitization"));
        assert!(s.contains("2026-10-12T07:33:00Z"));
        assert!(s.contains("id=\"W5M0MpCehiHzreSzNTczkc9d\""));
        assert!(s.contains("certificate.json"));
        // XML escaping of ampersands.
        let x2 = build_xmp("A & B", "", "p", "2026-10-12T07:33:00Z", &[]);
        assert!(String::from_utf8(x2).unwrap().contains("A &amp; B"));
    }
}
