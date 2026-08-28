use crate::schema2::Cert2Document;

pub struct Cert2Projector;

impl Cert2Projector {
    /// Pure, deterministic projection from journal execution records to Cert2Document (Δ321).
    pub fn project(
        executed_mechanisms: &[String],
        nist_classes: &[String],
        target_device: &str,
        target_serial: &str,
        timestamp_utc: u64,
        interrogation_contract: Option<&str>,
    ) -> Cert2Document {
        // Enforce anti-grade-laundering: minimum NIST class across all executed mechanisms
        let min_class = if nist_classes.contains(&"Clear".to_string()) || nist_classes.is_empty() {
            "Clear"
        } else {
            "Purge"
        };

        Cert2Document {
            schema_version: 2,
            target_device: target_device.to_string(),
            target_serial: target_serial.to_string(),
            nist_sanitization_class: min_class.to_string(),
            executed_mechanisms: executed_mechanisms.to_vec(),
            interrogation_contract: interrogation_contract.map(|s| s.to_string()),
            issued_at_utc: timestamp_utc,
        }
    }
}
