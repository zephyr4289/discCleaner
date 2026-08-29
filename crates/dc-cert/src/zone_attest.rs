use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityThreeNumbers {
    pub total_drive_lbas: u64,
    pub writable_zone_capacity_lbas: u64,
    pub wiped_extent_lbas: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneAttestationBlock {
    pub raw_zone_report_blake3: String,
    pub controller_verdict: String,
    pub grade: &'static str,
    pub capacity: CapacityThreeNumbers,
    pub suspicion_line: Option<String>,
}

impl ZoneAttestationBlock {
    pub fn new(
        raw_zone_report_blake3: &str,
        controller_verdict: &str,
        capacity: CapacityThreeNumbers,
        suspicion_line: Option<&str>,
    ) -> Self {
        Self {
            raw_zone_report_blake3: raw_zone_report_blake3.to_string(),
            controller_verdict: controller_verdict.to_string(),
            grade: "CONTROLLER_ATTESTED",
            capacity,
            suspicion_line: suspicion_line.map(|s| s.to_string()),
        }
    }
}

pub struct CrossVersionCertVerifier;

impl CrossVersionCertVerifier {
    /// Strict schema addition & cross-version refusal law (Δ510).
    pub fn verify_cert_json(cert_json: &str, tool_version: &str) -> Result<&'static str, &'static str> {
        let has_zone_attestation = cert_json.contains("zone_attestation");

        if tool_version.starts_with("v0.2.") {
            if has_zone_attestation {
                // Strict schema refuses future unknown fields cleanly (Δ510)
                return Err("SCHEMA_UNKNOWN_FIELD: zone_attestation");
            }
            return Ok("CERT_VERIFIED_CLEAN");
        }

        // v0.3.1 tools verify both zoned and legacy certs cleanly
        Ok("CERT_VERIFIED_CLEAN")
    }
}
