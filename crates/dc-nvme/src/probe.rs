//! Controller-side probing: Identify (capabilities), SMART/health snapshots,
//! and their translation into `dc_core::AttestedCapabilities` for the
//! StrategyCompiler. All I/O flows through `NvmeAdminTransport`, so every
//! function here is testable against a synthetic transport.

use crate::transport::{IoctlTaxonomy, NvmeAdminTransport};
use dc_core::AttestedCapabilities;
use dc_hw::{NvmeCodec, NvmeHealthLog, NvmeIdentifyController};
use serde::{Deserialize, Serialize};

/// Cryptographically-signable health snapshot embedded into certificates.
///
/// Captured BEFORE and AFTER a sanitization run: a diverging wear/error
/// profile between the two snapshots is the evidence an auditor needs that
/// the wiped drive is the same physical drive the certificate names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub critical_warning: u8,
    pub temperature_celsius: i32,
    pub available_spare_percent: u8,
    pub percentage_used: u8,
    pub media_errors: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub data_units_written: u128,
    pub captured_via: String,
}

impl From<NvmeHealthLog> for HealthSnapshot {
    fn from(h: NvmeHealthLog) -> Self {
        Self {
            critical_warning: h.critical_warning,
            // NVMe reports Kelvin; convert to Celsius (may go negative).
            temperature_celsius: h.temperature_kelvin as i32 - 273,
            available_spare_percent: h.available_spare_percent,
            percentage_used: h.percentage_used,
            media_errors: h.media_errors,
            power_cycles: h.power_cycles,
            power_on_hours: h.power_on_hours,
            data_units_written: h.data_units_written,
            captured_via: "nvme-admin-ioctl:log-page-0x02".to_string(),
        }
    }
}

/// Read the controller Identify block through the transport.
pub fn identify_controller(
    transport: &mut dyn NvmeAdminTransport,
) -> Result<NvmeIdentifyController, IoctlTaxonomy> {
    let cmd = NvmeCodec::encode_identify_controller();
    let payload = transport.admin_passthrough(&cmd)?;
    NvmeCodec::decode_identify_controller(&payload).map_err(|e| IoctlTaxonomy::OurBug {
        errno: libc::EINVAL,
        description: e,
    })
}

/// Read the SMART / Health log (page 0x02) through the transport.
pub fn read_health(
    transport: &mut dyn NvmeAdminTransport,
) -> Result<HealthSnapshot, IoctlTaxonomy> {
    let cmd = NvmeCodec::encode_get_health_log();
    let payload = transport.admin_passthrough(&cmd)?;
    let log = NvmeCodec::decode_health_log(&payload).map_err(|e| IoctlTaxonomy::OurBug {
        errno: libc::EINVAL,
        description: e,
    })?;
    Ok(HealthSnapshot::from(log))
}

/// Translate Identify Controller data into the core capability set.
///
/// - Format NVM support: OACS bit 1.
/// - Sanitize crypto/block: SANICAP bits 2/1.
/// - ATA/SCSI capabilities are structurally false on the NVMe ladder.
pub fn attest_capabilities(id: &NvmeIdentifyController) -> AttestedCapabilities {
    AttestedCapabilities {
        supports_sanitize_crypto: id.supports_sanitize_crypto(),
        supports_sanitize_block: id.supports_sanitize_block(),
        supports_format_nvm: id.supports_format_nvm(),
        supports_ata_security_enhanced: false,
        supports_dco_hpa: false,
        supports_scsi_sanitize: false,
    }
}

// ---------------------------------------------------------------------------
// Unit tests (synthetic transports)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use dc_core::DeviceTransportClass;

    struct SyntheticTransport {
        identify: Vec<u8>,
        health: Vec<u8>,
    }

    impl NvmeAdminTransport for SyntheticTransport {
        fn admin_passthrough(&mut self, cmd: &[u8; 64]) -> Result<Vec<u8>, IoctlTaxonomy> {
            match cmd[0] {
                0x06 => Ok(self.identify.clone()),
                0x02 => Ok(self.health.clone()),
                _ => Ok(vec![]),
            }
        }
    }

    fn synthetic() -> SyntheticTransport {
        // Identify Controller: OACS (256) = Format NVM bit set;
        // SANICAP (331) = CES|BES (0x06).
        let mut identify = vec![0u8; 4096];
        identify[4..24].copy_from_slice(b"SN-UNIT-PROBE-123456");
        identify[24..64].copy_from_slice(b"UNITMODEL-9X                            ");
        identify[256..258].copy_from_slice(&0x0002u16.to_le_bytes()); // OACS: format
        identify[331] = 0x06; // SANICAP: CES | BES
        identify[516..520].copy_from_slice(&1u32.to_le_bytes()); // NN = 1

        // Health log: critical_warning=0, temp=300K (27C), spare=100,
        // pct_used=42, media_errors=3, power_on_hours=12345.
        let mut health = vec![0u8; 512];
        health[1..3].copy_from_slice(&300u16.to_le_bytes());
        health[3] = 100;
        health[5] = 42;
        health[32..48].copy_from_slice(&1_000_000u128.to_le_bytes()); // DUR
        health[48..64].copy_from_slice(&2_000_000u128.to_le_bytes()); // DUW
        health[112..128].copy_from_slice(&150u128.to_le_bytes()); // power cycles
        health[128..144].copy_from_slice(&12345u128.to_le_bytes()); // power-on hours
        health[160..176].copy_from_slice(&3u128.to_le_bytes()); // media errors

        SyntheticTransport { identify, health }
    }

    #[test]
    fn identify_decodes_through_transport() {
        let mut t = synthetic();
        let id = identify_controller(&mut t).unwrap();
        assert_eq!(id.sn, "SN-UNIT-PROBE-123456");
        assert!(id.supports_format_nvm());
        assert!(id.supports_sanitize_crypto());
        assert!(id.supports_sanitize_block());
    }

    #[test]
    fn health_snapshot_translates_fields() {
        let mut t = synthetic();
        let h = read_health(&mut t).unwrap();
        assert_eq!(h.critical_warning, 0);
        assert_eq!(h.temperature_celsius, 27);
        assert_eq!(h.available_spare_percent, 100);
        assert_eq!(h.percentage_used, 42);
        assert_eq!(h.media_errors, 3);
        assert_eq!(h.power_on_hours, 12345);
        assert!(h.captured_via.contains("log-page-0x02"));
        // Serde roundtrip: certificates embed this struct verbatim.
        let j = serde_json::to_string(&h).unwrap();
        let back: HealthSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn capability_attestation_maps_identity_fields() {
        let mut t = synthetic();
        let id = identify_controller(&mut t).unwrap();
        let caps = attest_capabilities(&id);
        assert!(caps.supports_format_nvm);
        assert!(caps.supports_sanitize_crypto);
        assert!(caps.supports_sanitize_block);
        assert!(!caps.supports_ata_security_enhanced);
        assert!(!caps.supports_scsi_sanitize);

        // The StrategyCompiler must now accept this NVMe device for purge.
        let ladder =
            dc_core::StrategyCompiler::compile_strategy(DeviceTransportClass::Nvme, &caps, true)
                .unwrap();
        assert!(ladder
            .steps
            .iter()
            .any(|s| s.name == "NvmeSanitizeCryptoErase"));
    }

    #[test]
    fn no_sanitize_caps_builds_format_only_ladder() {
        let mut identify = vec![0u8; 4096];
        identify[256..258].copy_from_slice(&0x0002u16.to_le_bytes()); // format only
        identify[331] = 0x00; // no sanitize support
        let id = NvmeCodec::decode_identify_controller(&identify).unwrap();
        let caps = attest_capabilities(&id);
        assert!(caps.supports_format_nvm);
        assert!(!caps.supports_sanitize_crypto);
        assert!(!caps.supports_sanitize_block);
    }
}
