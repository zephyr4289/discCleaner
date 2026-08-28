pub mod cert;
pub mod project;
pub mod signer;

pub use cert::{
    CertVerificationResult, ExecutionDetails, ExecutionPassReport, FailureRecord,
    InterruptionRecord, OperatorDetails, SanitizationCertificate, SignatureDetails,
    UnsignedCertificate, VERIFICATION_SCHEME_DOC,
};
pub use project::CertificateProjector;
pub use signer::{verify_canonical_signature, OperatorKeyPair};

#[cfg(test)]
mod tests {
    use super::*;
    use dc_core::{
        BusType, DeviceIdentity, FastPathPolicy, JournalChainSummary, KernelIdentity,
        SanitizationPlan, StableIdentity, ToolBuild, VerifyLevel,
    };
    use dc_verify::VerificationReport;

    #[test]
    fn test_certificate_signing_and_tamper_detection() {
        let keypair = OperatorKeyPair::generate();

        let identity = DeviceIdentity {
            stable: StableIdentity {
                model: Some("TestSSD".to_string()),
                serial: Some("SN999".to_string()),
                wwn: None,
                size_bytes: 10 * 1024 * 1024 * 1024,
                bus: BusType::Nvme,
                dm_name: None,
                dm_uuid: None,
            },
            kernel: KernelIdentity { major: 259, minor: 0 },
            kernel_name: "nvme0n1".to_string(),
            dev_path: "/dev/nvme0n1".to_string(),
            logical_block_size: 512,
            physical_block_size: 4096,
        };

        let plan = SanitizationPlan::clear_zero(identity.stable.clone(), FastPathPolicy::PreferWriteZeroes);
        let plan_hash = plan.compute_plan_hash().unwrap();

        let mut cert = SanitizationCertificate::new(
            plan,
            plan_hash,
            identity,
            ExecutionDetails {
                started_utc: "2026-08-28T20:00:00Z".to_string(),
                finished_utc: "2026-08-28T20:10:00Z".to_string(),
                duration_mono_ms: 600000,
                interruptions: vec![],
                failures: vec![],
                passes: vec![ExecutionPassReport {
                    index: 0,
                    pattern: "Zero".to_string(),
                    fast_path_used: true,
                    windows_written: 5000,
                    throughput_kib_s: 3500000,
                }],
            },
            VerificationReport {
                level: VerifyLevel::Full,
                windows_checked: 5000,
                mismatch_count: 0,
                first_mismatch_lbas: vec![],
                stream_hash_blake3: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                stream_hash_sha256: None,
                entropy: None,
            },
            JournalChainSummary {
                path: std::path::PathBuf::from("/tmp/test.dcj"),
                chain_head: "0123456789abcdef".to_string(),
                record_count: 5,
                discarded_tail_bytes: 0,
                uuid: "test-uuid".to_string(),
                sealed: false,
            },
            keypair.public_key_hex(),
            keypair.key_fingerprint_blake3(),
        );

        // Sign certificate
        cert.sign(&keypair).unwrap();
        assert!(cert.verify_signature().unwrap());

        // Tamper with a field
        cert.verification.mismatch_count = 1;
        assert!(!cert.verify_signature().unwrap(), "Signature verification must fail on tampered cert");
    }
}
