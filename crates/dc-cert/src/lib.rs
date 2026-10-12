pub mod ccid;
pub mod cert;
pub mod cxl;
pub mod dualauth;
pub mod firmware;
pub mod iso7816;
pub mod keyring;
pub mod keystore;
pub mod package;
pub mod pq;
pub mod project;
pub mod project2;
pub mod schema2;
pub mod signer;
pub mod token;
pub mod tpm;
pub mod vault;
pub mod zk;
pub mod zone_attest;

pub use cert::{
    CertVerificationResult, ExecutionDetails, ExecutionPassReport, FailureRecord,
    HealthSnapshotEvidence, InterruptionRecord, OperatorDetails, PurgeCertificateEvidence,
    PurgeFallbackRecord, SanitizationCertificate, SignatureDetails, UnsignedCertificate,
    VERIFICATION_SCHEME_DOC,
};
pub use dualauth::{
    AuthSignatureEntry, AuthorizationSet, CustodyType, FLEET_MANIFEST_DOMAIN, PLAN_APPROVAL_DOMAIN,
};
pub use firmware::{
    AtaDeviceStatisticsEvidence, FirmwareAttestationEvidence, FirmwareIdentity,
    NvmeTelemetryEvidence, TelemetrySnapshot,
};
pub use keyring::{KeyringEntry, KeyringRegistry};
pub use keystore::{KeyStoreRegistry, SigningKeySourceKind, SigningSiteId};
pub use package::{EvidencePackageManifest, PackageArtifact, PackageVerifier};
pub use pq::{MlDsaOperatorKey, PostQuantumSignature};
pub use project::CertificateProjector;
pub use project2::Cert2Projector;
pub use schema2::Cert2Document;
pub use signer::{OperatorKeyPair, verify_canonical_signature};
pub use token::{
    HardwareCustodyAttestation, KeyDisclosure, PIV_AID, PivAlgorithm, PivSession, PivSlot,
};
pub use tpm::{AttestationFields, TpmAttestationEvidence};
pub use vault::{FabricSessionEvidence, PhotonManifestEvidence, VaultReportEvidence};
pub use zone_attest::{CapacityThreeNumbers, CrossVersionCertVerifier, ZoneAttestationBlock};

#[cfg(test)]
mod tests {
    use super::*;
    use dc_core::{
        BusType, DeviceIdentity, FastPathPolicy, JournalChainSummary, KernelIdentity,
        SanitizationPlan, StableIdentity, VerifyLevel,
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
            kernel: KernelIdentity {
                major: 259,
                minor: 0,
            },
            kernel_name: "nvme0n1".to_string(),
            dev_path: "/dev/nvme0n1".to_string(),
            logical_block_size: 512,
            physical_block_size: 4096,
        };

        let plan = SanitizationPlan::clear_zero(
            identity.stable.clone(),
            FastPathPolicy::PreferWriteZeroes,
        );
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
                stream_hash_blake3:
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
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
        assert!(
            !cert.verify_signature().unwrap(),
            "Signature verification must fail on tampered cert"
        );
    }
}

// ---------------------------------------------------------------------------
// Unit test layer (LLVM-style: focused, descriptive, per-module)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod unit_tests {
    use super::*;
    use ed25519_dalek::Signer;
    use std::path::PathBuf;

    fn plan_hash() -> &'static str {
        "3a7b9c1d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b"
    }

    // ---------------- dualauth: real cryptography ----------------

    #[test]
    fn dualauth_two_distinct_officers_authorize() {
        let a = OperatorKeyPair::generate();
        let b = OperatorKeyPair::generate();
        let mut set = AuthorizationSet::new(plan_hash());
        set.add_signature(AuthSignatureEntry {
            key_fingerprint: a.key_fingerprint_blake3(),
            public_key_hex: a.public_key_hex(),
            signature_hex: {
                let msg = AuthSignatureEntry::approval_message(PLAN_APPROVAL_DOMAIN, plan_hash());
                hex::encode(a.signing_key.sign(&msg).to_bytes())
            },
            is_hardware_token: false,
            hardware_attestation: None,
        });
        set.add_signature(AuthSignatureEntry {
            key_fingerprint: b.key_fingerprint_blake3(),
            public_key_hex: b.public_key_hex(),
            signature_hex: {
                let msg = AuthSignatureEntry::approval_message(PLAN_APPROVAL_DOMAIN, plan_hash());
                hex::encode(b.signing_key.sign(&msg).to_bytes())
            },
            is_hardware_token: false,
            hardware_attestation: None,
        });
        assert!(set.verify_pre_arm_authorization(plan_hash(), true).is_ok());
    }

    #[test]
    fn dualauth_blake3_of_strings_forgery_is_rejected() {
        // REG-DUALAUTH-FORGERY: the pre-hardening "signature" was a BLAKE3 of
        // public strings — computable by anyone. It must not authorize.
        let mut set = AuthorizationSet::new(plan_hash());
        set.add_signature(AuthSignatureEntry {
            key_fingerprint: blake3::hash(b"FAKE").to_hex().to_string(),
            public_key_hex: hex::encode([2u8; 32]),
            signature_hex: blake3::hash(format!("APPROVE_PLAN_{}_BY_X", plan_hash()).as_bytes())
                .to_hex()
                .to_string(),
            is_hardware_token: false,
            hardware_attestation: None,
        });
        set.add_signature(AuthSignatureEntry {
            key_fingerprint: blake3::hash(b"FAKE2").to_hex().to_string(),
            public_key_hex: hex::encode([3u8; 32]),
            signature_hex: blake3::hash(format!("APPROVE_PLAN_{}_BY_Y", plan_hash()).as_bytes())
                .to_hex()
                .to_string(),
            is_hardware_token: false,
            hardware_attestation: None,
        });
        assert!(set.verify_pre_arm_authorization(plan_hash(), true).is_err());
    }

    #[test]
    fn dualauth_single_officer_and_same_key_twice_fail_2pi() {
        let a = OperatorKeyPair::generate();
        let b = OperatorKeyPair::generate();
        let sig_of = |k: &OperatorKeyPair, hw: bool| AuthSignatureEntry {
            key_fingerprint: k.key_fingerprint_blake3(),
            public_key_hex: k.public_key_hex(),
            signature_hex: {
                let msg = AuthSignatureEntry::approval_message(PLAN_APPROVAL_DOMAIN, plan_hash());
                hex::encode(k.signing_key.sign(&msg).to_bytes())
            },
            is_hardware_token: hw,
            hardware_attestation: None,
        };
        // One signature: incomplete.
        let mut one = AuthorizationSet::new(plan_hash());
        one.add_signature(sig_of(&a, false));
        assert_eq!(
            one.verify_pre_arm_authorization(plan_hash(), true),
            Err("AUTHORIZATION_INCOMPLETE")
        );

        // Same key twice: NOT 2PI (v0.7.0: hardware flags without
        // attestation are refused BEFORE the 2PI completeness check, so
        // exercise the same-key rule with unclaimed software signatures).
        let mut twice = AuthorizationSet::new(plan_hash());
        twice.add_signature(sig_of(&a, false));
        twice.add_signature(sig_of(&a, false));
        assert_eq!(
            twice.verify_pre_arm_authorization(plan_hash(), true),
            Err("AUTHORIZATION_INCOMPLETE")
        );
        // REG-TOKEN-CUSTODY-PROOF (library half): claiming hardware
        // custody without a PIV attestation is a hard refusal.
        let mut claimed = AuthorizationSet::new(plan_hash());
        claimed.add_signature(sig_of(&a, true));
        claimed.add_signature(sig_of(&b, false));
        assert_eq!(
            claimed.verify_pre_arm_authorization(plan_hash(), true),
            Err("HW_CUSTODY_CLAIM_WITHOUT_ATTESTATION")
        );

        // Two distinct keys pass.
        let mut two = AuthorizationSet::new(plan_hash());
        two.add_signature(sig_of(&a, false));
        two.add_signature(sig_of(&b, false));
        assert!(two.verify_pre_arm_authorization(plan_hash(), true).is_ok());
    }

    #[test]
    fn dualauth_domain_separation_prevents_cross_protocol_replay() {
        let a = OperatorKeyPair::generate();
        let b = OperatorKeyPair::generate();
        // Sign under the FLEET domain but present as a PLAN approval.
        let mut set = AuthorizationSet::new(plan_hash());
        for k in [&a, &b] {
            let msg = AuthSignatureEntry::approval_message(FLEET_MANIFEST_DOMAIN, plan_hash());
            set.add_signature(AuthSignatureEntry {
                key_fingerprint: k.key_fingerprint_blake3(),
                public_key_hex: k.public_key_hex(),
                signature_hex: hex::encode(k.signing_key.sign(&msg).to_bytes()),
                is_hardware_token: false,
                hardware_attestation: None,
            });
        }
        assert_eq!(
            set.verify_pre_arm_authorization(plan_hash(), true),
            Err("SIGNATURE_INVALID"),
            "manifest-domain signatures must not authorize a plan wipe"
        );
    }

    #[test]
    fn dualauth_fingerprint_spoofing_is_rejected() {
        let a = OperatorKeyPair::generate();
        let b = OperatorKeyPair::generate();
        let msg = AuthSignatureEntry::approval_message(PLAN_APPROVAL_DOMAIN, plan_hash());
        let mut set = AuthorizationSet::new(plan_hash());
        // Valid signatures but a WRONG fingerprint for officer A.
        set.add_signature(AuthSignatureEntry {
            key_fingerprint: blake3::hash(b"not-the-real-fingerprint")
                .to_hex()
                .to_string(),
            public_key_hex: a.public_key_hex(),
            signature_hex: hex::encode(a.signing_key.sign(&msg).to_bytes()),
            is_hardware_token: false,
            hardware_attestation: None,
        });
        set.add_signature(AuthSignatureEntry {
            key_fingerprint: b.key_fingerprint_blake3(),
            public_key_hex: b.public_key_hex(),
            signature_hex: hex::encode(b.signing_key.sign(&msg).to_bytes()),
            is_hardware_token: false,
            hardware_attestation: None,
        });
        assert_eq!(
            set.verify_pre_arm_authorization(plan_hash(), true),
            Err("KEY_FINGERPRINT_MISMATCH")
        );
    }

    // ---------------- keyring: temporal semantics ----------------

    #[test]
    fn keyring_rotation_supersedes_old_key_at_t() {
        // REG-KEYRING-SUPERSEDED: signatures at-or-after the rotation time
        // are suspect (the historical keyring never checked this).
        let mut reg = KeyringRegistry::new();
        reg.register_key(KeyringEntry {
            key_hash: "K1".to_string(),
            identity: "Officer".to_string(),
            role: "Auditor".to_string(),
            active_from_utc: 100,
            superseded_at_utc: None,
            revoked_at_utc: None,
        });
        assert_eq!(
            reg.evaluate_signature_at_time("K1", 150).unwrap(),
            "VALID_AT_TIME"
        );

        reg.rotate_key_bilateral(
            "K1",
            KeyringEntry {
                key_hash: "K2".to_string(),
                identity: "Officer".to_string(),
                role: "Auditor".to_string(),
                active_from_utc: 200,
                superseded_at_utc: None,
                revoked_at_utc: None,
            },
            200,
        )
        .unwrap();

        assert_eq!(
            reg.evaluate_signature_at_time("K1", 199).unwrap(),
            "VALID_AT_TIME"
        );
        assert_eq!(
            reg.evaluate_signature_at_time("K1", 200).unwrap(),
            "SUSPECT_SUPERSEDED_KEY",
            "at-or-after rotation T the old key is suspect"
        );
        assert!(
            reg.evaluate_signature_at_time("K1", 50).is_err(),
            "before activation is an error"
        );
        assert_eq!(
            reg.evaluate_signature_at_time("K2", 250).unwrap(),
            "VALID_AT_TIME"
        );
    }

    #[test]
    fn keyring_revocation_semantics() {
        let mut reg = KeyringRegistry::new();
        reg.register_key(KeyringEntry {
            key_hash: "K".to_string(),
            identity: "O".to_string(),
            role: "R".to_string(),
            active_from_utc: 100,
            superseded_at_utc: None,
            revoked_at_utc: None,
        });
        reg.revoke_key("K", 500).unwrap();
        assert_eq!(
            reg.evaluate_signature_at_time("K", 499).unwrap(),
            "VALID_AT_TIME"
        );
        assert_eq!(
            reg.evaluate_signature_at_time("K", 500).unwrap(),
            "SUSPECT_REVOKED_KEY"
        );
        assert!(reg.evaluate_signature_at_time("UNKNOWN", 100).is_err());
    }

    // ---------------- signer: keyfile hygiene ----------------

    #[test]
    fn keyfile_round_trip_enforces_owner_only_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path: PathBuf = dir.path().join("operator.key");
        let kp = OperatorKeyPair::generate();
        kp.save_to_file(&path).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "saved keyfiles must be owner-only");

        let loaded = OperatorKeyPair::load_from_file(&path).unwrap();
        assert_eq!(loaded.public_key_hex(), kp.public_key_hex());

        // REG-KEYFILE-PERMS: world-readable key material is refused on load.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(OperatorKeyPair::load_from_file(&path).is_err());
    }

    // ---------------- strict parser ----------------

    #[test]
    fn strict_parser_rejects_bom_and_duplicate_keys() {
        let with_bom = format!("{}{{\"schema\":\"x\"}}", "\u{feff}");
        let res = SanitizationCertificate::verify_raw_cert_file(with_bom.as_bytes(), None, None);
        assert!(!res.is_valid);
        assert!(res.error_detail.unwrap().contains("BOM"));

        let dup = r#"{"schema":"a","schema":"b"}"#;
        let res = SanitizationCertificate::verify_raw_cert_file(dup.as_bytes(), None, None);
        assert!(!res.is_valid);
        assert!(res.error_detail.unwrap().contains("DUPLICATE_KEY"));
    }

    #[test]
    fn strict_parser_rejects_unknown_forward_fields() {
        // REG-CERT-UNKNOWN-FIELD (Δ169): serde must not silently ignore
        // forward-incompatible fields in certificates.
        let kp = OperatorKeyPair::generate();
        let mut cert = minimal_cert(&kp);
        cert.sign(&kp).unwrap();
        let json = serde_json::to_string(&cert).unwrap();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["unknown_forward_field"] = serde_json::json!("nope");
        let tampered = serde_json::to_string(&val).unwrap();
        let res = SanitizationCertificate::verify_raw_cert_file(tampered.as_bytes(), None, None);
        assert!(!res.is_valid);
    }

    fn minimal_cert(kp: &OperatorKeyPair) -> SanitizationCertificate {
        use dc_core::{
            BusType, DeviceIdentity, FastPathPolicy, JournalChainSummary, KernelIdentity,
            SanitizationPlan, StableIdentity, VerifyLevel,
        };
        use dc_verify::VerificationReport;
        let stable = StableIdentity {
            model: None,
            serial: Some("SN-U".to_string()),
            wwn: None,
            size_bytes: 1024 * 1024,
            bus: BusType::File,
            dm_name: None,
            dm_uuid: None,
        };
        SanitizationCertificate::new(
            SanitizationPlan::clear_zero(stable.clone(), FastPathPolicy::ForbidWriteZeroes),
            "hash".to_string(),
            DeviceIdentity {
                stable,
                kernel: KernelIdentity { major: 7, minor: 0 },
                kernel_name: "loop0".to_string(),
                dev_path: "/loop0".to_string(),
                logical_block_size: 512,
                physical_block_size: 4096,
            },
            ExecutionDetails {
                started_utc: "t".to_string(),
                finished_utc: "t".to_string(),
                duration_mono_ms: 1,
                interruptions: vec![],
                failures: vec![],
                passes: vec![],
            },
            VerificationReport {
                level: VerifyLevel::Full,
                windows_checked: 1,
                mismatch_count: 0,
                first_mismatch_lbas: vec![],
                stream_hash_blake3: "h".to_string(),
                stream_hash_sha256: None,
                entropy: None,
            },
            JournalChainSummary {
                path: PathBuf::from("/tmp/u.dcj"),
                chain_head: "c".to_string(),
                record_count: 1,
                discarded_tail_bytes: 0,
                uuid: "u".to_string(),
                sealed: false,
            },
            kp.public_key_hex(),
            kp.key_fingerprint_blake3(),
        )
    }
}
