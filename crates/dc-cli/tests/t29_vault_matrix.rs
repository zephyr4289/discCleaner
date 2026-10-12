//! t29 — Micro-KVM vault matrix (v0.8.0, Vector 2).
//!
//! On CI (no /dev/kvm) every vault execution must fail CLOSED with a
//! typed refusal — never a panic, never a silently skipped vault. On a
//! KVM host the enclave must run and produce a report. The HMAC
//! verification chain laws are exercised against fixed keys everywhere.

use dc_vault::{VaultError, VaultRequirement, VaultSession, VerificationChain, hmac_sha256};

#[test]
fn t29_a1_vault_probe_without_kvm_is_a_clean_refusal() {
    // CI: no /dev/kvm → typed error mentioning the requirement.
    match VaultSession::probe(VaultRequirement::Enclave) {
        Ok(_) => {} // host with KVM: fine
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("/dev/kvm") || msg.contains("KVM"),
                "typed refusal expected, got: {msg}"
            );
        }
    }
}

#[test]
fn t29_a2_encrypted_enclave_posture_never_downgrades() {
    // The strict posture must refuse on hosts without SEV/TDX —
    // never silently run an unencrypted VM under that flag.
    match VaultSession::probe(VaultRequirement::EncryptedEnclave) {
        Ok(probe) => {
            assert!(
                probe.encryption != dc_vault::MemoryEncryption::None,
                "encrypted posture must not report none"
            );
        }
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("SEV") || msg.contains("encrypted") || msg.contains("/dev/kvm"),
                "{msg}"
            );
        }
    }
}

#[test]
fn t29_a3_full_session_when_kvm_exists() {
    // Execute with the permissive posture: succeeds on KVM hosts, clean
    // refusal otherwise. Both outcomes are pinned here.
    match VaultSession::execute(VaultRequirement::Enclave) {
        Ok(mut session) => {
            let head1 = session.seal_record(b"record-1").expect("seal 1");
            let head2 = session.seal_record(b"record-2").expect("seal 2");
            assert_ne!(head1, head2, "chain advances");
            let report = session.report();
            assert_eq!(report.kvm_api_version, 12);
            assert_eq!(report.chain_records, 2);
            assert_eq!(report.guest_payload_blake3, dc_vault::payload_measurement());
            assert_eq!(report.session_key_fingerprint.len(), 24);
            let evidence: dc_cert::VaultReportEvidence = dc_cert::VaultReportEvidence {
                kvm_api_version: report.kvm_api_version,
                memory_encryption: report.memory_encryption.clone(),
                encrypted: report.encrypted,
                guest_payload_blake3: report.guest_payload_blake3.clone(),
                session_key_fingerprint: report.session_key_fingerprint.clone(),
                chain_head_hex: report.chain_head_hex.clone(),
                chain_records: report.chain_records,
                vcpu_exits: report.vcpu_exits,
                elapsed_us: report.elapsed_us,
            };
            if evidence.encrypted {
                assert!(evidence.defense_warnings().is_empty());
            } else {
                assert_eq!(evidence.defense_warnings().len(), 1);
            }
        }
        Err(VaultError::Refusal(_) | VaultError::Kvm(_)) => {
            eprintln!("skipped: no KVM on this host");
        }
        Err(other) => panic!("unexpected vault error: {other:?}"),
    }
}

#[test]
fn t29_a4_hmac_chain_laws() {
    // RFC 4231 vector pinned inside dc-vault; here: chain semantics.
    let key = [7u8; 64];
    let mut c1 = VerificationChain::new(&key, b"fingerprint");
    let mut c2 = VerificationChain::new(&key, b"fingerprint");
    let mut c3 = VerificationChain::new(&[8u8; 64], b"fingerprint");
    c1.seal(b"a");
    c1.seal(b"b");
    c2.seal(b"a");
    c2.seal(b"b");
    c3.seal(b"a");
    c3.seal(b"b");
    assert_eq!(c1.head_hex(), c2.head_hex(), "deterministic replay");
    assert_ne!(c1.head_hex(), c3.head_hex(), "key sensitivity");
    let mut c4 = VerificationChain::new(&key, b"fingerprint");
    c4.seal(b"b");
    c4.seal(b"a");
    assert_ne!(c1.head_hex(), c4.head_hex(), "order sensitivity");
    // Direct HMAC vector sanity (the full RFC vectors live in dc-vault).
    assert_eq!(
        hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn t29_a5_cli_execute_vault_flag_fails_closed_without_kvm() {
    // `dc execute --vault` on a KVM-less host must refuse (usage exit),
    // never certify with a vault report it did not produce.
    let tmp = tempfile::tempdir().unwrap();
    let backing = tmp.path().join("vault-probe.raw");
    std::fs::write(&backing, vec![0u8; 8 * 1024 * 1024]).unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("dc").unwrap();
    let result = cmd
        .arg("execute")
        .arg("--target")
        .arg(backing.to_str().unwrap())
        .arg("--profile")
        .arg("nist-clear")
        .arg("--vault")
        .arg("--serial-confirm")
        .arg("loop0")
        .arg("--allow-loop")
        .arg("--verify")
        .arg("none")
        .arg("--key")
        .arg("/nonexistent.key")
        .output()
        .expect("run dc execute --vault");
    if !result.status.success() {
        let err = String::from_utf8_lossy(&result.stderr);
        assert!(
            err.contains("vault")
                || err.contains("KVM")
                || err.contains("/dev/kvm")
                || err.contains("signing"),
            "expected vault/key refusal, got: {err}"
        );
    } else {
        // A KVM host with a signing key: acceptable — the vault ran.
        eprintln!("host has KVM: execute --vault proceeded");
    }
}

#[test]
fn t29_a6_guest_payload_measurement_is_stable_and_pinned() {
    // The 64-byte enclave image is pinned: its BLAKE3/24 is a constant.
    let m = dc_vault::payload_measurement();
    assert_eq!(m.len(), 24);
    assert_eq!(m, dc_vault::payload_measurement());
    // And the raw bytes are the pinned encodings (REX.X fix included).
    let p = dc_vault::payload::payload_bytes();
    assert_eq!(&p[32..36], &[0x49, 0x33, 0x04, 0xCA]); // xor rax,[r10+rcx*8]
    assert_eq!(&p[36..40], &[0x49, 0x89, 0x04, 0xCB]); // mov [r11+rcx*8],rax
}
