//! v0.12.0 Miracle integration tests: VDF time-lock weave, sonar
//! acoustic PUF, and Ghost Boot.
//!
//! * Library path: seeded 512-bit ceremony → VdfLock chain →
//!   verify_timeline (+ tamper rejection) — the CLI smoke shares
//!   exactly these calls.
//! * CLI: `dc vdf setup` / `dc vdf verify` / `dc baremetal info`.
//! * CLI wipe: `dc execute --vdf-lock` on a loop device produces a
//!   woven certificate whose timeline verifies.
//! * CLI guard: `dc execute --puf-guard` with a replay capture
//!   (debug seam, DC_SIGNAL_AT pattern) produces PUF evidence.
//! * `dc sonar enroll` / `verify` over the same replay seam.

use assert_cmd::prelude::*;
use std::process::Command;

fn dc_bin() -> Command {
    let mut c = Command::cargo_bin("dc").expect("dc binary");
    c.env("DC_SONAR_REPLAY_CAPTURE", "");
    c
}

// ---------------------------------------------------------------------------
// Library-level: the weave chain
// ---------------------------------------------------------------------------

#[test]
fn vdf_seeded_ceremony_chain_and_tamper_rejection() {
    // Reproducible drill ceremony at 512 bits (fast on CI).
    let (n_hex, info) =
        dc_vdf::generate_modulus(512, Some(b"v012-integration"), &mut |_| {}).unwrap();
    assert_eq!(info.modulus_bits, 512);

    let params = dc_vdf::VdfParams {
        scheme: dc_vdf::VdfParams::SCHEME.to_string(),
        modulus_n: n_hex,
        steps_per_pass: 2048,
        passes: 3,
        beacon: Some(hex::encode([0x5A; 16])),
        ceremony_note: "test".into(),
    };

    let mut lock = dc_vdf::VdfLock::new(&params, b"v012-run-material").expect("lock must enter");
    for _ in 0..3 {
        lock.advance(|_| true).expect("chain advances");
    }
    let ev = lock.evidence(None);
    let verdict = dc_vdf::verify_timeline(&ev);
    assert!(verdict.verified, "errors: {:?}", verdict.errors);
    assert_eq!(verdict.passes_verified, 3);
    assert_eq!(verdict.total_steps, 3 * 2048);
    assert!(verdict.min_elapsed_seconds_claim > 0.0);

    // Tampering any state breaks the chain.
    let mut bad = ev.clone();
    bad.passes[1].state = {
        let s: dc_vdf::BigUint<32> = dc_vdf::BigUint::from_hex(&bad.passes[1].state).unwrap();
        let mut limbs = s.0;
        limbs[2] ^= 1;
        hex::encode(dc_vdf::BigUint(limbs).to_bytes_be())
    };
    assert!(!dc_vdf::verify_timeline(&bad).verified);
}

#[test]
fn vdf_weave_patterns_are_state_keyed() {
    let (n_hex, _) = dc_vdf::generate_modulus(512, Some(b"v012-patterns"), &mut |_| {}).unwrap();
    let params = dc_vdf::VdfParams {
        scheme: dc_vdf::VdfParams::SCHEME.to_string(),
        modulus_n: n_hex,
        steps_per_pass: 512,
        passes: 2,
        beacon: None,
        ceremony_note: String::new(),
    };
    let mut lock = dc_vdf::VdfLock::new(&params, b"mat").unwrap();
    lock.advance(|_| true).unwrap();
    let s1 = lock.state_bytes();
    lock.advance(|_| true).unwrap();
    let s2 = lock.state_bytes();

    let mut a = [0u8; 4096];
    let mut b = [0u8; 4096];
    let src1 = dc_core::create_vdf_pattern_source(
        dc_core::VdfWeaveScheme::WesolowskiRsaUfoV1,
        [1; 32],
        0,
        &s1,
    );
    let src2 = dc_core::create_vdf_pattern_source(
        dc_core::VdfWeaveScheme::WesolowskiRsaUfoV1,
        [1; 32],
        1,
        &s2,
    );
    src1.fill(0, &mut a);
    src2.fill(0, &mut b);
    assert_ne!(
        a, b,
        "different chain states must key different media bytes"
    );

    // Same state, same pass → pure (deterministic re-derivation).
    let mut c = [0u8; 4096];
    src1.fill(0, &mut c);
    assert_eq!(a, c);
}

// ---------------------------------------------------------------------------
// CLI: vdf setup / verify / baremetal info
// ---------------------------------------------------------------------------

#[test]
fn vdf_setup_and_baremetal_info_via_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let params_path = tmp.path().join("vdf-params.json");

    let drill_seed = hex::encode(b"cli-drill-seed");
    dc_bin()
        .args([
            "vdf",
            "setup",
            "--bits",
            "512",
            "--seed",
            &drill_seed,
            "--steps-per-pass",
            "256",
            "--passes",
            "1",
            "--out",
        ])
        .arg(params_path.display().to_string())
        .assert()
        .success();

    let params: dc_vdf::VdfParams =
        serde_json::from_str(&std::fs::read_to_string(&params_path).unwrap()).unwrap();
    assert_eq!(params.scheme, dc_vdf::VdfParams::SCHEME);
    assert_eq!(params.steps_per_pass, 256);
    assert_eq!(params.passes, 1);
    // Reproducibility: same seed → same modulus.
    let params_path2 = tmp.path().join("vdf-params-2.json");
    dc_bin()
        .args([
            "vdf",
            "setup",
            "--bits",
            "512",
            "--seed",
            &drill_seed,
            "--steps-per-pass",
            "256",
            "--passes",
            "1",
            "--out",
        ])
        .arg(params_path2.display().to_string())
        .assert()
        .success();
    let params2: dc_vdf::VdfParams =
        serde_json::from_str(&std::fs::read_to_string(&params_path2).unwrap()).unwrap();
    assert_eq!(params.modulus_n, params2.modulus_n);

    dc_bin()
        .args(["baremetal", "info"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Ghost Boot"));
}

#[test]
fn vdf_verify_rejects_unwoven_certificate() {
    // A REAL certificate from an unwoven wipe carries no vdf section:
    // the audit path must refuse it.
    let Some((dev, _dir)) = loop_device() else {
        eprintln!("[v012] losetup unavailable — skipping loop test");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    dc_bin()
        .env("DC_SONAR_REPLAY_CAPTURE", "")
        .args([
            "execute",
            "--target",
            dev.display().to_string().as_str(),
            "--profile",
            "nist-clear",
            "--serial-confirm",
            "woven.img",
            "--allow-loop",
            "--no-progress",
            "--out-dir",
            out_dir.display().to_string().as_str(),
        ])
        .assert()
        .success();
    let cert_path: std::path::PathBuf = std::fs::read_dir(&out_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().ends_with(".cert.json"))
        .expect("certificate produced");
    dc_bin()
        .args(["vdf", "verify", "--certificate"])
        .arg(cert_path.display().to_string())
        .assert()
        .failure()
        .stderr(predicates::str::contains("no VDF timeline"));
    drop_loop(&dev);
}

// ---------------------------------------------------------------------------
// CLI: woven wipe on a loop device
// ---------------------------------------------------------------------------

fn loop_device() -> Option<(std::path::PathBuf, tempfile::TempDir)> {
    // Reuse the testkit loop spawner if present; otherwise skip.
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("woven.img");
    std::fs::write(&img, vec![0u8; 8 * 1024 * 1024]).unwrap();
    let out = std::process::Command::new("losetup")
        .args(["-f", "--show", "-b", "4096"])
        .arg(img.display().to_string())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if dev.is_empty() {
        return None;
    }
    Some((std::path::PathBuf::from(dev), dir))
}

fn drop_loop(dev: &std::path::Path) {
    let _ = std::process::Command::new("losetup")
        .args(["-d"])
        .arg(dev.display().to_string())
        .output();
}

#[test]
fn execute_vdf_lock_woven_certificate_and_audit() {
    let Some((dev, _dir)) = loop_device() else {
        eprintln!("[v012] losetup unavailable — skipping loop test");
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    // Fast drill parameters: 512-bit modulus, tiny steps.
    let params_path = tmp.path().join("vdf-params.json");
    let loop_seed = hex::encode(b"v012-loop-drill");
    dc_bin()
        .args([
            "vdf",
            "setup",
            "--bits",
            "512",
            "--seed",
            &loop_seed,
            "--steps-per-pass",
            "96",
            "--passes",
            "1",
            "--out",
        ])
        .arg(params_path.display().to_string())
        .assert()
        .success();

    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let res = dc_bin()
        .env("DC_SONAR_REPLAY_CAPTURE", "")
        .args([
            "execute",
            "--target",
            dev.display().to_string().as_str(),
            "--profile",
            "nist-clear",
            "--vdf-lock",
            params_path.display().to_string().as_str(),
            "--serial-confirm",
            "woven.img",
            "--allow-loop",
            "--no-progress",
            "--out-dir",
            out_dir.display().to_string().as_str(),
        ])
        .assert()
        .success();

    let _ = res;
    // Find the produced certificate.
    let certs: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.ends_with(".cert.json")
        })
        .collect();
    assert_eq!(certs.len(), 1, "exactly one certificate expected");
    let cert_path = certs[0].path();
    let cert: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cert_path).unwrap()).unwrap();

    // The weave evidence is present and complete.
    let vdf = cert.get("vdf").expect("vdf section in cert").clone();
    let ev: dc_vdf::TimelineEvidence = serde_json::from_value(vdf).unwrap();
    assert_eq!(ev.passes.len(), 1);
    assert_eq!(ev.steps_per_pass, 96);

    // Standalone audit: the timeline verifies through the CLI.
    dc_bin()
        .args(["vdf", "verify", "--certificate"])
        .arg(cert_path.display().to_string())
        .assert()
        .success()
        .stdout(predicates::str::contains("RESULT: VALID"));

    drop_loop(&dev);
}

// ---------------------------------------------------------------------------
// CLI: sonar enroll/verify + woven guard wipe over the replay seam
// ---------------------------------------------------------------------------

fn synthetic_capture() -> serde_json::Value {
    // Deterministic two-tone "chassis": stable peaks at 220.5/294 Hz.
    let hz = 4096.0f64;
    let n = 4096usize;
    let series: Vec<f32> = (0..n)
        .map(|t| {
            ((2.0 * std::f64::consts::PI * 220.5 * t as f64 / hz).sin() * 3.0
                + (2.0 * std::f64::consts::PI * 294.0 * t as f64 / hz).sin() * 1.1)
                as f32
        })
        .collect();
    serde_json::json!({
        "kind": "replay",
        "source": "iio:device0",
        "sample_hz": hz,
        "channels": ["x"],
        "series": [series],
        "duration_ms": 1000
    })
}

#[test]
fn sonar_enroll_verify_and_guarded_wipe_via_replay() {
    let Some((dev, _dir)) = loop_device() else {
        eprintln!("[v012] losetup unavailable — skipping loop test");
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let cap_path = tmp.path().join("capture.json");
    std::fs::write(&cap_path, synthetic_capture().to_string()).unwrap();

    // Enroll over the replay seam with a fixed challenge.
    let enr_path = tmp.path().join("sonar-enrollment.json");
    let fixed_challenge = hex::encode([0xABu8; 32]);
    dc_bin()
        .env("DC_SONAR_REPLAY_CAPTURE", cap_path.display().to_string())
        .args([
            "sonar",
            "enroll",
            "--target",
            dev.display().to_string().as_str(),
            "--captures",
            "3",
            "--challenge",
            &fixed_challenge,
            "--out",
            enr_path.display().to_string().as_str(),
        ])
        .assert()
        .success();

    let enr: dc_sonar::Enrollment =
        serde_json::from_str(&std::fs::read_to_string(&enr_path).unwrap()).unwrap();
    assert!(enr.bit_count > 0, "replay captures must enroll pairs");

    // Verify: same physical "chassis" (same replay) → MATCH.
    dc_bin()
        .env("DC_SONAR_REPLAY_CAPTURE", cap_path.display().to_string())
        .args([
            "sonar",
            "verify",
            "--target",
            dev.display().to_string().as_str(),
            "--enrollment",
            enr_path.display().to_string().as_str(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("MATCH"));

    // Guarded woven wipe: --puf-guard + --vdf-lock together.
    let params_path = tmp.path().join("vdf-params.json");
    let guarded_seed = hex::encode(b"v012-guarded");
    dc_bin()
        .args([
            "vdf",
            "setup",
            "--bits",
            "512",
            "--seed",
            &guarded_seed,
            "--steps-per-pass",
            "96",
            "--passes",
            "1",
            "--out",
            params_path.display().to_string().as_str(),
        ])
        .assert()
        .success();

    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    dc_bin()
        .env("DC_SONAR_REPLAY_CAPTURE", cap_path.display().to_string())
        .args([
            "execute",
            "--target",
            dev.display().to_string().as_str(),
            "--profile",
            "nist-clear",
            "--vdf-lock",
            params_path.display().to_string().as_str(),
            "--puf-guard",
            enr_path.display().to_string().as_str(),
            "--serial-confirm",
            "woven.img",
            "--allow-loop",
            "--no-progress",
            "--out-dir",
            out_dir.display().to_string().as_str(),
        ])
        .assert()
        .success();

    let certs: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".cert.json"))
        .collect();
    assert_eq!(certs.len(), 1);
    let cert: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(certs[0].path()).unwrap()).unwrap();
    let sonar = cert.get("sonar").expect("sonar evidence").clone();
    assert_eq!(
        sonar.get("all_matched").and_then(|v| v.as_bool()),
        Some(true)
    );
    let verifs = sonar
        .get("verifications")
        .and_then(|v| v.as_array())
        .expect("guard verifications recorded");
    assert!(
        verifs.len() >= 2,
        "pre + mid + post guard checks expected, got {}",
        verifs.len()
    );
    // And the vdf section coexists.
    assert!(cert.get("vdf").is_some());

    drop_loop(&dev);
}

#[test]
fn sonar_scan_reports_features() {
    let Some((dev, _dir)) = loop_device() else {
        eprintln!("[v012] losetup unavailable — skipping loop test");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let cap_path = tmp.path().join("capture.json");
    std::fs::write(&cap_path, synthetic_capture().to_string()).unwrap();
    dc_bin()
        .env("DC_SONAR_REPLAY_CAPTURE", cap_path.display().to_string())
        .args([
            "sonar",
            "scan",
            "--target",
            dev.display().to_string().as_str(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("peak"));
    drop_loop(&dev);
}
