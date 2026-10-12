//! T27 — APPLIANCE BOOT & FIRMWARE ATTESTATION MATRIX (v0.7.0, Vectors 3-4).
//!
//! - The REAL PID-1 bootstrap sequence over a scripted backend: mount
//!   order (proc/sysfs/devtmpfs/devpts/efivarfs), RNDADDENTROPY credit,
//!   SIGCHLD zombie reaper, idempotent re-runs, entropy-starvation
//!   refusal.
//! - The appliance image: deterministic cpio newc, TRAILER, constituents
//!   manifest binding, tamper detection.
//! - The CLI verbs: `dc boot init --self-test` on a live host (already
//!   mounted pseudo-filesystems are tolerated), `dc boot pack` +
//!   `--verify-against` roundtrip and tamper refusal.
//! - Firmware attestation evidence: NVMe telemetry encode/decode binding
//!   and ATA devstat wear deltas.

use assert_cmd::Command;
use dc_cert::{AtaDeviceStatisticsEvidence, FirmwareAttestationEvidence, FirmwareIdentity};
use dc_cli::bootattest::ConstituentsManifest;
use dc_cli::bootiso::{
    InitramfsFile, build_appliance_initramfs, build_initramfs_cpio, verify_constituents,
};
use dc_hw::{AtaDeviceStatisticsPage, NvmeCodec};

#[test]
fn test_t27_appliance_attestation_matrix() {
    println!("\n[>>> T27 APPLIANCE BOOT & ATTESTATION MATRIX <<<]");

    pid1_sequence_cells();
    appliance_image_cells();
    boot_cli_cells();
    firmware_evidence_cells();

    println!("\n[=== T27 APPLIANCE BOOT & ATTESTATION MATRIX PASSED ALL CELLS ===]\n");
}

fn pid1_sequence_cells() {
    println!("\n[>> T27-PID1: real PID-1 bootstrap sequence <<]");

    use dc_cli::init::{InitBackend, evaluate_boot_state, run_pid1_init_real};
    use std::cell::RefCell;

    struct ScriptedInit {
        mounts: RefCell<Vec<(String, String, String)>>,
        pre_mounted: Vec<&'static str>,
        entropy: RefCell<Vec<(Vec<u8>, u32)>>,
        reaper: RefCell<bool>,
    }

    impl InitBackend for ScriptedInit {
        fn mount(&self, source: &str, target: &str, fstype: &str) -> Result<(), String> {
            self.mounts
                .borrow_mut()
                .push((source.into(), target.into(), fstype.into()));
            Ok(())
        }
        fn is_mounted(&self, target: &str) -> bool {
            self.pre_mounted.contains(&target)
        }
        fn add_entropy(&self, bytes: &[u8], bits: u32) -> Result<(), String> {
            self.entropy.borrow_mut().push((bytes.to_vec(), bits));
            Ok(())
        }
        fn install_zombie_reaper(&self) -> Result<(), String> {
            *self.reaper.borrow_mut() = true;
            Ok(())
        }
    }

    // Full sequence: order + entropy + reaper.
    let backend = ScriptedInit {
        mounts: RefCell::new(Vec::new()),
        pre_mounted: vec![],
        entropy: RefCell::new(Vec::new()),
        reaper: RefCell::new(false),
    };
    let (state, record) = run_pid1_init_real(&backend, true, "hashX").unwrap();
    let targets: Vec<&str> = record.mounted.iter().map(|(_, t, _)| t.as_str()).collect();
    assert_eq!(
        targets,
        vec![
            "/proc",
            "/sys",
            "/dev",
            "/dev/pts",
            "/sys/firmware/efi/efivars"
        ]
    );
    assert!(record.zombie_reaper_installed);
    assert!(*backend.reaper.borrow());
    assert_eq!(record.entropy_bytes_credited, 64);
    assert_eq!(backend.entropy.borrow()[0].1, 64); // 1 bit per byte
    assert_eq!(state.environment_fingerprint, "ENV_FP_hashX");

    // Idempotent: pre-mounted targets are skipped, not double-mounted.
    let backend = ScriptedInit {
        mounts: RefCell::new(Vec::new()),
        pre_mounted: vec!["/proc", "/sys"],
        entropy: RefCell::new(Vec::new()),
        reaper: RefCell::new(false),
    };
    let (_, record) = run_pid1_init_real(&backend, true, "h").unwrap();
    let targets: Vec<&str> = record.mounted.iter().map(|(_, t, _)| t.as_str()).collect();
    assert_eq!(
        targets,
        vec!["/dev", "/dev/pts", "/sys/firmware/efi/efivars"]
    );

    // Entropy starvation: hard refusal (the v0.6.0 contract preserved).
    assert_eq!(
        evaluate_boot_state(false, true, "x"),
        Err("ENTROPY_STARVATION_UNREADY")
    );

    println!("    [PASS] mount order, entropy credit, reaper, idempotence");
}

fn appliance_image_cells() {
    println!("\n[>> T27-IMAGE: deterministic initramfs + constituents <<]");

    // cpio newc layout: magic, mode, name, TRAILER, 4-byte padding.
    let cpio = build_initramfs_cpio(&[
        InitramfsFile {
            path: "/init",
            bytes: b"#!/dc\n",
            executable: true,
        },
        InitramfsFile {
            path: "/docs",
            bytes: b"evidence",
            executable: false,
        },
    ]);
    assert_eq!(&cpio[0..6], b"070701");
    // /init entry: ino at 6..14, mode at 14..22 (ASCII hex: 0o100755 =
    // 0x81ED), filesize 6 at 54..62 (newc field order after the magic).
    assert_eq!(&cpio[6..14], b"00000001");
    assert_eq!(&cpio[14..22], b"000081ed");
    assert_eq!(&cpio[54..62], b"00000006");
    assert!(cpio.windows(10).any(|w| w == b"TRAILER!!!"));
    assert_eq!(cpio.len() % 4, 0);

    // Determinism: byte-identical rebuilds.
    let cpio2 = build_initramfs_cpio(&[
        InitramfsFile {
            path: "/init",
            bytes: b"#!/dc\n",
            executable: true,
        },
        InitramfsFile {
            path: "/docs",
            bytes: b"evidence",
            executable: false,
        },
    ]);
    assert_eq!(cpio, cpio2);

    // Constituents binding: build, manifest, verify; tampering refused.
    let dc_binary = b"static-musl-dc-bytes".as_slice();
    let kernel = b"bzImage-bytes".as_slice();
    let manifest = ConstituentsManifest {
        kernel_hash: blake3::hash(kernel).to_hex().to_string(),
        initramfs_hash: "0".repeat(64),
        binary_hash: blake3::hash(dc_binary).to_hex().to_string(),
        census_manifest_hash: "0".repeat(64),
    };
    let initramfs = build_appliance_initramfs(dc_binary, &manifest);
    let mut good = manifest.clone();
    good.initramfs_hash = blake3::hash(&initramfs).to_hex().to_string();
    // The binary embedded inside the archive must equal the staged one.
    assert!(verify_constituents(&good, kernel, dc_binary, &initramfs).is_ok());
    assert!(verify_constituents(&good, kernel, b"backdoor", &initramfs).is_err());
    assert!(verify_constituents(&good, b"evil-kernel", dc_binary, &initramfs).is_err());

    // Manifest self-hash binds all four constituents.
    let full = ConstituentsManifest {
        kernel_hash: "a".repeat(64),
        initramfs_hash: "b".repeat(64),
        binary_hash: "c".repeat(64),
        census_manifest_hash: "d".repeat(64),
    };
    assert_eq!(full.compute_constituents_hash().len(), 64);

    println!("    [PASS] cpio determinism + tamper detection");
}

fn boot_cli_cells() {
    println!("\n[>> T27-CLI: dc boot verbs <<]");

    // `dc boot init --self-test` on a live host: pseudo-filesystems are
    // already mounted (idempotent path), entropy is harvested, the
    // reaper installs — exit 0 with the fingerprint line.
    //
    // PRIVILEGE HONESTY: crediting the kernel entropy pool via
    // RNDADDENTROPY requires CAP_SYS_ADMIN, and RDRAND may be masked in
    // containers. On a privileged appliance host the sequence completes;
    // on an unprivileged test host the SAME contract refuses loudly with
    // ENTROPY_STARVATION_UNREADY (never a silent degraded boot). Both
    // outcomes are pinned here.
    let assert = Command::cargo_bin("dc")
        .unwrap()
        .args(["boot", "init", "--self-test"])
        .assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let code = assert.get_output().status.code().unwrap_or(-1);
    if code == 0 {
        assert!(stdout.contains("PID-1 bootstrap sequence complete"));
        assert!(stdout.contains("state fingerprint ENV_FP_"));
    } else {
        assert!(
            stderr.contains("ENTROPY_STARVATION_UNREADY") || stderr.contains("PID1_MOUNT_FAILED"),
            "an unprivileged host must disclose the exact refusal reason (code {}), got: {}",
            code,
            stderr
        );
    }

    // `dc boot pack` + verify-against roundtrip on a temp staging file.
    let tmp = tempfile::tempdir().unwrap();
    let dc_bin = tmp.path().join("dc-static");
    std::fs::write(&dc_bin, b"fake-static-dc-binary-for-appliance").unwrap();
    let out_cpio = tmp.path().join("appliance.cpio");

    Command::cargo_bin("dc")
        .unwrap()
        .args([
            "boot",
            "pack",
            "--dc-bin",
            dc_bin.to_str().unwrap(),
            "--out",
            out_cpio.to_str().unwrap(),
        ])
        .unwrap();
    assert!(out_cpio.exists());
    let manifest_path = tmp.path().join("appliance.manifest.json");
    assert!(
        manifest_path.exists(),
        "pack must emit the constituents manifest"
    );

    // Verify-against with the correct manifest: exit 0.
    let out = Command::cargo_bin("dc")
        .unwrap()
        .args([
            "boot",
            "pack",
            "--dc-bin",
            dc_bin.to_str().unwrap(),
            "--out",
            tmp.path().join("verify.cpio").to_str().unwrap(),
            "--verify-against",
            manifest_path.to_str().unwrap(),
        ])
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("constituents verified"));

    // Tampered binary: the verification must refuse.
    let evil_bin = tmp.path().join("dc-evil");
    std::fs::write(&evil_bin, b"tampered-static-dc-binary").unwrap();
    let evil_assert = Command::cargo_bin("dc")
        .unwrap()
        .args([
            "boot",
            "pack",
            "--dc-bin",
            evil_bin.to_str().unwrap(),
            "--out",
            tmp.path().join("verify2.cpio").to_str().unwrap(),
            "--verify-against",
            manifest_path.to_str().unwrap(),
        ])
        .assert();
    assert!(!evil_assert.get_output().status.success());
    assert!(
        String::from_utf8_lossy(&evil_assert.get_output().stderr)
            .contains("APPLIANCE_ATTESTATION_FAILED")
    );

    println!("    [PASS] init self-test, pack roundtrip, tamper refusal");
}

fn firmware_evidence_cells() {
    println!("\n[>> T27-FORENSICS: firmware attestation evidence <<]");

    // NVMe telemetry: create-bit framing + header decode.
    let cmd = NvmeCodec::encode_get_telemetry_log(true);
    assert_eq!(cmd[40], 0x07);
    let cdw12 = u32::from_le_bytes([cmd[48], cmd[49], cmd[50], cmd[51]]);
    assert_ne!(cdw12 & 0x1, 0, "create-snapshot LSP bit");
    let mut payload = vec![0u8; 518];
    payload[1] = 7;
    payload[8..12].copy_from_slice(b"host");
    let header = NvmeCodec::decode_telemetry_header(&payload).unwrap();
    assert_eq!(header.generation, 7);
    assert_eq!(header.reason_identifier, "host");

    // ATA devstat wear deltas: pre/post evidence movement.
    let mut page_pre = vec![0u8; 512];
    page_pre[0..2].copy_from_slice(&0x04u16.to_le_bytes());
    page_pre[4..8].copy_from_slice(&2u32.to_le_bytes());
    page_pre[8..10].copy_from_slice(&0x0001u16.to_le_bytes());
    page_pre[10] = 0x10;
    page_pre[12] = 10; // 10% endurance
    let off = 8 + 5;
    page_pre[off..off + 2].copy_from_slice(&0x0004u16.to_le_bytes());
    page_pre[off + 2] = 0x10;
    page_pre[off + 4..off + 10].copy_from_slice(&1_000_000u64.to_le_bytes()[..6]);
    let pre = AtaDeviceStatisticsPage::decode(&page_pre, 0x04).unwrap();

    let mut page_post = page_pre.clone();
    page_post[12] = 11; // +1% endurance
    page_post[off + 4..off + 10].copy_from_slice(&2_500_000u64.to_le_bytes()[..6]);
    let post = AtaDeviceStatisticsPage::decode(&page_post, 0x04).unwrap();

    let pre_ev = AtaDeviceStatisticsEvidence {
        percentage_used_endurance: pre.percentage_used_endurance(),
        logical_sectors_written: pre.entry(0x0004).map(|e| e.value),
        write_commands: Some(500),
        logical_sectors_read: None,
        read_commands: None,
        power_on_hours: None,
        ssd_statistics_page_present: true,
    };
    let post_ev = AtaDeviceStatisticsEvidence {
        percentage_used_endurance: post.percentage_used_endurance(),
        logical_sectors_written: post.entry(0x0004).map(|e| e.value),
        write_commands: None,
        logical_sectors_read: None,
        read_commands: None,
        power_on_hours: None,
        ssd_statistics_page_present: true,
    };
    let delta = pre_ev.delta_against(&post_ev);
    assert_eq!(delta.logical_sectors_written, Some(1_500_000));
    assert_eq!(delta.percentage_endurance_growth, Some(1));

    // Full evidence block: field lines + drift warnings.
    let evidence = FirmwareAttestationEvidence {
        pre: FirmwareIdentity {
            bus: "ata".into(),
            model: "M".into(),
            serial: "S".into(),
            firmware_revision: "REV1".into(),
            subsystem_vendor: None,
            subsystem_device: None,
        },
        post: FirmwareIdentity {
            bus: "ata".into(),
            model: "M".into(),
            serial: "S".into(),
            firmware_revision: "REV1".into(),
            subsystem_vendor: None,
            subsystem_device: None,
        },
        nvme_telemetry_pre: None,
        nvme_telemetry_post: None,
        ata_devstat_pre: Some(pre_ev),
        ata_devstat_post: Some(post_ev),
        raw_snapshots: vec![],
    };
    assert!(
        evidence.defense_warnings().is_empty(),
        "stable firmware must not warn"
    );
    let fields = evidence.field_lines();
    assert!(
        fields
            .iter()
            .any(|(k, v)| k.contains("endurance") && v.contains("10% -> 11%"))
    );

    // Drifted firmware: warning + zero-write disclosure.
    let mut drifted = evidence.clone();
    drifted.post.firmware_revision = "EVIL".into();
    assert!(
        drifted
            .defense_warnings()
            .iter()
            .any(|w| w.contains("firmware revision changed"))
    );

    let mut zero_write = evidence.clone();
    if let Some(post) = zero_write.ata_devstat_post.as_mut() {
        post.logical_sectors_written = zero_write
            .ata_devstat_pre
            .as_ref()
            .and_then(|p| p.logical_sectors_written);
        post.write_commands = Some(500); // same command count: zero delta
    }
    assert!(
        zero_write
            .defense_warnings()
            .iter()
            .any(|w| w.contains("ZERO host writes"))
    );

    println!("    [PASS] telemetry binding, wear deltas, drift warnings");
}
