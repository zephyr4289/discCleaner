//! t30 — Photon Bridge matrix (v0.8.0, Vector 3).
//!
//! Full-pipeline optical stream: evidence bytes → fountain frames →
//! QR-encoded terminal lines → (capture simulation with frame loss) →
//! frame decode → LT decode → BLAKE3 verification. Plus the CLI surface
//! (`dc photon manifest` / `stream` / `decode` on a dumped frame file).

use dc_photon::{FrameReassembler, FrameStream, PhotonRenderer};

#[test]
fn t30_a1_full_pipeline_with_total_frame_loss_tolerance() {
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i * 131 + 7) as u8).collect();
    let seed = 0x5EED_A001u64;
    let mut stream = FrameStream::new(&payload, 48, 4, seed).unwrap();
    // 48-byte blocks: (213 - 52) / (4 + 48) = 3 symbols/frame after
    // QR-capacity clamping.
    assert_eq!(stream.symbols_per_frame(), 3);
    let mut rx = FrameReassembler::new(seed);
    let mut result = None;
    let mut sent = 0u64;
    let mut captured = 0u64;
    for _ in 0..9000 {
        let frame = stream.next_frame();
        sent += 1;
        if sent.is_multiple_of(2) {
            continue; // 50% frame loss
        }
        captured += 1;
        if let Some(p) = rx.push_frame(&frame).unwrap() {
            result = Some(p);
            break;
        }
    }
    let out = result.expect("fountain survives 50% frame loss");
    assert_eq!(out, payload);
    assert!(captured > 0, "capture counter observed frames");
}

#[test]
fn t30_a2_manifest_round_trip_through_cert_evidence() {
    let payload: Vec<u8> = (0..5000u32).map(|i| (i * 11) as u8).collect();
    let seed = 0xC0FFEE00u64;
    let stream = FrameStream::new(&payload, 48, 4, seed).unwrap();
    let manifest = dc_cert::PhotonManifestEvidence {
        payload_blake3: hex::encode(stream.payload_blake3()),
        stream_id: format!("{:08x}", stream.stream_id()),
        payload_len: stream.payload_len() as u64,
        block_size: stream.block_size() as u32,
        symbols_per_frame: stream.symbols_per_frame() as u32,
        stream_seed: format!("{seed:016x}"),
        qr_version_ceiling: 10,
    };
    // JSON round trip (the archival format).
    let json = serde_json::to_string(&manifest).unwrap();
    let back: dc_cert::PhotonManifestEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
    assert!(
        manifest
            .field_lines()
            .iter()
            .any(|(k, v)| k.contains("BLAKE3") && v.len() == 64)
    );
}

#[test]
fn t30_a3_rendered_frames_are_deterministic_qr_art() {
    let payload: Vec<u8> = (0..1200u32).map(|i| (i * 3) as u8).collect();
    let mut s1 = FrameStream::new(&payload, 48, 4, 42).unwrap();
    let mut s2 = FrameStream::new(&payload, 48, 4, 42).unwrap();
    let renderer = PhotonRenderer::new(2, false);
    let f1 = renderer.render(&s1.next_frame()).unwrap();
    let f2 = renderer.render(&s2.next_frame()).unwrap();
    assert_eq!(f1, f2, "identical inputs render identical screens");
    assert!(f1.header_line.contains("DC-PHOTON"));
    // Only half-block glyphs + spaces on every line, uniform width.
    let w = f1.matrix_lines[0].chars().count();
    assert!(f1.matrix_lines.iter().all(|l| l.chars().count() == w));
    assert!(
        f1.matrix_lines
            .iter()
            .flat_map(|l| l.chars())
            .all(|c| "█▀▄ ".contains(c))
    );
}

#[test]
fn t30_a4_cross_stream_mixing_is_refused() {
    let a: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    let b: Vec<u8> = (0..3000u32).map(|i| (i * 13 + 1) as u8).collect();
    let mut sa = FrameStream::new(&a, 48, 4, 1).unwrap();
    let mut sb = FrameStream::new(&b, 48, 4, 1).unwrap();
    let mut rx = FrameReassembler::new(1);
    rx.push_frame(&sa.next_frame()).unwrap();
    let mixed = rx.push_frame(&sb.next_frame());
    assert!(
        mixed.is_err(),
        "frames from a different stream must be refused"
    );
}

#[test]
fn t30_a5_cli_manifest_and_stream_decode_round_trip() {
    use assert_cmd::Command;
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    let evidence = tmp.path().join("evidence.bin");
    let payload: Vec<u8> = (0..9000u32).map(|i| (i * 17 + 3) as u8).collect();
    std::fs::write(&evidence, &payload).unwrap();

    // manifest: prints the BLAKE3 of the file.
    let out = Command::cargo_bin("dc")
        .unwrap()
        .arg("photon")
        .arg("manifest")
        .arg(evidence.to_str().unwrap())
        .arg("--block-size")
        .arg("48")
        .arg("--seed")
        .arg("cafe")
        .output()
        .expect("manifest");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("payload BLAKE3"));
    assert!(text.contains("cafe"));

    // frame dump through the library (the stream command's --limit path
    // renders to the terminal; for the round trip we dump via the same
    // encoder the CLI uses).
    let seed = 0xCAFEu64;
    let mut stream = FrameStream::new(&payload, 48, 4, seed).unwrap();
    let dump = tmp.path().join("frames.txt");
    let mut file = std::fs::File::create(&dump).unwrap();
    for _ in 0..200 {
        let frame = stream.next_frame();
        writeln!(file, "{}", hex::encode(frame.encode())).unwrap();
    }

    // decode: recovers the payload and verifies the hash.
    let out = Command::cargo_bin("dc")
        .unwrap()
        .arg("photon")
        .arg("decode")
        .arg(dump.to_str().unwrap())
        .arg("--seed")
        .arg("cafe")
        .arg("--out")
        .arg(tmp.path().join("recovered.bin").to_str().unwrap())
        .output()
        .expect("decode");
    assert!(
        out.status.success(),
        "decode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let recovered = std::fs::read(tmp.path().join("recovered.bin")).unwrap();
    assert_eq!(recovered, payload);
}
