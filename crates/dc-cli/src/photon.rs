//! `dc photon` — bidirectional optical air-gap bridge (v0.8.0, Vector 3).
//!
//! `stream`: render the endless fountain-coded animated QR stream on the
//! terminal for an auditor to capture with an approved scanning device.
//! Nothing but photons crosses the SCIF boundary.
//!
//! `decode`: reassemble a captured frame dump back into the payload and
//! verify its BLAKE3 — the receiving-side self-check before archival.
//!
//! `manifest`: print the stream manifest (fountain parameters, seed) for
//! embedding into the certificate and the receiving audit record.

use crate::{PhotonArgs, PhotonSubcommands};
use dc_core::DcError;
use dc_photon::{FrameReassembler, FrameStream, PhotonRenderer};
use std::time::Duration;

pub fn cmd_photon(args: PhotonArgs) -> Result<(), DcError> {
    match &args.sub {
        PhotonSubcommands::Stream {
            file,
            fps,
            block_size,
            batch,
            quiet_zone,
            color,
            limit,
            seed,
        } => cmd_stream(&StreamArgs {
            file: file.clone(),
            fps: *fps,
            block_size: *block_size,
            batch: *batch,
            quiet_zone: *quiet_zone,
            color: *color,
            limit: *limit,
            seed: seed.clone(),
        }),
        PhotonSubcommands::Decode { frames, seed, out } => cmd_decode(&DecodeArgs {
            frames: frames.clone(),
            seed: seed.clone(),
            out: out.clone(),
        }),
        PhotonSubcommands::Manifest {
            file,
            block_size,
            seed,
        } => cmd_manifest(&ManifestArgs {
            file: file.clone(),
            block_size: *block_size,
            seed: seed.clone(),
        }),
    }
}

fn cmd_stream(s: &StreamArgs) -> Result<(), DcError> {
    let payload = std::fs::read(&s.file)
        .map_err(|e| DcError::Usage(format!("read {}: {e}", s.file.display())))?;
    let seed = parse_seed(&s.seed)?;
    let mut stream = FrameStream::new(&payload, s.block_size, s.batch, seed)
        .map_err(|e| DcError::Usage(format!("fountain init: {e}")))?;
    let renderer = PhotonRenderer::new(s.quiet_zone, s.color);

    eprintln!(
        "[photon-bridge] streaming {} bytes as fountain QR frames at {} fps — \
         hold the approved scanner steady; Ctrl-C stops the endless stream",
        payload.len(),
        s.fps
    );
    eprintln!(
        "[photon-bridge] stream_id={:08x} seed={:016x} (receiver needs this seed)",
        stream.stream_id(),
        seed
    );
    let frames = renderer.run(
        &mut stream,
        s.fps,
        s.limit.map(|_| std::time::Instant::now()),
        |rendered| {
            // Clear-ish frame: header, matrix, footer.
            println!();
            println!("{}", rendered.header_line);
            for line in &rendered.matrix_lines {
                println!("{line}");
            }
            println!("{}", rendered.footer_line);
            if let Some(limit) = s.limit {
                eprintln!("[photon-bridge] frame limit {limit} reached for test capture");
            }
        },
    );
    eprintln!("[photon-bridge] emitted {frames} frames");
    Ok(())
}

fn cmd_decode(d: &DecodeArgs) -> Result<(), DcError> {
    // Frame dump format (written by `stream --dump-frames`): one
    // hex-encoded frame per line.
    let dump = std::fs::read_to_string(&d.frames)
        .map_err(|e| DcError::Usage(format!("read {}: {e}", d.frames.display())))?;
    let seed = parse_seed(&d.seed)?;
    let mut rx = FrameReassembler::new(seed);
    let lines = dump.lines().filter(|l| !l.trim().is_empty());
    let mut result = None;
    for line in lines {
        let bytes = hex::decode(line.trim())
            .map_err(|e| DcError::Usage(format!("frame dump line: {e}")))?;
        let frame = dc_photon::Frame::decode(&bytes)
            .map_err(|e| DcError::Usage(format!("frame parse: {e}")))?;
        if let Some(payload) = rx
            .push_frame(&frame)
            .map_err(|e| DcError::Internal(format!("reassembly: {e}")))?
        {
            result = Some(payload);
            break;
        }
    }
    match result {
        Some(payload) => {
            let mut h = blake3::Hasher::new();
            h.update(&payload);
            let digest = h.finalize().to_hex();
            match &d.out {
                Some(path) => {
                    std::fs::write(path, &payload)
                        .map_err(|e| DcError::Internal(format!("write {}: {e}", path.display())))?;
                    println!(
                        "recovered {} bytes from {} frames (BLAKE3 {digest})",
                        payload.len(),
                        rx.frames_seen()
                    );
                }
                None => println!("recovered {} bytes (BLAKE3 {digest})", payload.len()),
            }
            Ok(())
        }
        None => {
            if let Some((done, total)) = rx.progress() {
                Err(DcError::Internal(format!(
                    "capture incomplete: {done}/{total} blocks — capture more frames"
                )))
            } else {
                Err(DcError::Usage("frame dump contained no frames".into()))
            }
        }
    }
}

fn cmd_manifest(m: &ManifestArgs) -> Result<(), DcError> {
    let payload_len = std::fs::metadata(&m.file)
        .map_err(|e| DcError::Usage(format!("stat {}: {e}", m.file.display())))?
        .len();
    let seed = parse_seed(&m.seed)?;
    // The manifest mirrors what `stream` will compute for the same inputs.
    let mut h = blake3::Hasher::new();
    // Hash in chunks to bound memory on large files.
    let file = std::fs::File::open(&m.file)
        .map_err(|e| DcError::Usage(format!("open {}: {e}", m.file.display())))?;
    use std::io::Read as _;
    let mut reader = std::io::BufReader::new(file);
    let mut chunk = [0u8; 65536];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| DcError::Internal(format!("read: {e}")))?;
        if n == 0 {
            break;
        }
        h.update(&chunk[..n]);
    }
    let digest: [u8; 32] = h.finalize().into();
    let stream_id = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    println!(
        "Photon manifest (embed into the certificate before streaming):\n  payload BLAKE3 : {}\n  stream id     : {:08x}\n  payload bytes  : {}\n  block size     : {}\n  symbols/frame  : auto (QR v10-M fit)\n  stream seed    : {:016x}\n  QR ceiling     : v10-M (213 bytes)",
        hex::encode(digest),
        stream_id,
        payload_len,
        m.block_size,
        seed
    );
    Ok(())
}

fn parse_seed(s: &str) -> Result<u64, DcError> {
    let cleaned = s.trim().trim_start_matches("0x");
    u64::from_str_radix(cleaned, 16)
        .map_err(|_| DcError::Usage(format!("--seed '{s}': expected hex")))
}

// ---------------------------------------------------------------------------
// CLI surface (constructed by clap in lib.rs)
// ---------------------------------------------------------------------------

pub struct StreamArgs {
    pub file: std::path::PathBuf,
    pub fps: f64,
    pub block_size: usize,
    pub batch: u8,
    pub quiet_zone: usize,
    pub color: bool,
    pub limit: Option<u64>,
    pub seed: String,
}

pub struct DecodeArgs {
    pub frames: std::path::PathBuf,
    pub seed: String,
    pub out: Option<std::path::PathBuf>,
}

pub struct ManifestArgs {
    pub file: std::path::PathBuf,
    pub block_size: usize,
    pub seed: String,
}

/// Dump frames to a file instead of the terminal — used by the test rig
/// (`stream --dump-frames`) and by capture-hardware bringup.
pub fn dump_frames(
    payload: &[u8],
    block_size: usize,
    batch: u8,
    seed: u64,
    count: u64,
    out: &std::path::Path,
) -> Result<u64, DcError> {
    let mut stream = FrameStream::new(payload, block_size, batch, seed)
        .map_err(|e| DcError::Usage(format!("fountain init: {e}")))?;
    use std::io::Write as _;
    let mut file = std::fs::File::create(out)
        .map_err(|e| DcError::Internal(format!("create {}: {e}", out.display())))?;
    let mut written = 0u64;
    for _ in 0..count {
        let frame = stream.next_frame();
        let bytes = frame.encode();
        writeln!(file, "{}", hex::encode(&bytes))
            .map_err(|e| DcError::Internal(format!("write frame: {e}")))?;
        written += 1;
    }
    Ok(written)
}

/// Bridge helper for the CLI wiring: a small duration constant used by the
/// stream pacing self-test.
pub const MIN_FRAME_PERIOD: Duration = Duration::from_millis(20);
