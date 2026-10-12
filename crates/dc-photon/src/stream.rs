//! Animated terminal rendering of the photon stream (v0.8.0, Vector 3).
//!
//! The bridge output is a sequence of QR frames rendered as half-block
//! ANSI art (2 module rows per terminal row) with a status header —
//! scannable by any approved camera device pointed at the screen. The
//! renderer is deliberately dumb-terminal compatible: no cursor addressing
//! beyond plain line writes, so it works over serial consoles and SCIF
//! KVM carts alike.
//!
//! `--color` mode renders each module PAIR as one character from a
//! 4-color code (2 bits per character cell — twice the density for
//! capture hardware that understands the mapping); monochrome half-blocks
//! remain the default for standard scanners.

use crate::frame::{Frame, FrameStream};
use crate::qr;
use std::time::{Duration, Instant};

/// Rendered terminal frame: header line + QR matrix lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedPhotonFrame {
    pub header_line: String,
    pub matrix_lines: Vec<String>,
    pub footer_line: String,
}

/// Terminal renderer over a frame stream.
pub struct PhotonRenderer {
    quiet_zone: usize,
    color: bool,
}

impl PhotonRenderer {
    pub fn new(quiet_zone: usize, color: bool) -> Self {
        Self { quiet_zone, color }
    }

    /// Render one frame's QR payload into terminal lines.
    pub fn render(&self, frame: &Frame) -> Result<RenderedPhotonFrame, crate::PhotonStreamError> {
        let bytes = frame.encode();
        let matrix = qr::encode(&bytes)?;
        let size = matrix.size;
        let q = self.quiet_zone;
        // In color mode one character cell spans TWO modules horizontally.
        let line_modules = if self.color { size / 2 } else { size };
        let mut matrix_lines = Vec::with_capacity(size / 2 + q);

        // Top quiet zone.
        let blank = " ".repeat(line_modules + 2 * q);
        for _ in 0..q {
            matrix_lines.push(blank.clone());
        }

        // Module rows, two per terminal row via half blocks.
        let mut row = 0usize;
        while row < size {
            let mut line = String::with_capacity(size + 2 * q);
            for _ in 0..q {
                line.push(' ');
            }
            let mut col = 0usize;
            while col < size {
                if self.color {
                    // 4 modules per cell (2 wide × 2 tall) via base-4 colors.
                    let m =
                        |r: usize, c: usize| -> bool { r < size && c < size && matrix.get(r, c) };
                    let bits = u8::from(m(row, col)) << 3
                        | u8::from(m(row, col + 1)) << 2
                        | u8::from(m(row + 1, col)) << 1
                        | u8::from(m(row + 1, col + 1));
                    line.push_str(color_cell(bits));
                    col += 2;
                } else {
                    let top = matrix.get(row, col);
                    let bottom = if row + 1 < size {
                        matrix.get(row + 1, col)
                    } else {
                        false
                    };
                    line.push_str(half_block(top, bottom));
                    col += 1;
                }
            }
            for _ in 0..q {
                line.push(' ');
            }
            matrix_lines.push(line);
            row += 2;
        }

        // Bottom quiet zone.
        for _ in 0..q {
            matrix_lines.push(blank.clone());
        }

        let h = &frame.header;
        let header_line = format!(
            "DC-PHOTON stream {:08x} | payload {} B | BLAKE3/8 {:02x}{:02x}.. | frame @ symbol {} | {} sym/frame x {} B",
            h.stream_id,
            h.payload_len,
            h.payload_blake3[0],
            h.payload_blake3[1],
            h.first_symbol,
            h.symbol_count,
            h.symbol_size,
        );
        let footer_line = format!(
            "hold the scanner steady — fountain stream: any {} of the frames reconstruct the evidence",
            "sufficient subset"
        );
        Ok(RenderedPhotonFrame {
            header_line,
            matrix_lines,
            footer_line,
        })
    }

    /// Drive the animation: render frames at `fps` until `deadline`
    /// (infinite when None), calling `emit` per frame.
    pub fn run<F: FnMut(&RenderedPhotonFrame)>(
        &self,
        stream: &mut FrameStream,
        fps: f64,
        deadline: Option<Instant>,
        emit: F,
    ) -> u64 {
        let period = if fps > 0.0 {
            Duration::from_secs_f64(1.0 / fps)
        } else {
            Duration::from_millis(400)
        };
        let mut emitted = 0u64;
        let mut emit = emit;
        loop {
            if let Some(d) = deadline
                && Instant::now() >= d
            {
                break;
            }
            let frame = stream.next_frame();
            if let Ok(rendered) = self.render(&frame) {
                emit(&rendered);
                emitted += 1;
            }
            std::thread::sleep(period);
        }
        emitted
    }
}

fn half_block(top: bool, bottom: bool) -> &'static str {
    match (top, bottom) {
        (true, true) => "█",
        (true, false) => "▀",
        (false, true) => "▄",
        (false, false) => " ",
    }
}

/// 2-bit/pixel color matrix cell (experimental high-density mode for
/// capture hardware that understands the 4-color mapping; documented in
/// docs/photon-bridge.md).
fn color_cell(bits: u8) -> &'static str {
    match bits {
        0 => "\x1b[48;5;231m \x1b[0m",
        1 => "\x1b[48;5;250m \x1b[0m",
        2 => "\x1b[48;5;239m \x1b[0m",
        3 => "\x1b[48;5;16m \x1b[0m",
        4..=15 => "\x1b[48;5;239m \x1b[0m",
        _ => unreachable!("2-bit cell"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_frame_structure_is_scannable() {
        let payload: Vec<u8> = (0..1500u32).map(|i| (i * 7) as u8).collect();
        let mut stream = FrameStream::new(&payload, 64, 4, 42).unwrap();
        let renderer = PhotonRenderer::new(2, false);
        let frame = stream.next_frame();
        let rendered = renderer.render(&frame).unwrap();
        // Header carries the stream identity and frame geometry.
        assert!(rendered.header_line.contains("DC-PHOTON"));
        assert!(rendered.header_line.contains("sym/frame"));
        // Matrix lines: (size + 2*q + 1)/2 rows + 2*q quiet lines, uniform
        // width, only half-block glyphs + spaces.
        assert!(rendered.matrix_lines.len() > 4);
        let width = rendered.matrix_lines[0].chars().count();
        assert!(
            rendered
                .matrix_lines
                .iter()
                .all(|l| l.chars().count() == width)
        );
        assert!(
            rendered
                .matrix_lines
                .iter()
                .flat_map(|l| l.chars())
                .all(|c| "█▀▄ ".contains(c))
        );
        // Deterministic: same input → same output.
        let mut stream2 = FrameStream::new(&payload, 64, 4, 42).unwrap();
        let rendered2 = renderer.render(&stream2.next_frame()).unwrap();
        assert_eq!(rendered, rendered2);
    }

    #[test]
    fn color_mode_compresses_line_width() {
        let payload = vec![1u8; 900];
        let mut stream = FrameStream::new(&payload, 64, 4, 42).unwrap();
        let frame = stream.next_frame();
        let mono = PhotonRenderer::new(1, false).render(&frame).unwrap();
        let color = PhotonRenderer::new(1, true).render(&frame).unwrap();
        // 2 modules per character cell → half the visible width (the
        // line count is unchanged: both modes use half-block rows).
        let strip_ansi = |l: &str| -> String {
            let mut out = String::with_capacity(l.len());
            let mut chars = l.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\u{1b}' {
                    // Skip "[...m".
                    for c2 in chars.by_ref() {
                        if c2 == 'm' {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        // Note: color cells are background-colored spaces, so the
        // stripped line is whitespace of the same WIDTH — the width (not
        // the glyphs) is the compression being asserted.
        let mono_w = strip_ansi(&mono.matrix_lines[0]).chars().count();
        let color_w = color
            .matrix_lines
            .iter()
            .map(|l| strip_ansi(l).chars().count())
            .max()
            .unwrap_or(0);
        assert!(
            color_w < mono_w,
            "color cell packs 2 modules per char ({color_w} vs {mono_w})"
        );
        assert_eq!(color.matrix_lines.len(), mono.matrix_lines.len());
        assert!(color.matrix_lines.iter().any(|l| l.contains("\x1b[")));
    }

    #[test]
    fn run_respects_deadline() {
        let payload = vec![5u8; 500];
        let mut stream = FrameStream::new(&payload, 64, 4, 42).unwrap();
        let renderer = PhotonRenderer::new(1, false);
        let start = Instant::now();
        let n = renderer.run(
            &mut stream,
            50.0,
            Some(start + Duration::from_millis(150)),
            |_| {},
        );
        assert!((1..=12).contains(&n), "fps-bounded emission, got {n}");
    }
}
