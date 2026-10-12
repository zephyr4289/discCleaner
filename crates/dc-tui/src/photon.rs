//! Photon-bridge pane for the live TUI (v0.8.0, Vector 3).
//!
//! When a purge/execute run carries the `--photon-export` posture, the
//! live progress view composes a `PhotonPane` next to the wipe heatmap:
//! the same animated fountain-QR stream `dc photon stream` renders
//! full-screen, embedded as a pane so the operator sees evidence leaving
//! through the optical channel without switching views.

use dc_photon::{PhotonRenderer, RenderedPhotonFrame};

/// Composition helper: pane header/footer lines for a rendered frame.
pub struct PhotonPane;

impl PhotonPane {
    /// Pure-text header line for the pane (no ANSI, TUI-safe).
    pub fn header(frame: &RenderedPhotonFrame) -> String {
        format!("PHOTON BRIDGE | {}", frame.header_line)
    }

    /// Pure-text footer line for the pane.
    pub fn footer(frame: &RenderedPhotonFrame) -> String {
        frame.footer_line.clone()
    }
}

/// State-carrying view model for embedding into `DisplayState`-style
/// renderers (keeps dc-tui decoupled from the stream itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhotonStreamView {
    pub stream_id: String,
    pub frames_rendered: u64,
    pub color_mode: bool,
}

impl PhotonStreamView {
    pub fn new(stream_id: &str) -> Self {
        Self {
            stream_id: stream_id.to_string(),
            frames_rendered: 0,
            color_mode: false,
        }
    }

    pub fn on_frame(&mut self, _frame: &RenderedPhotonFrame) {
        self.frames_rendered += 1;
    }

    /// TUI status line (pure text, phase-true: the count only moves when
    /// a frame actually rendered).
    pub fn status_line(&self) -> String {
        format!(
            "PHOTON: stream {} — {} frames on air",
            self.stream_id, self.frames_rendered
        )
    }
}

/// Renderer parity helper: the pane delegates matrix rendering to the
/// dc-photon renderer (half-block art), so the TUI and the standalone
/// `dc photon stream` command show IDENTICAL pixels.
pub fn pane_renderer(color: bool) -> PhotonRenderer {
    PhotonRenderer::new(2, color)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_counts_only_rendered_frames() {
        let mut v = PhotonStreamView::new("cafebabe");
        assert_eq!(v.status_line(), "PHOTON: stream cafebabe — 0 frames on air");
        // A frame arrives (constructed minimally via the real renderer).
        let payload = vec![7u8; 600];
        let mut stream = dc_photon::FrameStream::new(&payload, 64, 4, 42).unwrap();
        let renderer = pane_renderer(false);
        let frame = renderer.render(&stream.next_frame()).unwrap();
        v.on_frame(&frame);
        assert_eq!(v.frames_rendered, 1);
        assert_eq!(v.status_line(), "PHOTON: stream cafebabe — 1 frames on air");
        assert!(PhotonPane::header(&frame).starts_with("PHOTON BRIDGE | DC-PHOTON"));
        assert!(PhotonPane::footer(&frame).contains("fountain"));
    }
}
