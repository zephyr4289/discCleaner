//! cargo-fuzz target: the Photon Bridge frame codec + reassembler.
//!
//! The auditor's scanning device feeds corrupted camera frames back into
//! `dc photon receive` paths; the frame decoder and the LT reassembler must
//! reject malformed input without panicking regardless of how the
//! fountain headers, hashes and seeds are mangled.

#![no_main]

use dc_photon::frame::{Frame, FrameReassembler};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = Frame::decode(data) {
        // A syntactically valid frame goes into a reassembler seeded from
        // the input itself (wrong-seed symbols must be rejected cleanly,
        // never panic — the scanner cannot authenticate the seed).
        let seed = u64::from_le_bytes(
            data.get(..8)
                .map(|s| s.try_into().unwrap_or([0u8; 8]))
                .unwrap_or([0u8; 8]),
        );
        let mut reassembler = FrameReassembler::new(seed);
        let _ = reassembler.push_frame(&frame);
        // Progress counters must stay monotonically consistent even on
        // rejection paths (checked by internal invariants + no panic).
        let _ = reassembler.frames_seen();
        let _ = reassembler.progress();
    }
});
