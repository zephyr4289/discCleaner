//! cargo-fuzz target: the LT fountain symbol unpacker / peeling decoder.
//!
//! Corrupted camera captures deliver symbols whose bytes and ordering are
//! fully attacker-controlled. The ripple/peeling decoder (`LtDecoder`)
//! must fold arbitrary symbols without panicking, without unbounded
//! memory growth per symbol, and must never emit a wrong-but-accepted
//! payload (the stream hash catches that downstream — this harness pins
//! the "no crash" half).

#![no_main]

use dc_photon::lt::{LtDecoder, LtEncoder};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need header material: [block_size_mod u8][k_hi u8][k_lo u8][seed 8]
    if data.len() < 11 {
        return;
    }
    let block_size = (data[0] as usize).max(1) * 8; // 8..2040
    let k = (u16::from_be_bytes([data[1], data[2]]) as usize).max(1);
    let seed = u64::from_le_bytes(data[3..11].try_into().unwrap());

    let mut decoder = LtDecoder::new(k, block_size, seed);
    // Feed the rest of the corpus as consecutive fountain symbols; wrong
    // lengths are rejected by the decoder contract (never a panic).
    let symbol_bytes = &data[11..];
    let mut symbol_id = 0u64;
    for chunk in symbol_bytes.chunks_exact(block_size) {
        let _ = decoder.push_symbol(symbol_id, chunk);
        symbol_id += 1;
        // Hard bound: a malicious degree distribution must not let the
        // pending-symbol table grow without relation to input size.
        if symbol_id > 4096 {
            break;
        }
    }
    // Also exercise partial-size trailing chunk semantics via the encoder:
    // encode a garbage "payload" with the same parameters and interleave.
    let enc = LtEncoder::new(symbol_bytes, block_size, seed);
    if let Ok(enc) = enc {
        let mut roundtrip = LtDecoder::new(enc.num_blocks(), block_size, seed);
        for id in 0..(enc.num_blocks() as u64 + 4) {
            let _ = roundtrip.push_symbol(id, &enc.encode(id));
        }
        let _ = roundtrip.finish();
    }
});
