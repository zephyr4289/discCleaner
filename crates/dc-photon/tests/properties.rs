//! Property-based invariants of the Photon Bridge fountain stack
//! (v0.9.0, Phase 2 — proptest).
//!
//! The existing unit tests pin *specific* captures; these properties pin
//! the CODE over the whole input space:
//! 1. **Reconstruction under arbitrary packet loss** — for ANY payload,
//!    block size, seed and loss pattern, a 3x symbol stream tolerates up
//!    to 25% random symbol loss and still reconstructs the exact payload
//!    (envelope calibrated by `examples/lt_calibration.rs`: 0/400
//!    failures across k=2..62; zero loss needs no overhead at all
//!    thanks to the systematic-first design).
//! 2. **Order independence** — the same surviving symbols decode
//!    identically in ANY arrival order (a scanner misses frames, it
//!    never reorders physics, but the decoder must not care).
//! 3. **Non-malleability under symbol corruption** — a symbol whose
//!    bytes are flipped cannot silently produce a *different accepted*
//!    payload: either the decode fails, or the result diverges from the
//!    original (caught by the stream hash in production; here we pin
//!    the divergence property directly).

use dc_photon::lt::{LtDecoder, LtEncoder};
use proptest::prelude::*;

/// Deterministic per-case PRNG (SplitMix64 — same family the fountain
/// uses; independent reproducibility from (seed, index) pairs).
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Property 1: random drops of up to 25% of a 3x symbol stream.
    #[test]
    fn fountain_reconstruction_survives_random_drops(
        payload in prop::collection::vec(any::<u8>(), 1..1536),
        block_size in 16usize..=64,
        seed in any::<u64>(),
        drop_pct in 0u8..=25,
    ) {
        let enc = LtEncoder::new(&payload, block_size, seed).unwrap();
        let k = enc.num_blocks();
        let stream_len = k * 3 + 8; // 3x emission + slack
        let mut dec = LtDecoder::new(k, block_size, seed);
        let mut received = 0usize;
        for id in 0..stream_len as u64 {
            if mix(seed ^ id.rotate_left(17)) % 100 < drop_pct as u64 {
                continue; // this symbol got lost in the optical capture
            }
            dec.push_symbol(id, &enc.encode(id)).unwrap();
            received += 1;
        }
        // 25% loss of a 3x stream still leaves >= 2.2k symbols.
        prop_assert!(received >= k * 2, "case starved the decoder");
        let out = dec.finish().expect("fountain reconstruction");
        prop_assert_eq!(out.len(), k * block_size);
        prop_assert_eq!(&out[..payload.len()], &payload[..]);
    }

    /// Property 2: arrival order must not matter.
    #[test]
    fn fountain_decode_is_order_independent(
        payload in prop::collection::vec(any::<u8>(), 16..768),
        block_size in 16usize..=48,
        seed in any::<u64>(),
    ) {
        let enc = LtEncoder::new(&payload, block_size, seed).unwrap();
        let k = enc.num_blocks();
        let symbols: Vec<(u64, Vec<u8>)> =
            (0..(k + k / 2 + 8) as u64).map(|id| (id, enc.encode(id))).collect();

        // Deterministic Fisher-Yates under the case seed.
        let mut shuffled = symbols.clone();
        let mut state = seed | 1;
        for i in (1..shuffled.len()).rev() {
            state = mix(state);
            let j = (state % (i as u64 + 1)) as usize;
            shuffled.swap(i, j);
        }

        let mut dec = LtDecoder::new(k, block_size, seed);
        for (id, bytes) in &shuffled {
            dec.push_symbol(*id, bytes).unwrap();
        }
        let out = dec.finish().expect("shuffled decode");
        prop_assert_eq!(&out[..payload.len()], &payload[..]);
    }

    /// Property 3: corrupting a NECESSARY symbol never silently mimics the
    /// payload — the decode either fails, or diverges from the original.
    #[test]
    fn corrupted_symbol_never_silently_mimics_the_payload(
        payload in prop::collection::vec(any::<u8>(), 32..512),
        block_size in 16usize..=32,
        seed in any::<u64>(),
        flip_index in any::<usize>(),
    ) {
        let enc = LtEncoder::new(&payload, block_size, seed).unwrap();
        let k = enc.num_blocks();
        let stream: Vec<u64> = (0..(k as u64 + 8)).collect();
        let victim = flip_index as u64 % stream.len() as u64;

        // Clean decode: the control run (must reproduce the payload).
        let mut clean = LtDecoder::new(k, block_size, seed);
        for &id in &stream {
            clean.push_symbol(id, &enc.encode(id)).unwrap();
        }
        let clean_out = clean.finish().expect("clean control decode");
        prop_assert_eq!(&clean_out[..payload.len()], &payload[..]);

        // Necessity probe: decode WITHOUT the victim symbol at all.
        let mut without = LtDecoder::new(k, block_size, seed);
        for &id in &stream {
            if id != victim {
                without.push_symbol(id, &enc.encode(id)).unwrap();
            }
        }
        if without.finish().is_ok() {
            // The victim was redundant (systematic + tail redundancy);
            // corrupting it cannot be observed — nothing to assert.
            return Ok(());
        }

        // The victim is NECESSARY: corrupt one of its bytes. The XOR
        // peeling decoder must then either fail, or produce an output
        // that differs from the original — never an identical forgery.
        let mut corrupted = LtDecoder::new(k, block_size, seed);
        for &id in &stream {
            let mut sym = enc.encode(id);
            if id == victim && !sym.is_empty() {
                let at = (flip_index / 7) % sym.len();
                sym[at] ^= 0x80;
            }
            corrupted.push_symbol(id, &sym).unwrap();
        }
        match corrupted.finish() {
            Err(_) => { /* clean rejection: the good outcome */ }
            Ok(out) => prop_assert_ne!(&out[..payload.len()], &payload[..]),
        }
    }
}
