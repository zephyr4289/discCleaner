// Scratch calibration: LT peeling reliability vs (k, overhead, drop).
use dc_photon::lt::{LtDecoder, LtEncoder};

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn trial(k_target: usize, mult: usize, drop_pct: u64, seed: u64) -> bool {
    let payload_len = k_target * 16;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i * 31 + 7) as u8).collect();
    let enc = LtEncoder::new(&payload, 16, seed).unwrap();
    let k = enc.num_blocks();
    let stream_len = k * mult + 8;
    let mut dec = LtDecoder::new(k, 16, seed);
    for id in 0..stream_len as u64 {
        if mix(seed ^ id.rotate_left(17)) % 100 < drop_pct {
            continue;
        }
        dec.push_symbol(id, &enc.encode(id)).unwrap();
    }
    dec.finish().is_ok()
}

fn main() {
    for mult in [3usize, 4] {
        for drop in [0u64, 15, 25, 30] {
            let mut fails = 0usize;
            let mut worst_k = 0usize;
            let trials = 400;
            for t in 0..trials {
                let k = 2 + (t % 60); // k in 2..62
                if !trial(k, mult, drop, 0xDEAD_BEEF + t as u64 * 7919) {
                    fails += 1;
                    worst_k = worst_k.max(k);
                }
            }
            println!("mult={mult}x drop={drop}%: {fails}/{trials} failures (worst k={worst_k})");
        }
    }
}
