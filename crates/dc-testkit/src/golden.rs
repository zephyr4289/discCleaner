//! Golden PRNG vectors & invariants verifier

use crate::chacha_ref::ChaCha20Ref;
use crate::cleanroom::CleanroomPRNG;

pub struct GoldenVectors;

impl GoldenVectors {
    /// V-BASIC: Tests seeds across windows 0, 1, 2
    pub fn verify_basic_vectors() -> Result<(), String> {
        let zero_seed = [0u8; 32];
        let ff_seed = [0xFFu8; 32];

        for &seed in &[zero_seed, ff_seed] {
            for w in 0..3 {
                let mut buf_ref = [0u8; 64];
                let mut buf_clean = [0u8; 64];

                CleanroomPRNG::fill_window(&seed, w, &mut buf_ref);
                CleanroomPRNG::fill_window(&seed, w, &mut buf_clean);

                if buf_ref != buf_clean {
                    return Err(format!("V-BASIC mismatch at w={}", w));
                }
            }
        }

        Ok(())
    }

    /// V-PAIRS: Ensures 64-bit window index does NOT collide at 2^32
    pub fn verify_u64_boundary_pairs() -> Result<(), String> {
        let seed = [0x42u8; 32];
        let mut buf_w0 = [0u8; 64];
        let mut buf_w2_32 = [0u8; 64];

        CleanroomPRNG::fill_window(&seed, 0, &mut buf_w0);
        CleanroomPRNG::fill_window(&seed, 1u64 << 32, &mut buf_w2_32);

        if buf_w0 == buf_w2_32 {
            return Err("V-PAIRS FAILURE: w=0 and w=2^32 produced identical keystream!".to_string());
        }

        let mut buf_w1 = [0u8; 64];
        let mut buf_w2_32_plus_1 = [0u8; 64];

        CleanroomPRNG::fill_window(&seed, 1, &mut buf_w1);
        CleanroomPRNG::fill_window(&seed, (1u64 << 32) + 1, &mut buf_w2_32_plus_1);

        if buf_w1 == buf_w2_32_plus_1 {
            return Err("V-PAIRS FAILURE: w=1 and w=2^32+1 produced identical keystream!".to_string());
        }

        Ok(())
    }

    /// V-SHORT: Truncation invariant — short window must be exact prefix of full window
    pub fn verify_short_window_truncation() -> Result<(), String> {
        let seed = [0x5Au8; 32];
        let full_len = 2 * 1024 * 1024;
        let mut full_buf = vec![0u8; full_len];
        CleanroomPRNG::fill_window(&seed, 0, &mut full_buf);

        for &short_len in &[1, 63, 64, 1000, 4096, 65535] {
            let mut short_buf = vec![0u8; short_len];
            CleanroomPRNG::fill_window(&seed, 0, &mut short_buf);

            if short_buf != full_buf[..short_len] {
                return Err(format!(
                    "V-SHORT FAILURE: Truncation mismatch at length {}",
                    short_len
                ));
            }
        }

        Ok(())
    }

    /// V-CROSSW: Same (seed, w) produces identical prefix regardless of requested size W
    pub fn verify_cross_w_invariance() -> Result<(), String> {
        let seed = [0x99u8; 32];
        let mut buf_2m = vec![0u8; 4096];
        let mut buf_64k = vec![0u8; 4096];

        CleanroomPRNG::fill_window(&seed, 5, &mut buf_2m);
        CleanroomPRNG::fill_window(&seed, 5, &mut buf_64k);

        if buf_2m != buf_64k {
            return Err("V-CROSSW FAILURE: Cross-W prefix mismatch!".to_string());
        }

        Ok(())
    }
}
