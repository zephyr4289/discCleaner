pub mod entropy;
pub mod verifier;

pub use entropy::{EntropyCalculator, EntropyDiag};
pub use verifier::{StreamVerifier, VerificationReport};

#[cfg(test)]
mod tests {
    use super::*;
    use dc_core::VerifyLevel;
    use dc_io::VerifySink;

    #[test]
    fn test_zero_entropy_calculation() {
        let mut verifier = StreamVerifier::new(VerifyLevel::Full, 1024, 512, true, true);
        let zeros = vec![0u8; 1024];

        verifier.on_window(0, true, &zeros).unwrap();
        let report = verifier.finalize();

        assert_eq!(report.windows_checked, 1);
        assert_eq!(report.mismatch_count, 0);
        let entropy = report.entropy.unwrap();
        assert_eq!(entropy.h_min, 0.0);
        assert_eq!(entropy.h_max, 0.0);
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use dc_core::VerifyLevel;
    use dc_io::VerifySink;

    #[test]
    fn verifier_counts_mismatches_and_hash_locations() {
        let mut v = StreamVerifier::new(VerifyLevel::Full, 1024, 512, false, false);
        let w0 = vec![0xAA; 1024];
        let w1 = vec![0xBB; 1024];
        v.on_window(0, true, &w0).unwrap();
        v.on_window(1, false, &w1).unwrap(); // mismatch
        v.on_window(2, false, &w0).unwrap(); // mismatch
        let report = v.finalize();
        assert_eq!(report.windows_checked, 3);
        assert_eq!(report.mismatch_count, 2);
        // Window 1 starts at byte 1024 -> LBA 2.
        assert_eq!(report.first_mismatch_lbas, vec![2, 4]);
        assert!(report.stream_hash_sha256.is_none());
    }

    #[test]
    fn verifier_stream_hash_is_order_sensitive() {
        let a = {
            let mut v = StreamVerifier::new(VerifyLevel::Full, 1024, 512, false, false);
            v.on_window(0, true, &vec![1u8; 1024]).unwrap();
            v.on_window(1, true, &vec![2u8; 1024]).unwrap();
            v.finalize()
        };
        let b = {
            let mut v = StreamVerifier::new(VerifyLevel::Full, 1024, 512, false, false);
            v.on_window(0, true, &vec![2u8; 1024]).unwrap();
            v.on_window(1, true, &vec![1u8; 1024]).unwrap();
            v.finalize()
        };
        assert_ne!(a.stream_hash_blake3, b.stream_hash_blake3);
    }

    #[test]
    fn optional_sha256_digest_tracks_state() {
        let mut v = StreamVerifier::new(VerifyLevel::Full, 1024, 512, true, false);
        v.on_window(0, true, &vec![7u8; 1024]).unwrap();
        let report = v.finalize();
        let sha = report.stream_hash_sha256.expect("sha256 enabled");
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update([7u8; 1024]);
        assert_eq!(sha, hex::encode(h.finalize()));
    }

    #[test]
    fn entropy_zero_and_high_bounds() {
        let mut zero = EntropyCalculator::new();
        zero.update(&[0u8; 4096]);
        let z = zero.finalize().unwrap();
        assert_eq!(z.h_min, 0.0);
        assert_eq!(z.h_max, 0.0);

        let mut v = StreamVerifier::new(VerifyLevel::Full, 65536, 512, false, true);
        let mut buf = vec![0u8; 65536];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i * 31 + 7) as u8;
        }
        v.on_window(0, true, &buf).unwrap();
        let e = v.finalize().entropy.unwrap();
        assert!(
            e.h_min > 7.0,
            "scattered bytes must have real entropy: {}",
            e.h_min
        );
    }
}
