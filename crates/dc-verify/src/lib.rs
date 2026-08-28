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
