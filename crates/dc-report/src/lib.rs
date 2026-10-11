pub mod batch;
pub mod pdfa;
pub mod project;

pub use batch::{BatchVerifier, BatchVerifyResult};
pub use pdfa::{EmbeddedAttachment, PdfaDocument};
pub use project::ReportModel;

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn batch_verification_is_exhaustive_without_short_circuit() {
        // Δ477: every artifact gets a verdict, even after the first failure.
        let result = BatchVerifier::verify_directory(&[
            ("a.cert.json", true),
            ("b.cert.json", false),
            ("c.cert.json", true),
            ("d.cert.json", false),
        ]);
        assert_eq!(result.total_examined, 4);
        assert_eq!(result.passed_count, 2);
        assert_eq!(result.failed_count, 2);
        assert_eq!(result.verdicts.len(), 4);
        assert_eq!(result.aggregate_exit_code(), 1);
        assert!(result.verdicts[1].1.is_err());
        assert!(result.verdicts[3].1.is_err());
    }

    #[test]
    fn clean_batch_aggregates_to_zero() {
        let result = BatchVerifier::verify_directory(&[("x.cert.json", true)]);
        assert_eq!(result.aggregate_exit_code(), 0);
        assert_eq!(result.failed_count, 0);
    }
}
