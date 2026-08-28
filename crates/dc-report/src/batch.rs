use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchVerifyResult {
    pub total_examined: usize,
    pub passed_count: usize,
    pub failed_count: usize,
    pub verdicts: Vec<(String, Result<String, String>)>,
}

impl BatchVerifyResult {
    pub fn aggregate_exit_code(&self) -> u8 {
        if self.failed_count > 0 {
            1
        } else {
            0
        }
    }
}

pub struct BatchVerifier;

impl BatchVerifier {
    /// Exhaustive batch directory verification without short-circuiting (Δ477).
    pub fn verify_directory(artifacts: &[(&str, bool)]) -> BatchVerifyResult {
        let mut passed_count = 0;
        let mut failed_count = 0;
        let mut verdicts = Vec::new();

        for (path, is_valid) in artifacts {
            if *is_valid {
                passed_count += 1;
                verdicts.push((path.to_string(), Ok("VERIFIED_CLEAN".to_string())));
            } else {
                failed_count += 1;
                verdicts.push((path.to_string(), Err("VERIFICATION_FAILED".to_string())));
            }
        }

        BatchVerifyResult {
            total_examined: artifacts.len(),
            passed_count,
            failed_count,
            verdicts,
        }
    }
}
