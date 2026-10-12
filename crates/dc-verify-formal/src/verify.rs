//! Window-verification accounting: the verified-abstraction layer.
//!
//! The user-visible safety property ("no unverified LBA range may produce
//! a successful result") bottoms out in the accounting of
//! [`dc_verify::StreamVerifier`]: every window the engine reads back is
//! reported via `on_window(index, is_valid, data)` and the certificate
//! carries `windows_checked` / `mismatch_count`. If a single invalid
//! window could slip the counter, an unverified range would certify.
//!
//! Method (verified abstraction + validated refinement):
//!
//! 1. **Spec**: [`count_windows`] is a 5-line pure function over a list
//!    of `(window, is_valid)` observations — trivially auditable.
//! 2. **Kani** machine-checks the spec (see `proofs::kani_verify_model`):
//!    for ANY bounded sequence of symbolic observations, the counters
//!    are exact — no undercount of invalid windows is possible.
//! 3. **Refinement**: [`cross_validate`] drives the REAL
//!    `StreamVerifier` and the spec over all concrete observation
//!    sequences up to the given window count (2^n sequences for n
//!    windows — exhaustive for n ≤ 12) and asserts the real counters
//!    always equal the spec's.
//!
//! Together: the spec is proved, and the implementation is exhaustively
//! shown to agree with it at the bounded depths CI can afford.

use dc_verify::StreamVerifier;
use dc_verify::verifier::VerificationReport;
use serde_json::json;

/// The verified abstraction: counters over a list of observations.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowCounters {
    pub windows_checked: u64,
    pub mismatch_count: u64,
    pub first_mismatch_windows: Vec<u64>,
}

/// Spec function: count checked windows and mismatches exactly.
pub fn count_windows(observations: &[(u64, bool)]) -> WindowCounters {
    let mut c = WindowCounters {
        windows_checked: 0,
        mismatch_count: 0,
        first_mismatch_windows: Vec::new(),
    };
    for (window, is_valid) in observations {
        c.windows_checked += 1;
        if !is_valid {
            c.mismatch_count += 1;
            c.first_mismatch_windows.push(*window);
        }
    }
    c
}

/// The safety predicate over a finalized report: a report may only be
/// treated as a successful (full) verification when every window
/// checked out — i.e. `mismatch_count == 0` AND the number of windows
/// the plan required is fully covered (modeled by `required_windows`).
pub fn is_full_verification_clean(report: &VerificationReport, required_windows: u64) -> bool {
    report.mismatch_count == 0 && report.windows_checked >= required_windows
}

/// Drive the REAL StreamVerifier over `observations` (4-KiB zeroed
/// window payloads — the accounting does not depend on the bytes) and
/// compare its finalized counters to the spec.
pub fn cross_validate(observations: &[(u64, bool)]) -> WindowCounters {
    let mut v = StreamVerifier::new(dc_core::VerifyLevel::Full, 4096, 512, false, false);
    for (window, is_valid) in observations {
        let data = [0u8; 8];
        let _ = dc_io::VerifySink::on_window(&mut v, *window, *is_valid, &data);
    }
    let report = v.finalize();
    WindowCounters {
        windows_checked: report.windows_checked,
        mismatch_count: report.mismatch_count,
        // LBA = window * window_bytes / lbs with window_bytes=4096 and
        // lbs=512 -> window = lba / 8.
        first_mismatch_windows: report
            .first_mismatch_lbas
            .iter()
            .map(|lba| lba / 8)
            .collect(),
    }
}

/// Exhaustively compare the real verifier against the spec over ALL
/// 2^n validity patterns for n windows.
pub fn exhaustive_refinement_check(n_windows: u32) -> bool {
    let n = n_windows as usize;
    assert!(n <= 16, "2^16 sequences maximum for the bounded check");
    for mask in 0u32..(1u32 << n) {
        let observations: Vec<(u64, bool)> =
            (0..n).map(|i| (i as u64, (mask >> i) & 1 == 1)).collect();
        let spec = count_windows(&observations);
        let real = cross_validate(&observations);
        if spec.windows_checked != real.windows_checked
            || spec.mismatch_count != real.mismatch_count
            || spec.first_mismatch_windows != real.first_mismatch_windows
        {
            return false;
        }
    }
    true
}

pub fn report_json(passed: bool, n_windows: u32) -> String {
    json!({
        "checker": "verified-abstraction-refinement-v1",
        "spec": "count_windows: exact counters over (window, is_valid) observations",
        "kani_harness": "proofs::kani_verify_model (symbolic, all sequences)",
        "refinement_windows": n_windows,
        "sequences_validated": 1u64 << n_windows,
        "all_passed": passed,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_counts_exactly() {
        let obs = vec![(0, true), (1, false), (2, true), (3, false)];
        let c = count_windows(&obs);
        assert_eq!(c.windows_checked, 4);
        assert_eq!(c.mismatch_count, 2);
        assert_eq!(c.first_mismatch_windows, vec![1, 3]);
    }

    #[test]
    fn real_verifier_matches_spec_exhaustively_10() {
        // 2^10 = 1024 concrete observation sequences.
        assert!(
            exhaustive_refinement_check(10),
            "real StreamVerifier diverged from the verified spec"
        );
    }

    #[test]
    fn real_verifier_matches_spec_exhaustively_12() {
        // 2^12 = 4096 sequences — still sub-second.
        assert!(exhaustive_refinement_check(12));
    }

    #[test]
    fn empty_observation_stream() {
        let c = cross_validate(&[]);
        assert_eq!(c.windows_checked, 0);
        assert_eq!(c.mismatch_count, 0);
    }

    #[test]
    fn clean_full_verification_predicate() {
        let mut v = StreamVerifier::new(dc_core::VerifyLevel::Full, 4096, 512, false, false);
        for i in 0..8u64 {
            let _ = dc_io::VerifySink::on_window(&mut v, i, true, &[0u8; 8]);
        }
        let report = v.finalize();
        assert!(is_full_verification_clean(&report, 8));
        assert!(
            !is_full_verification_clean(&report, 9),
            "undercovered must fail"
        );
    }

    #[test]
    fn single_mismatch_breaks_cleanliness() {
        let mut v = StreamVerifier::new(dc_core::VerifyLevel::Full, 4096, 512, false, false);
        for i in 0..8u64 {
            let _ = dc_io::VerifySink::on_window(&mut v, i, i != 3, &[0u8; 8]);
        }
        let report = v.finalize();
        assert_eq!(report.mismatch_count, 1);
        assert!(!is_full_verification_clean(&report, 8));
    }
}
