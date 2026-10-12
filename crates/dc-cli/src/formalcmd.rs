//! `dc formal` — formal verification driver (v0.11.0, Frontier 3).
//!
//! `check` runs the exhaustive state-merged model check of the
//! sanitization FSM and prints/serializes the proof report.
//! `verify-model` runs the verified-abstraction refinement check for
//! the window accounting.
//!
//! The Kani symbolic harnesses run separately via
//! `scripts/kani-run.sh` (they need the cargo-kani toolchain — see
//! docs/formal-verification.md and .github/workflows/formal-verification.yml).

use crate::{FormalArgs, FormalSubcommands};
use dc_core::DcError;

pub fn cmd_formal(args: FormalArgs) -> Result<(), DcError> {
    match &args.sub {
        FormalSubcommands::Check { depth, report_out } => {
            let report = dc_verify_formal::fsm::exhaustive_check(*depth);
            println!("checker:              {}", report.checker);
            println!("depth:                {}", report.depth);
            println!("distinct (state,ctx): {}", report.distinct_states);
            println!("nodes explored:       {}", report.sequences_explored);
            for inv in &report.invariants {
                println!(
                    "  [{}] {} — {}",
                    if inv.passed { "PASS" } else { "FAIL" },
                    inv.id,
                    inv.statement
                );
                if let Some(cex) = &inv.counterexample_actions {
                    println!("        counterexample: {:?}", cex);
                }
            }
            println!(
                "RESULT: {}",
                if report.all_passed {
                    "all invariants hold (exhaustive at this depth)"
                } else {
                    "INVARIANT VIOLATED"
                }
            );
            if let Some(path) = report_out {
                let json = dc_verify_formal::fsm::report_json(&report);
                std::fs::write(path, json).map_err(|e| DcError::Usage(format!("I/O: {}", e)))?;
                println!("report:               {}", path.display());
            }
            if !report.all_passed {
                return Err(DcError::Usage(
                    "formal model check found an invariant violation".into(),
                ));
            }
            Ok(())
        }
        FormalSubcommands::VerifyModel { windows } => {
            if *windows > 16 {
                return Err(DcError::Usage(
                    "bounded refinement check supports at most 16 windows".into(),
                ));
            }
            let passed = dc_verify_formal::verify::exhaustive_refinement_check(*windows);
            println!(
                "verified abstraction: count_windows — exact counters over (window, is_valid)"
            );
            println!(
                "refinement: real StreamVerifier agrees on all 2^{} = {} concrete sequences",
                windows,
                1u64 << windows
            );
            println!(
                "RESULT: {}",
                if passed {
                    "refinement HOLDS"
                } else {
                    "DIVERGENCE"
                }
            );
            if !passed {
                return Err(DcError::Usage(
                    "real verifier diverged from the verified abstraction".into(),
                ));
            }
            Ok(())
        }
    }
}
