use crate::ledger::RigLedger;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub schema: String,            // "dc-release/1"
    pub tag: String,               // e.g. "v0.1.0"
    pub commit: String,
    pub target_triple: String,
    pub rustc_version: String,
    pub binary_blake3: String,
    pub unstripped_blake3: String,
    pub total_assertions: usize,
    pub ceremonies_completed: usize, // 9
}

pub struct DoublePassRunner;

impl DoublePassRunner {
    /// Execute test matrix twice in the same process session with leak detection (Δ190).
    pub fn run_twice<F>(matrix_fn: F) -> Result<(), String>
    where
        F: Fn() -> Result<(), String>,
    {
        // Pass 1: Fresh execution
        matrix_fn().map_err(|e| format!("Pass 1 failed: {}", e))?;

        // Pass 2: Contamination & Leak Detection sweep
        matrix_fn().map_err(|e| format!("Pass 2 (Leak Detection) failed: {}", e))?;

        Ok(())
    }
}

pub struct CoverageOracle;

impl CoverageOracle {
    /// Check that every registered assertion ID is executed and mapped (Δ192 Zero-Orphan Gate).
    pub fn verify_zero_orphans(
        registered_ids: &[&str],
        observed_ids: &HashSet<String>,
    ) -> Result<usize, Vec<String>> {
        let mut orphans = Vec::new();

        for &id in registered_ids {
            if !observed_ids.contains(id) {
                orphans.push(id.to_string());
            }
        }

        if orphans.is_empty() {
            Ok(observed_ids.len())
        } else {
            Err(orphans)
        }
    }
}
