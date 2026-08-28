use dc_core::journal::{JournalReader, JournalRecord};
use dc_core::Pattern;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproductionRecipe {
    pub schema: String,               // "dc-recipe/1"
    pub scheme: String,               // "chacha20-window-v1"
    pub doc_blake3: String,           // BLAKE3 of docs/reproduction/chacha20-window-v1.txt
    pub seed: String,                 // 64 hex chars (32 bytes)
    pub window_bytes: u64,
    pub device_bytes: u64,
    pub stream_hash_blake3: String,
}

pub struct RecipeExtractor;

impl RecipeExtractor {
    /// Extract ReproductionRecipe from an authentic .dcj journal file (Δ155).
    pub fn from_journal(journal_path: &Path) -> Result<ReproductionRecipe, String> {
        let (records, _) = JournalReader::read_and_verify_chain(journal_path)
            .map_err(|e| format!("Journal parse error: {}", e))?;

        let mut device_bytes = 0u64;
        let mut window_bytes = 2 * 1024 * 1024;
        let mut seed_opt = None;
        let mut stream_hash_opt = None;

        for rec in &records {
            match rec {
                JournalRecord::Header { plan, identity, .. } => {
                    device_bytes = identity.stable.size_bytes;
                    window_bytes = plan.window_bytes;

                    // Extract seed from plan passes
                    match &plan.mechanism {
                        dc_core::Mechanism::LogicalOverwrite { passes } => {
                            for p in passes {
                                match &p.pattern.pattern {
                                    Pattern::DeterministicRandom { seed, .. } => {
                                        seed_opt = Some(seed.clone());
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                JournalRecord::Verify { stream_hash_blake3, .. } => {
                    stream_hash_opt = Some(stream_hash_blake3.clone());
                }
                _ => {}
            }
        }

        let seed = seed_opt.ok_or_else(|| "No DeterministicRandom pass found in journal plan".to_string())?;
        let stream_hash_blake3 = stream_hash_opt.ok_or_else(|| "No Verify record found in journal".to_string())?;

        // Canonical doc hash (fixed BLAKE3 of chacha20-window-v1.txt)
        let doc_text = include_str!("../../../docs/reproduction/chacha20-window-v1.txt");
        let doc_blake3 = blake3::hash(doc_text.as_bytes()).to_hex().to_string();

        Ok(ReproductionRecipe {
            schema: "dc-recipe/1".to_string(),
            scheme: "chacha20-window-v1".to_string(),
            doc_blake3,
            seed,
            window_bytes,
            device_bytes,
            stream_hash_blake3,
        })
    }
}
