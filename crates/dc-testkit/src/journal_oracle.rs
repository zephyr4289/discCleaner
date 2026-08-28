use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct JournalOracle;

#[derive(Debug)]
pub struct JournalOracleReport {
    pub chain_head: String,
    pub record_count: u64,
    pub total_windows_committed: u64,
    pub verification_mismatches: u64,
    pub stream_hash_blake3: String,
    pub sequence: Vec<String>,
    pub failure_count: usize,
    pub resume_count: usize,
    pub last_failed_record: Option<serde_json::Value>,
    pub frontier_before_last_resume: u64,
}

impl JournalOracle {
    /// Independent in-test validator for DCJ1 hash chain and FSM transition-table grammar.
    pub fn parse_and_validate(path: &Path, expected_total_windows: u64) -> Result<JournalOracleReport, String> {
        let mut file = File::open(path).map_err(|e| format!("Failed to open journal {}: {}", path.display(), e))?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)
            .map_err(|e| format!("Failed to read magic: {}", e))?;

        if &magic != b"DCJ1" {
            return Err(format!("Invalid journal magic: {:?}", magic));
        }

        let mut prev_hash = [0u8; 32];
        let mut records = Vec::new();
        let mut sequence = Vec::new();
        let mut committed_windows = 0u64;
        let mut verify_mismatches = 0u64;
        let mut stream_hash = String::new();
        let mut failure_count = 0;
        let mut resume_count = 0;
        let mut last_failed = None;
        let mut frontier_before_resume = 0;

        let mut record_idx = 0;
        loop {
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("Error reading record len #{}: {}", record_idx, e)),
            }

            let len = u32::from_le_bytes(len_buf) as usize;
            let mut record_bytes = vec![0u8; len];
            file.read_exact(&mut record_bytes)
                .map_err(|e| format!("Error reading record body #{}: {}", record_idx, e))?;

            let mut stored_hash = [0u8; 32];
            file.read_exact(&mut stored_hash)
                .map_err(|e| format!("Error reading record hash #{}: {}", record_idx, e))?;

            // Recompute BLAKE3(record_bytes || prev_hash)
            let mut hasher = blake3::Hasher::new();
            hasher.update(&record_bytes);
            hasher.update(&prev_hash);
            let calculated_hash = hasher.finalize();

            if calculated_hash.as_bytes() != &stored_hash {
                return Err(format!(
                    "Journal chain hash mismatch at record #{}: computed {}, stored {}",
                    record_idx,
                    calculated_hash.to_hex(),
                    hex::encode(stored_hash)
                ));
            }

            let json: serde_json::Value = serde_json::from_slice(&record_bytes)
                .map_err(|e| format!("Invalid JSON at record #{}: {}", record_idx, e))?;

            let rec_type = json
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            sequence.push(rec_type.clone());

            if rec_type == "range_commit" {
                let num_win = json.get("num_windows").and_then(|v| v.as_u64()).unwrap_or(0);
                committed_windows += num_win;
            } else if rec_type == "verify" {
                verify_mismatches = json.get("mismatch_count").and_then(|v| v.as_u64()).unwrap_or(0);
                stream_hash = json
                    .get("stream_hash_blake3")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
            } else if rec_type == "failed" {
                failure_count += 1;
                last_failed = Some(json.clone());
            } else if rec_type == "resumed" {
                resume_count += 1;
                frontier_before_resume = json.get("from_window").and_then(|v| v.as_u64()).unwrap_or(0);
            }

            prev_hash = stored_hash;
            records.push(json);
            record_idx += 1;
        }

        // Validate FSM Transition Table (§9)
        Self::validate_transition_table(&sequence)?;

        Ok(JournalOracleReport {
            chain_head: hex::encode(prev_hash),
            record_count: records.len() as u64,
            total_windows_committed: committed_windows,
            verification_mismatches: verify_mismatches,
            stream_hash_blake3: stream_hash,
            sequence,
            failure_count,
            resume_count,
            last_failed_record: last_failed,
            frontier_before_last_resume: frontier_before_resume,
        })
    }

    fn validate_transition_table(sequence: &[String]) -> Result<(), String> {
        if sequence.is_empty() {
            return Err("Journal is empty".to_string());
        }

        if sequence.first().map(|s| s.as_str()) != Some("header") {
            return Err(format!("First record must be header, found {:?}", sequence.first()));
        }

        for i in 0..sequence.len().saturating_sub(1) {
            let curr = &sequence[i];
            let next = &sequence[i + 1];

            let valid = match curr.as_str() {
                "header" => next == "armed",
                "armed" => next == "begin_pass" || next == "resumed",
                "begin_pass" => next == "range_commit" || next == "failed" || next == "end_pass" || next == "interrupted",
                "range_commit" => next == "range_commit" || next == "failed" || next == "end_pass" || next == "interrupted",
                "failed" => next == "armed", // Terminal or followed by resume's Armed
                "interrupted" => next == "armed",
                "resumed" => next == "range_commit" || next == "end_pass" || next == "verify" || next == "failed",
                "end_pass" => next == "flushed" || next == "failed",
                "flushed" => next == "verify" || next == "begin_pass" || next == "failed",
                "verify" => next == "completed" || next == "failed",
                "completed" | "aborted" => false, // Terminal, cannot have successors
                _ => false,
            };

            if !valid {
                return Err(format!(
                    "Invalid FSM transition: {} -> {} at index {}",
                    curr, next, i
                ));
            }
        }

        Ok(())
    }
}
