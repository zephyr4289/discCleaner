use crate::error::DcError;
use crate::identity::DeviceIdentity;
use crate::pattern::PatternDescriptor;
use crate::plan::SanitizationPlan;
use crate::tool::ToolBuild;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const JOURNAL_MAGIC: &[u8; 4] = b"DCJ1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EngineTuning {
    pub qd: u32,
    pub pool_mib: u32,
    pub window_bytes: u64,
    pub checkpoint_mib: u64,
    pub checkpoint_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JournalRecord {
    Header {
        plan: SanitizationPlan,
        plan_hash: String,
        identity: DeviceIdentity,
        tool: ToolBuild,
        engine: String,
        tuning: EngineTuning,
        argv_hash: String,
        started_utc: String,
    },
    Armed {
        overrides: Vec<String>,
        locks_held: Vec<String>,
        at: String,
    },
    BeginPass {
        pass: u8,
        pattern: PatternDescriptor,
        window_bytes: u64,
    },
    RangeCommit {
        pass: u8,
        first_window: u64,
        num_windows: u64,
    },
    EndPass {
        pass: u8,
    },
    Flushed {
        pass: u8,
    },
    Verify {
        level: String,
        windows_checked: u64,
        mismatch_count: u64,
        first_mismatch_lbas: Vec<u64>,
        stream_hash_blake3: String,
        stream_hash_sha256: Option<String>,
        fast_path_used: bool,
    },
    Interrupted {
        at: String,
        hint: String,
    },
    Resumed {
        phase: String, // "pass_N", "verify"
        from_pass: u8,
        from_window: u64,
        discarded_tail_bytes: u64,
        at: String,
    },
    Failed {
        code: String,
        errno: Option<i32>,
        op: Option<String>,
        at_lba: Option<u64>,
        detail: String,
    },
    Aborted {
        at: String,
    },
    Completed {
        at: String,
        duration_mono_ms: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalChainSummary {
    pub path: PathBuf,
    pub chain_head: String,
    pub record_count: u64,
    pub discarded_tail_bytes: u64,
}

pub struct JournalWriter {
    file: File,
    path: PathBuf,
    prev_hash: [u8; 32],
    record_count: u64,
}

impl JournalWriter {
    pub fn create(path: &Path, header: JournalRecord) -> Result<Self, DcError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        // Write Magic DCJ1
        file.write_all(JOURNAL_MAGIC)?;
        file.flush()?;

        let mut writer = Self {
            file,
            path: path.to_path_buf(),
            prev_hash: [0u8; 32],
            record_count: 0,
        };

        writer.append(&header)?;
        Ok(writer)
    }

    pub fn resume_from_chain(
        path: &Path,
        chain_head_hex: &str,
        record_count: u64,
        truncate_offset: Option<u64>,
    ) -> Result<Self, DcError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        if let Some(trunc_len) = truncate_offset {
            file.set_len(trunc_len)?;
        }

        let hash_bytes = hex::decode(chain_head_hex)
            .map_err(|e| DcError::JournalCorrupt {
                record_index: record_count,
                reason: format!("Invalid chain head hex: {}", e),
            })?;

        if hash_bytes.len() != 32 {
            return Err(DcError::JournalCorrupt {
                record_index: record_count,
                reason: "Invalid chain head length".to_string(),
            });
        }

        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&hash_bytes);

        let mut writer_file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            file: writer_file,
            path: path.to_path_buf(),
            prev_hash,
            record_count,
        })
    }

    pub fn append(&mut self, record: &JournalRecord) -> Result<String, DcError> {
        let record_bytes = serde_json::to_vec(record)?;
        let len = record_bytes.len() as u32;

        // Hash chain: record_hash = BLAKE3(record_bytes || prev_hash)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&record_bytes);
        hasher.update(&self.prev_hash);
        let record_hash = hasher.finalize();

        // Write u32 len LE + record_bytes + 32-byte hash
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&record_bytes)?;
        self.file.write_all(record_hash.as_bytes())?;

        self.file.flush()?;
        self.file.sync_data()?;

        self.prev_hash = *record_hash.as_bytes();
        self.record_count += 1;

        // Check crash hook if enabled
        check_crash_hook(record);

        Ok(hex::encode(self.prev_hash))
    }

    pub fn current_chain_head(&self) -> String {
        hex::encode(self.prev_hash)
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn summary(&self) -> JournalChainSummary {
        JournalChainSummary {
            path: self.path.clone(),
            chain_head: self.current_chain_head(),
            record_count: self.record_count,
            discarded_tail_bytes: 0,
        }
    }
}

pub struct JournalReader;

impl JournalReader {
    pub fn read_and_verify_chain(
        path: &Path,
    ) -> Result<(Vec<JournalRecord>, JournalChainSummary), DcError> {
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();

        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_err() || &magic != JOURNAL_MAGIC {
            return Err(DcError::JournalCorrupt {
                record_index: 0,
                reason: "Invalid or missing DCJ1 journal magic".to_string(),
            });
        }

        let mut prev_hash = [0u8; 32];
        let mut records = Vec::new();
        let mut record_idx = 0;
        let mut last_valid_offset = 4u64;

        loop {
            let mut len_buf = [0u8; 4];
            let read_len_res = file.read_exact(&mut len_buf);
            if let Err(e) = read_len_res {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(DcError::StdIo(e));
            }

            let len = u32::from_le_bytes(len_buf) as usize;
            if len > 64 * 1024 * 1024 {
                // Check if this is a torn final record at EOF
                let curr_pos = file.stream_position().unwrap_or(last_valid_offset);
                if curr_pos + len as u64 > file_len {
                    // Torn final record: break and discard
                    break;
                }
                return Err(DcError::JournalCorrupt {
                    record_index: record_idx,
                    reason: format!("Unreasonable record length: {} bytes", len),
                });
            }

            let mut record_bytes = vec![0u8; len];
            if file.read_exact(&mut record_bytes).is_err() {
                // Incomplete final record body -> torn tail at EOF
                break;
            }

            let mut expected_hash = [0u8; 32];
            if file.read_exact(&mut expected_hash).is_err() {
                // Incomplete final record hash -> torn tail at EOF
                break;
            }

            let mut hasher = blake3::Hasher::new();
            hasher.update(&record_bytes);
            hasher.update(&prev_hash);
            let calculated_hash = hasher.finalize();

            if calculated_hash.as_bytes() != &expected_hash {
                // If this is at the very end of the file, it could be a torn tail, but if not, corruption
                let curr_pos = file.stream_position().unwrap_or(last_valid_offset);
                if curr_pos >= file_len {
                    // Torn tail hash
                    break;
                }
                return Err(DcError::JournalCorrupt {
                    record_index: record_idx,
                    reason: format!(
                        "Hash mismatch! Calculated: {}, Stored: {}",
                        hex::encode(calculated_hash.as_bytes()),
                        hex::encode(expected_hash)
                    ),
                });
            }

            let record: Result<JournalRecord, _> = serde_json::from_slice(&record_bytes);
            let valid_record = match record {
                Ok(r) => r,
                Err(e) => {
                    let curr_pos = file.stream_position().unwrap_or(last_valid_offset);
                    if curr_pos >= file_len {
                        break;
                    }
                    return Err(DcError::JournalCorrupt {
                        record_index: record_idx,
                        reason: format!("Failed to deserialize record JSON: {}", e),
                    });
                }
            };

            records.push(valid_record);
            prev_hash = expected_hash;
            last_valid_offset = file.stream_position().unwrap_or(last_valid_offset);
            record_idx += 1;
        }

        let discarded = file_len.saturating_sub(last_valid_offset);

        let summary = JournalChainSummary {
            path: path.to_path_buf(),
            chain_head: hex::encode(prev_hash),
            record_count: records.len() as u64,
            discarded_tail_bytes: discarded,
        };

        Ok((records, summary))
    }
}

/// Deterministic crash injection hook (activated by `DC_CRASH_AT=event[:count]`)
pub fn check_crash_hook(record: &JournalRecord) {
    if let Ok(crash_spec) = std::env::var("DC_CRASH_AT") {
        let parts: Vec<&str> = crash_spec.split(':').collect();
        let event = parts[0];
        let count_target: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);

        static COMMIT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let should_kill = match (event, record) {
            ("beginpass-write", JournalRecord::BeginPass { .. }) => true,
            ("endpass-write", JournalRecord::EndPass { .. }) => true,
            ("flushed-write", JournalRecord::Flushed { .. }) => true,
            ("resumed-write", JournalRecord::Resumed { .. }) => true,
            ("completed-write", JournalRecord::Completed { .. }) => true,
            ("commit", JournalRecord::RangeCommit { .. }) => {
                let current = COMMIT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                current == count_target
            }
            _ => false,
        };

        if should_kill {
            eprintln!("[CRASH_HOOK] Intentionally raising SIGKILL on event: {}", crash_spec);
            unsafe {
                libc::raise(libc::SIGKILL);
            }
        }
    }
}

/// Helper to trigger CQE or Verify-read crash hook
pub fn check_cqe_or_verify_crash(event_type: &str, count: u64) {
    if let Ok(crash_spec) = std::env::var("DC_CRASH_AT") {
        let parts: Vec<&str> = crash_spec.split(':').collect();
        let target_event = parts[0];
        let target_count: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);

        if target_event == event_type && count == target_count {
            eprintln!("[CRASH_HOOK] Intentionally raising SIGKILL on {}:{}", event_type, count);
            unsafe {
                libc::raise(libc::SIGKILL);
            }
        }
    }
}
