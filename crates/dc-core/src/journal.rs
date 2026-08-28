use crate::error::DcError;
use crate::identity::DeviceIdentity;
use crate::pattern::PatternDescriptor;
use crate::plan::SanitizationPlan;
use crate::tool::ToolBuild;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const JOURNAL_MAGIC: &[u8; 4] = b"DCJ1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JournalRecord {
    Header {
        plan: SanitizationPlan,
        plan_hash: String,
        identity: DeviceIdentity,
        tool: ToolBuild,
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
        at: String,
        from_pass: u8,
        from_window: u64,
    },
    Failed {
        code: String,
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
        }
    }
}

pub struct JournalReader;

impl JournalReader {
    pub fn read_and_verify_chain(
        path: &Path,
    ) -> Result<(Vec<JournalRecord>, JournalChainSummary), DcError> {
        let mut file = File::open(path)?;
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

        loop {
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Clean EOF
                    break;
                }
                Err(e) => return Err(DcError::StdIo(e)),
            }

            let len = u32::from_le_bytes(len_buf) as usize;
            if len > 64 * 1024 * 1024 {
                return Err(DcError::JournalCorrupt {
                    record_index: record_idx,
                    reason: format!("Unreasonable record length: {} bytes", len),
                });
            }

            let mut record_bytes = vec![0u8; len];
            file.read_exact(&mut record_bytes)
                .map_err(|e| DcError::JournalCorrupt {
                    record_index: record_idx,
                    reason: format!("Unexpected EOF while reading record body: {}", e),
                })?;

            let mut expected_hash = [0u8; 32];
            file.read_exact(&mut expected_hash)
                .map_err(|e| DcError::JournalCorrupt {
                    record_index: record_idx,
                    reason: format!("Unexpected EOF while reading record hash: {}", e),
                })?;

            let mut hasher = blake3::Hasher::new();
            hasher.update(&record_bytes);
            hasher.update(&prev_hash);
            let calculated_hash = hasher.finalize();

            if calculated_hash.as_bytes() != &expected_hash {
                return Err(DcError::JournalCorrupt {
                    record_index: record_idx,
                    reason: format!(
                        "Hash mismatch! Calculated: {}, Stored: {}",
                        hex::encode(calculated_hash.as_bytes()),
                        hex::encode(expected_hash)
                    ),
                });
            }

            let record: JournalRecord =
                serde_json::from_slice(&record_bytes).map_err(|e| DcError::JournalCorrupt {
                    record_index: record_idx,
                    reason: format!("Failed to deserialize record JSON: {}", e),
                })?;

            records.push(record);
            prev_hash = expected_hash;
            record_idx += 1;
        }

        let summary = JournalChainSummary {
            path: path.to_path_buf(),
            chain_head: hex::encode(prev_hash),
            record_count: records.len() as u64,
        };

        Ok((records, summary))
    }
}
