use crate::error::DcError;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditOutcome {
    Refusal { code: String, detail: String },
    PlanCompiled { plan_hash: String },
    Armed { journal_path: String },
    Executed { journal_path: String, chain_head: String },
    Resumed { journal_path: String },
    VerifyOnly { passed: bool },
    Error { detail: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp_utc: String,
    pub argv_hash: String,
    pub target_path: Option<String>,
    pub outcome: AuditOutcome,
}

pub struct AuditLogger {
    file: File,
    path: PathBuf,
    prev_hash: [u8; 32],
}

impl AuditLogger {
    pub fn open_or_create(path: &Path) -> Result<Self, DcError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        let mut prev_hash = [0u8; 32];
        let file_len = file.metadata()?.len();

        if file_len > 0 {
            // Read through file to find last hash
            file.seek(SeekFrom::Start(0))?;
            let mut magic = [0u8; 4];
            if file.read_exact(&mut magic).is_ok() && &magic == b"DCA1" {
                loop {
                    let mut len_buf = [0u8; 4];
                    if file.read_exact(&mut len_buf).is_err() {
                        break;
                    }
                    let len = u32::from_le_bytes(len_buf) as usize;
                    let mut rec = vec![0u8; len];
                    if file.read_exact(&mut rec).is_err() {
                        break;
                    }
                    let mut hash = [0u8; 32];
                    if file.read_exact(&mut hash).is_err() {
                        break;
                    }
                    prev_hash = hash;
                }
            }
        } else {
            file.write_all(b"DCA1")?;
            file.flush()?;
        }

        file.seek(SeekFrom::End(0))?;

        Ok(Self {
            file,
            path: path.to_path_buf(),
            prev_hash,
        })
    }

    pub fn log(&mut self, record: &AuditRecord) -> Result<String, DcError> {
        let record_bytes = serde_json::to_vec(record)?;
        let len = record_bytes.len() as u32;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&record_bytes);
        hasher.update(&self.prev_hash);
        let record_hash = hasher.finalize();

        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&record_bytes)?;
        self.file.write_all(record_hash.as_bytes())?;
        self.file.flush()?;
        self.file.sync_data()?;

        self.prev_hash = *record_hash.as_bytes();
        Ok(hex::encode(self.prev_hash))
    }

    pub fn verify_audit_file(path: &Path) -> Result<(usize, String), DcError> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != b"DCA1" {
            return Err(DcError::Usage("Invalid audit log magic (expected DCA1)".to_string()));
        }

        let mut prev_hash = [0u8; 32];
        let h = blake3::hash(b"DCA1");
        prev_hash.copy_from_slice(h.as_bytes());

        let mut count = 0;
        loop {
            let mut len_buf = [0u8; 4];
            if file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut rec = vec![0u8; len];
            file.read_exact(&mut rec)?;
            let mut hash = [0u8; 32];
            file.read_exact(&mut hash)?;

            let mut hasher = blake3::Hasher::new();
            hasher.update(&rec);
            hasher.update(&prev_hash);
            let expected = hasher.finalize();
            if hash != *expected.as_bytes() {
                return Err(DcError::Usage(format!("Audit chain mismatch at record {}", count)));
            }
            prev_hash = hash;
            count += 1;
        }

        Ok((count, hex::encode(prev_hash)))
    }
}
