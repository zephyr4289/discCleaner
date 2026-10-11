use crate::error::DcError;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// Hard cap on a single audit record's serialized size (defensive bound
/// against corrupt or hostile length prefixes before any allocation).
pub const AUDIT_MAX_RECORD_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditOutcome {
    Refusal {
        code: String,
        detail: String,
    },
    PlanCompiled {
        plan_hash: String,
    },
    Armed {
        journal_path: String,
    },
    Executed {
        journal_path: String,
        chain_head: String,
    },
    Resumed {
        journal_path: String,
    },
    VerifyOnly {
        passed: bool,
    },
    Error {
        detail: String,
    },
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
            .append(true)
            .create(true)
            .open(path)?;

        // Exclusive non-blocking flock: two concurrent `dc` processes must
        // never interleave records into one audit chain.
        unsafe {
            let fd = file.as_raw_fd();
            if libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
                return Err(DcError::Usage(
                    "Failed to acquire exclusive lock on audit log (another instance is active?)"
                        .to_string(),
                ));
            }
        }

        let mut prev_hash = [0u8; 32];
        let file_len = file.metadata()?.len();

        if file_len > 0 {
            // Read through file to find last hash. The chain seed MUST match
            // `verify_audit_file` (BLAKE3 of the magic) — see the fix for the
            // historical zero-seed asymmetry below.
            file.seek(SeekFrom::Start(0))?;
            let mut magic = [0u8; 4];
            if file.read_exact(&mut magic).is_err() || &magic != b"DCA1" {
                return Err(DcError::Usage(format!(
                    "Invalid audit log magic in '{}' (expected DCA1); refusing to append",
                    path.display()
                )));
            }
            let seed_hash = blake3::hash(b"DCA1");
            prev_hash.copy_from_slice(seed_hash.as_bytes());
            loop {
                let rec_start = file.stream_position()?;
                let mut len_buf = [0u8; 4];
                if file.read_exact(&mut len_buf).is_err() {
                    break;
                }
                let len = u32::from_le_bytes(len_buf) as u64;
                if len == 0 || len > AUDIT_MAX_RECORD_BYTES {
                    return Err(DcError::Usage(format!(
                        "Corrupt audit record length {} at offset {}",
                        len, rec_start
                    )));
                }
                let mut rec = vec![0u8; len as usize];
                if file.read_exact(&mut rec).is_err() {
                    break;
                }
                let mut hash = [0u8; 32];
                if file.read_exact(&mut hash).is_err() {
                    break;
                }
                prev_hash = hash;
            }
        } else {
            file.write_all(b"DCA1")?;
            file.flush()?;
            // Seed the chain exactly like the verifier: BLAKE3("DCA1").
            // (Historically this seeded with zeros while the verifier seeded
            // with BLAKE3("DCA1"), so the first record of every fresh log
            // could never verify.)
            let h = blake3::hash(b"DCA1");
            prev_hash.copy_from_slice(h.as_bytes());
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
        let total_file_size = file.metadata()?.len();
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != b"DCA1" {
            return Err(DcError::Usage(
                "Invalid audit log magic (expected DCA1)".to_string(),
            ));
        }

        let mut prev_hash = [0u8; 32];
        let h = blake3::hash(b"DCA1");
        prev_hash.copy_from_slice(h.as_bytes());

        let mut count = 0;
        loop {
            let rec_start = file.stream_position()?;
            let mut len_buf = [0u8; 4];
            if file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_buf) as u64;
            if len == 0 || len > AUDIT_MAX_RECORD_BYTES {
                return Err(DcError::Usage(format!(
                    "Corrupt audit record length {} at offset {}",
                    len, rec_start
                )));
            }
            // Never allocate beyond what the file itself can supply.
            if rec_start + 4 + len + 32 > total_file_size {
                return Err(DcError::Usage(format!(
                    "Truncated audit record at offset {} (declared {} bytes)",
                    rec_start, len
                )));
            }
            let mut rec = vec![0u8; len as usize];
            file.read_exact(&mut rec)?;
            let mut hash = [0u8; 32];
            file.read_exact(&mut hash)?;

            let mut hasher = blake3::Hasher::new();
            hasher.update(&rec);
            hasher.update(&prev_hash);
            let expected = hasher.finalize();
            if hash != *expected.as_bytes() {
                return Err(DcError::Usage(format!(
                    "Audit chain mismatch at record {}",
                    count
                )));
            }
            prev_hash = hash;
            count += 1;
        }

        Ok((count, hex::encode(prev_hash)))
    }

    /// Filesystem path of the underlying audit chain.
    pub fn path(&self) -> &Path {
        &self.path
    }
}
