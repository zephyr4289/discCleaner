use crate::error::DcError;
use crate::identity::DeviceIdentity;
use crate::pattern::PatternDescriptor;
use crate::plan::SanitizationPlan;
use crate::tool::ToolBuild;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
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
        uuid: String,
        sealed: bool,
        operator_pubkey: Option<String>,
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
        #[serde(default)]
        completed_through_pass: Option<u8>,
        #[serde(default)]
        completed_through_window: Option<u64>,
        #[serde(default)]
        signals_received: Option<u32>,
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
    pub uuid: String,
    pub sealed: bool,
}

pub struct JournalWriter {
    file: File,
    path: PathBuf,
    prev_hash: [u8; 32],
    record_count: u64,
    signing_key: Option<SigningKey>,
    uuid: String,
    sealed: bool,
}

impl JournalWriter {
    pub fn create_new(
        path: &Path,
        uuid: String,
        signing_key: Option<SigningKey>,
    ) -> Result<Self, DcError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        // Exclusive non-blocking flock on journal file (Δ43)
        unsafe {
            let fd = file.as_raw_fd();
            if libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
                return Err(DcError::JournalCorrupt {
                    record_index: 0,
                    reason: "Failed to acquire exclusive lock on journal file".to_string(),
                });
            }
        }

        file.write_all(JOURNAL_MAGIC)?;
        file.flush()?;
        file.sync_data()?;

        let mut initial_hash = [0u8; 32];
        let h = blake3::hash(JOURNAL_MAGIC);
        initial_hash.copy_from_slice(h.as_bytes());

        let sealed = signing_key.is_some();

        Ok(Self {
            file,
            path: path.to_path_buf(),
            prev_hash: initial_hash,
            record_count: 0,
            signing_key,
            uuid,
            sealed,
        })
    }

    pub fn open_for_resume(
        path: &Path,
        chain_head_hex: &str,
        record_count: u64,
        truncate_offset: Option<u64>,
        uuid: String,
        sealed: bool,
        signing_key: Option<SigningKey>,
    ) -> Result<Self, DcError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        // Exclusive non-blocking flock on journal file (Δ43)
        unsafe {
            let fd = file.as_raw_fd();
            if libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
                return Err(DcError::JournalCorrupt {
                    record_index: record_count,
                    reason: "Failed to acquire exclusive lock on journal file".to_string(),
                });
            }
        }

        if let Some(trunc_len) = truncate_offset {
            file.set_len(trunc_len)?;
        }

        let hash_bytes = hex::decode(chain_head_hex).map_err(|e| DcError::JournalCorrupt {
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
            signing_key,
            uuid,
            sealed,
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

        // Sealed journal: append 64-byte Ed25519 signature over (record_bytes || prev_hash) (Δ39)
        if let Some(ref sk) = self.signing_key {
            let mut msg = Vec::with_capacity(record_bytes.len() + 32);
            msg.extend_from_slice(&record_bytes);
            msg.extend_from_slice(&self.prev_hash);
            let sig = sk.sign(&msg);
            self.file.write_all(&sig.to_bytes())?;
        }

        self.file.flush()?;
        self.file.sync_data()?;

        self.prev_hash = *record_hash.as_bytes();
        self.record_count += 1;

        // Check crash and signal hooks if enabled (Δ87)
        check_crash_hook(record);
        check_signal_hook(record);

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
            uuid: self.uuid.clone(),
            sealed: self.sealed,
        }
    }
}

pub struct JournalReader;

impl JournalReader {
    pub fn read_and_verify_chain(
        path: &Path,
    ) -> Result<(Vec<JournalRecord>, JournalChainSummary), DcError> {
        // Path safety check: S_ISREG (Δ44)
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_file() {
            return Err(DcError::Usage(format!(
                "Invalid journal path: '{}' is not a regular file",
                path.display()
            )));
        }

        let mut file = File::open(path)?;
        let total_file_size = file.metadata()?.len();

        let mut magic = [0u8; 4];
        if let Err(e) = file.read_exact(&mut magic) {
            return Err(DcError::JournalCorrupt {
                record_index: 0,
                reason: format!("Cannot read journal magic: {}", e),
            });
        }

        if &magic != JOURNAL_MAGIC {
            return Err(DcError::JournalCorrupt {
                record_index: 0,
                reason: "Invalid journal magic".to_string(),
            });
        }

        let mut prev_hash = [0u8; 32];
        let h = blake3::hash(JOURNAL_MAGIC);
        prev_hash.copy_from_slice(h.as_bytes());

        let mut records = Vec::new();
        let mut record_idx = 0u64;
        let mut last_good_offset = 4u64;
        let mut discarded_tail = 0u64;
        let mut journal_uuid = String::new();
        let mut journal_sealed = false;
        let mut op_verifying_key: Option<VerifyingKey> = None;

        loop {
            let current_pos = file.stream_position()?;
            if current_pos == total_file_size {
                break; // Clean EOF
            }

            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(_) => {
                    // Torn length prefix at EOF
                    discarded_tail = total_file_size - last_good_offset;
                    break;
                }
            }

            let len = u32::from_le_bytes(len_buf) as usize;

            // Bounds check against remaining file size (Δ79)
            if (current_pos + 4 + len as u64 + 32) > total_file_size && !journal_sealed {
                discarded_tail = total_file_size - last_good_offset;
                break;
            }

            let mut record_bytes = vec![0u8; len];
            if file.read_exact(&mut record_bytes).is_err() {
                // Torn record body at EOF
                discarded_tail = total_file_size - last_good_offset;
                break;
            }

            let mut hash_bytes = [0u8; 32];
            if file.read_exact(&mut hash_bytes).is_err() {
                // Torn record hash at EOF
                discarded_tail = total_file_size - last_good_offset;
                break;
            }

            // Verify hash chain
            let mut hasher = blake3::Hasher::new();
            hasher.update(&record_bytes);
            hasher.update(&prev_hash);
            let expected_hash = hasher.finalize();

            if hash_bytes != *expected_hash.as_bytes() {
                return Err(DcError::JournalCorrupt {
                    record_index: record_idx,
                    reason: "BLAKE3 hash chain mismatch".to_string(),
                });
            }

            let record: JournalRecord = match serde_json::from_slice(&record_bytes) {
                Ok(r) => r,
                Err(e) => {
                    return Err(DcError::JournalCorrupt {
                        record_index: record_idx,
                        reason: format!("JSON record parse error: {}", e),
                    });
                }
            };

            // Inspect Header (Record 0) for sealed journal state and UUID (Δ39, Δ40)
            if record_idx == 0 {
                if let JournalRecord::Header {
                    ref uuid,
                    sealed,
                    ref operator_pubkey,
                    ..
                } = record
                {
                    journal_uuid = uuid.clone();
                    journal_sealed = sealed;
                    if sealed {
                        if let Some(pk_hex) = operator_pubkey {
                            let pk_bytes = hex::decode(pk_hex).map_err(|_| DcError::JournalCorrupt {
                                record_index: 0,
                                reason: "Invalid operator_pubkey hex in Header".to_string(),
                            })?;
                            let vk = VerifyingKey::from_bytes(
                                pk_bytes.as_slice().try_into().map_err(|_| DcError::JournalCorrupt {
                                    record_index: 0,
                                    reason: "Invalid operator_pubkey length in Header".to_string(),
                                })?,
                            ).map_err(|_| DcError::JournalCorrupt {
                                record_index: 0,
                                reason: "Invalid Ed25519 public key in Header".to_string(),
                            })?;
                            op_verifying_key = Some(vk);
                        }
                    }
                }
            }

            // If sealed journal, verify Ed25519 signature per record (Δ39)
            if journal_sealed {
                let mut sig_bytes = [0u8; 64];
                if file.read_exact(&mut sig_bytes).is_err() {
                    return Err(DcError::JournalCorrupt {
                        record_index: record_idx,
                        reason: "Missing Ed25519 signature in sealed journal record".to_string(),
                    });
                }

                if let Some(ref vk) = op_verifying_key {
                    let mut msg = Vec::with_capacity(record_bytes.len() + 32);
                    msg.extend_from_slice(&record_bytes);
                    msg.extend_from_slice(&prev_hash);
                    let sig = Signature::from_bytes(&sig_bytes);
                    if vk.verify(&msg, &sig).is_err() {
                        return Err(DcError::JournalCorrupt {
                            record_index: record_idx,
                            reason: "Invalid Ed25519 digital signature in sealed journal record".to_string(),
                        });
                    }
                }
            }

            prev_hash = hash_bytes;
            records.push(record);
            record_idx += 1;
            last_good_offset = file.stream_position()?;
        }

        let summary = JournalChainSummary {
            path: path.to_path_buf(),
            chain_head: hex::encode(prev_hash),
            record_count: records.len() as u64,
            discarded_tail_bytes: discarded_tail,
            uuid: journal_uuid,
            sealed: journal_sealed,
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
            ("header-write", JournalRecord::Header { .. }) => true,
            ("armed-write", JournalRecord::Armed { .. }) => true,
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

/// Deterministic signal injection hook (activated by `DC_SIGNAL_AT=event[:count]`) (Δ87)
pub fn check_signal_hook(record: &JournalRecord) {
    if let Ok(sig_spec) = std::env::var("DC_SIGNAL_AT") {
        let parts: Vec<&str> = sig_spec.split(':').collect();
        let event = parts[0];
        let count_target: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);

        static COMMIT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let should_signal = match (event, record) {
            ("commit-write", JournalRecord::RangeCommit { .. }) => {
                let current = COMMIT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                current == count_target
            }
            ("endpass", JournalRecord::EndPass { .. }) => true,
            ("flushed", JournalRecord::Flushed { .. }) => true,
            ("verify", JournalRecord::Verify { .. }) => true,
            _ => false,
        };

        if should_signal {
            eprintln!("[SIGNAL_HOOK] Intentionally raising SIGINT on event: {}", sig_spec);
            unsafe {
                libc::kill(libc::getpid(), libc::SIGINT);
            }
        }
    }
}

/// Helper to trigger CQE or Verify-read signal hook (Δ87)
pub fn check_cqe_or_verify_signal(event_type: &str, count: u64) {
    if let Ok(sig_spec) = std::env::var("DC_SIGNAL_AT") {
        let parts: Vec<&str> = sig_spec.split(':').collect();
        let target_event = parts[0];
        let target_count: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);

        if target_event == event_type && count == target_count {
            eprintln!("[SIGNAL_HOOK] Intentionally raising SIGINT on {}:{}", event_type, count);
            unsafe {
                libc::kill(libc::getpid(), libc::SIGINT);
            }
        }
    }
}
