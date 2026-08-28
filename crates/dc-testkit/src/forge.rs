use ed25519_dalek::{Signer, SigningKey};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub struct JournalForge;

#[derive(Clone, Debug)]
pub struct RawRecordEntry {
    pub offset: u64,
    pub len: u32,
    pub body_bytes: Vec<u8>,
    pub stored_hash: [u8; 32],
    pub stored_sig: Option<[u8; 64]>,
}

impl JournalForge {
    /// Parse all raw records from a DCJ1 journal file.
    pub fn parse_raw_records(path: &Path) -> Result<(Vec<RawRecordEntry>, bool), String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let file_len = file.metadata().map_err(|e| e.to_string())?.len();

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).map_err(|e| e.to_string())?;
        if &magic != b"DCJ1" {
            return Err("Invalid DCJ1 magic".to_string());
        }

        let mut records = Vec::new();
        let mut is_sealed = false;

        loop {
            let offset = file.stream_position().map_err(|e| e.to_string())?;
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.to_string()),
            }

            let len = u32::from_le_bytes(len_buf) as usize;
            if offset + 4 + len as u64 + 32 > file_len {
                break;
            }

            let mut body_bytes = vec![0u8; len];
            file.read_exact(&mut body_bytes).map_err(|e| e.to_string())?;

            let mut stored_hash = [0u8; 32];
            file.read_exact(&mut stored_hash).map_err(|e| e.to_string())?;

            // Detect sealed status from record 0
            if records.is_empty() {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                    if let Some(s) = val.get("sealed").and_then(|v| v.as_bool()) {
                        is_sealed = s;
                    }
                }
            }

            let mut stored_sig = None;
            if is_sealed {
                let mut sig_buf = [0u8; 64];
                if file.read_exact(&mut sig_buf).is_ok() {
                    stored_sig = Some(sig_buf);
                }
            }

            records.push(RawRecordEntry {
                offset,
                len: len as u32,
                body_bytes,
                stored_hash,
                stored_sig,
            });
        }

        Ok((records, is_sealed))
    }

    /// Write raw records back to file.
    pub fn write_raw_records(path: &Path, records: &[RawRecordEntry]) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| e.to_string())?;

        file.write_all(b"DCJ1").map_err(|e| e.to_string())?;

        for r in records {
            file.write_all(&r.len.to_le_bytes()).map_err(|e| e.to_string())?;
            file.write_all(&r.body_bytes).map_err(|e| e.to_string())?;
            file.write_all(&r.stored_hash).map_err(|e| e.to_string())?;
            if let Some(ref sig) = r.stored_sig {
                file.write_all(sig).map_err(|e| e.to_string())?;
            }
        }

        file.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Flip single byte in journal file at absolute byte offset.
    pub fn flip_byte_at_offset(path: &Path, offset: u64) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| e.to_string())?;

        file.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
        let mut b = [0u8; 1];
        file.read_exact(&mut b).map_err(|e| e.to_string())?;
        b[0] ^= 0xFF; // Bit-flip

        file.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
        file.write_all(&b).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Recompute single record's self hash (L1 repair without cascading).
    pub fn recompute_record_hash(path: &Path, record_idx: usize) -> Result<(), String> {
        let (mut records, _) = Self::parse_raw_records(path)?;
        if record_idx >= records.len() {
            return Err("Record index out of bounds".to_string());
        }

        let prev_hash = if record_idx == 0 {
            [0u8; 32]
        } else {
            records[record_idx - 1].stored_hash
        };

        let mut hasher = blake3::Hasher::new();
        hasher.update(&records[record_idx].body_bytes);
        hasher.update(&prev_hash);
        records[record_idx].stored_hash = *hasher.finalize().as_bytes();

        Self::write_raw_records(path, &records)
    }

    /// Recompute full cascade of hashes from record 0 to end (L1 + L2 repair).
    pub fn recompute_full_cascade(path: &Path) -> Result<(), String> {
        let (mut records, _) = Self::parse_raw_records(path)?;
        let mut prev_hash = [0u8; 32];

        for r in records.iter_mut() {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&r.body_bytes);
            hasher.update(&prev_hash);
            r.stored_hash = *hasher.finalize().as_bytes();
            prev_hash = r.stored_hash;
        }

        Self::write_raw_records(path, &records)
    }

    /// Splice out / delete a middle record.
    pub fn splice_out_record(path: &Path, record_idx: usize) -> Result<(), String> {
        let (mut records, _) = Self::parse_raw_records(path)?;
        if record_idx >= records.len() {
            return Err("Index out of bounds".to_string());
        }
        records.remove(record_idx);
        Self::write_raw_records(path, &records)
    }

    /// Reorder two adjacent records.
    pub fn reorder_adjacent_records(path: &Path, idx: usize) -> Result<(), String> {
        let (mut records, _) = Self::parse_raw_records(path)?;
        if idx + 1 >= records.len() {
            return Err("Index out of bounds".to_string());
        }
        records.swap(idx, idx + 1);
        Self::write_raw_records(path, &records)
    }

    /// Duplicate a record in-place.
    pub fn duplicate_record(path: &Path, idx: usize) -> Result<(), String> {
        let (mut records, _) = Self::parse_raw_records(path)?;
        if idx >= records.len() {
            return Err("Index out of bounds".to_string());
        }
        let dup = records[idx].clone();
        records.insert(idx + 1, dup);
        Self::write_raw_records(path, &records)
    }

    /// Chop last N records from journal tail.
    pub fn chop_tail_records(path: &Path, count: usize) -> Result<(), String> {
        let (mut records, _) = Self::parse_raw_records(path)?;
        for _ in 0..count {
            records.pop();
        }
        Self::write_raw_records(path, &records)
    }

    /// Re-sign all records with an attack signing key (L3 attack test).
    pub fn re_sign_with_attack_key(path: &Path, attack_key: &SigningKey) -> Result<(), String> {
        let (mut records, _) = Self::parse_raw_records(path)?;
        let mut prev_hash = [0u8; 32];

        for r in records.iter_mut() {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&r.body_bytes);
            hasher.update(&prev_hash);
            r.stored_hash = *hasher.finalize().as_bytes();

            let mut msg = Vec::with_capacity(r.body_bytes.len() + 32);
            msg.extend_from_slice(&r.body_bytes);
            msg.extend_from_slice(&prev_hash);
            let sig = attack_key.sign(&msg);
            r.stored_sig = Some(sig.to_bytes());

            prev_hash = r.stored_hash;
        }

        Self::write_raw_records(path, &records)
    }
}
