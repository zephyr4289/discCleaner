use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct AuditOracle;

impl AuditOracle {
    pub fn parse_and_validate(path: &Path) -> Result<Vec<serde_json::Value>, String> {
        let mut file = File::open(path).map_err(|e| format!("Failed to open audit log {}: {}", path.display(), e))?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)
            .map_err(|e| format!("Failed to read audit magic: {}", e))?;

        if &magic != b"DCA1" {
            return Err(format!("Invalid audit log magic: {:?}", magic));
        }

        let mut prev_hash = [0u8; 32];
        let mut records = Vec::new();
        let mut idx = 0;

        loop {
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("Error reading audit len #{}: {}", idx, e)),
            }

            let len = u32::from_le_bytes(len_buf) as usize;
            let mut record_bytes = vec![0u8; len];
            file.read_exact(&mut record_bytes)
                .map_err(|e| format!("Error reading audit body #{}: {}", idx, e))?;

            let mut stored_hash = [0u8; 32];
            file.read_exact(&mut stored_hash)
                .map_err(|e| format!("Error reading audit hash #{}: {}", idx, e))?;

            let mut hasher = blake3::Hasher::new();
            hasher.update(&record_bytes);
            hasher.update(&prev_hash);
            let calculated_hash = hasher.finalize();

            if calculated_hash.as_bytes() != &stored_hash {
                return Err(format!(
                    "Audit log hash mismatch at record #{}: computed {}, stored {}",
                    idx,
                    calculated_hash.to_hex(),
                    hex::encode(stored_hash)
                ));
            }

            let json: serde_json::Value = serde_json::from_slice(&record_bytes)
                .map_err(|e| format!("Invalid JSON at audit record #{}: {}", idx, e))?;

            prev_hash = stored_hash;
            records.push(json);
            idx += 1;
        }

        Ok(records)
    }
}
