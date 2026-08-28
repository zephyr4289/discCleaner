use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringEntry {
    pub key_hash: String,
    pub identity: String,
    pub role: String,
    pub active_from_utc: u64,
    pub superseded_at_utc: Option<u64>,
    pub revoked_at_utc: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringRegistry {
    pub schema: String, // "dc-keyring/1"
    pub entries: Vec<KeyringEntry>,
}

impl KeyringRegistry {
    pub fn new() -> Self {
        Self {
            schema: "dc-keyring/1".to_string(),
            entries: Vec::new(),
        }
    }

    pub fn register_key(&mut self, entry: KeyringEntry) {
        self.entries.push(entry);
    }

    /// Bilateral rotation: old key is superseded at timestamp T and new key begins active window (Δ450).
    pub fn rotate_key_bilateral(
        &mut self,
        old_key_hash: &str,
        mut new_entry: KeyringEntry,
        timestamp_utc: u64,
    ) -> Result<(), &'static str> {
        let old = self
            .entries
            .iter_mut()
            .find(|e| e.key_hash == old_key_hash)
            .ok_or("OLD_KEY_NOT_FOUND_IN_KEYRING")?;

        old.superseded_at_utc = Some(timestamp_utc);
        new_entry.active_from_utc = timestamp_utc;
        self.entries.push(new_entry);
        Ok(())
    }

    /// Revocation at-or-after T: future signatures become suspect, historical anchored past stands (Δ452).
    pub fn revoke_key(&mut self, key_hash: &str, timestamp_utc: u64) -> Result<(), &'static str> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.key_hash == key_hash)
            .ok_or("KEY_NOT_FOUND_IN_KEYRING")?;

        entry.revoked_at_utc = Some(timestamp_utc);
        Ok(())
    }

    /// Evaluate signature validity at time (Δ451, Δ452).
    pub fn evaluate_signature_at_time(
        &self,
        key_hash: &str,
        signed_at_utc: u64,
    ) -> Result<&'static str, &'static str> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.key_hash == key_hash)
            .ok_or("KEY_UNKNOWN_IN_REGISTRY")?;

        // 1. If key was revoked, check if signature was generated post-revocation
        if let Some(rev_t) = entry.revoked_at_utc {
            if signed_at_utc >= rev_t {
                return Ok("SUSPECT_REVOKED_KEY");
            }
        }

        // 2. Check if key was active at signed time
        if signed_at_utc < entry.active_from_utc {
            return Err("SIGNATURE_PRIOR_TO_KEY_ACTIVATION");
        }

        Ok("VALID_AT_TIME")
    }
}
