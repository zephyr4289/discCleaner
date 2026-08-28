use dc_cert::{KeyringEntry, KeyringRegistry};

pub struct KeyLifecycleVerbs;

impl KeyLifecycleVerbs {
    /// Register a newly generated key into the keyring registry (Δ450, Δ453).
    pub fn register_generated_key(
        registry: &mut KeyringRegistry,
        key_hash: &str,
        identity: &str,
        role: &str,
        timestamp_utc: u64,
    ) {
        registry.register_key(KeyringEntry {
            key_hash: key_hash.to_string(),
            identity: identity.to_string(),
            role: role.to_string(),
            active_from_utc: timestamp_utc,
            superseded_at_utc: None,
            revoked_at_utc: None,
        });
    }

    /// Rotate an existing key to a new key entry bilaterally (Δ450, Δ453).
    pub fn rotate_key(
        registry: &mut KeyringRegistry,
        old_key_hash: &str,
        new_key_entry: KeyringEntry,
        timestamp_utc: u64,
    ) -> Result<(), &'static str> {
        registry.rotate_key_bilateral(old_key_hash, new_key_entry, timestamp_utc)
    }

    /// Revoke a compromised or retired key (Δ452, Δ453).
    pub fn revoke_key(
        registry: &mut KeyringRegistry,
        key_hash: &str,
        timestamp_utc: u64,
    ) -> Result<(), &'static str> {
        registry.revoke_key(key_hash, timestamp_utc)
    }
}
