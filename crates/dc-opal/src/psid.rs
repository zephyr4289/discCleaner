use std::fmt;

pub struct PsidSecret {
    bytes: Vec<u8>,
}

impl PsidSecret {
    /// Load PSID secret into memory (Δ367).
    pub fn load_from_slice(raw: &[u8]) -> Self {
        Self {
            bytes: raw.to_vec(),
        }
    }

    /// Compute cryptographic BLAKE3 hash of the PSID secret (the only value allowed in logs/evidence).
    pub fn compute_hash(&self) -> String {
        blake3::hash(&self.bytes).to_hex().to_string()
    }

    /// Access inner slice (internal use only).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for PsidSecret {
    fn drop(&mut self) {
        // Enforce volatile memory zeroization on Drop (Δ367)
        for b in self.bytes.iter_mut() {
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

impl fmt::Debug for PsidSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PsidSecret(hash={})", self.compute_hash())
    }
}
