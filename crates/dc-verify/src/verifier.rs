use crate::entropy::{EntropyCalculator, EntropyDiag};
use dc_core::{DcError, VerifyLevel};
use dc_io::VerifySink;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VerificationReport {
    pub level: VerifyLevel,
    pub windows_checked: u64,
    pub mismatch_count: u64,
    pub first_mismatch_lbas: Vec<u64>,
    pub stream_hash_blake3: String,
    pub stream_hash_sha256: Option<String>,
    pub entropy: Option<EntropyDiag>,
}

pub struct StreamVerifier {
    level: VerifyLevel,
    window_bytes: u64,
    logical_block_size: u32,
    enable_sha256: bool,
    enable_entropy: bool,
    blake3_hasher: blake3::Hasher,
    sha256_hasher: Option<Sha256>,
    entropy_calc: Option<EntropyCalculator>,
    windows_checked: u64,
    mismatch_count: u64,
    first_mismatch_lbas: Vec<u64>,
}

impl StreamVerifier {
    pub fn new(
        level: VerifyLevel,
        window_bytes: u64,
        logical_block_size: u32,
        enable_sha256: bool,
        enable_entropy: bool,
    ) -> Self {
        Self {
            level,
            window_bytes,
            logical_block_size: logical_block_size.max(512),
            enable_sha256,
            enable_entropy,
            blake3_hasher: blake3::Hasher::new(),
            sha256_hasher: if enable_sha256 { Some(Sha256::new()) } else { None },
            entropy_calc: if enable_entropy {
                Some(EntropyCalculator::new())
            } else {
                None
            },
            windows_checked: 0,
            mismatch_count: 0,
            first_mismatch_lbas: Vec::new(),
        }
    }

    pub fn finalize(self) -> VerificationReport {
        let b3_digest = self.blake3_hasher.finalize();
        let sha256_digest = self.sha256_hasher.map(|h| hex::encode(h.finalize()));
        let entropy = self.entropy_calc.and_then(|e| e.finalize());

        VerificationReport {
            level: self.level,
            windows_checked: self.windows_checked,
            mismatch_count: self.mismatch_count,
            first_mismatch_lbas: self.first_mismatch_lbas,
            stream_hash_blake3: b3_digest.to_hex().to_string(),
            stream_hash_sha256: sha256_digest,
            entropy,
        }
    }
}

impl VerifySink for StreamVerifier {
    fn on_window(&mut self, window_index: u64, is_valid: bool, data: &[u8]) -> Result<(), DcError> {
        self.windows_checked += 1;

        if !is_valid {
            self.mismatch_count += 1;
            if self.first_mismatch_lbas.len() < 64 {
                let lba = (window_index * self.window_bytes) / self.logical_block_size as u64;
                self.first_mismatch_lbas.push(lba);
            }
        }

        // In-order streaming hash
        self.blake3_hasher.update(data);
        if let Some(sha) = &mut self.sha256_hasher {
            sha.update(data);
        }

        // Entropy diagnostic
        if let Some(entropy) = &mut self.entropy_calc {
            entropy.update(data);
        }

        Ok(())
    }
}
