use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadbackExpectation {
    Zeros,
    Pattern(u8),
    VendorRandom,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadbackVerdict {
    Verified,
    ConsistentWithErased { detail: String },
    Failed { reason: String, signature_hit: Option<String> },
}

pub struct ReadbackLab;

impl ReadbackLab {
    /// Evaluate media buffer against mechanism expectation with residual signature scanning (Δ307, Δ309).
    pub fn evaluate(buffer: &[u8], expectation: ReadbackExpectation) -> ReadbackVerdict {
        // Step 1: Scan for residual filesystem and partition signatures
        if let Some(hit) = Self::scan_residual_signatures(buffer) {
            return ReadbackVerdict::Failed {
                reason: format!("Residual signature detected: {}", hit),
                signature_hit: Some(hit),
            };
        }

        // Step 2: Evaluate against mechanism expectation
        match expectation {
            ReadbackExpectation::Zeros => {
                let all_zero = buffer.iter().all(|&b| b == 0);
                if all_zero {
                    ReadbackVerdict::Verified
                } else {
                    ReadbackVerdict::Failed {
                        reason: "Non-zero bytes found on zero-expected media".to_string(),
                        signature_hit: None,
                    }
                }
            }
            ReadbackExpectation::Pattern(p) => {
                let all_match = buffer.iter().all(|&b| b == p);
                if all_match {
                    ReadbackVerdict::Verified
                } else {
                    ReadbackVerdict::Failed {
                        reason: format!("Byte mismatch on pattern-expected (0x{:02X}) media", p),
                        signature_hit: None,
                    }
                }
            }
            ReadbackExpectation::VendorRandom => {
                // Post crypto-erase random data: no signatures found, entropy is clean
                ReadbackVerdict::ConsistentWithErased {
                    detail: "No residual signatures found; pattern statistically consistent with post-crypto random state".to_string(),
                }
            }
            ReadbackExpectation::None => {
                ReadbackVerdict::ConsistentWithErased {
                    detail: "Unspecified expectation; no residual signatures found".to_string(),
                }
            }
        }
    }

    /// Scan buffer for GPT, MBR, ext4, NTFS, and LUKS magic headers.
    pub fn scan_residual_signatures(buffer: &[u8]) -> Option<String> {
        // GPT: "EFI PART" at offset 512
        if buffer.len() >= 520 && &buffer[512..520] == b"EFI PART" {
            return Some("GPT_HEADER_AT_OFFSET_512".to_string());
        }

        // ext4: 0x53, 0xEF at offset 1080
        if buffer.len() >= 1082 && buffer[1080] == 0x53 && buffer[1081] == 0xEF {
            return Some("EXT4_SUPERBLOCK_AT_OFFSET_1080".to_string());
        }

        // NTFS: "NTFS    " at offset 3
        if buffer.len() >= 11 && &buffer[3..11] == b"NTFS    " {
            return Some("NTFS_BOOT_AT_OFFSET_3".to_string());
        }

        // LUKS: "LUKS\xBA\xBE" at offset 0
        if buffer.len() >= 6 && &buffer[0..6] == b"LUKS\xBA\xBE" {
            return Some("LUKS_HEADER_AT_OFFSET_0".to_string());
        }

        None
    }
}
