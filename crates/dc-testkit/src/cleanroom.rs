use crate::chacha_ref::ChaCha20Ref;
use std::path::Path;

pub struct CleanroomPRNG;

impl CleanroomPRNG {
    /// Fill buffer for a given window index using the Δ55 normative recipe.
    pub fn fill_window(seed: &[u8; 32], window_idx: u64, buf: &mut [u8]) {
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&window_idx.to_le_bytes());
        nonce[8..12].copy_from_slice(&[0, 0, 0, 0]);

        buf.fill(0);
        let mut cipher = ChaCha20Ref::new(seed, &nonce, 0);
        cipher.apply_keystream(buf);
    }

    /// Compute full disk BLAKE3 stream hash across all windows.
    pub fn compute_stream_digest(
        seed: &[u8; 32],
        total_size_bytes: u64,
        window_bytes: u64,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        let total_windows = (total_size_bytes + window_bytes - 1) / window_bytes;

        let mut buf = vec![0u8; window_bytes as usize];

        for w in 0..total_windows {
            let win_start = w * window_bytes;
            let win_len = ((total_size_bytes - win_start) as usize).min(window_bytes as usize);

            Self::fill_window(seed, w, &mut buf[..win_len]);
            hasher.update(&buf[..win_len]);
        }

        hasher.finalize().to_hex().to_string()
    }

    /// Validate a certificate file against cleanroom reproduction.
    pub fn verify_certificate_reproduction(cert_path: &Path) -> Result<bool, String> {
        let content = std::fs::read_to_string(cert_path).map_err(|e| e.to_string())?;
        let cert_json: serde_json::Value = serde_json::from_str(&content).map_err(|e| e.to_string())?;

        let scheme = cert_json
            .pointer("/plan/mechanism/passes/0/pattern/DeterministicRandom/scheme")
            .and_then(|v| v.as_str())
            .or_else(|| {
                cert_json.pointer("/plan/mechanism/passes/1/pattern/DeterministicRandom/scheme").and_then(|v| v.as_str())
            })
            .ok_or_else(|| "Missing DeterministicRandom scheme in certificate".to_string())?;

        if scheme != "chacha20-window-v1" && scheme != "ChaCha20WindowV1" {
            return Err(format!("UNKNOWN_SCHEME: {}", scheme));
        }

        let seed_hex = cert_json
            .pointer("/plan/mechanism/passes/0/pattern/DeterministicRandom/seed")
            .and_then(|v| v.as_str())
            .or_else(|| {
                cert_json.pointer("/plan/mechanism/passes/1/pattern/DeterministicRandom/seed").and_then(|v| v.as_str())
            })
            .ok_or_else(|| "Missing seed in certificate".to_string())?;

        let seed_bytes = hex::decode(seed_hex).map_err(|e| format!("Invalid seed hex: {}", e))?;
        if seed_bytes.len() != 32 {
            return Err("Invalid seed length".to_string());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        let size_bytes = cert_json
            .pointer("/device/capacity_bytes")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "Missing capacity_bytes in cert".to_string())?;

        let window_bytes = cert_json
            .pointer("/plan/window_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(2 * 1024 * 1024);

        let expected_hash = cert_json
            .pointer("/verification/stream_hash_blake3")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing stream_hash_blake3 in cert".to_string())?;

        let calculated_hash = Self::compute_stream_digest(&seed, size_bytes, window_bytes);

        if calculated_hash == expected_hash {
            Ok(true)
        } else {
            Err(format!(
                "Reproduction hash mismatch! Computed: {}, Cert: {}",
                calculated_hash, expected_hash
            ))
        }
    }
}
