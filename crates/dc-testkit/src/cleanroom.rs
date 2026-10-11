use crate::chacha_ref::ChaCha20Ref;
use crate::recipe::ReproductionRecipe;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedPointEntropy {
    pub shannon_entropy_x1e6: u64, // Shannon entropy scaled by 1,000,000 (e.g. 7.999990 -> 7999990)
    pub chi_square_x1e6: u64,      // Chi-square test statistic scaled by 1,000,000
}

pub struct CleanroomPRNG;

impl CleanroomPRNG {
    /// Fill buffer for a given window index using the Δ55/Δ157 normative recipe.
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
        let total_windows = total_size_bytes.div_ceil(window_bytes);

        let mut buf = vec![0u8; window_bytes as usize];

        for w in 0..total_windows {
            let win_start = w * window_bytes;
            let win_len = ((total_size_bytes - win_start) as usize).min(window_bytes as usize);

            Self::fill_window(seed, w, &mut buf[..win_len]);
            hasher.update(&buf[..win_len]);
        }

        hasher.finalize().to_hex().to_string()
    }

    /// Compute fixed-point Shannon entropy and Chi-square statistics (Δ159).
    pub fn compute_fixed_point_entropy(data: &[u8]) -> FixedPointEntropy {
        if data.is_empty() {
            return FixedPointEntropy {
                shannon_entropy_x1e6: 0,
                chi_square_x1e6: 0,
            };
        }

        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }

        let n = data.len() as f64;
        let mut shannon = 0.0f64;
        let expected = n / 256.0;
        let mut chi_square = 0.0f64;

        for &c in &counts {
            if c > 0 {
                let p = (c as f64) / n;
                shannon -= p * p.log2();
            }
            let diff = (c as f64) - expected;
            chi_square += (diff * diff) / expected;
        }

        FixedPointEntropy {
            shannon_entropy_x1e6: (shannon * 1_000_000.0).round() as u64,
            chi_square_x1e6: (chi_square * 1_000_000.0).round() as u64,
        }
    }

    /// BLAKE3 of the canonical reproduction contract document, as embedded in
    /// this test kit. Rigs compare this against the on-disk file to prove the
    /// deployed document and the cleanroom build agree (Δ157).
    pub fn doc_blake3() -> String {
        let doc_text = include_str!("../../../docs/reproduction/chacha20-window-v1.txt");
        blake3::hash(doc_text.as_bytes()).to_hex().to_string()
    }

    /// Verify a ReproductionRecipe directly against cleanroom reconstruction (Δ155).
    pub fn verify_recipe(recipe: &ReproductionRecipe) -> Result<bool, String> {
        if recipe.scheme != "chacha20-window-v1" {
            return Err(format!("UNKNOWN_SCHEME: {}", recipe.scheme));
        }

        let doc_text = include_str!("../../../docs/reproduction/chacha20-window-v1.txt");
        let expected_doc_blake3 = blake3::hash(doc_text.as_bytes()).to_hex().to_string();

        if recipe.doc_blake3 != expected_doc_blake3 {
            return Err(format!(
                "DOC_HASH_MISMATCH: Recipe was built under doc {}, expected {}",
                recipe.doc_blake3, expected_doc_blake3
            ));
        }

        let seed_bytes =
            hex::decode(&recipe.seed).map_err(|e| format!("Invalid seed hex: {}", e))?;
        if seed_bytes.len() != 32 {
            return Err("Invalid seed length (must be 32 bytes)".to_string());
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        let calculated_hash =
            Self::compute_stream_digest(&seed, recipe.device_bytes, recipe.window_bytes);

        if calculated_hash == recipe.stream_hash_blake3 {
            Ok(true)
        } else {
            Err(format!(
                "STREAM_HASH_MISMATCH: Calculated {}, Recipe {}",
                calculated_hash, recipe.stream_hash_blake3
            ))
        }
    }

    /// Certificate-only cleanroom reproduction (A2 Moat, Δ161).
    ///
    /// The independent auditor's oracle: given ONLY a certificate file,
    /// re-derive the entire media stream digest from the committed seed and
    /// geometry, and compare against the certificate's attested
    /// `verification.stream_hash_blake3`. A valid certificate must yield
    /// `Ok(true)`; any tampering with the seed must yield
    /// `Err(STREAM_HASH_MISMATCH)`; an unrecognized PRNG scheme must yield
    /// `Err(UNKNOWN_SCHEME: ...)`.
    pub fn verify_certificate_reproduction(cert_path: &Path) -> Result<bool, String> {
        let content = std::fs::read_to_string(cert_path)
            .map_err(|e| format!("Failed to read certificate {}: {}", cert_path.display(), e))?;
        let root: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid certificate JSON: {}", e))?;

        // Locate the DeterministicRandom pass (internally tagged: variant
        // fields are flattened into the pattern object).
        let passes = root
            .pointer("/plan/mechanism/passes")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "NO_PASSES_IN_PLAN: plan.mechanism.passes missing".to_string())?;

        let mut seed_hex: Option<String> = None;
        let mut scheme: Option<String> = None;
        for p in passes {
            let pat = p
                .get("pattern")
                .ok_or("PASS_MISSING_PATTERN: pass has no pattern object")?;
            if pat.get("type").and_then(|v| v.as_str()) == Some("deterministic_random") {
                seed_hex = Some(
                    pat.get("seed")
                        .and_then(|v| v.as_str())
                        .ok_or("PATTERN_MISSING_SEED: deterministic_random pattern lacks seed")?
                        .to_string(),
                );
                scheme = Some(
                    pat.get("scheme")
                        .and_then(|v| v.as_str())
                        .ok_or("PATTERN_MISSING_SCHEME: deterministic_random pattern lacks scheme")?
                        .to_string(),
                );
            }
        }

        let scheme = scheme.ok_or("NO_DETERMINISTIC_RANDOM_PASS: no reproducible pass in plan")?;
        if scheme != "chacha20-window-v1" {
            return Err(format!("UNKNOWN_SCHEME: {}", scheme));
        }

        let seed_hex =
            seed_hex.ok_or("NO_DETERMINISTIC_RANDOM_PASS: no reproducible pass in plan")?;
        let seed_bytes = hex::decode(&seed_hex)
            .map_err(|e| format!("Invalid seed hex in certificate: {}", e))?;
        if seed_bytes.len() != 32 {
            return Err("Invalid seed length (must be 32 bytes)".to_string());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        let device_bytes = root
            .pointer("/device/stable/size_bytes")
            .and_then(|v| v.as_u64())
            .ok_or("MISSING_DEVICE_SIZE: certificate lacks device.stable.size_bytes")?;
        let window_bytes = root
            .pointer("/plan/window_bytes")
            .and_then(|v| v.as_u64())
            .ok_or("MISSING_WINDOW_BYTES: certificate lacks plan.window_bytes")?;
        let expected_hash = root
            .pointer("/verification/stream_hash_blake3")
            .and_then(|v| v.as_str())
            .ok_or("MISSING_STREAM_HASH: certificate lacks verification.stream_hash_blake3")?
            .to_string();

        let calculated_hash = Self::compute_stream_digest(&seed, device_bytes, window_bytes);

        if calculated_hash == expected_hash {
            Ok(true)
        } else {
            Err(format!(
                "STREAM_HASH_MISMATCH: cleanroom re-derived {}, certificate attests {}",
                calculated_hash, expected_hash
            ))
        }
    }
}
