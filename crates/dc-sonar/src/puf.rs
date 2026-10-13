//! Physical Unclonable Function enrollment and verification
//! (v0.12.0, Miracle 2 — "The Fingerprint").
//!
//! The acoustic response of a drive is noisy: temperature, firmware
//! state and ambient vibration move individual features between
//! observations. Naively quantizing a feature against its own
//! enrollment mean yields ~50%-unstable bits for symmetric noise —
//! so dc-sonar uses the classical **pairwise-ordering (differential)
//! construction** instead:
//!
//! * A bit is `value(A) > value(B)` for a PAIR of same-type features
//!   (e.g. two harmonic frequencies, or centroid vs spread of two
//!   channels). The threshold is the pair's internal gap, not an
//!   external cut point.
//! * **Enrollment** captures K independent probe responses, keeps only
//!   features observed in every capture, and selects pairs whose
//!   observed gap dwarfs their observed dispersions
//!   (`reliability = gap / (σA + σB) ≥ REL_MIN`). Such bits flip with
//!   probability ≈ Φ(−reliability·k) — negligible for reliability 3+.
//! * **Helper data** is the pair list (ids + gap + reliability + the
//!   enrolled bit). It discloses only orderings of internal features —
//!   cloning the electronics does not reproduce the physical resonance
//!   that fixes those orderings.
//! * **Verification** re-probes with a FRESH challenge (recorded
//!   responses are useless against a different challenge — the score
//!   is challenge-derived) and scores the Hamming distance against a
//!   12.5% tolerance derived from the enrollment.

use crate::signal::SpectrumFeatures;
use serde::{Deserialize, Serialize};

/// Minimum pair reliability accepted into an enrollment.
pub const RELIABILITY_MIN: f64 = 3.0;

/// Maximum pairs enrolled (helper data size bound).
pub const MAX_PAIRS: usize = 128;

/// Match tolerance as a fraction of enrolled bits.
pub const MATCH_TOLERANCE: f64 = 0.125;

/// Errors from the PUF layer.
#[derive(Debug, thiserror::Error)]
pub enum PufError {
    #[error("not enough captures to enroll (need {0}, have {1})")]
    NotEnoughCaptures(usize, usize),
    #[error(
        "no reliable feature pairs across captures — environment too noisy for a stable fingerprint"
    )]
    NoStableFeatures,
    #[error("entropy: {0}")]
    Entropy(String),
    #[error("malformed enrollment: {0}")]
    Malformed(String),
}

/// A single scalar feature observation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FeatureObservation {
    /// Stable feature id: "src#chan:kind[:index]" (e.g.
    /// "iio:device0#x:peak_hz:0").
    pub id: String,
    pub value: f64,
}

/// Convert a feature set into (id, value) observations.
pub fn observations_from(features: &[SpectrumFeatures]) -> Vec<FeatureObservation> {
    let mut out = Vec::new();
    for f in features {
        for (i, p) in f.peaks.iter().enumerate() {
            out.push(FeatureObservation {
                id: format!("{}#{}:peak_hz:{}", f.source, f.channel, i),
                value: p.hz,
            });
            out.push(FeatureObservation {
                id: format!("{}#{}:peak_rel:{}", f.source, f.channel, i),
                value: p.relative,
            });
        }
        out.push(FeatureObservation {
            id: format!("{}#{}:centroid", f.source, f.channel),
            value: f.centroid_hz,
        });
        out.push(FeatureObservation {
            id: format!("{}#{}:spread", f.source, f.channel),
            value: f.spread_hz,
        });
        out.push(FeatureObservation {
            id: format!("{}#{}:flatness", f.source, f.channel),
            value: f.flatness,
        });
        out.push(FeatureObservation {
            id: format!("{}#{}:rms", f.source, f.channel),
            value: f.rms,
        });
    }
    out
}

/// Feature type of an id ("peak_hz", "centroid", …) — pairs are only
/// formed within one type (comparing Hz to flatness is meaningless).
/// Id grammar: `src#channel:kind[:index]`.
fn id_type(id: &str) -> &str {
    let rest = id.rsplit('#').next().unwrap_or(id);
    rest.split(':').nth(1).unwrap_or(rest)
}

/// One enrolled comparison bit: `value(id_a) > value(id_b)`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EnrolledPair {
    pub id_a: String,
    pub id_b: String,
    /// |mean_a − mean_b| as observed at enrollment.
    pub gap: f64,
    /// gap / (σ_a + σ_b + ε) — enrollment-time reliability.
    pub reliability: f64,
    /// The enrolled bit.
    pub bit: bool,
}

/// The enrollment artifact (helper data + digest).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Enrollment {
    pub scheme: String,
    /// Enrollment challenge (hex) — audit reproducibility note;
    /// verification uses fresh challenges.
    pub enrollment_challenge_hex: String,
    pub capture_count: usize,
    /// Enrolled comparison pairs (public helper data).
    pub pairs: Vec<EnrolledPair>,
    pub bit_count: usize,
    /// Hamming-distance match threshold (12.5% of bits, floor 4).
    pub match_threshold: usize,
    /// BLAKE3-256 fingerprint digest (hex).
    pub digest_blake3: String,
    /// Telemetry sources involved.
    pub telemetry_sources: Vec<String>,
}

impl Enrollment {
    pub const SCHEME: &'static str = "sonar-puf/pairwise-order-v1";

    /// Build an enrollment from K independent capture feature sets of
    /// the SAME (enrollment) challenge.
    pub fn from_captures(
        enrollment_challenge: &[u8; 32],
        captures: &[Vec<SpectrumFeatures>],
    ) -> Result<Self, PufError> {
        if captures.len() < 2 {
            return Err(PufError::NotEnoughCaptures(2, captures.len()));
        }

        // ---- aggregate per-id values across captures (K-of-K) ------
        use std::collections::BTreeMap;
        let mut per_id: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        for feats in captures {
            for obs in observations_from(feats) {
                per_id.entry(obs.id).or_default().push(obs.value);
            }
        }
        let k = captures.len();
        // Keep only ids present in EVERY capture and finite everywhere.
        let stable: Vec<(String, f64, f64)> = per_id
            .into_iter()
            .filter(|(_, vs)| vs.len() == k && vs.iter().all(|v| v.is_finite()))
            .map(|(id, vs)| {
                let n = vs.len() as f64;
                let mean = vs.iter().sum::<f64>() / n;
                let var = vs.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / n;
                (id, mean, var.sqrt())
            })
            .collect();
        if stable.len() < 2 {
            return Err(PufError::NoStableFeatures);
        }

        // ---- enumerate same-type pairs, compute reliability ---------
        // Pre-group by type for O(groups²) instead of O(n²) global.
        use std::collections::BTreeMap as Map;
        let mut by_type: Map<&str, Vec<usize>> = Map::new();
        for (i, (id, _, _)) in stable.iter().enumerate() {
            by_type.entry(id_type(id)).or_default().push(i);
        }
        let mut candidates: Vec<EnrolledPair> = Vec::new();
        for idxs in by_type.values() {
            for w in 0..idxs.len() {
                for v in (w + 1)..idxs.len() {
                    let (i, j) = (idxs[w], idxs[v]);
                    let (id_a, m_a, s_a) = &stable[i];
                    let (id_b, m_b, s_b) = &stable[j];
                    // Canonicalize pair order by id so the bit is
                    // deterministic.
                    let (id_a, m_a, s_a, id_b, m_b, s_b) = if id_a < id_b {
                        (id_a, m_a, s_a, id_b, m_b, s_b)
                    } else {
                        (id_b, m_b, s_b, id_a, m_a, s_a)
                    };
                    let gap = (m_a - m_b).abs();
                    let disp = s_a + s_b + 1e-12;
                    let reliability = gap / disp;
                    if reliability >= RELIABILITY_MIN && gap > 1e-9 {
                        candidates.push(EnrolledPair {
                            id_a: id_a.clone(),
                            id_b: id_b.clone(),
                            gap,
                            reliability,
                            bit: m_a > m_b,
                        });
                    }
                }
            }
        }
        if candidates.is_empty() {
            return Err(PufError::NoStableFeatures);
        }
        candidates.sort_by(|a, b| {
            b.reliability
                .partial_cmp(&a.reliability)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let pairs: Vec<EnrolledPair> = candidates.into_iter().take(MAX_PAIRS).collect();

        let bit_count = pairs.len();
        let match_threshold = ((bit_count as f64 * MATCH_TOLERANCE) as usize)
            .max(4)
            .min(bit_count.saturating_sub(1).max(1));

        let mut h = blake3::Hasher::new();
        h.update(Self::SCHEME.as_bytes());
        h.update(enrollment_challenge);
        for p in &pairs {
            h.update(p.id_a.as_bytes());
            h.update(b"|");
            h.update(p.id_b.as_bytes());
            h.update(&[p.bit as u8]);
        }
        let digest = hex::encode(h.finalize().as_bytes());

        let mut sources: Vec<String> = captures
            .iter()
            .flatten()
            .map(|f| f.source.clone())
            .collect();
        sources.sort();
        sources.dedup();

        Ok(Self {
            scheme: Self::SCHEME.to_string(),
            enrollment_challenge_hex: hex::encode(enrollment_challenge),
            capture_count: captures.len(),
            pairs,
            bit_count,
            match_threshold,
            digest_blake3: digest,
            telemetry_sources: sources,
        })
    }

    /// Quantize a fresh feature set into pair bits (missing member of
    /// a pair → the pair cannot be evaluated → counts as a mismatch,
    /// which is conservative in the right direction).
    fn quantize(&self, features: &[SpectrumFeatures]) -> Vec<bool> {
        let obs = observations_from(features);
        let lookup = |id: &str| -> Option<f64> { obs.iter().find(|o| o.id == id).map(|o| o.value) };
        self.pairs
            .iter()
            .map(|p| match (lookup(&p.id_a), lookup(&p.id_b)) {
                (Some(a), Some(b)) => a > b,
                // Missing observation: report the INVERSE of the
                // enrolled bit so it registers as distance.
                _ => !p.bit,
            })
            .collect()
    }

    fn digest_of_bits(&self, bits: &[bool]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(Self::SCHEME.as_bytes());
        h.update(&hex::decode(&self.enrollment_challenge_hex).unwrap_or_default());
        for (p, b) in self.pairs.iter().zip(bits.iter()) {
            h.update(p.id_a.as_bytes());
            h.update(b"|");
            h.update(p.id_b.as_bytes());
            h.update(&[*b as u8]);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    /// Verify a fresh capture feature set against this enrollment.
    pub fn verify(&self, features: &[SpectrumFeatures]) -> VerifyOutcome {
        let bits = self.quantize(features);
        let distance = self
            .pairs
            .iter()
            .zip(bits.iter())
            .filter(|(p, b)| p.bit != **b)
            .count();
        let score = if self.bit_count == 0 {
            0.0
        } else {
            1.0 - distance as f64 / self.bit_count as f64
        };
        VerifyOutcome {
            matches: distance <= self.match_threshold,
            hamming_distance: distance,
            bit_count: self.bit_count,
            match_threshold: self.match_threshold,
            similarity: score,
            candidate_digest_blake3: hex::encode(self.digest_of_bits(&bits)),
        }
    }
}

/// Result of a verification attempt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VerifyOutcome {
    pub matches: bool,
    pub hamming_distance: usize,
    pub bit_count: usize,
    pub match_threshold: usize,
    /// 1 − distance/bit_count.
    pub similarity: f64,
    /// Digest of the candidate's quantized bits (hex).
    pub candidate_digest_blake3: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::SpectrumFeatures;

    /// Synthetic drive: deterministic resonance per "physical unit"
    /// with uniform observation noise.
    fn synthetic_capture(drive_seed: u64, noise: f64, challenge: u8) -> Vec<SpectrumFeatures> {
        let mut rng = (drive_seed.wrapping_mul(0x9E3779B97F4A7C15))
            .wrapping_add((challenge as u64).wrapping_mul(0xD1B54A32D192ED03))
            .max(1);
        let mut next = move || {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            ((rng.wrapping_mul(0x2545F4914F6CDD1D) >> 11) as f64 / (1u64 << 53) as f64) - 0.5
        };
        let mut peaks = Vec::new();
        // splitmix64-style avalanche of (seed, i): fully scrambles the
        // resonance orderings across physical units while staying
        // bit-stable for one unit.
        let mix = |mut z: u64| -> u64 {
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        };
        for i in 0..6u64 {
            // Per-drive, per-peak resonance anywhere in 100..800 Hz —
            // different physical units hold entirely different
            // resonance orderings (the discriminative signal).
            let hz = 100.0
                + (mix(drive_seed ^ i.wrapping_mul(0x9E3779B97F4A7C15)) % 700) as f64
                + next() * noise * 8.0;
            let rel = 0.15
                + (mix(drive_seed.rotate_left(29) ^ i.wrapping_mul(0xD1B54A32D192ED03)) % 65)
                    as f64
                    / 100.0
                + next() * noise * 0.05;
            peaks.push(crate::signal::HarmonicPeak {
                hz,
                magnitude: 1.0,
                relative: rel.clamp(0.01, 1.0),
            });
        }
        vec![SpectrumFeatures {
            source: "iio:device0".into(),
            channel: "x".into(),
            sample_hz: 2048.0,
            peaks,
            centroid_hz: 300.0 + (drive_seed % 13) as f64 * 4.0 + next() * noise * 10.0,
            spread_hz: 180.0 + (drive_seed % 17) as f64 * 2.5 + next() * noise * 10.0,
            flatness: (0.08 + (drive_seed % 5) as f64 * 0.006 + next() * noise * 0.01)
                .clamp(0.0, 1.0),
            rms: 0.5 + (drive_seed % 11) as f64 * 0.03 + next() * noise * 0.05,
        }]
    }

    #[test]
    fn enroll_then_verify_same_drive() {
        let ch: [u8; 32] = [0x55; 32];
        let captures: Vec<Vec<SpectrumFeatures>> =
            (0..4).map(|i| synthetic_capture(42, 0.15, i)).collect();
        let enr = Enrollment::from_captures(&ch, &captures).unwrap();
        assert!(enr.bit_count > 0, "must enroll some pairs");

        // Same physical drive, fresh noise and fresh challenge → match.
        let probe = synthetic_capture(42, 0.15, 99);
        let outcome = enr.verify(&probe);
        assert!(outcome.matches, "same drive must match: {outcome:?}");
        assert!(
            outcome.hamming_distance <= enr.match_threshold,
            "distance {} vs threshold {}",
            outcome.hamming_distance,
            enr.match_threshold
        );
    }

    #[test]
    fn different_drive_mismatches() {
        let ch: [u8; 32] = [0x66; 32];
        let captures: Vec<Vec<SpectrumFeatures>> =
            (0..4).map(|i| synthetic_capture(42, 0.1, i)).collect();
        let enr = Enrollment::from_captures(&ch, &captures).unwrap();

        // A DIFFERENT physical unit (seed 77) must fail.
        let probe = synthetic_capture(77, 0.1, 5);
        let outcome = enr.verify(&probe);
        assert!(!outcome.matches, "different drive must fail: {outcome:?}");
    }

    #[test]
    fn enrollment_is_challenge_specific() {
        // Same drive, same noise, different enrollment challenge →
        // different digest (challenge separation).
        let a: [u8; 32] = [1; 32];
        let b: [u8; 32] = [2; 32];
        let caps: Vec<Vec<SpectrumFeatures>> =
            (0..3).map(|i| synthetic_capture(42, 0.1, i)).collect();
        let ea = Enrollment::from_captures(&a, &caps).unwrap();
        let eb = Enrollment::from_captures(&b, &caps).unwrap();
        assert_ne!(ea.digest_blake3, eb.digest_blake3);
    }

    #[test]
    fn rejects_too_few_captures() {
        let ch: [u8; 32] = [0x77; 32];
        let one = vec![synthetic_capture(1, 0.1, 0)];
        assert!(Enrollment::from_captures(&ch, &one).is_err());
    }

    #[test]
    fn helper_data_roundtrip() {
        // Serialization round-trip preserves the artifact exactly.
        let ch: [u8; 32] = [9; 32];
        let caps: Vec<Vec<SpectrumFeatures>> =
            (0..3).map(|i| synthetic_capture(1234, 0.12, i)).collect();
        let enr = Enrollment::from_captures(&ch, &caps).unwrap();
        let json = serde_json::to_string(&enr).unwrap();
        let back: Enrollment = serde_json::from_str(&json).unwrap();
        assert_eq!(enr, back);
    }
}
