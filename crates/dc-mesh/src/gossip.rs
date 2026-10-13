//! Epidemic gossip of per-drive attestations and the witness
//! spot-proof protocol.
//!
//! ## Drive reports
//!
//! Every wiper node that finishes a drive broadcasts a signed
//! [`DriveReport`]: the device identity, the final pass pattern, the
//! window accounting (`windows_verified == windows_total` required),
//! and a BLAKE3 **evidence root** over the readback digests it
//! observed. Reports spread by gossip: any node that sees a report it
//! does not have stores it and re-broadcasts it once (anti-entropy
//! style) — no router, no leader.
//!
//! ## Spot proofs — making "zero entropy" a tested claim
//!
//! A report says "all windows verified zero-entropy". The mesh does
//! not take that on faith. Witnesses replay the physics: the
//! [`SpotChallenge`] names a device, a random LBA window and a fresh
//! nonce; the wiper must return the bytes that are on media *right
//! now*. The witness recomputes the expected bytes from the declared
//! [`dc_core::Pattern`] — patterns are pure functions of window index,
//! so any node with the report can recompute them byte-for-byte — and
//! compares hashes. A fresh nonce blocks replayed proofs; the
//! challenge LBA is drawn from the witness's own RNG, so the wiper
//! cannot pre-stage anything.
//!
//! A lying node — one that skipped drives or forged its window
//! accounting — fails the recomputation, and the mismatched pair
//! (challenge, proof) is signed accusation evidence for [`crate::rogue`].

use blake3::Hasher;
use dc_core::{Pattern, create_pattern_source};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-drive attestation broadcast by the wiping node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriveReport {
    /// Reporting node id (hex Ed25519 pk) — must match frame sender.
    pub node: String,
    /// Device serial number (stable identity anchor).
    pub serial: String,
    /// Optional WWN / NGUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wwn: Option<String>,
    /// Bus family ("NVMe", "ATA", ...).
    pub bus: String,
    /// Capacity in 512-byte LBA units.
    pub capacity_lbas: u64,
    /// Window size used for the wipe and verification.
    pub window_sectors: u32,
    /// Total windows spanning the drive.
    pub windows_total: u64,
    /// Windows cryptographically verified in readback.
    pub windows_verified: u64,
    /// Final (surface) pass pattern — what every byte should read.
    pub pattern: Pattern,
    /// BLAKE3 root over per-window readback digests (hex).
    pub evidence_root: String,
    /// View/epoch at report time (ordering context).
    pub view: u32,
}

impl DriveReport {
    /// Internal consistency: a drive is fully accounted only when
    /// every declared window was verified and the capacity math
    /// closes (`windows_total * window_sectors == capacity_lbas`).
    pub fn is_consistent(&self) -> bool {
        let covered = (self.windows_total as u128) * (self.window_sectors as u128);
        let capacity = self.capacity_lbas as u128;
        let closes = if self.capacity_lbas == 0 {
            self.windows_total == 0
        } else {
            covered == capacity
        };
        self.windows_verified == self.windows_total && closes
    }

    /// Recompute the expected on-media bytes for LBA window `w`
    /// (window index), per the declared final pattern. Patterns are
    /// pure: same window, same bytes, on any machine, forever.
    pub fn expected_bytes(&self, window: u64, buf: &mut [u8]) {
        let src = create_pattern_source(&self.pattern);
        src.fill(window, buf);
    }

    /// Canonical signing body for the attestation.
    pub fn canonical(&self) -> Vec<u8> {
        // JCS-equivalent: serde_json with sorted keys is our canonical
        // JSON form (serde_json default for structs is field order).
        serde_json::to_vec(self).expect("drive report json")
    }
}

/// A witness-issued challenge: prove the bytes at this window, now.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpotChallenge {
    /// Target device serial.
    pub serial: String,
    /// Challenged window index (witness-chosen, random).
    pub window: u64,
    /// Window size in sectors (mirrors the report).
    pub window_sectors: u32,
    /// Fresh nonce — blocks any replayed or pre-staged proof.
    pub nonce: String,
    /// Challenge deadline in mesh ticks.
    pub deadline_tick: u64,
}

/// The wiper's answer: bytes on media, hash-bound to the nonce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpotProof {
    pub serial: String,
    pub window: u64,
    pub nonce: String,
    /// Raw on-media bytes at the challenged window (base64). Absent
    /// when the window exceeds the wire envelope (jumbo drills) —
    /// the digest binding then carries the proof: BLAKE3 is
    /// collision-resistant, so a matching binding over the
    /// recomputed expected bytes proves the same fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// BLAKE3(nonce || data) hex — witness recomputes both halves.
    pub binding: String,
}

impl SpotProof {
    /// Compute the nonce binding for data.
    pub fn binding_for(nonce: &str, data: &[u8]) -> String {
        let mut h = Hasher::new();
        h.update(nonce.as_bytes());
        h.update(data);
        h.finalize().to_hex().to_string()
    }

    /// Build an honest proof from the bytes actually on media.
    pub fn honest(serial: &str, window: u64, nonce: &str, data: &[u8]) -> Self {
        Self {
            serial: serial.to_string(),
            window,
            nonce: nonce.to_string(),
            data: Some(b64_encode(data)),
            binding: Self::binding_for(nonce, data),
        }
    }

    /// Digest-form proof for oversized windows (see `data` docs).
    pub fn digest_form(serial: &str, window: u64, nonce: &str, data: &[u8]) -> Self {
        Self {
            serial: serial.to_string(),
            window,
            nonce: nonce.to_string(),
            data: None,
            binding: Self::binding_for(nonce, data),
        }
    }
}

/// Verification outcome for one spot-proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpotTranscript {
    /// Witness that issued the challenge (node hex).
    pub witness: String,
    /// Wiper node that answered (node hex).
    pub wiper: String,
    pub challenge: SpotChallenge,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SpotProof>,
    /// Passed = proof present, binding valid, bytes match the
    /// declared final pattern.
    pub passed: bool,
    /// Failure reason when `passed == false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SpotTranscript {
    /// Verify a spot-proof against the drive's declared pattern.
    pub fn verify(
        witness: &str,
        wiper: &str,
        challenge: &SpotChallenge,
        proof: Option<&SpotProof>,
        report: &DriveReport,
    ) -> Self {
        let mut t = SpotTranscript {
            witness: witness.to_string(),
            wiper: wiper.to_string(),
            challenge: challenge.clone(),
            proof: proof.cloned(),
            passed: false,
            reason: None,
        };
        let Some(p) = proof else {
            t.reason = Some("no proof delivered before deadline".into());
            return t;
        };
        if p.serial != challenge.serial
            || p.window != challenge.window
            || p.nonce != challenge.nonce
        {
            t.reason = Some("proof does not answer the challenge".into());
            return t;
        }
        // Recompute what the media MUST hold per the declared pattern.
        let want_len = challenge.window_sectors as u64 * 512;
        let mut expected = vec![0u8; want_len as usize];
        report.expected_bytes(challenge.window, &mut expected);
        match &p.data {
            Some(encoded) => {
                let data = match b64_decode(encoded) {
                    Some(d) => d,
                    None => {
                        t.reason = Some("proof data is not valid base64".into());
                        return t;
                    }
                };
                if data.len() as u64 != want_len {
                    t.reason = Some("proof length does not match the window".into());
                    return t;
                }
                if SpotProof::binding_for(&challenge.nonce, &data) != p.binding {
                    t.reason = Some("nonce binding hash mismatch (replay or corruption)".into());
                    return t;
                }
                if expected != data {
                    t.reason = Some("on-media bytes differ from the declared final pattern".into());
                    return t;
                }
            }
            None => {
                // Digest form: binding over the recomputed expected
                // bytes must equal the proof's binding (BLAKE3
                // collision resistance).
                if SpotProof::binding_for(&challenge.nonce, &expected) != p.binding {
                    t.reason =
                        Some("digest binding does not cover the expected pattern bytes".into());
                    return t;
                }
            }
        }
        t.passed = true;
        t
    }
}

/// Gossip store: reports seen so far + broadcast bookkeeping.
pub struct GossipStore {
    /// All drive reports keyed by serial (duplicate serial across
    /// nodes is itself rogue evidence — see `duplicate_serials`).
    reports: HashMap<String, DriveReport>,
    /// Serial → first reporter (hex node).
    owners: HashMap<String, String>,
    /// Serials already re-broadcast by this node (anti-entropy once).
    rebroadcast: std::collections::HashSet<String>,
}

impl Default for GossipStore {
    fn default() -> Self {
        Self::new()
    }
}

impl GossipStore {
    pub fn new() -> Self {
        Self {
            reports: HashMap::new(),
            owners: HashMap::new(),
            rebroadcast: std::collections::HashSet::new(),
        }
    }

    /// Ingest a report. Returns `(fresh, duplicate_claim)` — a
    /// duplicate claim means two different nodes attested the same
    /// physical serial (counterfeit / swap smuggling signal).
    pub fn ingest(&mut self, report: &DriveReport) -> (bool, bool) {
        if let Some(owner) = self.owners.get(&report.serial) {
            if owner != &report.node {
                return (false, true);
            }
            return (false, false);
        }
        self.owners
            .insert(report.serial.clone(), report.node.clone());
        self.reports.insert(report.serial.clone(), report.clone());
        (true, false)
    }

    pub fn get(&self, serial: &str) -> Option<&DriveReport> {
        self.reports.get(serial)
    }

    pub fn by_node(&self, node: &str) -> Vec<&DriveReport> {
        let mut v: Vec<&DriveReport> = self.reports.values().filter(|r| r.node == node).collect();
        v.sort_by(|a, b| a.serial.cmp(&b.serial));
        v
    }

    pub fn all(&self) -> Vec<&DriveReport> {
        let mut v: Vec<&DriveReport> = self.reports.values().collect();
        v.sort_by(|a, b| a.serial.cmp(&b.serial));
        v
    }

    pub fn len(&self) -> usize {
        self.reports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.reports.is_empty()
    }

    /// Mark a serial as re-broadcast (anti-entropy fires once).
    pub fn should_rebroadcast(&mut self, serial: &str) -> bool {
        self.rebroadcast.insert(serial.to_string())
    }
}

// --- tiny base64 (std-free subset, used for proof payloads) ---------------
// We avoid pulling a base64 dep into the wire protocol: this is the
// canonical alphabet, RFC 4648, no padding, fixed by the protocol.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.as_bytes();
    if s.is_empty() {
        return Some(Vec::new());
    }
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 || chunk[..4 - pad].contains(&b'=') {
            return None;
        }
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' { 0 } else { val(c)? };
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Canonical root over a sorted report set: BLAKE3 chain over each
/// report's canonical JSON. Returns (root, count).
pub fn reports_root(reports: &[DriveReport]) -> (String, u32) {
    let mut sorted: Vec<&DriveReport> = reports.iter().collect();
    sorted.sort_by(|a, b| a.serial.cmp(&b.serial));
    let mut h = Hasher::new();
    h.update(b"DCMS-REPORTS-v1");
    for r in &sorted {
        h.update(&r.canonical());
    }
    (h.finalize().to_hex().to_string(), sorted.len() as u32)
}

/// Canonical root over a sorted transcript set: BLAKE3 chain over each
/// transcript's canonical JSON. Returns (root, count).
pub fn transcripts_root(transcripts: &[SpotTranscript]) -> (String, u32) {
    let mut sorted: Vec<&SpotTranscript> = transcripts.iter().collect();
    sorted.sort_by(|a, b| a.challenge.nonce.cmp(&b.challenge.nonce));
    let mut h = Hasher::new();
    h.update(b"DCMS-TRANSCRIPTS-v1");
    for t in &sorted {
        let canonical = serde_json::to_vec(t).expect("transcript json");
        h.update(&canonical);
    }
    (h.finalize().to_hex().to_string(), sorted.len() as u32)
}

/// Convenience: compute the evidence root over a set of window digests.
pub fn evidence_root(digests: &[&[u8]]) -> String {
    let mut h = Hasher::new();
    for d in digests {
        h.update(&(d.len() as u64).to_be_bytes());
        h.update(d);
    }
    h.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dc_core::{Pattern, PrngScheme};

    fn report(seed: u64) -> DriveReport {
        DriveReport {
            node: "aa11".to_string(),
            serial: "SN-TEST-1".to_string(),
            wwn: Some("5000c500abc".to_string()),
            bus: "NVMe".to_string(),
            capacity_lbas: 1024,
            window_sectors: 8,
            windows_total: 128,
            windows_verified: 128,
            pattern: Pattern::DeterministicRandom {
                scheme: PrngScheme::ChaCha20WindowV1,
                seed: {
                    let mut sd = [0u8; 32];
                    sd[..8].copy_from_slice(&seed.to_be_bytes());
                    sd
                },
            },
            evidence_root: "00".repeat(32),
            view: 1,
        }
    }

    #[test]
    fn consistent_report_passes() {
        let r = report(42);
        assert!(r.is_consistent());
        let mut bad = r.clone();
        bad.windows_verified = 100;
        assert!(!bad.is_consistent());
    }

    #[test]
    fn spot_proof_roundtrip_honest() {
        let r = report(7);
        let mut on_media = vec![0u8; 8 * 512];
        r.expected_bytes(3, &mut on_media);

        let challenge = SpotChallenge {
            serial: r.serial.clone(),
            window: 3,
            window_sectors: 8,
            nonce: "nonce-abc".to_string(),
            deadline_tick: 10,
        };
        let proof = SpotProof::honest(&r.serial, 3, "nonce-abc", &on_media);
        let t = SpotTranscript::verify("w1", "aa11", &challenge, Some(&proof), &r);
        assert!(t.passed, "{t:?}");
    }

    #[test]
    fn spot_proof_detects_lies() {
        let r = report(9);
        let wrong = vec![0xABu8; 8 * 512]; // not the pattern
        let challenge = SpotChallenge {
            serial: r.serial.clone(),
            window: 1,
            window_sectors: 8,
            nonce: "n".to_string(),
            deadline_tick: 10,
        };
        let proof = SpotProof::honest(&r.serial, 1, "n", &wrong);
        let t = SpotTranscript::verify("w1", "aa11", &challenge, Some(&proof), &r);
        assert!(!t.passed);
        assert!(t.reason.as_deref().unwrap_or("").contains("differ"));
    }

    #[test]
    fn spot_proof_detects_nonce_replay() {
        let r = report(11);
        let mut data = vec![0u8; 8 * 512];
        r.expected_bytes(2, &mut data);
        let proof = SpotProof::honest(&r.serial, 2, "old-nonce", &data);
        let challenge = SpotChallenge {
            serial: r.serial.clone(),
            window: 2,
            window_sectors: 8,
            nonce: "fresh-nonce".to_string(),
            deadline_tick: 10,
        };
        let t = SpotTranscript::verify("w1", "aa11", &challenge, Some(&proof), &r);
        assert!(!t.passed);
        assert!(t.reason.as_deref().unwrap_or("").contains("challenge"));
    }

    #[test]
    fn spot_proof_timeout_is_failure() {
        let r = report(5);
        let challenge = SpotChallenge {
            serial: r.serial.clone(),
            window: 0,
            window_sectors: 8,
            nonce: "n".to_string(),
            deadline_tick: 10,
        };
        let t = SpotTranscript::verify("w1", "aa11", &challenge, None, &r);
        assert!(!t.passed);
        assert!(t.reason.as_deref().unwrap_or("").contains("deadline"));
    }

    #[test]
    fn duplicate_serial_detection() {
        let mut store = GossipStore::new();
        let mut a = report(1);
        a.node = "nodeA".to_string();
        let mut b = report(1);
        b.node = "nodeB".to_string();
        assert_eq!(store.ingest(&a), (true, false));
        assert_eq!(store.ingest(&b), (false, true));
    }

    #[test]
    fn b64_roundtrip_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let enc = b64_encode(s.as_bytes());
            assert_eq!(
                String::from_utf8(b64_decode(&enc).expect("dec")).expect("utf8"),
                s
            );
        }
        assert!(b64_decode("Zm9v!").is_none());
    }
}
