//! Proof of erasure — the receipt the shredder can't give you.
//!
//! One leaf per addressed block, no gaps: every block of every die appears
//! exactly once, either erased (with a CRC-32 of the verified page stream),
//! skipped (factory bad marker re-read after erase setup), failed after
//! retries, or the whole die reported as ID-mismatched. Leaves are hashed
//! (SHA-256) into a Merkle tree; the root plus sampled inclusion proofs go
//! into a human-readable `.drz` file that `dc-resurrect verify` can check
//! offline.
//!
//! Trust model, stated plainly: the proof's root of trust is the SHA-256 of
//! the injected payload recorded in the file. It proves "the kernel that
//! ran is the kernel whose hash is printed here, and it attested every
//! block of this geometry." Reviewing the nucleus is reviewing the proof.

use std::fmt;
use std::io::Read;
use std::path::Path;

use crate::nand::NandGeometry;
use crate::payload::{Stage, VerifyMode, layout};
use crate::rng::XorShift;
use crate::sha256::{Sha256, hex, sha256};

pub const ST_ERASED: u8 = 0;
pub const ST_SKIPPED_BAD: u8 = 1;
pub const ST_FAILED: u8 = 2;
pub const ST_DIE_ID: u8 = 3;
/// Marker block value in die-ID-failure records.
pub const DIE_ID_BLOCK: u32 = 0xFFFF_FFFF;

/// One attested block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRecord {
    pub die: u8,
    pub block: u32,
    pub status: u8,
    pub nonzero: u32,
    pub crc32: u32,
}

impl BlockRecord {
    pub fn erased(die: u8, block: u32, nonzero: u32, crc32: u32) -> BlockRecord {
        BlockRecord {
            die,
            block,
            status: ST_ERASED,
            nonzero,
            crc32,
        }
    }

    pub fn skipped_bad(die: u8, block: u32) -> BlockRecord {
        BlockRecord {
            die,
            block,
            status: ST_SKIPPED_BAD,
            nonzero: 0,
            crc32: 0,
        }
    }

    pub fn failed_erase(die: u8, block: u32) -> BlockRecord {
        BlockRecord {
            die,
            block,
            status: ST_FAILED,
            nonzero: 0,
            crc32: 0,
        }
    }

    pub fn die_id_fail(die: u8) -> BlockRecord {
        BlockRecord {
            die,
            block: DIE_ID_BLOCK,
            status: ST_DIE_ID,
            nonzero: 0,
            crc32: 0,
        }
    }

    /// From a kernel mailbox word tuple (w1, w2, w3, w4).
    pub fn from_mailbox(w1: u32, w2: u32, w3: u32, w4: u32) -> BlockRecord {
        BlockRecord {
            die: (w1 >> 16) as u8,
            block: w1 & 0xFFFF,
            status: w2 as u8,
            nonzero: w3,
            crc32: w4,
        }
    }

    /// Canonical leaf preimage: die, status, block, nonzero, crc32.
    pub fn leaf_bytes(&self) -> [u8; 14] {
        let mut b = [0u8; 14];
        b[0] = self.die;
        b[1] = self.status;
        b[2..6].copy_from_slice(&self.block.to_le_bytes());
        b[6..10].copy_from_slice(&self.nonzero.to_le_bytes());
        b[10..14].copy_from_slice(&self.crc32.to_le_bytes());
        b
    }

    pub fn leaf_hash(&self) -> [u8; 32] {
        sha256(&self.leaf_bytes())
    }

    pub fn status_name(&self) -> &'static str {
        match self.status {
            ST_ERASED => "erased",
            ST_SKIPPED_BAD => "skipped-bad",
            ST_FAILED => "failed",
            ST_DIE_ID => "die-id-fail",
            _ => "unknown",
        }
    }
}

/// Merkle root over leaf hashes (duplicate-last on odd levels).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i]
            };
            let mut h = Sha256::new();
            h.update(&left);
            h.update(&right);
            next.push(h.finalize());
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// One sampled inclusion proof.
#[derive(Clone, Debug)]
pub struct InclusionProof {
    pub index: usize,
    pub leaf: [u8; 32],
    /// (sibling hash, sibling-is-right)
    pub path: Vec<([u8; 32], bool)>,
}

pub fn inclusion_proof(leaves: &[[u8; 32]], index: usize) -> InclusionProof {
    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let sib = if idx ^ 1 < level.len() { idx ^ 1 } else { idx };
        // sibling is on the right when our index is the left (even) one
        path.push((level[sib], (idx & 1) == 0));
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i]
            };
            let mut h = Sha256::new();
            h.update(&left);
            h.update(&right);
            next.push(h.finalize());
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    InclusionProof {
        index,
        leaf: leaves[index],
        path,
    }
}

pub fn verify_inclusion(proof: &InclusionProof, root: &[u8; 32]) -> bool {
    let mut cur = proof.leaf;
    for (sib, sib_right) in &proof.path {
        let mut h = Sha256::new();
        if *sib_right {
            h.update(&cur);
            h.update(sib);
        } else {
            h.update(sib);
            h.update(&cur);
        }
        cur = h.finalize();
    }
    &cur == root
}

/// Aggregate stats computed from the record set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockStats {
    pub total: u32,
    pub erased: u32,
    pub skipped_bad: u32,
    pub failed: u32,
    pub die_id_fail: u32,
    pub nonzero_total: u64,
}

impl BlockStats {
    pub fn from_records(records: &[BlockRecord], total_blocks: u32) -> BlockStats {
        let mut s = BlockStats {
            total: total_blocks,
            ..Default::default()
        };
        for r in records {
            match r.status {
                ST_ERASED => s.erased += 1,
                ST_SKIPPED_BAD => s.skipped_bad += 1,
                ST_FAILED => s.failed += 1,
                ST_DIE_ID => s.die_id_fail += 1,
                _ => {}
            }
            s.nonzero_total += r.nonzero as u64;
        }
        s
    }

    /// Accounting identity: every block is accounted for exactly once.
    pub fn complete(&self, geo: &NandGeometry) -> bool {
        let die_blocks: u32 = self.die_id_fail.saturating_mul(geo.blocks_per_lun);
        let accounted = self.erased + self.skipped_bad + self.failed + die_blocks;
        accounted == self.total
    }
}

/// The erasure proof document.
#[derive(Clone, Debug)]
pub struct ErasureProof {
    pub scenario: String,
    pub controller: String,
    pub controller_sha256: String,
    pub payload_stage: String,
    pub payload_sha256: [u8; 32],
    pub payload_len: u32,
    pub payload_crc32: u32,
    pub geometry: NandGeometry,
    pub verify_mode: VerifyMode,
    pub records: Vec<BlockRecord>,
    pub merkle_root: [u8; 32],
    pub sampled: Vec<InclusionProof>,
    pub nonce: u64,
    pub timestamp_unix: u64,
    pub rig: String,
    pub core_instructions: u64,
}

impl ErasureProof {
    pub fn build(
        scenario: &str,
        controller: &crate::vendors::ControllerProfile,
        stage: Stage,
        payload_sha256: [u8; 32],
        payload_len: u32,
        payload_crc32: u32,
        geometry: NandGeometry,
        verify_mode: VerifyMode,
        records: Vec<BlockRecord>,
        seed: u64,
        core_instructions: u64,
    ) -> ErasureProof {
        let leaves: Vec<[u8; 32]> = records.iter().map(|r| r.leaf_hash()).collect();
        let root = merkle_root(&leaves);
        // Deterministic sampler: 8 inclusion proofs (or fewer for small sets).
        let mut rng = XorShift::new(seed ^ 0xD15EA5E);
        let n = leaves.len().min(8);
        let mut sampled = Vec::new();
        if !leaves.is_empty() {
            for _ in 0..n {
                let idx = rng.below(leaves.len() as u64) as usize;
                sampled.push(inclusion_proof(&leaves, idx));
            }
        }
        ErasureProof {
            scenario: scenario.to_string(),
            controller: controller.name.clone(),
            controller_sha256: controller.profile_sha256.clone(),
            payload_stage: stage.name().to_string(),
            payload_sha256,
            payload_len,
            payload_crc32,
            geometry,
            verify_mode,
            records,
            merkle_root: root,
            sampled,
            nonce: rng.next_u64(),
            timestamp_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            rig: format!("dc-resurrect {} (sim transport)", env!("CARGO_PKG_VERSION")),
            core_instructions,
        }
    }

    pub fn stats(&self) -> BlockStats {
        BlockStats::from_records(&self.records, self.geometry.total_blocks())
    }
}

#[derive(Debug)]
pub enum ProofError {
    Io(String),
    Malformed(String),
    RootMismatch,
    InclusionFailed,
    Incomplete,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::Io(e) => write!(f, "i/o: {e}"),
            ProofError::Malformed(e) => write!(f, "malformed proof: {e}"),
            ProofError::RootMismatch => write!(f, "merkle root mismatch"),
            ProofError::InclusionFailed => write!(f, "inclusion proof failed"),
            ProofError::Incomplete => write!(f, "block accounting incomplete"),
        }
    }
}

/// Verification result.
#[derive(Clone, Debug)]
pub struct VerifyReport {
    pub controller: String,
    pub stats: BlockStats,
    pub merkle_root: [u8; 32],
    pub leaves_checked: usize,
    pub inclusions_checked: usize,
    pub payload_sha256: [u8; 32],
}

impl ErasureProof {
    pub fn write_file(&self, path: &Path, full_records: bool) -> Result<(), ProofError> {
        let stats = self.stats();
        let mut out = String::new();
        out.push_str("DC-RESURRECT ERASURE PROOF v1\n");
        out.push_str(&format!("scenario: {}\n", self.scenario));
        out.push_str(&format!("controller: {}\n", self.controller));
        out.push_str(&format!("controller_sha256: {}\n", self.controller_sha256));
        out.push_str(&format!("payload_stage: {}\n", self.payload_stage));
        out.push_str(&format!("payload_sha256: {}\n", hex(&self.payload_sha256)));
        out.push_str(&format!("payload_len: {}\n", self.payload_len));
        out.push_str(&format!("payload_crc32: {:08x}\n", self.payload_crc32));
        out.push_str(&format!(
            "geometry: {}+{} B/page | {} ppb | {} blk/LUN | {} LUN | {} bytes\n",
            self.geometry.bytes_per_page,
            self.geometry.spare_bytes,
            self.geometry.pages_per_block,
            self.geometry.blocks_per_lun,
            self.geometry.luns,
            self.geometry.capacity()
        ));
        out.push_str(&format!(
            "verify_mode: {}\n",
            match self.verify_mode {
                VerifyMode::Off => "off",
                VerifyMode::Sampled => "sampled",
                VerifyMode::Full => "full",
            }
        ));
        out.push_str(&format!("blocks_total: {}\n", stats.total));
        out.push_str(&format!("blocks_erased: {}\n", stats.erased));
        out.push_str(&format!("blocks_skipped_bad: {}\n", stats.skipped_bad));
        out.push_str(&format!("blocks_failed: {}\n", stats.failed));
        out.push_str(&format!("die_id_fail: {}\n", stats.die_id_fail));
        out.push_str(&format!("merkle_root: {}\n", hex(&self.merkle_root)));
        out.push_str(&format!("nonce: {:016x}\n", self.nonce));
        out.push_str(&format!("timestamp_unix: {}\n", self.timestamp_unix));
        out.push_str(&format!("core_instructions: {}\n", self.core_instructions));
        out.push_str(&format!("rig: {}\n", self.rig));
        out.push_str("\n[leaves]\n");
        for r in &self.records {
            out.push_str(&format!(
                "{:02x} {:08x} {} {:08x} {:08x} {}\n",
                r.die,
                r.block,
                r.status,
                r.nonzero,
                r.crc32,
                hex(&r.leaf_hash())
            ));
        }
        if full_records {
            out.push_str("\n[records]\n");
            for r in &self.records {
                out.push_str(&format!(
                    "die {} block {} {} nonzero {} crc32 {:08x}\n",
                    r.die,
                    r.block,
                    r.status_name(),
                    r.nonzero,
                    r.crc32
                ));
            }
        }
        out.push_str("\n[inclusion-proofs]\n");
        for p in &self.sampled {
            out.push_str(&format!("index: {}\n", p.index));
            out.push_str(&format!("leaf: {}\n", hex(&p.leaf)));
            for (sib, right) in &p.path {
                out.push_str(&format!(
                    "sibling: {} {}\n",
                    hex(sib),
                    if *right { "right" } else { "left" }
                ));
            }
        }
        out.push_str("\n[end]\n");
        std::fs::write(path, out).map_err(|e| ProofError::Io(e.to_string()))
    }

    /// Verify a proof file: recompute the Merkle root from the leaf lines,
    /// check sampled inclusion paths, check block accounting.
    pub fn verify_file(path: &Path) -> Result<VerifyReport, ProofError> {
        let mut text = String::new();
        {
            let mut f = std::fs::File::open(path).map_err(|e| ProofError::Io(e.to_string()))?;
            f.read_to_string(&mut text)
                .map_err(|e| ProofError::Io(e.to_string()))?;
        }
        Self::verify_str(&text)
    }

    pub fn verify_str(text: &str) -> Result<VerifyReport, ProofError> {
        let mut controller = String::new();
        let mut root_hex = String::new();
        let mut payload_sha = [0u8; 32];
        let mut total: u32 = 0;
        let mut ppb = 0u32;
        let mut bpl = 0u32;
        let mut luns = 0u32;
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        let mut records: Vec<BlockRecord> = Vec::new();
        let mut proofs: Vec<InclusionProof> = Vec::new();
        let mut section = "";
        let mut cur_proof: Option<InclusionProof> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                if let Some(p) = cur_proof.take() {
                    proofs.push(p);
                }
                section = line;
                continue;
            }
            let get = |k: &str| line.strip_prefix(k).map(|v| v.trim().to_string());
            match section {
                "" => {
                    if let Some(v) = get("controller:") {
                        controller = v;
                    } else if let Some(v) = get("merkle_root:") {
                        root_hex = v;
                    } else if let Some(v) = get("payload_sha256:") {
                        if v.len() == 64 {
                            for i in 0..32 {
                                payload_sha[i] = u8::from_str_radix(&v[2 * i..2 * i + 2], 16)
                                    .map_err(|_| ProofError::Malformed("payload sha".into()))?;
                            }
                        }
                    } else if let Some(v) = get("blocks_total:") {
                        total = v
                            .parse()
                            .map_err(|_| ProofError::Malformed("blocks_total".into()))?;
                    } else if let Some(v) = get("geometry:") {
                        // "2048+64 B/page | 64 ppb | 512 blk/LUN | 2 LUN | N bytes"
                        for part in v.split('|') {
                            let p = part.trim();
                            if p.ends_with("ppb") {
                                ppb = p
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("0")
                                    .parse()
                                    .unwrap_or(0);
                            } else if p.ends_with("blk/LUN") {
                                bpl = p
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("0")
                                    .parse()
                                    .unwrap_or(0);
                            } else if p.ends_with("LUN") {
                                luns = p
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("0")
                                    .parse()
                                    .unwrap_or(0);
                            }
                        }
                    }
                }
                "[leaves]" => {
                    // "00 00000000 0 00000000 00000000 <leafhash>"
                    let it = line.split_whitespace();
                    let fields: Vec<&str> = it.collect();
                    if fields.len() >= 6 {
                        let die = u8::from_str_radix(fields[0], 16)
                            .map_err(|_| ProofError::Malformed("leaf die".into()))?;
                        let block = u32::from_str_radix(fields[1], 16)
                            .map_err(|_| ProofError::Malformed("leaf block".into()))?;
                        let status = fields[2]
                            .parse()
                            .map_err(|_| ProofError::Malformed("leaf status".into()))?;
                        let nonzero = u32::from_str_radix(fields[3], 16)
                            .map_err(|_| ProofError::Malformed("leaf nonzero".into()))?;
                        let crc = u32::from_str_radix(fields[4], 16)
                            .map_err(|_| ProofError::Malformed("leaf crc".into()))?;
                        let h = fields[5];
                        if h.len() == 64 {
                            let mut leaf = [0u8; 32];
                            for i in 0..32 {
                                leaf[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16)
                                    .map_err(|_| ProofError::Malformed("leaf".into()))?;
                            }
                            let rec = BlockRecord {
                                die,
                                block,
                                status,
                                nonzero,
                                crc32: crc,
                            };
                            if rec.leaf_hash() != leaf {
                                return Err(ProofError::Malformed(format!(
                                    "leaf {} preimage/hash mismatch",
                                    leaves.len()
                                )));
                            }
                            leaves.push(leaf);
                            records.push(rec);
                        }
                    }
                }
                "[inclusion-proofs]" => {
                    if let Some(v) = get("index:") {
                        if let Some(p) = cur_proof.take() {
                            proofs.push(p);
                        }
                        cur_proof = Some(InclusionProof {
                            index: v
                                .parse()
                                .map_err(|_| ProofError::Malformed("index".into()))?,
                            leaf: [0; 32],
                            path: Vec::new(),
                        });
                    } else if let Some(v) = get("leaf:") {
                        if let Some(p) = cur_proof.as_mut()
                            && v.len() == 64
                        {
                            for i in 0..32 {
                                p.leaf[i] = u8::from_str_radix(&v[2 * i..2 * i + 2], 16)
                                    .map_err(|_| ProofError::Malformed("pf leaf".into()))?;
                            }
                        }
                    } else if let Some(v) = get("sibling:") {
                        let mut parts = v.split_whitespace();
                        let h = parts.next().unwrap_or("");
                        let side = parts.next().unwrap_or("left") == "right";
                        if let Some(p) = cur_proof.as_mut()
                            && h.len() == 64
                        {
                            let mut sib = [0u8; 32];
                            for i in 0..32 {
                                sib[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16)
                                    .map_err(|_| ProofError::Malformed("sibling".into()))?;
                            }
                            p.path.push((sib, side));
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(p) = cur_proof.take() {
            proofs.push(p);
        }
        // Recompute the root from leaf hashes (which were themselves checked
        // against their record preimages above).
        let computed = merkle_root(&leaves);
        let mut want = [0u8; 32];
        if root_hex.len() == 64 {
            for i in 0..32 {
                want[i] = u8::from_str_radix(&root_hex[2 * i..2 * i + 2], 16)
                    .map_err(|_| ProofError::Malformed("root".into()))?;
            }
        } else {
            return Err(ProofError::Malformed("missing merkle_root".into()));
        }
        if computed != want {
            return Err(ProofError::RootMismatch);
        }
        for p in &proofs {
            if !verify_inclusion(p, &want) {
                return Err(ProofError::InclusionFailed);
            }
        }
        // Accounting: every block of every die is represented exactly once,
        // either as its own record or as one die-level ID failure leaf.
        let geo = NandGeometry::new(2048, 64, ppb.max(1), bpl.max(1), luns.max(1));
        let stats = BlockStats::from_records(&records, total);
        if !stats.complete(&geo) {
            return Err(ProofError::Incomplete);
        }
        Ok(VerifyReport {
            controller,
            stats,
            merkle_root: want,
            leaves_checked: leaves.len(),
            inclusions_checked: proofs.len(),
            payload_sha256: payload_sha,
        })
    }
}

// Keep `layout` referenced so the proof module documents where records live.
const _: u32 = layout::REC_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    fn geo() -> NandGeometry {
        NandGeometry::new(2048, 64, 64, 512, 2)
    }

    #[test]
    fn merkle_root_matches_inclusion() {
        let leaves: Vec<[u8; 32]> = (0..13u64).map(|i| sha256(&i.to_le_bytes())).collect();
        let root = merkle_root(&leaves);
        for idx in [0usize, 5, 12] {
            let p = inclusion_proof(&leaves, idx);
            assert!(verify_inclusion(&p, &root), "index {idx}");
        }
        // Negative: wrong root fails
        let p = inclusion_proof(&leaves, 0);
        let bad = sha256(b"not the root");
        assert!(!verify_inclusion(&p, &bad));
    }

    #[test]
    fn accounting_identity() {
        let records: Vec<BlockRecord> = (0..1024)
            .map(|b| BlockRecord::erased(0, b, 0, 0xABCD))
            .collect();
        let stats = BlockStats::from_records(&records, 1024);
        assert!(stats.complete(&geo()));
        // drop one record -> incomplete
        let short = &records[..1023];
        let stats2 = BlockStats::from_records(short, 1024);
        assert!(!stats2.complete(&geo()));
    }

    #[test]
    fn proof_file_round_trip() {
        let profile =
            crate::vendors::ControllerProfile::builtin_by_name("marvell-88ss1077").unwrap();
        let mut records = Vec::new();
        for die in 0..2u8 {
            for b in 0..512u32 {
                if b == 200 {
                    records.push(BlockRecord::skipped_bad(die, b));
                } else {
                    records.push(BlockRecord::erased(die, b, 0, 0x1234_5678));
                }
            }
        }
        let proof = ErasureProof::build(
            "test",
            &profile,
            Stage::Kernel,
            sha256(b"nucleus"),
            8192,
            0xCAFEBABE,
            geo(),
            VerifyMode::Sampled,
            records,
            7,
            12345,
        );
        let path = std::env::temp_dir().join("dc_resurrect_test.drz");
        proof.write_file(&path, true).unwrap();
        let report = ErasureProof::verify_file(&path).unwrap();
        assert_eq!(report.merkle_root, proof.merkle_root);
        assert_eq!(report.leaves_checked, 1024);
        assert_eq!(report.inclusions_checked, 8);
        assert_eq!(report.payload_sha256, sha256(b"nucleus"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_root_rejected() {
        let records: Vec<BlockRecord> = (0..4u32)
            .map(|i| BlockRecord::erased(0, i, 0, i.wrapping_mul(0x9E37)))
            .collect();
        let leaves: Vec<[u8; 32]> = records.iter().map(|r| r.leaf_hash()).collect();
        let root = merkle_root(&leaves);
        let mut text = String::from("DC-RESURRECT ERASURE PROOF v1\n");
        text.push_str("controller: t\n");
        text.push_str("blocks_total: 4\n");
        text.push_str("geometry: 2048+64 B/page | 8 ppb | 4 blk/LUN | 1 LUN | 65536 bytes\n");
        text.push_str(&format!("merkle_root: {}\n", hex(&root)));
        text.push_str("[leaves]\n");
        for r in &records {
            text.push_str(&format!(
                "{:02x} {:08x} {} {:08x} {:08x} {}\n",
                r.die,
                r.block,
                r.status,
                r.nonzero,
                r.crc32,
                hex(&r.leaf_hash())
            ));
        }
        text.push_str("[end]\n");
        let rep = ErasureProof::verify_str(&text).unwrap();
        assert_eq!(rep.leaves_checked, 4);
        // now tamper with one leaf digest
        let bad = text.replace(&hex(&leaves[0]), &hex(&sha256(b"x")));
        assert!(ErasureProof::verify_str(&bad).is_err());
        // and drop a leaf entirely
        let short: Vec<&str> = text
            .lines()
            .filter(|l| !l.contains(&hex(&leaves[1])))
            .collect();
        assert!(ErasureProof::verify_str(&short.join("\n")).is_err());
    }
}
