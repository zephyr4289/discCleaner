use crate::ata_lying::BridgeLieClass;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeClassification {
    Honest,
    Lie { class: BridgeLieClass, detail: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMatrixEntry {
    pub sequence: u64,
    pub vid: u16,
    pub pid: u16,
    pub firmware: String,
    pub protocol: String, // "UAS" or "BOT"
    pub command_class: String,
    pub classification: BridgeClassification,
    pub evidence_bundle_hash: String,
    pub prev_entry_hash: String,
    pub entry_hash: String,
}

pub struct BridgeMatrixLedger {
    pub entries: Vec<BridgeMatrixEntry>,
}

impl BridgeMatrixLedger {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Append a new bridge characterization entry with cryptographic hash chaining (Δ296).
    pub fn append(
        &mut self,
        vid: u16,
        pid: u16,
        firmware: &str,
        protocol: &str,
        command_class: &str,
        classification: BridgeClassification,
        evidence_bundle_hash: &str,
    ) -> BridgeMatrixEntry {
        let sequence = self.entries.len() as u64;
        let prev_entry_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string());

        let mut payload = format!(
            "{}:{:#06x}:{:#06x}:{}:{}:{}:{:?}:{}:{}",
            sequence, vid, pid, firmware, protocol, command_class, classification, evidence_bundle_hash, prev_entry_hash
        );
        let entry_hash = blake3::hash(payload.as_bytes()).to_hex().to_string();

        let entry = BridgeMatrixEntry {
            sequence,
            vid,
            pid,
            firmware: firmware.to_string(),
            protocol: protocol.to_string(),
            command_class: command_class.to_string(),
            classification,
            evidence_bundle_hash: evidence_bundle_hash.to_string(),
            prev_entry_hash,
            entry_hash,
        };

        self.entries.push(entry.clone());
        entry
    }

    /// Verify the cryptographic integrity of the bridge matrix ledger.
    pub fn verify_chain(&self) -> bool {
        for (i, entry) in self.entries.iter().enumerate() {
            let expected_prev = if i == 0 {
                "0000000000000000000000000000000000000000000000000000000000000000"
            } else {
                &self.entries[i - 1].entry_hash
            };

            if entry.prev_entry_hash != expected_prev {
                return false;
            }

            let payload = format!(
                "{}:{:#06x}:{:#06x}:{}:{}:{}:{:?}:{}:{}",
                entry.sequence,
                entry.vid,
                entry.pid,
                entry.firmware,
                entry.protocol,
                entry.command_class,
                entry.classification,
                entry.evidence_bundle_hash,
                entry.prev_entry_hash
            );
            let calculated_hash = blake3::hash(payload.as_bytes()).to_hex().to_string();
            if entry.entry_hash != calculated_hash {
                return false;
            }
        }
        true
    }
}
