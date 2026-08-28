use dc_core::fleet::{
    AssignmentRow, BatchManifest, BatchReconstructor, ChildJournalState, FleetJobOutcome,
    FleetReport,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockChildProcess {
    pub slot_id: usize,
    pub serial: String,
    pub is_terminal: bool,
    pub terminal_outcome: Option<String>,
    pub received_signal: Option<String>,
}

pub struct FleetRigMock {
    pub manifest: BatchManifest,
    pub children: Vec<MockChildProcess>,
}

impl FleetRigMock {
    pub fn new(slot_count: usize) -> Self {
        let mut rows = Vec::new();
        let mut children = Vec::new();

        for i in 0..slot_count {
            let serial = format!("MOCK_SED_SERIAL_{:03}", i);
            rows.push(AssignmentRow {
                slot_id: i,
                expected_serial: serial.clone(),
                plan_profile: "default_purge".to_string(),
                scan_attestation: format!("BARCODE_SCAN_{:03}", i),
            });
            children.push(MockChildProcess {
                slot_id: i,
                serial,
                is_terminal: false,
                terminal_outcome: None,
                received_signal: None,
            });
        }

        Self {
            manifest: BatchManifest::new("BATCH_2026_08_29_001", rows),
            children,
        }
    }

    /// Forward operator signal to all active (non-terminal) children (Δ378).
    /// Completed children are untouched (FLEET-VICTORY).
    pub fn forward_operator_signal(&mut self, signal: &str) {
        for child in &mut self.children {
            if !child.is_terminal {
                child.received_signal = Some(signal.to_string());
                child.is_terminal = true;
                child.terminal_outcome = Some("INTERRUPTED".to_string());
            }
        }
    }

    /// Mark specific slot as clean completed
    pub fn mark_completed(&mut self, slot_id: usize) {
        if let Some(child) = self.children.iter_mut().find(|c| c.slot_id == slot_id) {
            child.is_terminal = true;
            child.terminal_outcome = Some("CLEAN_COMPLETED".to_string());
        }
    }

    /// Generate child journal states for evidence reconstruction
    pub fn export_child_journal_states(&self) -> Vec<ChildJournalState> {
        self.children
            .iter()
            .map(|c| ChildJournalState {
                slot_id: c.slot_id,
                serial: c.serial.clone(),
                terminal_state: c.terminal_outcome.clone(),
                cert_hash: if c.terminal_outcome.as_deref() == Some("CLEAN_COMPLETED") {
                    Some(format!("CERT_HASH_{:03}", c.slot_id))
                } else {
                    None
                },
            })
            .collect()
    }

    /// Reconstruct batch state from child journals (Δ381).
    pub fn reconstruct_report(&self) -> FleetReport {
        let journals = self.export_child_journal_states();
        BatchReconstructor::reconstruct_from_evidence(&self.manifest, &journals)
    }
}
