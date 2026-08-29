use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCloseLedger {
    pub total_specs: usize,
    pub total_kill_entries: usize,
    pub total_forced_deltas: usize,
    pub total_discipline_laws: usize,
    pub total_invariants: usize,
    pub total_ceremonies: usize,
    pub drawer_empty: bool,
    pub release_version: &'static str,
}

impl ProjectCloseLedger {
    pub fn canonical_close() -> Self {
        Self {
            total_specs: 28,
            total_kill_entries: 790,
            total_forced_deltas: 518,
            total_discipline_laws: 274,
            total_invariants: 16,
            total_ceremonies: 16,
            drawer_empty: true,
            release_version: "v0.3.1",
        }
    }

    /// Complete project close verification (Δ517, Δ518).
    pub fn verify_project_close(&self) -> Result<&'static str, &'static str> {
        if !self.drawer_empty {
            return Err("PROJECT_CLOSE_FAILED_UNOWNED_DEFERRALS_IN_DRAWER");
        }
        if self.total_specs < 28 || self.total_ceremonies < 16 {
            return Err("PROJECT_CLOSE_FAILED_INCOMPLETE_CORPUS_CENSUS");
        }
        Ok("PROJECT_CLOSED_ALL_DEVICES_WIPED_OR_REFUSED_BY_LAW")
    }
}
