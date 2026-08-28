use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdGen(pub u32);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometryStage {
    pub op: String,
    pub fd_gen: FdGen,
    pub cap_before: u64,
    pub cap_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometryTransaction {
    pub id: String,
    pub stages: Vec<GeometryStage>,
    pub current_capacity: u64,
    pub native_capacity: u64,
    pub dco_max_capacity: u64,
    pub committed: bool,
}

impl GeometryTransaction {
    pub fn begin(current: u64, native: u64, dco: u64) -> Self {
        Self {
            id: format!("geom-tx-{}", blake3::hash(&current.to_le_bytes()).to_hex()[0..8].to_string()),
            stages: Vec::new(),
            current_capacity: current,
            native_capacity: native,
            dco_max_capacity: dco,
            committed: false,
        }
    }

    /// Record a DCO restore stage (triggers POR and advances FdGen).
    pub fn stage_dco_restore(&mut self, current_gen: FdGen) -> FdGen {
        let before = self.native_capacity;
        self.native_capacity = self.dco_max_capacity;
        self.stages.push(GeometryStage {
            op: "DCO_RESTORE".to_string(),
            fd_gen: current_gen,
            cap_before: before,
            cap_after: self.dco_max_capacity,
        });
        FdGen(current_gen.0 + 1) // Advance generation after device reset
    }

    /// Record an HPA unlock stage.
    pub fn stage_hpa_unlock(&mut self, current_gen: FdGen) {
        let before = self.current_capacity;
        self.current_capacity = self.native_capacity;
        self.stages.push(GeometryStage {
            op: "HPA_UNLOCK".to_string(),
            fd_gen: current_gen,
            cap_before: before,
            cap_after: self.native_capacity,
        });
    }

    /// Commit the geometry transaction after final re-read.
    pub fn commit(&mut self) {
        self.committed = true;
    }
}
