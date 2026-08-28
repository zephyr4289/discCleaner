use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeCommitSpec {
    pub first_window: u64,
    pub num_windows: u64,
}

pub struct CompletionTracker {
    committed: u64,
    contiguous: u64,
    harvested_holes: BTreeSet<u64>,
}

impl CompletionTracker {
    pub fn new(start_window: u64) -> Self {
        Self {
            committed: start_window,
            contiguous: start_window,
            harvested_holes: BTreeSet::new(),
        }
    }

    /// Record CQE harvest for `window`. Advances contiguous watermark.
    pub fn on_cqe(&mut self, window: u64) {
        if window < self.contiguous {
            return; // Duplicate or already contiguous
        }

        self.harvested_holes.insert(window);

        // Advance contiguous watermark as far as possible
        while self.harvested_holes.remove(&self.contiguous) {
            self.contiguous += 1;
        }
    }

    /// Check if contiguous prefix is ahead of committed watermark.
    pub fn can_commit(&self) -> bool {
        self.contiguous > self.committed
    }

    /// Get current contiguous harvested watermark.
    pub fn contiguous_watermark(&self) -> u64 {
        self.contiguous
    }

    /// Commit contiguous prefix up to `upto` (bounded by contiguous watermark).
    /// Guarantees that the committed range NEVER contains a hole (INV2 / Δ135).
    pub fn commit(&mut self, upto: u64) -> Option<RangeCommitSpec> {
        let target = upto.min(self.contiguous);
        if target > self.committed {
            let spec = RangeCommitSpec {
                first_window: self.committed,
                num_windows: target - self.committed,
            };
            self.committed = target;
            Some(spec)
        } else {
            None
        }
    }

    /// Commit all harvested contiguous windows so far.
    pub fn commit_all_contiguous(&mut self) -> Option<RangeCommitSpec> {
        self.commit(self.contiguous)
    }

    pub fn committed_watermark(&self) -> u64 {
        self.committed
    }
}
