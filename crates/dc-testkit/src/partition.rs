use dc_core::JOURNAL_MAGIC;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PredictedOutcome {
    CorruptMagic,
    Boundary { complete_records: usize },
    TornTail { complete_records: usize, discarded_bytes: usize },
}

pub struct PartitionOracle;

impl PartitionOracle {
    /// Compute all structural breakpoint offsets in the untruncated journal (Δ90).
    pub fn compute_breakpoints(bytes: &[u8]) -> Vec<usize> {
        let mut breakpoints = Vec::new();
        breakpoints.push(0);

        if bytes.len() < 4 || &bytes[..4] != JOURNAL_MAGIC {
            return breakpoints;
        }

        breakpoints.push(4); // End of magic

        let mut offset = 4;
        while offset < bytes.len() {
            if offset + 4 > bytes.len() {
                break;
            }

            let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            breakpoints.push(offset + 4); // End of len

            if offset + 4 + len > bytes.len() {
                break;
            }
            breakpoints.push(offset + 4 + len); // End of body

            if offset + 4 + len + 32 > bytes.len() {
                break;
            }
            breakpoints.push(offset + 4 + len + 32); // End of hash

            offset = offset + 4 + len + 32;
        }

        breakpoints.sort_unstable();
        breakpoints.dedup();
        breakpoints
    }

    /// Predict the exact outcome for a pure truncation at offset `o` (Δ89, Δ90).
    pub fn predict_pure_truncation(bytes: &[u8], offset: usize) -> PredictedOutcome {
        if offset < 4 {
            return PredictedOutcome::CorruptMagic;
        }

        if &bytes[..4] != JOURNAL_MAGIC {
            return PredictedOutcome::CorruptMagic;
        }

        let mut current_offset = 4;
        let mut last_good_record_end = 4;
        let mut complete_records = 0;

        while current_offset < offset {
            if current_offset + 4 > offset {
                break;
            }

            let len = u32::from_le_bytes(bytes[current_offset..current_offset + 4].try_into().unwrap()) as usize;
            let rec_total_len = 4 + len + 32;

            if current_offset + rec_total_len <= offset {
                current_offset += rec_total_len;
                last_good_record_end = current_offset;
                complete_records += 1;
            } else {
                break;
            }
        }

        if offset == last_good_record_end {
            PredictedOutcome::Boundary { complete_records }
        } else {
            PredictedOutcome::TornTail {
                complete_records,
                discarded_bytes: offset - last_good_record_end,
            }
        }
    }
}
