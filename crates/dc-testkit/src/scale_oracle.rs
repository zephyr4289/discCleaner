use crate::cleanroom::CleanroomPRNG;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub struct ScaleOracle;

impl ScaleOracle {
    /// Perform stratified cleanroom memory comparison across 64 evenly spaced windows and boundary sectors.
    pub fn verify_stratified_windows(
        dev_path: &Path,
        seed: &[u8; 32],
        total_size_bytes: u64,
        window_bytes: u64,
    ) -> Result<bool, String> {
        let mut file = File::open(dev_path).map_err(|e| e.to_string())?;
        let total_windows = (total_size_bytes + window_bytes - 1) / window_bytes;

        // Pick 64 stratified windows including first, last, middle, and boundaries
        let mut sample_indices = Vec::new();
        sample_indices.push(0);
        sample_indices.push(total_windows.saturating_sub(1));

        let step = (total_windows / 64).max(1);
        for i in (0..total_windows).step_by(step as usize) {
            sample_indices.push(i);
        }
        sample_indices.sort_unstable();
        sample_indices.dedup();

        let mut expected_buf = vec![0u8; window_bytes as usize];
        let mut actual_buf = vec![0u8; window_bytes as usize];

        for &w in &sample_indices {
            let win_start = w * window_bytes;
            let win_len = ((total_size_bytes - win_start) as usize).min(window_bytes as usize);

            // Generate cleanroom expected
            CleanroomPRNG::fill_window(seed, w, &mut expected_buf[..win_len]);

            // Read device actual
            file.seek(SeekFrom::Start(win_start)).map_err(|e| e.to_string())?;
            file.read_exact(&mut actual_buf[..win_len]).map_err(|e| e.to_string())?;

            if expected_buf[..win_len] != actual_buf[..win_len] {
                return Err(format!(
                    "ScaleOracle stratified mismatch at window #{} (LBA offset {})",
                    w, win_start / 512
                ));
            }
        }

        Ok(true)
    }
}
