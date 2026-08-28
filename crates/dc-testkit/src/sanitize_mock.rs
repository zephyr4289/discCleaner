use dc_hw::NvmeSanitizeStatus;

pub trait SanitizeStatusSource {
    fn poll_status(&mut self) -> Result<NvmeSanitizeStatus, String>;
}

pub struct MockLogFeed {
    sequence: Vec<NvmeSanitizeStatus>,
    index: usize,
}

impl MockLogFeed {
    pub fn new(sequence: Vec<NvmeSanitizeStatus>) -> Self {
        Self { sequence, index: 0 }
    }

    /// Helper to create a monotonic progress sequence (0% -> 50% -> 100% completed).
    pub fn monotonic() -> Self {
        Self::new(vec![
            NvmeSanitizeStatus {
                progress_permille: 0,
                is_in_progress: true,
                is_completed: false,
                is_failed: false,
                raw_sstat: 2,
                raw_sprog: 0,
            },
            NvmeSanitizeStatus {
                progress_permille: 500,
                is_in_progress: true,
                is_completed: false,
                is_failed: false,
                raw_sstat: 2,
                raw_sprog: 32768,
            },
            NvmeSanitizeStatus {
                progress_permille: 1000,
                is_in_progress: false,
                is_completed: true,
                is_failed: false,
                raw_sstat: 1,
                raw_sprog: 65535,
            },
        ])
    }

    /// Helper to create a stuck progress sequence.
    pub fn stuck() -> Self {
        Self::new(vec![
            NvmeSanitizeStatus {
                progress_permille: 400,
                is_in_progress: true,
                is_completed: false,
                is_failed: false,
                raw_sstat: 2,
                raw_sprog: 26214,
            },
            NvmeSanitizeStatus {
                progress_permille: 400,
                is_in_progress: true,
                is_completed: false,
                is_failed: false,
                raw_sstat: 2,
                raw_sprog: 26214,
            },
            NvmeSanitizeStatus {
                progress_permille: 400,
                is_in_progress: true,
                is_completed: false,
                is_failed: false,
                raw_sstat: 2,
                raw_sprog: 26214,
            },
        ])
    }
}

impl SanitizeStatusSource for MockLogFeed {
    fn poll_status(&mut self) -> Result<NvmeSanitizeStatus, String> {
        if self.sequence.is_empty() {
            return Err("Empty mock sequence".to_string());
        }

        let status = if self.index < self.sequence.len() {
            let s = self.sequence[self.index].clone();
            self.index += 1;
            s
        } else {
            self.sequence.last().unwrap().clone()
        };

        Ok(status)
    }
}
