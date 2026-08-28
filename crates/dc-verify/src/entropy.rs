use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EntropyDiag {
    pub h_min: f64,
    pub h_mean: f64,
    pub h_max: f64,
    pub chi2_max: f64,
    pub windows: u64,
}

pub struct EntropyCalculator {
    h_min: f64,
    h_max: f64,
    h_sum: f64,
    chi2_max: f64,
    windows: u64,
}

impl EntropyCalculator {
    pub fn new() -> Self {
        Self {
            h_min: f64::INFINITY,
            h_max: f64::NEG_INFINITY,
            h_sum: 0.0,
            chi2_max: 0.0,
            windows: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }

        let total_bytes = data.len() as f64;
        let mut entropy = 0.0;
        let expected_per_byte = total_bytes / 256.0;
        let mut chi2 = 0.0;

        for &c in &counts {
            if c > 0 {
                let p = c as f64 / total_bytes;
                entropy -= p * p.log2();
            }
            let diff = c as f64 - expected_per_byte;
            chi2 += (diff * diff) / expected_per_byte;
        }

        self.h_min = self.h_min.min(entropy);
        self.h_max = self.h_max.max(entropy);
        self.h_sum += entropy;
        self.chi2_max = self.chi2_max.max(chi2);
        self.windows += 1;
    }

    pub fn finalize(&self) -> Option<EntropyDiag> {
        if self.windows == 0 {
            return None;
        }

        Some(EntropyDiag {
            h_min: self.h_min,
            h_mean: self.h_sum / self.windows as f64,
            h_max: self.h_max,
            chi2_max: self.chi2_max,
            windows: self.windows,
        })
    }
}
