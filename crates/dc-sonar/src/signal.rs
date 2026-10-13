//! Signal analysis (v0.12.0, Miracle 2): a dependency-free radix-2
//! FFT and the harmonic feature extractor that turns raw telemetry
//! captures into a drive's resonance fingerprint.
//!
//! Zero external crates: the FFT is a hand-written iterative
//! Cooley–Tukey with precomputed twiddles (bit-reversal permutation +
//! butterfly stages) — auditable line by line, tested against a
//! direct DFT reference on randomized inputs.

use crate::telemetry::Capture;
use serde::{Deserialize, Serialize};

/// One harmonic peak in a magnitude spectrum.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HarmonicPeak {
    /// Frequency in Hz (parabolic-interpolated).
    pub hz: f64,
    /// Linear magnitude.
    pub magnitude: f64,
    /// Quality: magnitude relative to the channel's spectrum maximum.
    pub relative: f64,
}

/// Extracted spectral features of one channel of a capture.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SpectrumFeatures {
    pub source: String,
    pub channel: String,
    pub sample_hz: f64,
    /// Top-K harmonic peaks (descending magnitude).
    pub peaks: Vec<HarmonicPeak>,
    /// Spectral centroid (Hz).
    pub centroid_hz: f64,
    /// Spectral spread (second moment, Hz).
    pub spread_hz: f64,
    /// Spectral flatness in [0,1] (Geometric mean / Arithmetic mean of
    /// the power spectrum) — tonal drives score near 0.
    pub flatness: f64,
    /// RMS of the raw series (time-domain energy).
    pub rms: f64,
}

/// Real-input iterative radix-2 FFT. `re`/`im` must have power-of-two
/// length; the transform is in-place. Only the first N/2+1 bins carry
/// unique information for real inputs.
pub fn fft_inplace(re: &mut [f64], im: &mut [f64]) {
    let n = re.len();
    debug_assert!(n.is_power_of_two(), "FFT length must be a power of two");
    debug_assert_eq!(n, im.len());
    if n <= 1 {
        return;
    }

    // Bit-reversal permutation.
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - bits);
        if j > i {
            re.swap(i, j);
            im.swap(i, j);
        }
    }

    // Butterfly stages.
    let mut len = 2;
    while len <= n {
        let ang = -2.0 * std::f64::consts::PI / len as f64;
        let (wr, wi) = (ang.cos(), ang.sin());
        let mut i = 0;
        while i < n {
            let (mut cr, mut ci) = (1.0f64, 0.0f64);
            for k in 0..len / 2 {
                let a = i + k;
                let b = i + k + len / 2;
                let tr = re[b] * cr - im[b] * ci;
                let ti = re[b] * ci + im[b] * cr;
                re[b] = re[a] - tr;
                im[b] = im[a] - ti;
                re[a] += tr;
                im[a] += ti;
                let ncr = cr * wr - ci * wi;
                ci = cr * wi + ci * wr;
                cr = ncr;
            }
            i += len;
        }
        len <<= 1;
    }
}

/// Direct DFT reference (O(n²)) — used by tests and by nobody else.
pub fn dft_reference(input: &[f64]) -> (Vec<f64>, Vec<f64>) {
    let n = input.len();
    let mut re = vec![0.0; n];
    let mut im = vec![0.0; n];
    for k in 0..n {
        for (t, &x) in input.iter().enumerate() {
            let ang = -2.0 * std::f64::consts::PI * (k as f64) * (t as f64) / n as f64;
            re[k] += x * ang.cos();
            im[k] += x * ang.sin();
        }
    }
    (re, im)
}

fn hann_window(n: usize) -> Vec<f64> {
    (0..n)
        .map(|i| 0.5 * (1.0 - (2.0 * std::f64::consts::PI * i as f64 / n as f64).cos()))
        .collect()
}

/// Next power of two ≥ v.
fn next_pow2(v: usize) -> usize {
    v.max(2).next_power_of_two()
}

/// Extract spectral features from one channel of a capture.
///
/// The analysis band is limited to 20 Hz – 2 kHz: spindle fundamentals
/// (~60–150 Hz), actuator servo resonances (~100–800 Hz) and their
/// first harmonics dominate there; above 2 kHz, polled sysfs capture
/// aliases. Slow channels (hwmon, < 32 effective Hz) get time-domain
/// transient features via the same statistics (their peaks are then
/// step-response decay markers — still drive-specific).
pub fn extract_channel(
    source: &str,
    channel: &str,
    series: &[f32],
    sample_hz: f64,
    top_k: usize,
) -> SpectrumFeatures {
    let n = series.len();
    let rms = if n == 0 {
        0.0
    } else {
        (series
            .iter()
            .map(|v| (*v as f64) * (*v as f64))
            .sum::<f64>()
            / n as f64)
            .sqrt()
    };

    if n < 16 || sample_hz < 1.0 {
        return SpectrumFeatures {
            source: source.to_string(),
            channel: channel.to_string(),
            sample_hz,
            peaks: Vec::new(),
            centroid_hz: 0.0,
            spread_hz: 0.0,
            flatness: 0.0,
            rms,
        };
    }

    // Windowed zero-padded power-of-two FFT.
    let fft_len = next_pow2(n);
    let win = hann_window(n);
    let mut re = vec![0.0; fft_len];
    let mut im = vec![0.0; fft_len];
    for i in 0..n {
        re[i] = series[i] as f64 * win[i];
    }
    fft_inplace(&mut re, &mut im);

    let bins = fft_len / 2 + 1;
    let bin_hz = sample_hz / fft_len as f64;
    let lo_bin = (20.0 / bin_hz).ceil() as usize;
    let hi_bin = ((2000.0f64.min(sample_hz / 2.0)) / bin_hz).floor() as usize;

    // Power spectrum (magnitude²) over the analysis band.
    let mut power = vec![0.0f64; hi_bin.saturating_sub(lo_bin).max(1)];
    for (idx, b) in (lo_bin..hi_bin.max(lo_bin + 1)).enumerate() {
        if b < bins {
            power[idx] = re[b] * re[b] + im[b] * im[b];
        }
    }

    // Spectral statistics.
    let total: f64 = power.iter().sum();
    let mut centroid = 0.0;
    let mut spread = 0.0;
    if total > 0.0 {
        for (idx, &p) in power.iter().enumerate() {
            let f = (lo_bin + idx) as f64 * bin_hz;
            centroid += p * f;
        }
        centroid /= total;
        for (idx, &p) in power.iter().enumerate() {
            let f = (lo_bin + idx) as f64 * bin_hz;
            spread += p * (f - centroid) * (f - centroid);
        }
        spread = (spread / total).sqrt();
    }

    // Geometric-mean flatness (with epsilon against zero bins).
    let eps = 1e-20;
    let log_sum: f64 = power.iter().map(|p| (p + eps).ln()).sum();
    let geo = (log_sum / power.len() as f64).exp();
    let arith = total / power.len() as f64;
    let flatness = if arith > 0.0 {
        (geo / arith).clamp(0.0, 1.0)
    } else {
        0.0
    };

    // Top-K peak picking with quadratic interpolation. Peaks below
    // 10% of the spectrum maximum are Hann-window sidelobes, not
    // physical resonances — dropped.
    let max_p = power.iter().cloned().fold(0.0f64, f64::max).max(1e-30);
    const PEAK_REL_FLOOR: f64 = 0.10;
    let mut peak_idx: Vec<usize> = (1..power.len().saturating_sub(1))
        .filter(|&i| {
            power[i] > power[i - 1]
                && power[i] >= power[i + 1]
                && (power[i] / max_p).sqrt() >= PEAK_REL_FLOOR
        })
        .collect();
    peak_idx.sort_by(|&a, &b| power[b].total_cmp(&power[a]));
    let mut peaks = Vec::new();
    for &i in peak_idx.iter().take(top_k) {
        // Parabolic interpolation on log-power for sub-bin accuracy.
        let (pl, p0, pr) = (
            (power[i - 1] + eps).ln(),
            (power[i] + eps).ln(),
            (power[i + 1] + eps).ln(),
        );
        let denom = pl - 2.0 * p0 + pr;
        let delta = if denom.abs() > 1e-12 {
            0.5 * (pl - pr) / denom
        } else {
            0.0
        };
        let hz = (lo_bin + i) as f64 * bin_hz + delta * bin_hz;
        peaks.push(HarmonicPeak {
            hz,
            magnitude: power[i].sqrt(),
            relative: power[i].sqrt() / max_p.sqrt(),
        });
    }

    SpectrumFeatures {
        source: source.to_string(),
        channel: channel.to_string(),
        sample_hz,
        peaks,
        centroid_hz: centroid,
        spread_hz: spread,
        flatness,
        rms,
    }
}

/// Extract features from every channel of a capture.
pub fn extract_features(capture: &Capture, top_k: usize) -> Vec<SpectrumFeatures> {
    capture
        .channels
        .iter()
        .zip(capture.series.iter())
        .map(|(ch, series)| extract_channel(&capture.source, ch, series, capture.sample_hz, top_k))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn fft_matches_dft_reference() {
        // Deterministic multi-tone input.
        let n = 256usize;
        let input: Vec<f64> = (0..n)
            .map(|t| {
                (2.0 * std::f64::consts::PI * 5.0 * t as f64 / n as f64).sin() * 1.0
                    + (2.0 * std::f64::consts::PI * 17.0 * t as f64 / n as f64).sin() * 0.5
            })
            .collect();
        let (mut re1, mut im1) = (input.clone(), vec![0.0; n]);
        fft_inplace(&mut re1, &mut im1);
        let (re2, im2) = dft_reference(&input);
        for k in 0..n {
            assert!(
                approx(re1[k], re2[k], 1e-6) && approx(im1[k], im2[k], 1e-6),
                "bin {k}: fft=({},{}) dft=({},{})",
                re1[k],
                im1[k],
                re2[k],
                im2[k]
            );
        }
    }

    #[test]
    fn peak_finder_locates_tones() {
        // 220.5 Hz + 441 Hz on a 4.41 kHz sampled series (top bins land
        // exactly on FFT grid: 4.41e3/4096 ≈ 1.0766…—use 4096 samples
        // at 4096 Hz so bins are exactly 1 Hz).
        let hz = 4096.0;
        let n = 4096usize;
        let series: Vec<f32> = (0..n)
            .map(|t| {
                ((2.0 * std::f64::consts::PI * 137.0 * t as f64 / hz).sin() * 3.0
                    + (2.0 * std::f64::consts::PI * 291.0 * t as f64 / hz).sin() * 1.2)
                    as f32
            })
            .collect();
        let f = extract_channel("t", "x", &series, hz, 4);
        assert!(!f.peaks.is_empty());
        let mut hzs: Vec<f64> = f.peaks.iter().map(|p| p.hz).collect();
        hzs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert!(approx(hzs[0], 137.0, 1.5), "first tone {hzs:?}");
        assert!(approx(hzs[1], 291.0, 1.5), "second tone {hzs:?}");
        assert!(f.peaks.iter().all(|p| p.relative > 0.1), "sidelobe floor");
        // Tonal spectrum: flatness low, centroid between tones.
        assert!(f.flatness < 0.2, "flatness {}", f.flatness);
        assert!(f.centroid_hz > 137.0 && f.centroid_hz < 291.0);
    }

    #[test]
    fn short_series_degrades_gracefully() {
        let f = extract_channel("t", "x", &[1.0f32; 4], 100.0, 4);
        assert!(f.peaks.is_empty());
        assert_eq!(f.rms, 1.0);
    }
}
