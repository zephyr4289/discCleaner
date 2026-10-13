//! Sub-microsecond program/erase latency statistics.
//!
//! The ISPP (incremental step-pulse programming) loop and the
//! erase-verify retry loop are the controller's timing knobs. A
//! fresh cell programs in the first one or two ISPP steps; a worn
//! cell — its floating gate darkened by trapped charge — needs more
//! steps, more often. The controller cannot hide this without also
//! hiding the wall-clock time each operation takes, which is exactly
//! what the host CAN measure: sub-microsecond timestamp deltas
//! around write/erase submissions.
//!
//! This module turns raw latency samples into distribution evidence:
//! histograms, descriptive statistics, and a two-sample comparison
//! between a fresh baseline and a stressed population with a
//! Welch-style t statistic (large samples → effectively normal by
//! CLT) that says how many sigmas the stressed channel sits from
//! the fresh one.

use serde::{Deserialize, Serialize};

/// One measured operation latency, nanosecond resolution.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct LatencySample {
    /// Operation kind tag ("program" / "erase" / "read").
    pub op: &'static str,
    /// Latency in nanoseconds.
    pub ns: u64,
}

/// Descriptive statistics over a latency population.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LatencyStats {
    pub n: usize,
    pub min_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
    /// Population variance (ns²).
    pub var_ns2: f64,
    /// 50th percentile.
    pub p50_ns: u64,
    /// 95th percentile.
    pub p95_ns: u64,
    /// 99th percentile.
    pub p99_ns: u64,
}

impl LatencyStats {
    /// Compute stats over raw samples (op-uniform: one call per op kind).
    pub fn compute(samples: &[u64]) -> Self {
        assert!(!samples.is_empty(), "latency stats need samples");
        let mut s = samples.to_vec();
        s.sort_unstable();
        let n = s.len();
        let mean = s.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
        let var = if n > 1 {
            s.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / n as f64
        } else {
            0.0
        };
        Self {
            n,
            min_ns: s[0],
            max_ns: s[n - 1],
            mean_ns: mean,
            var_ns2: var,
            p50_ns: percentile_sorted(&s, 0.50),
            p95_ns: percentile_sorted(&s, 0.95),
            p99_ns: percentile_sorted(&s, 0.99),
        }
    }

    /// Coefficient of variation — the wear-sensitive shape metric:
    /// worn channels show heavier ISPP-retry tails, i.e. relative
    /// variance grows even when the mean is normalized away.
    pub fn cv(&self) -> f64 {
        if self.mean_ns > 0.0 {
            self.var_ns2.sqrt() / self.mean_ns
        } else {
            0.0
        }
    }
}

fn percentile_sorted(sorted: &[u64], q: f64) -> u64 {
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Fixed-width histogram (log2-spaced bins over [lo, hi]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatencyHistogram {
    /// Bin lower bounds (ns), monotone.
    pub bin_edges_ns: Vec<u64>,
    /// Counts per bin.
    pub counts: Vec<u64>,
}

impl LatencyHistogram {
    /// Build a histogram of `bins` log2-spaced buckets spanning the
    /// observed range.
    pub fn build(samples: &[u64], bins: usize) -> Self {
        assert!(bins >= 2, "need at least 2 bins");
        let min = *samples.iter().min().expect("samples");
        let max = (*samples.iter().max().expect("samples")).max(min + 1);
        // log2-spaced edges: edge_i = 2^(log2(lo) + i/(b-1) * log2(hi/lo))
        let (lo2, hi2) = ((min as f64).log2(), (max as f64).log2());
        let mut edges: Vec<u64> = Vec::with_capacity(bins);
        for i in 0..bins {
            let e = 2f64.powf(lo2 + (i as f64 / (bins - 1) as f64) * (hi2 - lo2));
            edges.push(e.round() as u64);
        }
        edges[bins - 1] = max; // clamp float wobble at the top
        let mut counts = vec![0u64; bins - 1];
        for &s in samples {
            let mut b = counts.len() - 1;
            for (i, &e) in edges.iter().enumerate().skip(1) {
                if s < e {
                    b = i - 1;
                    break;
                }
            }
            counts[b] += 1;
        }
        Self {
            bin_edges_ns: edges,
            counts,
        }
    }
}

/// Two-sample Welch t statistic (stressed vs baseline).
///
/// Not a hypothesis test engine: the certificate keeps the t value
/// itself as evidence ("how many sigmas apart") and applies its own
/// thresholds — the wear verdict must remain auditable arithmetic,
/// not a p-value black box.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ShiftEvidence {
    /// Welch t statistic (|t| sigmas of separation).
    pub t: f64,
    /// Mean shift in ns (stressed − baseline).
    pub delta_mean_ns: f64,
    /// Variance ratio (stressed / baseline).
    pub var_ratio: f64,
}

impl ShiftEvidence {
    pub fn compare(baseline: &LatencyStats, stressed: &LatencyStats) -> Self {
        let (n1, n2) = (baseline.n as f64, stressed.n as f64);
        let se = ((baseline.var_ns2 / n1) + (stressed.var_ns2 / n2)).sqrt();
        let t = if se > 0.0 {
            (stressed.mean_ns - baseline.mean_ns) / se
        } else {
            0.0
        };
        Self {
            t,
            delta_mean_ns: stressed.mean_ns - baseline.mean_ns,
            var_ratio: if baseline.var_ns2 > 0.0 {
                stressed.var_ns2 / baseline.var_ns2
            } else {
                1.0
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_describe_a_population() {
        // 1..=100 ns: mean 50.5, known variance.
        let samples: Vec<u64> = (1..=100).collect();
        let s = LatencyStats::compute(&samples);
        assert_eq!(s.n, 100);
        assert_eq!(s.min_ns, 1);
        assert_eq!(s.max_ns, 100);
        assert!((s.mean_ns - 50.5).abs() < 1e-9);
        // variance of 1..100 = (100^2-1)/12 = 833.25
        assert!((s.var_ns2 - 833.25).abs() < 1e-6);
        assert!(s.p50_ns >= 49 && s.p50_ns <= 52);
        assert!(s.p95_ns >= 90 && s.p95_ns <= 96);
        assert!(s.p99_ns >= 96 && s.p99_ns <= 100);
        assert!(s.cv() > 0.5, "uniform 1..100 has cv ~0.57");
    }

    #[test]
    fn histogram_buckets_everything() {
        let samples: Vec<u64> = (1..=64).collect();
        let h = LatencyHistogram::build(&samples, 8);
        assert_eq!(h.counts.iter().sum::<u64>(), 64);
        // Edges are monotone non-decreasing.
        let mut prev = 0;
        for &e in &h.bin_edges_ns {
            assert!(e >= prev);
            prev = e;
        }
    }

    #[test]
    fn welch_shift_separates_worn_from_fresh() {
        // Fresh: tight around 100 ns. Worn: wider, slower, ~200 ns.
        let fresh: Vec<u64> = (0..256).map(|i| 95 + (i % 11) as u64).collect();
        let worn: Vec<u64> = (0..256).map(|i| 150 + ((i * 31) % 200) as u64).collect();
        let f = LatencyStats::compute(&fresh);
        let w = LatencyStats::compute(&worn);
        let ev = ShiftEvidence::compare(&f, &w);
        assert!(ev.t > 10.0, "t={}", ev.t);
        assert!(ev.delta_mean_ns > 50.0);
        assert!(ev.var_ratio > 5.0);
        // Identity comparison: zero separation.
        let self_ev = ShiftEvidence::compare(&f, &f);
        assert!(self_ev.t.abs() < 1e-9);
        assert!((self_ev.delta_mean_ns).abs() < 1e-9);
        assert!((self_ev.var_ratio - 1.0).abs() < 1e-9);
    }

    #[test]
    fn single_sample_does_not_nan() {
        let s = LatencyStats::compute(&[42]);
        assert_eq!(s.mean_ns, 42.0);
        assert_eq!(s.var_ns2, 0.0);
        assert_eq!(s.cv(), 0.0);
        let _ = ShiftEvidence::compare(&s, &s);
    }
}
