//! # PRML read channel: Johnson-Nyquist floor & soft-decision LLRs.
//!
//! The proof instrument of the whole engine. After annihilation,
//! the head is micro-stepped back over the guard bands and the raw
//! read channel produces **soft-decision log-likelihood ratios**
//! (LLRs) for the hypothesis *"the previous recording's bit
//! `b_k` was +1"* at every cell. The certificate then proves those
//! LLRs are statistically indistinguishable from thermal noise.
//!
//! ## Physics
//!
//! **Johnson-Nyquist noise floor.** The read element's thermal
//! voltage noise over the channel bandwidth is
//!
//! ```text
//! σ_v = sqrt(4 · k_B · T · R · B)
//! ```
//!
//! with Boltzmann's constant `k_B`, media temperature `T`, read
//! element resistance `R` and channel bandwidth `B`. Expressed in
//! normalized read-signal units (nominal MR peak output = 1.0),
//! this is the amplitude reference every SNR in the certificate is
//! measured against — *the* thermal floor below which the mission
//! drives the old-bit signal (target: −20 dB).
//!
//! **PR4 partial response.** The classic `h(D) = 1 − D²` target
//! models the ISI of a saturating read path;
//! `y_k = x_k − x_{k−2} + n_k`. A 4-state max-log BCJR
//! (forward/backward Viterbi) turns the equalized samples into
//! per-bit soft decisions. Under noise-only input the LLR sequence
//! is zero-mean — any residual old-bit signal biases it, which is
//! exactly what the hypothesis test detects.
//!
//! **Aggregate multi-column estimator.** The MFM adversary reads
//! MANY lateral guard-band columns, each carrying an independently
//! noised copy of the same old-bit sequence (amplitude `a_c` per
//! column). Their optimal detector accumulates per-bit deflection
//! `Σ_c a_c²/σ²` — so the certificate must bound the *aggregate*
//! noncentrality `λ = K·Σ_c a_c²/σ²`, not any single column.
//! [`AggregateSnr`] fits per-column amplitudes with per-column
//! centering (removing the known constant wipe pattern), computes
//! the χ² omnibus statistic, and bounds `λ` at 99% confidence by
//! inverting the noncentral-χ² quantile equation
//! `T_obs = C + λ − z₀.₉₉·sqrt(2(C + 2λ))`.

use crate::SimRng;
/// Physical constants and front-end parameters of the read path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReadFrontEnd {
    /// Media temperature during readback (K).
    pub temperature_k: f64,
    /// Read-element resistance (Ω).
    pub resistance_ohm: f64,
    /// Channel bandwidth (Hz).
    pub bandwidth_hz: f64,
    /// Full-scale read signal (V, peak) the normalized unit maps to.
    pub full_scale_v: f64,
}

impl Default for ReadFrontEnd {
    fn default() -> Self {
        Self {
            temperature_k: 320.0,
            resistance_ohm: 45.0,
            bandwidth_hz: 300.0e6,
            full_scale_v: 1.0e-3,
        }
    }
}

/// Boltzmann constant (J/K).
pub const K_BOLTZMANN: f64 = 1.380_649e-23;

impl ReadFrontEnd {
    /// Johnson-Nyquist RMS noise voltage (V).
    pub fn johnson_nyquist_v(&self) -> f64 {
        (4.0 * K_BOLTZMANN * self.temperature_k * self.resistance_ohm * self.bandwidth_hz).sqrt()
    }

    /// Johnson-Nyquist floor in normalized read-signal units.
    ///
    /// This is σ of the additive Gaussian noise on every readback
    /// sample — the physical reference of all SNR claims.
    pub fn noise_sigma(&self) -> f64 {
        self.johnson_nyquist_v() / self.full_scale_v
    }
}

/// PR4 partial-response channel with additive Gaussian noise.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrmlChannel {
    /// Per-sample noise sigma (normalized units; typically the
    /// Johnson-Nyquist floor).
    pub noise_sigma: f64,
}

impl PrmlChannel {
    pub fn new(noise_sigma: f64) -> Self {
        Self { noise_sigma }
    }

    /// Equalize a ±1 symbol sequence through the PR4 target with
    /// additive noise: `y_k = x_k − x_{k−2} + n_k`.
    ///
    /// The two pre-history bits are treated as `+1` — the same
    /// convention the 4-state trellis of [`Self::soft_llrs`] uses
    /// for its initial state, so the first symbols decode coherently.
    pub fn run(&self, symbols: &[f64], rng: &mut SimRng) -> Vec<f64> {
        let sigma = self.noise_sigma;
        symbols
            .iter()
            .enumerate()
            .map(|(k, x)| {
                let past = if k >= 2 { symbols[k - 2] } else { 1.0 };
                x - past + sigma * rng.next_normal()
            })
            .collect()
    }

    /// 4-state max-log-BCJR soft-decision LLRs for the PR4
    /// trellis.
    ///
    /// Positive LLR ⇒ bit +1 more likely. Under noise-only the LLR
    /// distribution is symmetric around zero — the property the
    /// certificate's hypothesis test exploits.
    pub fn soft_llrs(&self, samples: &[f64]) -> Vec<f64> {
        let n = samples.len();
        if n == 0 {
            return Vec::new();
        }
        let s2 = 2.0 * self.noise_sigma * self.noise_sigma;
        // States: (b_{k-2}, b_{k-1}) as index (2*b_prev2 + b_prev1)
        // with bits mapped to ±1 via sign().
        const STATES: usize = 4;
        let neg_inf = f64::NEG_INFINITY;
        let mut alpha = [neg_inf; STATES];
        let mut beta = [neg_inf; STATES];
        // Initial state 0 (both history bits treated as 0 → sign +1).
        alpha[0] = 0.0;
        // Forward pass.
        let mut alpha_hist: Vec<[f64; STATES]> = Vec::with_capacity(n + 1);
        alpha_hist.push(alpha);
        for y_k in samples.iter() {
            let mut next = [neg_inf; STATES];
            for (s, a_s) in alpha.iter().enumerate() {
                if *a_s == neg_inf {
                    continue;
                }
                let (b_prev2, b_prev1) = state_bits(s);
                for bit in 0..2u8 {
                    let x = if bit == 0 { 1.0 } else { -1.0 };
                    let x_prev2 = if b_prev2 == 0 { 1.0 } else { -1.0 };
                    let out = x - x_prev2;
                    // Path likelihood metric (maximized): negative
                    // squared distance / (2σ²).
                    let metric = -(y_k - out).powi(2) / s2;
                    let ns = state_index(b_prev1, bit);
                    let cand = a_s + metric;
                    if cand > next[ns] {
                        next[ns] = cand;
                    }
                }
            }
            alpha = next;
            alpha_hist.push(alpha);
        }
        // Terminal: any state admissible (data may end mid-stream).
        for b in beta.iter_mut() {
            *b = 0.0;
        }
        // Backward pass, storing per-step beta.
        let mut beta_hist: Vec<[f64; STATES]> = vec![[neg_inf; STATES]; n + 1];
        beta_hist[n] = beta;
        for k in (0..n).rev() {
            let mut next = [neg_inf; STATES];
            for (s, next_s) in next.iter_mut().enumerate() {
                let (b_prev2, b_prev1) = state_bits(s);
                for bit in 0..2u8 {
                    let x = if bit == 0 { 1.0 } else { -1.0 };
                    let x_prev2 = if b_prev2 == 0 { 1.0 } else { -1.0 };
                    let out = x - x_prev2;
                    let metric = -(samples[k] - out).powi(2) / s2;
                    let ns = state_index(b_prev1, bit);
                    let cand = beta_hist[k + 1][ns] + metric;
                    if cand > *next_s {
                        *next_s = cand;
                    }
                }
            }
            beta_hist[k] = next;
        }
        // LLR_k = M(b_k = +1) − M(b_k = −1) over merged paths
        // (likelihood metrics: higher = better).
        let mut llrs = Vec::with_capacity(n);
        for (k, y_k) in samples.iter().enumerate() {
            let mut m_plus = neg_inf;
            let mut m_minus = neg_inf;
            for (s, alpha_k_s) in alpha_hist[k].iter().enumerate() {
                if *alpha_k_s == neg_inf {
                    continue;
                }
                let (b_prev2, _b_prev1) = state_bits(s);
                let x_prev2 = if b_prev2 == 0 { 1.0 } else { -1.0 };
                for bit in 0..2u8 {
                    let x = if bit == 0 { 1.0 } else { -1.0 };
                    let out = x - x_prev2;
                    let metric = -(y_k - out).powi(2) / s2;
                    let ns = ((state_bits(s).1 as usize) << 1) | bit as usize;
                    let total = alpha_k_s + metric + beta_hist[k + 1][ns];
                    if bit == 0 {
                        m_plus = m_plus.max(total);
                    } else {
                        m_minus = m_minus.max(total);
                    }
                }
            }
            if m_plus == neg_inf && m_minus == neg_inf {
                llrs.push(0.0);
            } else if m_plus == neg_inf {
                llrs.push(-f64::INFINITY);
            } else if m_minus == neg_inf {
                llrs.push(f64::INFINITY);
            } else {
                llrs.push(m_plus - m_minus);
            }
        }
        llrs
    }
}

#[inline]
fn state_bits(s: usize) -> (u8, u8) {
    (((s >> 1) & 1) as u8, (s & 1) as u8)
}

#[inline]
fn state_index(prev2: u8, prev1: u8) -> usize {
    ((prev2 as usize) << 1) | prev1 as usize
}

/// ln Γ(1/2) = ln √π.
const LN_GAMMA_HALF: f64 = 0.572_364_942_924_700_1;

/// Upper regularized incomplete gamma `Q(1/2, x)` via the standard
/// series / continued-fraction pair (Numerical Recipes §6.2,
/// double-precision convergence).
///
/// `Q(1/2, x) = erfc(sqrt(x))` — this is the engine behind a
/// full-precision `Q` function; the tail at 10⁻⁶ matters for the
/// Neyman-Pearson bounds.
fn gammq_half(x: f64) -> f64 {
    if x < 1.5 {
        // Series for P(1/2, x).
        let mut ap = 0.5_f64;
        let mut sum = 1.0 / ap;
        let mut del = sum;
        for _ in 0..1000 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * 1e-17 {
                break;
            }
        }
        let p = sum * (-x + 0.5 * x.ln() - LN_GAMMA_HALF).exp();
        1.0 - p
    } else {
        // Modified Lentz continued fraction for Q(1/2, x).
        let tiny = 1e-300;
        let mut b = x + 0.5;
        let mut c = 1.0 / tiny;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..1000 {
            let an = -(i as f64) * (i as f64 - 0.5);
            b += 2.0;
            d = an * d + b;
            if d.abs() < tiny {
                d = tiny;
            }
            c = b + an / c;
            if c.abs() < tiny {
                c = tiny;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < 1e-17 {
                break;
            }
        }
        (-x + 0.5 * x.ln() - LN_GAMMA_HALF).exp() * h
    }
}

/// Upper tail of the standard normal: `Q(x) = P(Z > x)`.
///
/// Negative arguments use the symmetry `Q(−x) = 1 − Q(x)` (the
/// incomplete-gamma engine only covers the upper tail).
pub fn q_function(x: f64) -> f64 {
    if x >= 0.0 {
        0.5 * gammq_half(0.5 * x * x)
    } else {
        1.0 - 0.5 * gammq_half(0.5 * x * x)
    }
}

/// Inverse of `Q` via bisection on the CDF (monotone, doubles the
/// mantissa every two iterations).
pub fn q_inverse(p: f64) -> f64 {
    assert!((0.0..=1.0).contains(&p), "p must be a probability");
    if p >= 1.0 {
        return f64::NEG_INFINITY;
    }
    if p <= 0.0 {
        return f64::INFINITY;
    }
    let mut lo = -40.0;
    let mut hi = 40.0;
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if q_function(mid) > p {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    0.5 * (lo + hi)
}

/// 99% one-sided z-quantile: `z₀.₉₉ = Q⁻¹(0.01)`.
pub const Z99: f64 = 2.326_347_874_040_840_8;

/// Matched-filter LLR of a known-plaintext adversary for
/// `z_k = a·b_k + w_k` with noise sigma.
#[inline]
pub fn matched_filter_llr(z: f64, b: f64, amplitude: f64, sigma: f64) -> f64 {
    2.0 * amplitude * z * b / (sigma * sigma)
}

/// Detection horizon: independent bits an adversary needs to
/// separate "old data present" from "wiped" at false-alarm
/// probability `p_fa` and detection power `p_d`, given per-bit
/// linear SNR.
///
/// From the Neyman-Pearson lemma, the optimal detector's required
/// sample count for two Gaussian-mean hypotheses is
/// `n* = (Q⁻¹(p_fa) − Q⁻¹(p_d))² / SNR`.
pub fn detection_horizon(snr_linear: f64, p_fa: f64, p_d: f64) -> f64 {
    if snr_linear <= 0.0 {
        return f64::INFINITY;
    }
    let z_fa = q_inverse(p_fa);
    let z_d = q_inverse(p_d);
    let sep = z_fa - z_d;
    (sep * sep) / snr_linear
}

/// Multi-column aggregate SNR estimate — the statistically sound
/// bound on what a bank-of-columns MFM adversary can extract.
///
/// Model per column `c`: `z_ck = μ_c + a_c·b_k + w_ck`, with the
/// constant `μ_c` absorbing the (adversary-known) final wipe
/// pattern and any residual DC. The estimator:
///
/// * fits `â_c` per column (per-column centering removes `μ_c`),
/// * pools `â = Σ_c â_c / C` (detects sign-aligned ghosts),
/// * computes the omnibus statistic `T = K·Σ_c â_c²/σ̂²`
///   (`χ²_C`-distributed under the noise-only hypothesis —
///   catches any sign-mixing configuration),
/// * bounds the aggregate noncentrality
///   `λ = K·Σ_c a_c²/σ²` at 99% by inverting the noncentral-χ²
///   quantile equation
///   `T_obs = C + λ − z₀.₉₉·sqrt(2(C + 2λ))`.
///
/// The adversary's per-bit aggregate SNR is `λ/K`; that is the
/// quantity the certificate drives below −20 dB.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregateSnr {
    /// Per-column amplitude estimates `â_c`.
    pub per_column_amplitude: Vec<f64>,
    /// Pooled (sign-aligned) amplitude estimate.
    pub pooled_amplitude: f64,
    /// Centered-residual noise sigma.
    pub sigma: f64,
    /// Omnibus statistic `T = K·Σ â_c²/σ̂²`.
    pub chi2: f64,
    /// Number of columns (χ² degrees of freedom).
    pub dof: usize,
    /// 99% upper bound on the aggregate noncentrality λ.
    pub lambda_upper: f64,
    /// Bit cells per column.
    pub cells: usize,
}

impl AggregateSnr {
    /// Fit from a column-major readback matrix `z_columns` (one
    /// vector per lateral column) and the known-plaintext bits `b`.
    pub fn fit(z_columns: &[Vec<f64>], b: &[f64]) -> Self {
        let k = b.len();
        let c = z_columns.len();
        assert!(c > 0 && k > 0, "need at least one column and one cell");
        let mut per_column = Vec::with_capacity(c);
        let mut sum_pooled = 0.0_f64;
        let mut sse = 0.0_f64;
        for zc in z_columns {
            let mu = zc.iter().sum::<f64>() / k as f64;
            let mut dot = 0.0_f64;
            for (z, bi) in zc.iter().zip(b) {
                dot += (z - mu) * bi;
            }
            let amp = dot / k as f64;
            per_column.push(amp);
            sum_pooled += dot;
            for (z, bi) in zc.iter().zip(b) {
                let r = (z - mu) - amp * bi;
                sse += r * r;
            }
        }
        let pooled = sum_pooled / (c * k) as f64;
        let sigma = (sse / (c * k) as f64).sqrt();
        let chi2 = if sigma > 0.0 {
            per_column.iter().map(|a| k as f64 * a * a).sum::<f64>() / (sigma * sigma)
        } else {
            0.0
        };
        let lambda_upper = lambda_upper_bound(chi2, c);
        Self {
            per_column_amplitude: per_column,
            pooled_amplitude: pooled,
            sigma,
            chi2,
            dof: c,
            lambda_upper,
            cells: k,
        }
    }

    /// Point estimate of the per-bit aggregate SNR (dB).
    pub fn per_bit_snr_db(&self) -> f64 {
        10.0 * (self.chi2 / self.cells as f64).log10()
    }

    /// 99% upper bound on the per-bit aggregate SNR (dB) —
    /// **the certified number**.
    pub fn per_bit_snr_upper_db(&self) -> f64 {
        10.0 * (self.lambda_upper / self.cells as f64).log10()
    }

    /// Sign-aligned pooled SNR (dB) — what a naive single-pool
    /// adversary measures on a bright, aligned ghost.
    pub fn pooled_snr_db(&self) -> f64 {
        if self.sigma <= 0.0 {
            return f64::INFINITY;
        }
        let r = self.pooled_amplitude / self.sigma;
        10.0 * (r * r).log10()
    }

    /// Bits an optimal distinguisher needs at the certified bound.
    pub fn detection_horizon_bits(&self, p_fa: f64, p_d: f64) -> f64 {
        detection_horizon(self.lambda_upper / self.cells as f64, p_fa, p_d)
    }
}

/// Solve `T_obs = C + λ − z₀.₉₉·sqrt(2(C + 2λ))` for the largest
/// non-excluded λ (scan-then-bisect: the rhs is convex in λ).
fn lambda_upper_bound(t_obs: f64, dof: usize) -> f64 {
    let c = dof as f64;
    let g = |lam: f64| -> f64 { c + lam - Z99 * (2.0 * (c + 2.0 * lam)).sqrt() - t_obs };
    // Scan up in λ for a sign change of g (g convex, tends to +∞).
    let mut lo = 0.0_f64;
    let mut hi = 1.0_f64;
    let mut iters = 0;
    while g(hi) < 0.0 && iters < 60 {
        hi *= 2.0;
        iters += 1;
    }
    if g(hi) < 0.0 {
        return f64::INFINITY; // not bounded within range — signal is loud
    }
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if g(mid) < 0.0 {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi.max(0.0)
}

/// Single-column SNR estimate (legacy/simple path, used for
/// exposition and the baseline single-column read).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnrEstimate {
    /// Estimated amplitude `â` of the old-bit signal.
    pub amplitude: f64,
    /// Residual noise sigma.
    pub sigma: f64,
    /// Sample count.
    pub n: usize,
}

impl SnrEstimate {
    /// Estimate `a` and `sigma` from observed samples `z` against
    /// the known old bits `b` (±1).
    pub fn fit(z: &[f64], b: &[f64]) -> Self {
        assert_eq!(z.len(), b.len(), "z and b must be paired");
        let n = z.len().max(1);
        let amp = z.iter().zip(b).map(|(zi, bi)| zi * bi).sum::<f64>() / n as f64;
        let sigma = (z
            .iter()
            .zip(b)
            .map(|(zi, bi)| {
                let r = zi - amp * bi;
                r * r
            })
            .sum::<f64>()
            / n as f64)
            .sqrt();
        Self {
            amplitude: amp,
            sigma,
            n: z.len(),
        }
    }

    /// Per-cell amplitude SNR (linear).
    pub fn snr_linear(&self) -> f64 {
        if self.sigma <= 0.0 {
            return f64::INFINITY;
        }
        (self.amplitude * self.amplitude) / (self.sigma * self.sigma)
    }

    /// Per-cell amplitude SNR in dB.
    pub fn snr_db(&self) -> f64 {
        10.0 * self.snr_linear().log10()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn johnson_nyquist_floor_matches_the_physics() {
        let fe = ReadFrontEnd::default();
        // sqrt(4 k T R B) = sqrt(4 · 1.38e-23 · 320 · 45 · 3e8) ≈ 13.8 µV.
        let v = fe.johnson_nyquist_v();
        assert!((1.2e-5..1.6e-5).contains(&v), "σ_v = {v} V");
        // Normalized: ~0.0138 in read-signal units.
        let sigma = fe.noise_sigma();
        assert!((0.010..0.020).contains(&sigma), "σ = {sigma}");
    }

    #[test]
    fn pr4_channel_implements_the_target() {
        let ch = PrmlChannel::new(0.001); // near-noiseless
        let mut rng = SimRng::new(5);
        // x = +1 at i%3==0 else −1.
        let syms: Vec<f64> = (0..32)
            .map(|i| if i % 3 == 0 { 1.0 } else { -1.0 })
            .collect();
        let y = ch.run(&syms, &mut rng);
        assert_eq!(y.len(), 32);
        // y_3 = x_3 − x_1 = +1 − (−1) = +2.
        assert!((y[3] - 2.0).abs() < 0.01, "y3 = {}", y[3]);
        // y_4 = x_4 − x_2 = −1 − (−1) = 0.
        assert!((y[4] - 0.0).abs() < 0.01, "y4 = {}", y[4]);
        // y_0 = x_0 − (+1 pre-history) = 0.
        assert!((y[0] - 0.0).abs() < 0.01, "y0 = {}", y[0]);
    }

    #[test]
    fn soft_llrs_recover_symbols_at_low_noise() {
        let ch = PrmlChannel::new(0.02);
        let mut rng = SimRng::new(9);
        let syms: Vec<f64> = (0..256)
            .map(|i| if (i / 7) % 2 == 0 { 1.0 } else { -1.0 })
            .collect();
        let y = ch.run(&syms, &mut rng);
        let llrs = ch.soft_llrs(&y);
        let mut correct = 0usize;
        for (k, l) in llrs.iter().enumerate() {
            if (*l > 0.0) == (syms[k] > 0.0) {
                correct += 1;
            }
        }
        assert!(
            correct >= 250,
            "PR4 max-log decoded {correct}/256 symbols at σ=0.02"
        );
    }

    #[test]
    fn constant_wipe_pattern_decodes_as_one_consistent_symbol() {
        // The wiped track reads back as the constant zero-symbol.
        // PR4's duo-binary null at DC makes +1 and −1 constants
        // indistinguishable (both equalize to y ≈ 0) — exactly what
        // a wiped track should look like: a consistent constant
        // with no per-bit structure. The BCJR must decode ALL bits
        // to one symbol (any mixture would be residual data).
        let ch = PrmlChannel::new(0.03);
        let mut rng = SimRng::new(21);
        let wipe = vec![-1.0_f64; 512];
        let y = ch.run(&wipe, &mut rng);
        let llrs = ch.soft_llrs(&y);
        let pos = llrs.iter().filter(|l| **l > 0.0).count();
        let neg = llrs.iter().filter(|l| **l < 0.0).count();
        assert!(
            pos.min(neg) <= llrs.len() / 20,
            "constant wipe must decode consistently (pos={pos}, neg={neg})"
        );
        // And the decode is confident (large |LLR|), not a coin
        // toss: median |LLR| well above the noise unit.
        let mut abs_sorted: Vec<f64> = llrs.iter().map(|l| l.abs()).collect();
        abs_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = abs_sorted[abs_sorted.len() / 2];
        assert!(median > 0.5, "median |LLR| = {median} — decode too soft");
    }

    #[test]
    fn aggregate_estimator_certifies_a_clean_wipe() {
        // 8 columns of pure centered noise, 4096 cells: per-bit
        // aggregate bound must land below −20 dB.
        let mut rng = SimRng::new(31);
        let k = 4096usize;
        let b: Vec<f64> = (0..k)
            .map(|_| if rng.next_f64() < 0.5 { 1.0 } else { -1.0 })
            .collect();
        let cols: Vec<Vec<f64>> = (0..8)
            .map(|_| {
                // A known constant wipe pattern (removed by
                // per-column centering) plus instrument noise.
                let mu = 0.3;
                (0..k).map(|_| mu + 0.15 * rng.next_normal()).collect()
            })
            .collect();
        let est = AggregateSnr::fit(&cols, &b);
        assert!(
            est.per_bit_snr_upper_db() < -20.0,
            "clean wipe bound {} dB",
            est.per_bit_snr_upper_db()
        );
        // Omnibus statistic in its null range: χ²_8 ≈ 15.5 at the
        // 95th percentile.
        assert!(est.chi2 < 20.0, "χ² = {}", est.chi2);
    }

    #[test]
    fn aggregate_estimator_flags_a_bright_aligned_ghost() {
        let mut rng = SimRng::new(37);
        let k = 4096usize;
        let b: Vec<f64> = (0..k)
            .map(|_| if rng.next_f64() < 0.5 { 1.0 } else { -1.0 })
            .collect();
        let cols: Vec<Vec<f64>> = (0..8)
            .map(|_| {
                (0..k)
                    .map(|i| 0.4 * b[i] + 0.1 * rng.next_normal())
                    .collect()
            })
            .collect();
        let est = AggregateSnr::fit(&cols, &b);
        // Pooled SNR ≈ (0.4/0.1)² ≈ +12 dB; horizon collapses to a
        // handful of bits.
        assert!(
            est.pooled_snr_db() > 5.0,
            "pooled {} dB",
            est.pooled_snr_db()
        );
        assert!(est.detection_horizon_bits(1e-6, 0.99) < 200.0);
    }

    #[test]
    fn aggregate_estimator_catches_sign_mixed_ghosts() {
        // Opposite-sign amplitudes across columns: the pooled
        // estimate cancels, the omnibus χ² does not.
        let mut rng = SimRng::new(41);
        let k = 2048usize;
        let b: Vec<f64> = (0..k)
            .map(|_| if rng.next_f64() < 0.5 { 1.0 } else { -1.0 })
            .collect();
        let cols: Vec<Vec<f64>> = (0..8)
            .enumerate()
            .map(|(c, _)| {
                let sign = if c % 2 == 0 { 1.0 } else { -1.0 };
                (0..k)
                    .map(|i| sign * 0.3 * b[i] + 0.08 * rng.next_normal())
                    .collect()
            })
            .collect();
        let est = AggregateSnr::fit(&cols, &b);
        assert!(est.pooled_amplitude.abs() < 0.05, "pooled cancels");
        assert!(
            est.per_bit_snr_upper_db() > 0.0,
            "omnibus bound {} dB must flag the mixed ghost",
            est.per_bit_snr_upper_db()
        );
    }

    #[test]
    fn snr_estimate_recovers_a_known_amplitude() {
        let mut rng = SimRng::new(13);
        let a = 0.05_f64;
        let sigma = 0.14_f64;
        let mut z = Vec::new();
        let mut b = Vec::new();
        for _ in 0..4096 {
            let bit = if rng.next_f64() < 0.5 { 1.0 } else { -1.0 };
            b.push(bit);
            z.push(a * bit + sigma * rng.next_normal());
        }
        let est = SnrEstimate::fit(&z, &b);
        assert!((est.amplitude - a).abs() < 0.01, "â = {}", est.amplitude);
        assert!((est.sigma - sigma).abs() < 0.01, "σ̂ = {}", est.sigma);
        assert!((est.snr_db() - 10.0 * (a * a / (sigma * sigma)).log10()).abs() < 1.0);
    }

    #[test]
    fn q_function_and_inverse_agree() {
        for p in [0.1_f64, 0.01, 1e-3, 1e-6] {
            let x = q_inverse(p);
            let back = q_function(x);
            assert!(((back - p) / p).abs() < 1e-9, "Q({x}) = {back} vs {p}");
        }
        // Known values: Q(1.2816) ≈ 0.10, Q(4.7534) ≈ 1e-6.
        assert!((q_function(1.281_551_565_544_600_4) - 0.1).abs() < 1e-12);
        assert!((q_function(4.753_424_308_822_899) - 1e-6).abs() < 1e-15);
        // erfc identities through gammq_half: Q(0) = 0.5 exactly.
        assert!((q_function(0.0) - 0.5).abs() < 1e-15);
    }

    #[test]
    fn detection_horizon_scales_as_one_over_snr() {
        // At SNR = 0.01 (−20 dB), P_FA=1e-6, P_D=0.99:
        // (4.7534 + 2.3263)² ≈ 50.1 → 5010 cells.
        let n = detection_horizon(0.01, 1e-6, 0.99);
        assert!((n - 5010.0).abs() < 15.0, "horizon = {n}");
        let n2 = detection_horizon(0.001, 1e-6, 0.99);
        assert!((n2 / n - 10.0).abs() < 0.01, "10 dB deeper → 10× the cells");
        assert_eq!(detection_horizon(0.0, 1e-6, 0.99), f64::INFINITY);
    }

    #[test]
    fn lambda_upper_bound_is_monotone_and_conservative() {
        // Null-range observations get bounded; loud ones blow up.
        let quiet = lambda_upper_bound(10.0, 8);
        assert!(quiet > 0.0 && quiet < 60.0, "quiet bound = {quiet}");
        let loud = lambda_upper_bound(200.0, 8);
        assert!(loud > 150.0, "loud bound = {loud}");
        assert!(lambda_upper_bound(1e9, 8) > 1e8);
        // Monotone in T.
        assert!(lambda_upper_bound(20.0, 8) > quiet);
    }
}
