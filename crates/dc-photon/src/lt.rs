//! Luby Transform (LT) fountain coding (v0.8.0, Vector 3).
//!
//! The evidence stream must be extractable from a SCIF over *photons only*:
//! a terminal screen photographed or scanned by an approved device. A
//! single QR frame cannot carry a 20 KB certificate, and any frame may be
//! blurred or skipped by the capture. Fountain coding dissolves the
//! problem: the transmitter emits an UNBOUNDED stream of encoded symbols,
//! and the receiver reconstructs the payload from any k·(1+ε) of them —
//! no frame ordering, no retransmission, no back-channel.
//!
//! Implementation notes:
//! - Robust Soliton degree distribution (Luby, "LT Codes", FOCS 2002):
//!   ideal-soliton body plus a spike near k/R with R = c·ln(k/δ)·√k,
//!   c = 0.1, δ = 0.5. Normalization absorbs the constant factor; only
//!   the shape is load-bearing (pinned by tests below).
//! - Symbol neighbors derive deterministically from (stream_seed,
//!   symbol_id) via splitmix64 — no per-symbol metadata on the wire.
//! - Decoding is ripple-driven peeling, O(k log k) expected.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LtError {
    #[error("fountain decode failed: decoded {decoded}/{total} blocks — capture more frames")]
    DecodeIncomplete { decoded: usize, total: usize },
    #[error("fountain parameter invalid: {0}")]
    Invalid(String),
}

/// Splitmix64: deterministic, well-mixed. Carries no secrecy — its only
/// job is binding (stream_seed, symbol_id) → neighbor set identically on
/// both sides of the air gap.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Debiased uniform value in [0, bound) (Lemire).
    fn below(&mut self, bound: u64) -> u64 {
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let x = self.next();
            let m = (x as u128) * (bound as u128);
            let lo = m as u64;
            if lo >= threshold {
                return (m >> 64) as u64;
            }
        }
    }
}

/// Robust Soliton probability mass over degrees 1..=k (index 0 unused).
pub fn robust_soliton(k: usize, c: f64, delta: f64) -> Vec<f64> {
    let k_f = k.max(1) as f64;
    // Ideal soliton body.
    let mut rho = vec![0.0f64; k + 1];
    rho[1] = 1.0 / k_f;
    for (i, slot) in rho.iter_mut().enumerate().skip(2) {
        *slot = 1.0 / ((i as f64) * (i as f64 - 1.0));
    }
    // Robustness spike around k/R.
    let r = (c * (k_f / delta).ln() * k_f.sqrt()).max(1.0);
    let spike = ((k_f / r).floor() as usize).clamp(1, k);
    let mut tau = vec![0.0f64; k + 1];
    for (i, slot) in tau.iter_mut().enumerate().take(spike).skip(1) {
        *slot = r / ((i as f64) * (spike as f64));
    }
    tau[spike] = (r * (r / delta).ln()) / (spike as f64);
    if !tau[spike].is_finite() || tau[spike] < 0.0 {
        tau[spike] = 0.0;
    }
    // μ = (ρ + τ) / Z
    let mut mu = vec![0.0f64; k + 1];
    let mut sum = 0.0;
    for i in 1..=k {
        mu[i] = (rho[i] + tau[i]).max(0.0);
        sum += mu[i];
    }
    if sum > 0.0 {
        for v in &mut mu {
            *v /= sum;
        }
    }
    mu
}

fn build_cdf(mu: &[f64]) -> Vec<f64> {
    let mut cdf = Vec::with_capacity(mu.len().saturating_sub(1));
    let mut acc = 0.0f64;
    for v in &mu[1..] {
        acc += v;
        cdf.push(acc.min(1.0));
    }
    cdf
}

fn sample_degree(rng: &mut SplitMix64, cdf: &[f64]) -> usize {
    let x = (rng.next() as f64) / (u64::MAX as f64);
    let idx = cdf
        .partition_point(|c| *c < x)
        .min(cdf.len().saturating_sub(1));
    idx + 1
}

/// Neighbor derivation shared by encoder and decoder.
///
/// **Systematic-first design**: symbol ids `0..k` ARE the source blocks
/// (degree 1, verbatim) — a clean capture decodes at ~zero overhead; the
/// fountain tail (ids ≥ k, rebased to 0.. for seeding) repairs any blocks
/// the scanner missed. This mirrors the systematic-LT construction used by
/// production fountain implementations and is pinned by the loss-tolerance
/// tests at up to 50% frame loss.
fn neighbors(symbol_id: u64, k: usize, cdf: &[f64], stream_seed: u64) -> Vec<usize> {
    if symbol_id < k as u64 {
        return vec![symbol_id as usize];
    }
    let fountain_id = symbol_id - k as u64;
    let mut rng = SplitMix64::new(stream_seed ^ fountain_id.rotate_left(32));
    let degree = sample_degree(&mut rng, cdf).min(k);
    // Distinct neighbors without replacement (partial Fisher–Yates).
    let mut avail: Vec<usize> = (0..k).collect();
    let mut picked = Vec::with_capacity(degree);
    for _ in 0..degree {
        let j = rng.below(avail.len() as u64) as usize;
        picked.push(avail.swap_remove(j));
    }
    picked
}

/// The fountain encoder: emits symbols on demand, forever.
pub struct LtEncoder {
    blocks: Vec<Vec<u8>>,
    block_size: usize,
    stream_seed: u64,
    cdf: Vec<f64>,
}

impl LtEncoder {
    pub fn new(payload: &[u8], block_size: usize, stream_seed: u64) -> Result<Self, LtError> {
        if block_size == 0 || block_size > 65535 {
            return Err(LtError::Invalid("block size must be 1..=65535".into()));
        }
        let k = payload.len().div_ceil(block_size).max(1);
        let mut blocks = Vec::with_capacity(k);
        for i in 0..k {
            let start = i * block_size;
            let end = ((i + 1) * block_size).min(payload.len());
            let mut b = payload.get(start..end).unwrap_or(&[]).to_vec();
            while b.len() < block_size {
                b.push(0);
            }
            blocks.push(b);
        }
        let cdf = build_cdf(&robust_soliton(k, 0.1, 0.5));
        Ok(Self {
            blocks,
            block_size,
            stream_seed,
            cdf,
        })
    }

    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn stream_seed(&self) -> u64 {
        self.stream_seed
    }

    /// Encode symbol `symbol_id`: XOR of its neighbor blocks.
    pub fn encode(&self, symbol_id: u64) -> Vec<u8> {
        let ns = neighbors(symbol_id, self.blocks.len(), &self.cdf, self.stream_seed);
        let mut out = vec![0u8; self.block_size];
        for n in ns {
            for (o, b) in out.iter_mut().zip(self.blocks[n].iter()) {
                *o ^= b;
            }
        }
        out
    }
}

/// Ripple-driven peeling decoder.
pub struct LtDecoder {
    k: usize,
    block_size: usize,
    stream_seed: u64,
    cdf: Vec<f64>,
    decoded: Vec<Option<Vec<u8>>>,
    /// Pending symbols: XOR-folded value + unresolved neighbor list.
    /// Entries are never removed (indices stay valid); spent entries have
    /// an empty unresolved list and are inert.
    pending: Vec<(Vec<u8>, Vec<usize>)>,
    /// block -> indices into `pending` that still reference it.
    references: Vec<Vec<usize>>,
    resolved: usize,
}

impl LtDecoder {
    pub fn new(k: usize, block_size: usize, stream_seed: u64) -> Self {
        let cdf = build_cdf(&robust_soliton(k, 0.1, 0.5));
        Self {
            k,
            block_size,
            stream_seed,
            cdf,
            decoded: vec![None; k],
            pending: Vec::new(),
            references: vec![Vec::new(); k],
            resolved: 0,
        }
    }

    pub fn resolved_count(&self) -> usize {
        self.resolved
    }

    /// Total blocks to resolve.
    pub fn num_blocks(&self) -> usize {
        self.k
    }

    /// Feed one received symbol; peels eagerly.
    pub fn push_symbol(&mut self, symbol_id: u64, bytes: &[u8]) -> Result<(), LtError> {
        if bytes.len() != self.block_size {
            return Err(LtError::Invalid(format!(
                "symbol size {} != block size {}",
                bytes.len(),
                self.block_size
            )));
        }
        let ns = neighbors(symbol_id, self.k, &self.cdf, self.stream_seed);
        let mut value = bytes.to_vec();
        let mut unresolved = Vec::with_capacity(ns.len());
        for n in ns {
            if let Some(d) = &self.decoded[n] {
                for (o, b) in value.iter_mut().zip(d.iter()) {
                    *o ^= b;
                }
            } else {
                unresolved.push(n);
            }
        }
        match unresolved.len() {
            0 => Ok(()), // carries nothing new
            1 => {
                let b = unresolved[0];
                self.resolve(b, value);
                Ok(())
            }
            _ => {
                let idx = self.pending.len();
                for n in &unresolved {
                    self.references[*n].push(idx);
                }
                self.pending.push((value, unresolved));
                Ok(())
            }
        }
    }

    /// Resolve a block and ripple through every pending symbol referencing
    /// it (classic peeling).
    fn resolve(&mut self, block: usize, value: Vec<u8>) {
        debug_assert!(self.decoded[block].is_none());
        self.decoded[block] = Some(value);
        self.resolved += 1;
        let mut queue = vec![block];
        while let Some(b) = queue.pop() {
            let refs = std::mem::take(&mut self.references[b]);
            let val = self.decoded[b].clone().expect("resolved");
            for p in refs {
                let Some((v, unres)) = self.pending.get_mut(p) else {
                    continue;
                };
                if unres.is_empty() {
                    continue; // already peeled
                }
                // Fold b out of this pending symbol.
                if let Some(pos) = unres.iter().position(|x| *x == b) {
                    unres.swap_remove(pos);
                    for (o, d) in v.iter_mut().zip(val.iter()) {
                        *o ^= d;
                    }
                }
                // A pending that collapsed to exactly one unknown
                // reveals it; clear its unresolved list so it can never
                // fire again (double-apply guard).
                if unres.len() == 1 {
                    let revealed = unres[0];
                    unres.clear();
                    let value = std::mem::take(v);
                    if self.decoded[revealed].is_none() {
                        self.decoded[revealed] = Some(value);
                        self.resolved += 1;
                        queue.push(revealed);
                    }
                }
            }
        }
    }

    /// Finish: all blocks resolved → payload with padding retained.
    pub fn finish(self) -> Result<Vec<u8>, LtError> {
        if self.resolved < self.k {
            return Err(LtError::DecodeIncomplete {
                decoded: self.resolved,
                total: self.k,
            });
        }
        let mut out = Vec::with_capacity(self.k * self.block_size);
        for b in &self.decoded {
            out.extend_from_slice(b.as_ref().expect("resolved"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    fn round_trip(payload: &[u8], block_size: usize, overhead_pct: usize) {
        let enc = LtEncoder::new(payload, block_size, 0xC0FFEE).unwrap();
        let mut dec = LtDecoder::new(enc.num_blocks(), block_size, 0xC0FFEE);
        let need = enc.num_blocks() + enc.num_blocks() * overhead_pct / 100 + 8;
        for id in 0..need as u64 {
            dec.push_symbol(id, &enc.encode(id)).unwrap();
        }
        let out = dec.finish().expect("fountain decode");
        assert_eq!(out.len(), enc.num_blocks() * block_size);
        assert_eq!(&out[..payload.len()], payload);
    }

    #[test]
    fn round_trips_various_sizes() {
        // Systematic phase: ~10% fountain overhead suffices.
        round_trip(&deterministic_payload(4096), 64, 10);
        round_trip(&deterministic_payload(1), 64, 10);
        round_trip(&deterministic_payload(65), 64, 10);
        round_trip(&deterministic_payload(3000), 16, 10);
        round_trip(&deterministic_payload(20000), 128, 10);
    }

    #[test]
    fn symbols_are_loss_tolerant() {
        let payload = deterministic_payload(3000);
        let enc = LtEncoder::new(&payload, 32, 7).unwrap();
        let mut dec = LtDecoder::new(enc.num_blocks(), 32, 7);
        // Feed only 1 of every 2 symbols (50% symbol loss) — the fountain
        // tail must repair every systematically-missed block.
        let mut fed = 0;
        let mut id = 0u64;
        while fed < enc.num_blocks() * 3 {
            if id.is_multiple_of(2) {
                dec.push_symbol(id, &enc.encode(id)).unwrap();
                fed += 1;
            }
            id += 1;
            assert!(id < enc.num_blocks() as u64 * 64, "runaway stream");
        }
        let out = dec.finish().expect("loss-tolerant decode");
        assert_eq!(&out[..payload.len()], &payload);
    }

    #[test]
    fn incomplete_capture_is_a_clean_error() {
        let payload = deterministic_payload(4096);
        let enc = LtEncoder::new(&payload, 64, 1).unwrap();
        let mut dec = LtDecoder::new(enc.num_blocks(), 64, 1);
        for id in 0..(enc.num_blocks() / 3) as u64 {
            dec.push_symbol(id, &enc.encode(id)).unwrap();
        }
        match dec.finish() {
            Err(LtError::DecodeIncomplete { decoded, total }) => {
                assert_eq!(total, enc.num_blocks());
                assert!(decoded < total);
            }
            other => panic!("expected incomplete, got {other:?}"),
        }
    }

    #[test]
    fn deterministic_neighbors_and_distribution_shape() {
        let k = 128;
        let cdf = build_cdf(&robust_soliton(k, 0.1, 0.5));
        // Systematic phase: ids < k ARE the blocks.
        assert_eq!(neighbors(42, k, &cdf, 99), vec![42]);
        // Fountain phase: deterministic, distinct, bounded.
        let a = neighbors(k as u64 + 42, k, &cdf, 99);
        let b = neighbors(k as u64 + 42, k, &cdf, 99);
        assert_eq!(a, b, "same (symbol, seed) → same neighbor set");
        assert!(!a.is_empty());
        assert!(a.len() <= k);
        let mut sorted = a.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), a.len(), "neighbors are distinct");

        let mu = robust_soliton(1000, 0.1, 0.5);
        let sum: f64 = mu[1..].iter().sum();
        assert!((sum - 1.0).abs() < 1e-6, "normalized, sum={sum}");
        // Mean degree stays sub-linear (robust-soliton shape).
        let mean: f64 = (1..=1000).map(|i| i as f64 * mu[i]).sum();
        assert!(mean < 30.0, "mean degree {mean} must stay sub-linear");
    }
}
