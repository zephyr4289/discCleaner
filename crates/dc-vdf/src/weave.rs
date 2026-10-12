//! The Drive Weave (v0.12.0, Miracle 1): binds each overwrite pass of
//! a sanitization run to a link of a Wesolowski VDF chain, so the
//! on-media bytes themselves carry a mathematical wall-clock lower
//! bound between passes.
//!
//! Chain construction, for `n` passes and `steps_per_pass = s`:
//!
//! ```text
//! x ──2^s──▶ state_1 ──2^s──▶ state_2 ──2^s──▶ … ──2^s──▶ state_n
//!            [pass 0]         [pass 1]                  [pass n-1]
//! ```
//!
//! The executor materializes `state_i` (costing exactly `s` sequential
//! squarings after `state_{i-1}` was recorded) *before* writing pass
//! `i`, and the pass keystream is
//! `ChaCha20(key = BLAKE3(state_i ‖ pass_index), nonce = window)`.
//!
//! What an auditor can then prove, with zero trust in clocks, NTP or
//! the operator:
//!
//! 1. Each Wesolowski proof `π_i` checks out (milliseconds).
//! 2. Every pass on media hashes to a keystream keyed by `state_i`
//!    (read-back verification / journal fingerprints).
//! 3. States form a genuine chain: `n·s` non-parallelizable squarings
//!    separate the first state from the last one written.
//!
//! ⇒ the wipe occupied at least `n·s / (best hardware squaring rate)`
//! of physical time between its first and last woven write. Combined
//! with a public beacon anchor at start, the certificate pins both
//! "started no earlier than T₁" and "finished no earlier than T₂".

use crate::bigint::{BigUint, Montgomery};
use crate::vdf::{RSA_LIMBS, VdfError, WesolowskiProver, verify_link};
use dc_core::vdf_pass_seed;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Width used by the executor lock.
pub type Bn = BigUint<RSA_LIMBS>;

/// Published puzzle parameters (the output of `dc vdf setup`).
///
/// SECURITY MODEL: the modulus is generated in a one-time ceremony and
/// its factorization is DESTROYED (see docs/vdf-timelock.md). Nobody —
/// including the wiping machine — may know it, or the sequential-squar-
/// ing lower bound collapses (factoring N lets one jump 2^T via λ(N)).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VdfParams {
    pub scheme: String, // "wesolowski-rsa-ufo/v1"
    /// Modulus N, hex (odd, 512–2048 bits, factorization destroyed).
    pub modulus_n: String,
    /// Sequential squarings between consecutive pass states.
    pub steps_per_pass: u64,
    /// Number of woven passes this parameter set is calibrated for.
    pub passes: u8,
    /// Optional public beacon value (hex) anchoring the run start in
    /// externally verifiable time (e.g. a published randomness beacon).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon: Option<String>,
    /// Free-form ceremony note (air-gap machine IDs, witnesses…).
    #[serde(default)]
    pub ceremony_note: String,
}

impl VdfParams {
    pub const SCHEME: &'static str = "wesolowski-rsa-ufo/v1";

    /// Parse and validate the modulus into a Montgomery context.
    pub fn context(&self) -> Result<Montgomery<RSA_LIMBS>, VdfError> {
        let n: Bn = BigUint::from_hex(&self.modulus_n).map_err(VdfError::Parse)?;
        let bits = n.bits();
        if !(512..=2048).contains(&bits) {
            return Err(VdfError::BadModulus(bits));
        }
        if !n.is_odd() {
            return Err(VdfError::BadModulus(bits));
        }
        Montgomery::new(n).map_err(VdfError::Parse)
    }

    pub fn total_steps(&self) -> u64 {
        self.steps_per_pass.saturating_mul(self.passes as u64)
    }
}

/// One pass binding recorded by the executor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PassBinding {
    pub pass_index: u8,
    /// Chain state `state_i`, hex (canonical BE, width of N).
    pub state: String,
    /// BLAKE3 of the ChaCha20 key actually keyed by this state
    /// (`vdf_pass_seed(state_i, pass_index)`), hex — matches the
    /// journal's BeginPass descriptor fingerprint exactly.
    pub seed_fingerprint: String,
    /// Fiat–Shamir challenge prime ℓ_i, hex.
    pub challenge_prime: String,
    /// Wesolowski proof π_i, hex.
    pub proof: String,
    /// Wall-clock note (advisory, NOT part of the mathematical claim).
    pub materialized_after_ms: u64,
}

/// Executor-side time-lock. `advance()` is called between passes;
/// each call performs `steps_per_pass` sequential squarings and one
/// streaming Wesolowski proof, then hands the caller the state that
/// keys the next pass's keystream.
pub struct VdfLock {
    ctx: Montgomery<RSA_LIMBS>,
    n_bytes: Vec<u8>,
    /// Challenge x, canonical bytes (BLAKE3-derived; 256-bit < N).
    x_bytes: Vec<u8>,
    /// Current chain state (Montgomery form).
    state_m: Bn,
    steps_per_pass: u64,
    next_pass: u8,
    bindings: Vec<PassBinding>,
    started: Instant,
    squarings_done: u64,
    beacon: Option<String>,
}

impl VdfLock {
    /// Derive the challenge `x` from run-binding material (journal
    /// UUID, drive identity, OS entropy) and enter the chain at
    /// `state_0 = x`.
    pub fn new(params: &VdfParams, run_material: &[u8]) -> Result<Self, VdfError> {
        let ctx = params.context()?;
        let n_bytes = ctx.n.to_bytes_be();
        // x = BLAKE3("dc-vdf/x/v1" || N || beacon || run_material)
        let mut h = blake3::Hasher::new();
        h.update(b"dc-vdf/x/v1");
        h.update(&n_bytes);
        if let Some(b) = &params.beacon
            && let Ok(b) = hex::decode(b.trim_start_matches("0x"))
        {
            h.update(&b);
        }
        h.update(run_material);
        let x = Bn::from_bytes_be(h.finalize().as_bytes()); // 256-bit < N ✓
        if x.is_zero() || x.binary_gcd(&ctx.n).cmp_to(&Bn::ONE) != std::cmp::Ordering::Equal {
            return Err(VdfError::BadChallenge);
        }
        let x_bytes = x.to_bytes_be();
        Ok(Self {
            state_m: ctx.to_mont(&x),
            ctx,
            n_bytes,
            x_bytes,
            steps_per_pass: params.steps_per_pass,
            next_pass: 0,
            bindings: Vec::new(),
            started: Instant::now(),
            squarings_done: 0,
            beacon: params.beacon.clone(),
        })
    }

    /// Advance the chain by one pass: `steps_per_pass` squarings plus
    /// the streaming proof, then return the binding for the upcoming
    /// pass. The returned state's canonical bytes key the pass
    /// keystream via `dc_core::vdf_pass_seed`.
    pub fn advance(
        &mut self,
        mut progress: impl FnMut(u64) -> bool,
    ) -> Result<PassBinding, VdfError> {
        if self.next_pass == u8::MAX {
            return Err(VdfError::Range("pass index overflow".into()));
        }
        let pass_index = self.next_pass;
        let base = self.ctx.from_mont(&self.state_m); // state_{i-1} normal

        // ---- the sequential delay (state advance) -------------------
        let y_m = self
            .ctx
            .repeat_square(&self.state_m, self.steps_per_pass, &mut progress);
        let y = self.ctx.from_mont(&y_m);
        self.squarings_done += self.steps_per_pass;
        let state_bytes = y.to_bytes_be();

        // ---- Wesolowski proof for this link --------------------------
        let prover = WesolowskiProver::new(&self.ctx);
        let proof = prover.prove_link(&base, &y, self.steps_per_pass, progress)?;

        let seed_fp = {
            let seed = vdf_pass_seed(&state_bytes, pass_index);
            hex::encode(blake3_hash(&seed))
        };
        let binding = PassBinding {
            pass_index,
            state: hex::encode(&state_bytes),
            seed_fingerprint: seed_fp,
            challenge_prime: proof.challenge.to_hex(),
            proof: hex::encode(&proof.pi),
            materialized_after_ms: self.started.elapsed().as_millis() as u64,
        };
        self.bindings.push(binding.clone());
        self.state_m = y_m;
        self.next_pass += 1;
        Ok(binding)
    }

    /// Canonical bytes of the current chain state (for constructing
    /// the pattern source of the pass that was just advanced to).
    pub fn state_bytes(&self) -> Vec<u8> {
        self.ctx.from_mont(&self.state_m).to_bytes_be()
    }

    /// State the NEXT pass will be keyed by (peek without advancing —
    /// used by the verification phase to re-derive the last pass).
    pub fn next_pass_index(&self) -> u8 {
        self.next_pass
    }

    /// Build the certificate evidence section.
    pub fn evidence(&self, measured_sps: Option<f64>) -> TimelineEvidence {
        TimelineEvidence {
            scheme: VdfParams::SCHEME.to_string(),
            modulus_n: hex::encode(&self.n_bytes),
            challenge_x: hex::encode(&self.x_bytes),
            steps_per_pass: self.steps_per_pass,
            beacon: self.beacon.clone(),
            passes: self.bindings.clone(),
            measured_squarings_per_second: measured_sps,
            squarings_done: self.squarings_done,
        }
    }

    pub fn squarings_done(&self) -> u64 {
        self.squarings_done
    }

    /// Configured steps between pass states.
    pub fn steps_per_pass(&self) -> u64 {
        self.steps_per_pass
    }
}

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Certificate-facing evidence (mirrored in `dc-cert::vdf`; every
/// field hex/numeric so the certificate stays plain-JSON auditable).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TimelineEvidence {
    pub scheme: String,
    pub modulus_n: String,
    pub challenge_x: String,
    pub steps_per_pass: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon: Option<String>,
    pub passes: Vec<PassBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_squarings_per_second: Option<f64>,
    pub squarings_done: u64,
}

/// Conservative adversary model for the wall-clock claim: ASIC-class
/// 2048-bit Montgomery squaring throughput. Fielded 2048-bit RSA
/// verifiers on 3 nm logic land in the low millions of squarings per
/// second; we assume a 10× margin over a generous 2M/s figure. The
/// claim is explicitly a *lower bound under this documented model* —
/// auditors may substitute their own and re-derive from `steps`.
pub const ADVERSARY_SQUARINGS_PER_SECOND: f64 = 20_000_000.0;

/// Verdict of `verify_timeline`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TimelineVerdict {
    pub verified: bool,
    pub passes_verified: u32,
    pub total_steps: u64,
    /// Mathematical lower bound on elapsed physical time between the
    /// first and last woven writes: total_steps / adversary rate.
    pub min_elapsed_seconds_claim: f64,
    pub errors: Vec<String>,
}

/// Standalone audit verification of a weave timeline: checks the full
/// chain `x → state_1 → … → state_n` link by link (Wesolowski verify
/// per link) and computes the time lower-bound claim.
pub fn verify_timeline(ev: &TimelineEvidence) -> TimelineVerdict {
    let mut errors = Vec::new();
    let mut verified_passes = 0u32;

    let parse = |h: &str| -> Option<Bn> { BigUint::from_hex(h).ok() };
    let n = match parse(&ev.modulus_n) {
        Some(v) if v.is_odd() && (512..=2048).contains(&v.bits()) => v,
        _ => {
            errors.push("modulus N missing/malformed/out of range".into());
            return TimelineVerdict {
                verified: false,
                passes_verified: 0,
                total_steps: 0,
                min_elapsed_seconds_claim: 0.0,
                errors,
            };
        }
    };
    let ctx = match Montgomery::new(n) {
        Ok(c) => c,
        Err(e) => {
            errors.push(format!("montgomery init: {e}"));
            return TimelineVerdict {
                verified: false,
                passes_verified: 0,
                total_steps: 0,
                min_elapsed_seconds_claim: 0.0,
                errors,
            };
        }
    };
    let x = match parse(&ev.challenge_x) {
        Some(v) if v.cmp_to(&ctx.n) == std::cmp::Ordering::Less => v,
        _ => {
            errors.push("challenge x missing or >= N".into());
            return TimelineVerdict {
                verified: false,
                passes_verified: 0,
                total_steps: 0,
                min_elapsed_seconds_claim: 0.0,
                errors,
            };
        }
    };

    let mut prev = x;
    let mut expected_pass: u8 = 0;
    let mut total_steps = 0u64;
    for b in &ev.passes {
        if b.pass_index != expected_pass {
            errors.push(format!(
                "pass index discontinuity: expected {expected_pass}, got {}",
                b.pass_index
            ));
            // continue checking the rest at the reported index
            expected_pass = b.pass_index;
        }
        let state = match parse(&b.state) {
            Some(v) => v,
            None => {
                errors.push(format!("pass {}: state malformed", b.pass_index));
                continue;
            }
        };
        let pi = match parse(&b.proof) {
            Some(v) => v,
            None => {
                errors.push(format!("pass {}: proof malformed", b.pass_index));
                continue;
            }
        };
        let l = match BigUint::<2>::from_hex(&b.challenge_prime) {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!("pass {}: challenge prime malformed", b.pass_index));
                continue;
            }
        };
        if verify_link(&ctx, &prev, &state, ev.steps_per_pass, &pi, &l) {
            verified_passes += 1;
            total_steps += ev.steps_per_pass;
        } else {
            errors.push(format!(
                "pass {}: Wesolowski link INVALID (state {}, steps {})",
                b.pass_index,
                &b.state[..b.state.len().min(16)],
                ev.steps_per_pass
            ));
        }
        // Cross-check the recorded keystream fingerprint.
        let state_bytes = state.to_bytes_be();
        let seed = dc_core::vdf_pass_seed(&state_bytes, b.pass_index);
        let fp = hex::encode(blake3_hash(&seed));
        if fp != b.seed_fingerprint {
            errors.push(format!(
                "pass {}: seed fingerprint mismatch (journal binding broken)",
                b.pass_index
            ));
        }
        prev = state;
        expected_pass += 1;
    }

    let verified =
        !ev.passes.is_empty() && verified_passes == ev.passes.len() as u32 && errors.is_empty();
    TimelineVerdict {
        verified,
        passes_verified: verified_passes,
        total_steps,
        min_elapsed_seconds_claim: total_steps as f64 / ADVERSARY_SQUARINGS_PER_SECOND,
        errors,
    }
}

/// Recompute an honest local rate note for the certificate: the
/// measured squarings/sec of THIS machine (advisory only; the binding
/// claim uses the adversary model above).
pub fn local_rate_note(measured: Option<f64>) -> String {
    match measured {
        Some(sps) => format!(
            "executor measured {:.0} squarings/s on this hardware (advisory); \
             the time-lock claim uses the {} squarings/s adversary model",
            sps, ADVERSARY_SQUARINGS_PER_SECOND as u64
        ),
        None => format!(
            "executor rate not measured; the time-lock claim uses the {} \
             squarings/s adversary model",
            ADVERSARY_SQUARINGS_PER_SECOND as u64
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony;

    fn small_params(steps: u64, passes: u8) -> VdfParams {
        // 512-bit modulus from the (fast) ceremony at 512 bits.
        let (n_hex, _) = ceremony::generate_modulus(512, None, &mut |_| {}).unwrap();
        VdfParams {
            scheme: VdfParams::SCHEME.to_string(),
            modulus_n: n_hex,
            steps_per_pass: steps,
            passes,
            beacon: Some(hex::encode([0xAB; 16])),
            ceremony_note: "test ceremony".into(),
        }
    }

    #[test]
    fn chain_roundtrip_and_verify() {
        let params = small_params(4096, 3);
        let mut lock = VdfLock::new(&params, b"journal-uuid-test").unwrap();
        let _b0 = lock.advance(|_| true).unwrap();
        let _b1 = lock.advance(|_| true).unwrap();
        let _b2 = lock.advance(|_| true).unwrap();

        let ev = lock.evidence(Some(123_456.7));
        let verdict = verify_timeline(&ev);
        assert!(verdict.verified, "errors: {:?}", verdict.errors);
        assert_eq!(verdict.passes_verified, 3);
        assert_eq!(verdict.total_steps, 3 * 4096);

        // Tamper one state → chain breaks.
        let mut bad = ev.clone();
        bad.passes[1].state = {
            let s: Bn = BigUint::from_hex(&bad.passes[1].state).unwrap();
            let mut limbs = s.0;
            limbs[2] ^= 1;
            hex::encode(BigUint(limbs).to_bytes_be())
        };
        let v2 = verify_timeline(&bad);
        assert!(!v2.verified);
    }

    #[test]
    fn binding_is_run_specific() {
        // Different run material → different chain → different states.
        let params = small_params(1024, 1);
        let mut a = VdfLock::new(&params, b"run-A").unwrap();
        let mut b = VdfLock::new(&params, b"run-B").unwrap();
        let sa = a.advance(|_| true).unwrap();
        let sb = b.advance(|_| true).unwrap();
        assert_ne!(sa.state, sb.state);
    }
}
