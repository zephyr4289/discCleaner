//! `dc-verify-formal` — formal verification of the sanitization core
//! (v0.11.0, Frontier 3).
//!
//! Unit tests and fuzzing find bugs that reachable inputs expose; they
//! cannot prove the ABSENCE of bugs. In sanitization, a fail-open bug
//! that reports a drive as wiped when a single block was skipped is
//! catastrophic, so this crate delivers two complementary machine-checked
//! layers on top of the existing test suites:
//!
//! # Layer 1 — always-on exhaustive model checking (`cargo test`)
//!
//! [`fsm`] enumerates every action sequence of the REAL
//! [`dc_core::FsmOrchestrator`] up to a configurable depth (11 actions,
//! depth 7 ≈ 19.5M sequences after state deduplication) and checks the
//! certification invariants:
//!
//! * **INV-1 (no uncertified success)**: `Certified` is reachable only
//!   through sequences in which `begin_verify()` returned `Ok` — i.e. no
//!   action order skips verification and still certifies.
//! * **INV-2 (permit gating)**: `begin_pass()`/`begin_flush()` (the only
//!   minters of the unforgeable `WritePermit`) reject every state outside
//!   `{Armed, Flushing}` / `{Executing}` respectively — fail-closed.
//! * **INV-3 (verification accounting)**: a symbolic model of the window
//!   verifier ([`verify`]) provably counts every invalid window, and is
//!   cross-validated against the REAL [`dc_verify::StreamVerifier`] on
//!   all bounded concrete inputs.
//!
//! This layer runs on every `cargo test --workspace` (CI included) — the
//! proofs are regression-pinned continuously.
//!
//! # Layer 2 — Kani bounded symbolic proofs (`cargo kani`)
//!
//! `proofs/` contains `#[cfg(kani)]` harnesses (invisible to normal
//! builds; the `kani` crate resolves under the cargo-kani toolchain):
//!
//! * `fsm_guards_are_fail_closed` — symbolic action sequences: Kani
//!   explores ALL executions up to the unwind bound, proving INV-1/INV-2
//!   without input enumeration.
//! * `secretbuf_zeroizes_all_paths` — any buffer content, any panic-free
//!   path: after `zeroize_now()` the exposed memory is all-zero, and the
//!   `Debug` rendering never contains the secret (libc mlock/munlock are
//!   stubbed — they are orthogonal to the zeroization property).
//!
//! Run with `scripts/kani-run.sh` (installs cargo-kani, runs the
//! harnesses, emits `proofs/proof-certificate.json`). The CI workflow
//! `.github/workflows/formal-verification.yml` re-runs it on a schedule
//! and on demand.
//!
//! # Proof certificates
//!
//! Both layers emit structured artifacts under `proofs/`: the exhaustive
//! checker reports (state count, depth, invariants checked, verdict) and
//! the Kani driver summarizes harnesses × verdicts. These are committed
//! as the auditable record of what was mechanically checked.

pub mod fsm;
pub mod verify;

#[cfg(kani)]
pub mod proofs;

use serde::{Deserialize, Serialize};

/// Structured result of the exhaustive model check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelCheckReport {
    pub checker: String,
    pub depth: u32,
    pub distinct_states: u64,
    pub sequences_explored: u64,
    pub invariants: Vec<InvariantResult>,
    pub all_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvariantResult {
    pub id: String,
    pub statement: String,
    pub passed: bool,
    pub counterexample_actions: Option<Vec<String>>,
}

/// Run the full always-on model check at the given depth.
pub fn run_model_check(depth: u32) -> ModelCheckReport {
    fsm::exhaustive_check(depth)
}
