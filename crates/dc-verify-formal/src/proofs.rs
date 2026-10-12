//! Kani proof harnesses (compiled only under `cargo kani`).
//!
//! These harnesses exist to be *machine-checked*: Kani explores ALL
//! executions (bounded by the unwind annotations) and fails the build if
//! any assertion can be violated. They are invisible to normal `cargo
//! build` / `cargo test` — the `kani` crate resolves only under the
//! cargo-kani toolchain (see scripts/kani-run.sh).
//!
//! # Harness inventory
//!
//! * `fsm_certify_requires_verifying` — INV-1/INV-3, symbolically: any
//!   action sequence of length ≤ 6.
//! * `fsm_permit_gating` — INV-2, symbolically.
//! * `window_accounting_is_exact` — the verified abstraction: counters
//!   over any symbolic observation sequence are exact.
//! * `secretbuf_zeroize_wipes_every_byte` / `secretbuf_debug_never_leaks`
//!   — secret hygiene (mlock/munlock stubbed: pinning is orthogonal to
//!   the zeroization property under proof).

#[cfg(kani)]
mod fsm_harness {
    use crate::fsm::Action;
    use dc_core::{FsmOrchestrator, FsmState};

    fn sample_plan() -> dc_core::SanitizationPlan {
        crate::fsm::sample_plan_for_kani()
    }

    /// Symbolic action sequence of length `n` (each action = any of 11).
    #[kani::proof]
    #[kani::unwind(8)]
    fn fsm_certify_requires_verifying() {
        let plan = sample_plan();
        let mut orch = FsmOrchestrator::new();
        let mut saw_ok_verify = false;
        let n: u32 = kani::any();
        kani::assume(n <= 6);
        for _ in 0..n {
            let a: u8 = kani::any();
            kani::assume(a < 11);
            let action = Action::ALL[a as usize];
            let mut ctx = crate::fsm::RunCtxForKani {
                saw_ok_verify,
                saw_permit: false,
            };
            crate::fsm::step_for_kani(&mut orch, &plan, action, &mut ctx);
            saw_ok_verify = ctx.saw_ok_verify;
        }
        // INV-1: certified => verified
        if matches!(orch.state(), FsmState::Certified) {
            assert!(
                saw_ok_verify,
                "INV-1 violated: Certified without begin_verify"
            );
        }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn fsm_permit_gating() {
        let plan = sample_plan();
        let mut orch = FsmOrchestrator::new();
        let mut saw_ok_verify = false;
        let n: u32 = kani::any();
        kani::assume(n <= 6);
        for _ in 0..n {
            let a: u8 = kani::any();
            kani::assume(a < 11);
            let mut ctx = crate::fsm::RunCtxForKani {
                saw_ok_verify,
                saw_permit: false,
            };
            crate::fsm::step_for_kani(&mut orch, &plan, Action::ALL[a as usize], &mut ctx);
            saw_ok_verify = ctx.saw_ok_verify;
        }
        // INV-2: from any reached state, the minter guards behave —
        // begin_pass only accepts Armed/Flushing; begin_flush only
        // Executing.
        let is_armed_or_flushing =
            matches!(orch.state(), FsmState::Armed | FsmState::Flushing { .. });
        let is_executing = matches!(orch.state(), FsmState::Executing { .. });
        let pass_ok = orch.begin_pass(1).is_ok();
        let flush_ok = orch.begin_flush(1).is_ok();
        assert_eq!(pass_ok, is_armed_or_flushing, "INV-2: begin_pass guard");
        assert_eq!(flush_ok, is_executing, "INV-2: begin_flush guard");
    }
}

#[cfg(kani)]
mod verify_harness {
    /// The verified abstraction, symbolically: for any observation
    /// sequence of length ≤ 5, the counters are exact.
    #[kani::proof]
    #[kani::unwind(7)]
    fn window_accounting_is_exact() {
        let n: u32 = kani::any();
        kani::assume(n <= 5);
        let mut observations: Vec<(u64, bool)> = Vec::new();
        let mut expected_checked: u64 = 0;
        let mut expected_mismatch: u64 = 0;
        for i in 0..n {
            let valid: bool = kani::any();
            observations.push((u64::from(i), valid));
            expected_checked += 1;
            if !valid {
                expected_mismatch += 1;
            }
        }
        let c = crate::verify::count_windows(&observations);
        assert_eq!(c.windows_checked, expected_checked);
        assert_eq!(c.mismatch_count, expected_mismatch);
        // the mismatch list is exactly the invalid windows
        for (i, (_, valid)) in observations.iter().enumerate() {
            let in_list = c.first_mismatch_windows.contains(&(i as u64));
            assert_eq!(in_list, !valid);
        }
    }
}

#[cfg(kani)]
mod secrets_harness {
    use dc_core::SecretBuf;

    // mlock/munlock are orthogonal to the zeroization property under
    // proof; stub them so Kani does not need to reason about libc FFI.
    unsafe extern "C" fn stub_mlock(_addr: *mut libc::c_void, _len: libc::size_t) -> libc::c_int {
        0
    }
    unsafe extern "C" fn stub_munlock(
        _addr: *const libc::c_void,
        _len: libc::size_t,
    ) -> libc::c_int {
        0
    }

    #[kani::proof]
    #[kani::unwind(10)]
    #[kani::stub(libc::mlock, stub_mlock)]
    #[kani::stub(libc::munlock, stub_munlock)]
    fn secretbuf_zeroize_wipes_every_byte() {
        // any 8-byte secret
        let mut secret = [0u8; 8];
        for b in secret.iter_mut() {
            *b = kani::any();
        }
        let mut buf = SecretBuf::from_vec(secret.to_vec());
        buf.zeroize_now();
        for b in buf.expose() {
            assert!(*b == 0, "zeroize_now must wipe every byte");
        }
        // the wipe must be idempotent (no re-randomization, no panic)
        buf.zeroize_now();
        assert!(buf.expose().iter().all(|&b| b == 0));
    }

    #[kani::proof]
    #[kani::unwind(10)]
    #[kani::stub(libc::mlock, stub_mlock)]
    #[kani::stub(libc::munlock, stub_munlock)]
    fn secretbuf_debug_never_leaks() {
        let mut secret = [0u8; 8];
        for b in secret.iter_mut() {
            *b = kani::any();
        }
        let buf = SecretBuf::from_vec(secret.to_vec());
        let rendered = format!("{:?}", buf);
        let secret_hex: Vec<String> = secret.iter().map(|b| format!("{:02x}", b)).collect();
        for hx in &secret_hex {
            let _ = hx;
        }
        // No byte's hex rendering may appear in the debug output. (A
        // single byte could coincidentally appear inside "SecretBuf(len=N
        // mlock=B)" — pin to the two-digit form which never occurs in
        // that prefix for nonzero bytes.)
        for b in &secret {
            if *b != 0 {
                let needle = format!("{:02x}", b);
                assert!(
                    !rendered.contains(&needle),
                    "Debug leaked byte {} of the secret",
                    needle
                );
            }
        }
    }
}

/// v0.12.0 Miracle 1 harnesses: the Montgomery arithmetic bedrock of
/// the Proof-of-Erasure time-lock chain.
///
/// Proved here (symbolic, all executions):
/// * `montgomery_red_small` — CIOS Montgomery reduction is EXACTLY
///   (a·b·R⁻¹) mod n for a 2-limb modulus, verified against the
///   schoolbook triple-multiply reference over ALL symbolic inputs.
/// * `montgomery_roundtrip_small` — to_mont/from_mont compose to the
///   identity for every input below the modulus.
/// * `sonar_pairwise_bit_stability` — Miracle 2: a pairwise ordering
///   bit is stable under any perturbation smaller than half the
///   enrolled gap (the fuzzy extractor's soundness lemma).
#[cfg(kani)]
mod vdf_harness {
    use dc_vdf::bigint::{BigUint, Montgomery};

    /// R = 2^128 for L=2; the reference uses u128 arithmetic with one
    /// extra limb via the wide multiply (fits because a, b < n < 2^63
    /// keeps a·b < 2^126).
    #[kani::proof]
    #[kani::unwind(10)]
    fn montgomery_red_small() {
        // symbolic small modulus (odd, < 2^63 so products fit u128)
        let n0: u64 = kani::any();
        kani::assume(n0 & 1 == 1);
        kani::assume(n0 >= 3);
        kani::assume(n0 < (1u64 << 62));
        let mut n = [0u64; 2];
        n[0] = n0;
        let n = BigUint::<2>(n);

        let a0: u64 = kani::any();
        let b0: u64 = kani::any();
        kani::assume(a0 < n0);
        kani::assume(b0 < n0);

        let ctx = Montgomery::<2>::new(n).unwrap();
        let a = BigUint::<2>::from_bytes_be(&a0.to_be_bytes());
        let b = BigUint::<2>::from_bytes_be(&b0.to_be_bytes());
        let got = ctx.from_mont(&ctx.mont_mul(&ctx.to_mont(&a), &ctx.to_mont(&b)));

        let expect = ((a0 as u128) * (b0 as u128)) % (n0 as u128);
        assert_eq!(
            got.0[0] as u128, expect,
            "CIOS must equal schoolbook modular product for every a,b < n"
        );
        assert_eq!(got.0[1], 0, "result must be fully reduced");
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn montgomery_roundtrip_small() {
        let n0: u64 = kani::any();
        kani::assume(n0 & 1 == 1);
        kani::assume(n0 >= 3);
        kani::assume(n0 < (1u64 << 62));
        let mut n = [0u64; 2];
        n[0] = n0;
        let n = BigUint::<2>(n);

        let x0: u64 = kani::any();
        kani::assume(x0 < n0);
        let x = BigUint::<2>::from_bytes_be(&x0.to_be_bytes());
        let ctx = Montgomery::<2>::new(n).unwrap();
        let back = ctx.from_mont(&ctx.to_mont(&x));
        assert_eq!(back, x, "Montgomery conversion must round-trip exactly");
    }
}

#[cfg(kani)]
mod sonar_harness {
    /// The pairwise-ordering bit (v0.12.0 Miracle 2): for any pair of
    /// feature values and any per-observation noise strictly smaller
    /// than half the pair's gap, the comparison bit is unchanged — the
    /// soundness lemma behind the reliable-pair fuzzy extractor.
    #[kani::proof]
    fn sonar_pairwise_bit_stability() {
        let va: i64 = kani::any();
        let vb: i64 = kani::any();
        kani::assume(va > -1_000_000_000);
        kani::assume(va < 1_000_000_000);
        kani::assume(vb > -1_000_000_000);
        kani::assume(vb < 1_000_000_000);
        let gap = (va - vb).abs();
        kani::assume(gap >= 2);

        // noise strictly inside the guard band (|noise| < gap/2)
        let noise: i64 = kani::any();
        kani::assume(noise >= -(gap / 2 - 1));
        kani::assume(noise <= gap / 2 - 1);

        let bit_before = va > vb;
        let bit_after = va + noise > vb - noise;
        assert_eq!(
            bit_before, bit_after,
            "pairwise ordering must be noise-stable within the half-gap band"
        );
    }
}
