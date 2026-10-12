//! The sanitization compliance circuit.
//!
//! **What it proves**: "a drive with *some* serial number, *some*
//! operator credential and *some* internal block topology was sanitized
//! with a successful hardware purge, at least one purge pass, and full
//! block-level verification — committed under a Poseidon audit root —
//! under the profile / tenant / timestamp context given in the public
//! statement" — **without revealing the serial, block topology, pass
//! count, or operator identity**.
//!
//! # Public statement (the verifier sees exactly this)
//!
//! | # | input | binding |
//! |---|-------|---------|
//! | 1 | `profile_hash` | Poseidon root of the NIST SP 800-88 / IEEE 2883 profile parameters |
//! | 2 | `tenant_id` | customer / tenant identifier the audit is owed to |
//! | 3 | `ts` | sanitization timestamp |
//! | 4 | `vk_commitment` | Poseidon commitment to the operator credential (proves *an* authorized key was used, hides *which*) |
//! | 5 | `audit_root` | Poseidon root over all private audit fields |
//!
//! # Private witness (stays hidden)
//!
//! drive serial (≤ 128 bits), block-verification merkle root, pass count,
//! verified/total block counts, sanitize success flag, operator secret,
//! blinding nonce.
//!
//! # Constraints
//!
//! 1. bit-decomposition + range bounds: serial ≤ 2¹²⁸, passes ≤ 2⁸,
//!    verified/total ≤ 2³² (booleanity + reconstruction constraints)
//! 2. `verified == total` — every window verified (fail-closed
//!    equivalence with the engine's full-verification requirement)
//! 3. `sanitize_success == 1` — the controller-attested purge command
//!    completed successfully
//! 4. `passes ≥ 1` — at least one purge pass (OR over pass bits)
//! 5. in-circuit Poseidon sponge over all fields == `audit_root`
//! 6. in-circuit Poseidon commitment over (operator secret, nonce) ==
//!    `vk_commitment`

use crate::field::Fr;
use crate::poseidon::PoseidonConfig;
use crate::r1cs::{LinComb, R1cs};
use zeroize::Zeroize;

/// Circuit identifier — bound into every proving/verifying key and
/// receipt; changing the circuit structure requires a new id.
pub const CIRCUIT_ID: &str = "dc-zk/compliance/v1";

/// Number of public statement inputs (excluding the constant one).
pub const NUM_PUBLIC: usize = 5;

// variable layout
pub const V_ONE: usize = 0;
pub const V_PROFILE: usize = 1;
pub const V_TENANT: usize = 2;
pub const V_TS: usize = 3;
pub const V_VK: usize = 4;
pub const V_ROOT: usize = 5;
pub const V_SERIAL: usize = 6;
pub const V_BLOCKROOT: usize = 7;
pub const V_PASSES: usize = 8;
pub const V_VERIFIED: usize = 9;
pub const V_TOTAL: usize = 10;
pub const V_SUCCESS: usize = 11;
pub const V_OPSECRET: usize = 12;
pub const V_NONCE: usize = 13;

/// The public statement (what the verifier checks against expectations).
#[derive(Clone, Debug, PartialEq)]
pub struct ComplianceStatement {
    pub profile_hash: Fr,
    pub tenant_id: Fr,
    pub ts: Fr,
    pub vk_commitment: Fr,
    pub audit_root: Fr,
}

impl ComplianceStatement {
    pub fn to_public_list(&self) -> Vec<Fr> {
        vec![
            self.profile_hash,
            self.tenant_id,
            self.ts,
            self.vk_commitment,
            self.audit_root,
        ]
    }
}

/// The private witness. `serial` is zeroized on drop — the serial is
/// exactly the kind of confidential metadata this circuit exists to hide.
#[derive(Clone, Debug)]
pub struct ComplianceWitness {
    pub serial: [u8; 16],
    pub block_root: Fr,
    pub passes: u8,
    pub verified_blocks: u32,
    pub total_blocks: u32,
    pub sanitize_success: bool,
    pub operator_secret: Fr,
    pub nonce: Fr,
}

impl Drop for ComplianceWitness {
    fn drop(&mut self) {
        self.serial.zeroize();
    }
}

/// Derive the audit root (the Poseidon commitment over all audit fields)
/// — used by the witness builder and by the certificate embedder so the
/// on-certificate statement matches what the circuit computes.
pub fn audit_root_of(w: &ComplianceWitness, stmt: &ComplianceStatement) -> Fr {
    let cfg = PoseidonConfig::new(b"dc-zk/audit-root/v1");
    cfg.sponge(&absorb_elements(w, stmt))
}

/// Derive the operator key commitment from the secret.
pub fn vk_commitment_of(operator_secret: &Fr, nonce: &Fr) -> Fr {
    let cfg = PoseidonConfig::new(b"dc-zk/vk-commit/v1");
    cfg.sponge(&[*operator_secret, *nonce])
}

fn absorb_elements(w: &ComplianceWitness, stmt: &ComplianceStatement) -> Vec<Fr> {
    vec![
        serial_to_fr(&w.serial),
        w.block_root,
        Fr::from_be_bytes_reduced(&u64::from(w.passes).to_be_bytes()),
        Fr::from_be_bytes_reduced(&u64::from(w.verified_blocks).to_be_bytes()),
        Fr::from_be_bytes_reduced(&u64::from(w.total_blocks).to_be_bytes()),
        if w.sanitize_success {
            Fr::ONE
        } else {
            Fr::ZERO
        },
        w.operator_secret,
        w.nonce,
        stmt.profile_hash,
        stmt.tenant_id,
        stmt.ts,
    ]
}

fn serial_to_fr(serial: &[u8; 16]) -> Fr {
    Fr::from_be_bytes_reduced(serial)
}

/// Allocate `nbits` boolean variables decomposing `value`, with
/// booleanity and reconstruction constraints. Returns (var indices,
/// values).
fn bit_decompose(
    cs: &mut R1cs,
    value_var: usize,
    value: Fr,
    nbits: usize,
    next_var: &mut usize,
    witness: &mut Vec<Fr>,
) -> Vec<usize> {
    let mut bits = Vec::with_capacity(nbits);
    let mut limbs = value.canonical_limbs();
    let _ = &mut limbs;
    // compute the canonical bit vector of the value
    let can = value.canonical_limbs();
    let mut recon = LinComb::empty();
    let mut bit_vars = Vec::with_capacity(nbits);
    for i in 0..nbits {
        let bit = (can[i / 64] >> (i % 64)) & 1 == 1;
        let v = *next_var;
        *next_var += 1;
        witness.push(if bit { Fr::ONE } else { Fr::ZERO });
        bit_vars.push(v);
        bits.push(bit);
        // booleanity: b * b = b
        cs.constrain(
            &LinComb::var(v, Fr::ONE),
            &LinComb::var(v, Fr::ONE),
            &LinComb::var(v, Fr::ONE),
        );
        let mut coeff = Fr::ONE;
        for _ in 0..i {
            coeff = coeff.double();
        }
        recon.add_term(v, coeff);
    }
    // reconstruction: sum b_i 2^i == value
    cs.constrain(&recon, &LinComb::one(), &LinComb::var(value_var, Fr::ONE));
    let _ = limbs;
    bit_vars
}

/// OR-of-bits: constrain at least one of the given boolean vars to be 1
/// (De Morgan: product of (1 - b_i) == 0). Witness values are derived from
/// the already-populated bit slots in `witness`.
fn constrain_at_least_one(
    cs: &mut R1cs,
    bits: &[usize],
    next_var: &mut usize,
    witness: &mut Vec<Fr>,
) {
    let mut acc: Option<(usize, Fr)> = None;
    for &b in bits {
        let b_val = witness[b];
        // z_i = 1 - b_i: allocate and constrain z = one - b
        let z_val = Fr::ONE.sub(&b_val);
        let zv = *next_var;
        *next_var += 1;
        witness.push(z_val);
        cs.constrain(
            &LinComb::var(zv, Fr::ONE),
            &LinComb::one(),
            &LinComb::var(0, Fr::ONE).add(&LinComb::var(b, Fr::ONE.neg())),
        );
        acc = Some(match acc {
            None => (zv, z_val),
            Some((prev, prev_val)) => {
                // p = prev * zv
                let p_val = prev_val.mul(&z_val);
                let pv = *next_var;
                *next_var += 1;
                witness.push(p_val);
                cs.constrain(
                    &LinComb::var(prev, Fr::ONE),
                    &LinComb::var(zv, Fr::ONE),
                    &LinComb::var(pv, Fr::ONE),
                );
                (pv, p_val)
            }
        });
    }
    if let Some((p, _)) = acc {
        // p * 1 = 0 (product of negations must vanish)
        cs.constrain(
            &LinComb::var(p, Fr::ONE),
            &LinComb::one(),
            &LinComb::empty(),
        );
    }
}

/// Build the compliance circuit (constraints only — deterministic).
pub fn compliance_circuit() -> R1cs {
    let mut cs = R1cs::new(V_NONCE + 1, NUM_PUBLIC);
    // Temporary structures to track allocation during a "dry run" that
    // mirrors prove-time synthesis. We use a dummy witness for shape.
    let dummy_w = dummy_witness();
    let dummy_stmt = ComplianceStatement {
        profile_hash: Fr::from_be_bytes_reduced(&[1]),
        tenant_id: Fr::from_be_bytes_reduced(&[2]),
        ts: Fr::from_be_bytes_reduced(&[3]),
        vk_commitment: vk_commitment_of(&dummy_w.operator_secret, &dummy_w.nonce),
        audit_root: audit_root_of(&dummy_w, &placeholder_stmt_for(&dummy_w)),
    };
    let mut witness: Vec<Fr> = Vec::new();
    let mut next_var = V_NONCE + 1;
    build_constraints(&mut cs, &dummy_stmt, &dummy_w, &mut next_var, &mut witness);
    cs.num_vars = next_var;
    cs
}

fn placeholder_stmt_for(_w: &ComplianceWitness) -> ComplianceStatement {
    ComplianceStatement {
        profile_hash: Fr::from_be_bytes_reduced(&[1]),
        tenant_id: Fr::from_be_bytes_reduced(&[2]),
        ts: Fr::from_be_bytes_reduced(&[3]),
        vk_commitment: Fr::ZERO,
        audit_root: Fr::ZERO,
    }
}

fn dummy_witness() -> ComplianceWitness {
    ComplianceWitness {
        serial: [0u8; 16],
        block_root: Fr::ZERO,
        passes: 1,
        verified_blocks: 1,
        total_blocks: 1,
        sanitize_success: true,
        operator_secret: Fr::from_be_bytes_reduced(&[0x42; 31]),
        nonce: Fr::from_be_bytes_reduced(&[0x24; 31]),
    }
}

/// The full constraint builder — also used at prove time so the circuit
/// shape and the witness are guaranteed consistent (same code path).
fn build_constraints(
    cs: &mut R1cs,
    stmt: &ComplianceStatement,
    w: &ComplianceWitness,
    next_var: &mut usize,
    witness: &mut Vec<Fr>,
) {
    // seed the fixed public/private witness slots
    let base = vec![
        (V_ONE, Fr::ONE),
        (V_PROFILE, stmt.profile_hash),
        (V_TENANT, stmt.tenant_id),
        (V_TS, stmt.ts),
        (V_VK, stmt.vk_commitment),
        (V_ROOT, stmt.audit_root),
        (V_SERIAL, serial_to_fr(&w.serial)),
        (V_BLOCKROOT, w.block_root),
        (
            V_PASSES,
            Fr::from_be_bytes_reduced(&u64::from(w.passes).to_be_bytes()),
        ),
        (
            V_VERIFIED,
            Fr::from_be_bytes_reduced(&u64::from(w.verified_blocks).to_be_bytes()),
        ),
        (
            V_TOTAL,
            Fr::from_be_bytes_reduced(&u64::from(w.total_blocks).to_be_bytes()),
        ),
        (
            V_SUCCESS,
            if w.sanitize_success {
                Fr::ONE
            } else {
                Fr::ZERO
            },
        ),
        (V_OPSECRET, w.operator_secret),
        (V_NONCE, w.nonce),
    ];
    for (var, val) in base {
        if witness.len() <= var {
            witness.resize(var + 1, Fr::ZERO);
        }
        witness[var] = val;
        cs.num_vars = cs.num_vars.max(var + 1);
    }

    // 1. bit decompositions
    let _serial_bits = bit_decompose(cs, V_SERIAL, witness[V_SERIAL], 128, next_var, witness);
    let pass_bits = bit_decompose(cs, V_PASSES, witness[V_PASSES], 8, next_var, witness);
    bit_decompose(cs, V_VERIFIED, witness[V_VERIFIED], 32, next_var, witness);
    bit_decompose(cs, V_TOTAL, witness[V_TOTAL], 32, next_var, witness);

    // 2. verified == total
    let mut diff = LinComb::var(V_VERIFIED, Fr::ONE);
    diff.add_term(V_TOTAL, Fr::ONE.neg());
    cs.constrain(&diff, &LinComb::one(), &LinComb::empty());

    // 3. sanitize success == 1
    cs.constrain(
        &LinComb::var(V_SUCCESS, Fr::ONE),
        &LinComb::one(),
        &LinComb::var(0, Fr::ONE),
    );
    // (and booleanity of the flag itself)
    cs.constrain(
        &LinComb::var(V_SUCCESS, Fr::ONE),
        &LinComb::var(V_SUCCESS, Fr::ONE),
        &LinComb::var(V_SUCCESS, Fr::ONE),
    );

    // 4. passes >= 1
    constrain_at_least_one(cs, &pass_bits, next_var, witness);

    // 5. audit-root sponge over everything
    let root_cfg = PoseidonConfig::new(b"dc-zk/audit-root/v1");
    let inputs = vec![
        (V_SERIAL, witness[V_SERIAL]),
        (V_BLOCKROOT, witness[V_BLOCKROOT]),
        (V_PASSES, witness[V_PASSES]),
        (V_VERIFIED, witness[V_VERIFIED]),
        (V_TOTAL, witness[V_TOTAL]),
        (V_SUCCESS, witness[V_SUCCESS]),
        (V_OPSECRET, witness[V_OPSECRET]),
        (V_NONCE, witness[V_NONCE]),
        (V_PROFILE, witness[V_PROFILE]),
        (V_TENANT, witness[V_TENANT]),
        (V_TS, witness[V_TS]),
    ];
    let (root_out, _root_val) = root_cfg.synth_sponge(cs, &inputs, next_var, witness);
    // output must equal the public audit root
    let mut lc = LinComb::var(root_out, Fr::ONE);
    lc.add_term(V_ROOT, Fr::ONE.neg());
    cs.constrain(&lc, &LinComb::one(), &LinComb::empty());

    // 6. vk commitment sponge
    let vk_cfg = PoseidonConfig::new(b"dc-zk/vk-commit/v1");
    let (vk_out, _vk_val) = vk_cfg.synth_sponge(
        cs,
        &[
            (V_OPSECRET, witness[V_OPSECRET]),
            (V_NONCE, witness[V_NONCE]),
        ],
        next_var,
        witness,
    );
    let mut lc = LinComb::var(vk_out, Fr::ONE);
    lc.add_term(V_VK, Fr::ONE.neg());
    cs.constrain(&lc, &LinComb::one(), &LinComb::empty());
}

/// Build the full witness vector for a statement + private witness.
pub fn build_witness(stmt: &ComplianceStatement, w: &ComplianceWitness) -> Vec<Fr> {
    let mut cs = R1cs::new(V_NONCE + 1, NUM_PUBLIC);
    let mut witness: Vec<Fr> = Vec::new();
    let mut next_var = V_NONCE + 1;
    build_constraints(&mut cs, stmt, w, &mut next_var, &mut witness);
    witness.truncate(next_var);
    witness
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (ComplianceStatement, ComplianceWitness) {
        let w = ComplianceWitness {
            serial: [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8,
            ],
            block_root: Fr::from_be_bytes_reduced(&[0x77; 31]),
            passes: 3,
            verified_blocks: 4096,
            total_blocks: 4096,
            sanitize_success: true,
            operator_secret: Fr::from_be_bytes_reduced(&[0x42; 31]),
            nonce: Fr::from_be_bytes_reduced(&[0x24; 31]),
        };
        let stmt = ComplianceStatement {
            profile_hash: Fr::from_be_bytes_reduced(&[0x11; 31]),
            tenant_id: Fr::from_be_bytes_reduced(&[0x22; 31]),
            ts: Fr::from_be_bytes_reduced(&1_770_000_000u64.to_be_bytes()),
            vk_commitment: vk_commitment_of(&w.operator_secret, &w.nonce),
            audit_root: Fr::ZERO, // filled below
        };
        let stmt = ComplianceStatement {
            audit_root: audit_root_of(&w, &stmt),
            ..stmt
        };
        (stmt, w)
    }

    #[test]
    fn witness_satisfies_circuit() {
        let (stmt, w) = sample();
        let wit = build_witness(&stmt, &w);
        let cs = compliance_circuit();
        assert_eq!(cs.num_vars, wit.len(), "witness covers all vars");
        assert!(
            cs.is_satisfied_by(&wit),
            "compliance witness must satisfy the circuit"
        );
    }

    #[test]
    fn non_compliant_witnesses_fail() {
        let (stmt, w) = sample();
        // a: unverified blocks remain
        let wa = ComplianceWitness {
            verified_blocks: w.verified_blocks - 1,
            ..clone_w(&w)
        };
        let stmt_a = ComplianceStatement {
            audit_root: audit_root_of(&wa, &stmt),
            ..stmt.clone()
        };
        let cs = compliance_circuit();
        let wit = build_witness(&stmt_a, &wa);
        assert!(!cs.is_satisfied_by(&wit), "verified < total must fail");

        // b: sanitize failed
        let wb = ComplianceWitness {
            sanitize_success: false,
            ..clone_w(&w)
        };
        let stmt_b = ComplianceStatement {
            audit_root: audit_root_of(&wb, &stmt),
            ..stmt.clone()
        };
        let wit = build_witness(&stmt_b, &wb);
        assert!(!cs.is_satisfied_by(&wit), "sanitize_success=0 must fail");

        // c: zero passes
        let wc = ComplianceWitness {
            passes: 0,
            ..clone_w(&w)
        };
        let stmt_c = ComplianceStatement {
            audit_root: audit_root_of(&wc, &stmt),
            ..stmt.clone()
        };
        let wit = build_witness(&stmt_c, &wc);
        assert!(!cs.is_satisfied_by(&wit), "passes=0 must fail");

        // d: wrong audit root binding
        let wit = build_witness(&stmt, &w);
        let mut bad = wit.clone();
        // tamper the private serial var
        bad[V_SERIAL] = bad[V_SERIAL].add(&Fr::ONE);
        assert!(!cs.is_satisfied_by(&bad), "serial change breaks the root");

        // e: wrong vk commitment
        let stmt_e = ComplianceStatement {
            vk_commitment: Fr::from_be_bytes_reduced(&[0x99; 31]),
            ..stmt.clone()
        };
        let wit = build_witness(&stmt_e, &w);
        assert!(
            !cs.is_satisfied_by(&wit),
            "vk commitment mismatch must fail"
        );
    }

    fn clone_w(w: &ComplianceWitness) -> ComplianceWitness {
        ComplianceWitness {
            serial: w.serial,
            block_root: w.block_root,
            passes: w.passes,
            verified_blocks: w.verified_blocks,
            total_blocks: w.total_blocks,
            sanitize_success: w.sanitize_success,
            operator_secret: w.operator_secret,
            nonce: w.nonce,
        }
    }

    #[test]
    fn circuit_shape_is_stable() {
        let cs = compliance_circuit();
        assert_eq!(cs.num_public, NUM_PUBLIC);
        assert!(
            cs.num_constraints() > 2000,
            "expected a substantial circuit, got {}",
            cs.num_constraints()
        );
        assert!(
            cs.num_constraints() < 100_000,
            "circuit unexpectedly large: {}",
            cs.num_constraints()
        );
    }
}
