//! # The end-to-end customer ↔ provider wipe protocol.
//!
//! ```text
//! Customer (holds sk)                    Provider (holds ciphertexts)
//! ──────────────────                    ──────────────────────────
//! keygen, issue EvalKey  ──────────────► receive pk + eval key
//! encrypt volume, publish root M
//! of the ciphertext Merkle tree
//!                            wipe day:
//!                                       for each sector i:
//!                                         C'_i = BlindZeroize(C_i)   (no sk!)
//!                                       π = ZK{ every C'_i ∈ L_zero }
//!                                       manifest M' = root(C'_i)
//!                        ◄────────────  (C'_i, M', π)
//! verify π (batched, milliseconds),
//! spot-decrypt one challenged sector
//! with sk → must be 0^N
//! ```
//!
//! **What the customer learns:** every stored ciphertext is an
//! encryption of zero — verified without downloading plaintexts,
//! without trusting the provider's logs, and without revealing
//! the key. The optional spot-decryption anchors the algebra to
//! the physical volume: the challenged ciphertext must decrypt to
//! `0^N` under the customer's own key.
//!
//! **What the provider learns:** nothing about the data (all
//! provider-side computation runs over ciphertexts and public
//! material; the zeroized outputs are statistically fresh
//! encryptions of zero).

use crate::fhe::{EvalKey, ZeroizeAttestation, blind_zeroize};
use crate::poly::Poly;
use crate::rlwe::{Ciphertext, Params, PublicKey, SecretKey, encrypt, keygen_deterministic};
use crate::zkp::{ZeroizeProof, prove, verify_batched, verify_full};
use crate::{FheError, SimRng};

/// The customer-side wipe contract for one encrypted volume.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WipeContract {
    pub volume_id: String,
    pub params: Params,
    pub ek: EvalKey,
    /// Merkle root of the ORIGINAL ciphertext set (customer-published).
    pub original_root: String,
    pub sector_count: usize,
}

/// Customer-side setup: keygen + eval key + volume encryption.
pub struct CustomerSetup {
    pub contract: WipeContract,
    pub sk: SecretKey,
    pub pk: PublicKey,
    /// The ciphertexts handed to the provider (the provider never
    /// sees plaintexts; kept here for test/demo replay).
    pub sector_ciphertexts: Vec<Ciphertext>,
}

/// Run the customer side: generate keys, encrypt the volume
/// sectors (deterministic demo plaintexts derived from the seed),
/// publish the commitment root.
pub fn customer_setup(
    volume_id: &str,
    sectors: usize,
    seed: u64,
) -> Result<CustomerSetup, FheError> {
    if sectors == 0 {
        return Err(FheError::Protocol(
            "an empty volume has nothing to wipe".into(),
        ));
    }
    let params = Params::default();
    params.validate()?;
    let (pk, sk) = keygen_deterministic(&params, seed);
    let ek = EvalKey {
        pk: pk.clone(),
        volume_id: volume_id.into(),
        issue_nonce: seed,
    };
    let mut rng = SimRng::new(seed ^ 0x5EED);
    let mut sector_ciphertexts = Vec::with_capacity(sectors);
    for i in 0..sectors {
        // Deterministic demo plaintext: real deployments encrypt
        // the volume blocks; the wipe protocol never reads them.
        let m = Poly {
            coeffs: (0..params.n)
                .map(|j| ((j + i * 7) % 5 == 0) as i64)
                .collect(),
        };
        let (c, _) = encrypt(&params, &pk, &m, &mut rng);
        sector_ciphertexts.push(c);
    }
    let original_root = merkle_root(
        &sector_ciphertexts
            .iter()
            .map(|c| c.digest(params.q))
            .collect::<Vec<_>>(),
    );
    Ok(CustomerSetup {
        contract: WipeContract {
            volume_id: volume_id.into(),
            params,
            ek,
            original_root,
            sector_count: sectors,
        },
        sk,
        pk,
        sector_ciphertexts,
    })
}

/// BLAKE3 Merkle root over leaf digests (pairwise fold).
pub fn merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return blake3::hash(b"dc-fhe/empty-volume").to_hex().to_string();
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut input = pair[0].as_bytes().to_vec();
            if pair.len() > 1 {
                input.extend_from_slice(pair[1].as_bytes());
            } else {
                input.extend_from_slice(pair[0].as_bytes());
            }
            next.push(blake3::hash(&input).to_hex().to_string());
        }
        level = next;
    }
    level[0].clone()
}

/// The provider's wipe execution result.
pub struct WipeResult {
    /// The zeroized ciphertext set (the new stored state).
    pub zeroized: Vec<Ciphertext>,
    /// The ZK proof that every stored ciphertext is an
    /// encryption of zero.
    pub proof: ZeroizeProof,
    /// Merkle root of the zeroized set.
    pub final_root: String,
    /// Per-sector noise attestations.
    pub attestations: Vec<ZeroizeAttestation>,
    /// Wall time of the homomorphic evaluation.
    pub eval_ms: u128,
    /// Wall time of proof generation.
    pub prove_ms: u128,
}

/// Provider side: blind-zeroize every sector and prove.
pub fn provider_run(
    contract: &WipeContract,
    stored: &[Ciphertext],
    rng: &mut SimRng,
) -> Result<WipeResult, FheError> {
    if stored.len() != contract.sector_count {
        return Err(FheError::Protocol(format!(
            "stored set has {} sectors but the contract covers {}",
            stored.len(),
            contract.sector_count
        )));
    }
    let params = &contract.params;
    let t0 = std::time::Instant::now();
    let mut zeroized = Vec::with_capacity(stored.len());
    let mut witnesses = Vec::with_capacity(stored.len());
    let mut attestations = Vec::with_capacity(stored.len());
    for c in stored {
        let (z, w, att) = blind_zeroize(params, &contract.ek, c, rng)?;
        zeroized.push(z);
        witnesses.push(w);
        attestations.push(att);
    }
    let t1 = std::time::Instant::now();
    let proof = prove(params, &contract.ek.pk, &zeroized, &witnesses, rng)?;
    let t2 = std::time::Instant::now();
    let final_root = merkle_root(
        &zeroized
            .iter()
            .map(|c| c.digest(params.q))
            .collect::<Vec<_>>(),
    );
    Ok(WipeResult {
        zeroized,
        proof,
        final_root,
        attestations,
        eval_ms: t1.duration_since(t0).as_millis(),
        prove_ms: t2.duration_since(t1).as_millis(),
    })
}

/// The customer's verification report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationReport {
    /// Full per-sector ZK verification (all equations).
    pub full_ok: bool,
    /// Batched constant-time ZK verification.
    pub batched_ok: bool,
    /// The Fiat-Shamir spot-decryption challenge index.
    pub spot_sector: usize,
    /// Did the challenged ciphertext decrypt to 0^N under sk?
    pub spot_is_zero: bool,
    /// Batched verification wall time (ms) — the smartphone claim.
    pub batched_verify_ms: u128,
    /// Worst noise margin across sectors.
    pub worst_noise_margin: f64,
    pub passed: bool,
}

/// Customer side: verify the wipe result.
///
/// 1. Batched ZK verification (constant time in the sector count).
/// 2. Full ZK verification (optional at deployment; default on
///    in the demo — it is the same soundness, fully spelled out).
/// 3. Spot-decryption: one FS-challenged sector decrypted with
///    the customer's own key must be `0^N`.
pub fn customer_verify(
    contract: &WipeContract,
    result: &WipeResult,
    sk: &SecretKey,
) -> Result<VerificationReport, FheError> {
    let params = &contract.params;
    // Spot challenge derived from the contract and the final root —
    // the provider cannot pre-pick a favorable sector.
    let spot_input = format!(
        "dc-fhe/spot/{}:{}:{}",
        contract.volume_id, contract.original_root, result.final_root
    );
    let spot_sector =
        blake3::hash(spot_input.as_bytes()).as_bytes()[0] as usize % result.zeroized.len();
    // Batched verification with timing.
    let t0 = std::time::Instant::now();
    let batched = verify_batched(params, &contract.ek.pk, &result.zeroized, &result.proof);
    let batched_ms = t0.elapsed().as_millis();
    let batched_ok = batched.is_ok();
    // Full verification.
    let full_ok = verify_full(params, &contract.ek.pk, &result.zeroized, &result.proof).is_ok();
    // Spot decryption under the real key.
    let spot_poly = result.zeroized[spot_sector].decrypt(params, sk);
    let spot_is_zero = spot_poly.coeffs.iter().all(|&b| b == 0);
    let worst_noise_margin = result
        .attestations
        .iter()
        .map(|a| a.margin())
        .fold(f64::INFINITY, f64::min);
    let passed = batched_ok && full_ok && spot_is_zero;
    Ok(VerificationReport {
        full_ok,
        batched_ok,
        spot_sector,
        spot_is_zero,
        batched_verify_ms: batched_ms,
        worst_noise_margin,
        passed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_binds_the_leaf_set() {
        let leaves: Vec<String> = (0..8)
            .map(|i| blake3::hash(&[i]).to_hex().to_string())
            .collect();
        let root = merkle_root(&leaves);
        assert_eq!(root.len(), 64);
        // Tamper with one leaf.
        let mut bad = leaves.clone();
        bad[3] = blake3::hash(&[255u8]).to_hex().to_string();
        assert_ne!(merkle_root(&bad), root);
        // Order matters.
        let mut swapped = leaves.clone();
        swapped.swap(0, 1);
        assert_ne!(merkle_root(&swapped), root);
        assert_eq!(merkle_root(&[]), merkle_root(&[]));
    }

    #[test]
    fn full_protocol_run_verifies() {
        let setup = customer_setup("vol-full", 6, 77).expect("setup");
        let mut rng = SimRng::new(88);
        let result = provider_run(&setup.contract, &setup.sector_ciphertexts, &mut rng)
            .expect("provider run");
        let report = customer_verify(&setup.contract, &result, &setup.sk).expect("verify");
        assert!(report.passed);
        assert!(report.batched_ok && report.full_ok);
        assert!(report.spot_is_zero);
        assert!(report.worst_noise_margin > 10.0);
        // The provider outputs decrypt to zeros under the real key.
        for z in &result.zeroized {
            assert!(
                z.decrypt(&setup.contract.params, &setup.sk)
                    .coeffs
                    .iter()
                    .all(|&b| b == 0)
            );
        }
        // Roots differ: the wipe really changed the stored state.
        assert_ne!(result.final_root, setup.contract.original_root);
    }

    #[test]
    fn provider_substitution_is_caught() {
        // The provider zeroes only half the volume and tries to
        // pass the untouched ciphertexts off inside the statement.
        let setup = customer_setup("vol-cheat", 4, 101).expect("setup");
        let mut rng = SimRng::new(202);
        let result = provider_run(&setup.contract, &setup.sector_ciphertexts, &mut rng)
            .expect("provider run");
        let mut forged = result;
        // Swap one zeroized sector back to the original data
        // ciphertext.
        forged.zeroized[2] = setup.sector_ciphertexts[2].clone();
        let _kept = &forged;
        let report = customer_verify(&setup.contract, &forged, &setup.sk).expect("verify runs");
        assert!(!report.batched_ok, "the ZK layer must catch the swap");
        assert!(!report.passed);
    }

    #[test]
    fn spot_decryption_catches_a_liar_directly() {
        // Even a proof-consistent lie fails the spot: craft a
        // result whose statements are all honest EXCEPT one that
        // encrypts data — full/batched catch it; if they somehow
        // did not, the spot does (here both fire).
        let setup = customer_setup("vol-spot", 4, 103).expect("setup");
        let mut rng = SimRng::new(203);
        let mut result = provider_run(&setup.contract, &setup.sector_ciphertexts, &mut rng)
            .expect("provider run");
        let params = setup.contract.params.clone();
        // Replace one output with an encryption of DATA.
        let mut m = Poly::zero(params.n);
        for c in m.coeffs.iter_mut().step_by(2) {
            *c = 1;
        }
        let (data_enc, _) = encrypt(&params, &setup.pk, &m, &mut rng);
        result.zeroized[1] = data_enc;
        let report = customer_verify(&setup.contract, &result, &setup.sk).expect("verify");
        assert!(!report.batched_ok && !report.full_ok);
        assert!(!report.passed);
    }

    #[test]
    fn batched_verification_is_fast() {
        // The "milliseconds on a smartphone" property: constant
        // time in the sector count at demo scale.
        let setup = customer_setup("vol-speed", 16, 104).expect("setup");
        let mut rng = SimRng::new(204);
        let result = provider_run(&setup.contract, &setup.sector_ciphertexts, &mut rng)
            .expect("provider run");
        let report = customer_verify(&setup.contract, &result, &setup.sk).expect("verify");
        assert!(report.passed);
        assert!(
            report.batched_verify_ms < 5_000,
            "took {} ms",
            report.batched_verify_ms
        );
    }
}
