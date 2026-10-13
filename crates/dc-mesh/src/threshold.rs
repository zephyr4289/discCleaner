//! Threshold co-signing: FROST2 Schnorr over Ed25519, plus an
//! ML-DSA-44 post-quantum t-of-n signature set.
//!
//! **No single machine can forge the swarm certificate.** The final
//! decommission record is co-signed by the cluster as a collective:
//!
//! ## Classical layer — FROST2 (Ed25519, t-of-n)
//!
//! The Flexible Round-Optimized Schnorr Threshold scheme (FROST2 /
//! "simplified FROST" variant) in its trusted-dealer distribution
//! form for ad-hoc swarm ceremonies:
//!
//! * **Ceremony (offline, once per cluster):** a dealer generates a
//!   group secret `x`, Shamir-shares it at degree `t-1` — polynomial
//!   `p(·)` with `p(0) = x` — and hands node `i` the share
//!   `x_i = p(i)` plus Pedersen-style coefficient commitments
//!   `C_j = a_j·B`. Shares are *verifiable*: `x_i·B == Σ_j i^j·C_j`.
//!   The dealer's copy of `x` is zeroized on drop; after the
//!   ceremony **nobody on Earth holds the group key** — only `t`
//!   cooperating nodes can reconstruct it implicitly, by signing.
//! * **Round 1:** each participating signer picks nonce pair
//!   `(d_i, e_i)` and publishes commitments `(D_i, E_i)`.
//! * **Aggregation:** `ρ = H(pkg ∥ m ∥ commitments)`,
//!   `R = Π(D_i · E_i^ρ)`.
//! * **Round 2:** challenge `c = H(R ∥ Y ∥ m)`, each signer releases
//!   `z_i = d_i + ρ·e_i + λ_i·x_i·c` where `λ_i` is the signer's
//!   Lagrange coefficient over the participant set.
//! * **Signature:** `(R, z = Σ z_i)`; verification `z·B == R + c·Y`.
//!
//! A forged certificate needs `t` shares — an attacker must break
//! into a threshold of the physical cluster, not one jump box.
//!
//! ## Post-quantum layer — ML-DSA-44 t-of-n set
//!
//! Lattice threshold signatures are an open research area; we do not
//! fake one. Instead the seal collects **`t` distinct ML-DSA-44
//! signatures from `t` different member keys**, each independently
//! verifiable, quantum-resistant, and non-aggregable: a seal is
//! valid iff ≥ `t` entries verify under distinct membership keys.
//! The two layers are ANDed — a forger must defeat both Ed25519
//! FROST *and* collect `t` lattice keys.

use crate::{MeshError, byzantine_tolerance};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use dc_pq::{MlDsa44PublicKey, MlDsa44Signature};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// FROST domain-separation prefixes.
const DST_RHO: &[u8] = b"DCMS-FROST2-rho-v1";
const DST_CHALLENGE: &[u8] = b"DCMS-FROST2-c-v1";

/// Threshold parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdParams {
    /// Signers required (t).
    pub threshold: u16,
    /// Shares issued (n).
    pub participants: u16,
}

impl ThresholdParams {
    /// Sanity: t ≥ 2 (threshold of 1 is no threshold) and t ≤ n.
    pub fn validate(&self) -> Result<(), MeshError> {
        if self.threshold < 2 {
            return Err(MeshError::Threshold("threshold must be >= 2".into()));
        }
        if self.threshold > self.participants {
            return Err(MeshError::Threshold(
                "threshold cannot exceed participants".into(),
            ));
        }
        Ok(())
    }

    /// Sensible default: t = n - f for the membership size.
    pub fn default_for(participants: usize) -> Self {
        let f = byzantine_tolerance(participants) as u16;
        Self {
            threshold: participants.saturating_sub(f as usize).max(2) as u16,
            participants: participants as u16,
        }
    }
}

/// A Shamir share (secret part), zeroized on drop.
#[derive(Clone)]
pub struct ShareSecret {
    pub index: u16,
    scalar: Scalar,
}

impl Drop for ShareSecret {
    fn drop(&mut self) {
        // Scalar has no zeroize impl; overwrite via to_bytes zeroize.
        let mut b = self.scalar.to_bytes();
        b.zeroize();
        self.scalar = Scalar::from_bytes_mod_order(b);
    }
}

impl std::fmt::Debug for ShareSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ShareSecret(index {})", self.index)
    }
}

/// Public share material (publishable).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharePublic {
    pub index: u16,
    /// Hex-encoded compressed point x_i·B.
    pub share_pub: String,
}

/// The dealer's published key set (group key + share pks + commitments).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThresholdPublicKey {
    pub params: ThresholdParams,
    /// Group public key Y = x·B (hex compressed).
    pub group_pub: String,
    /// Share public keys Y_i (one per participant index).
    pub shares: Vec<SharePublic>,
    /// Polynomial commitments C_j = a_j·B (hex, j = 0..t).
    pub commitments: Vec<String>,
}

impl ThresholdPublicKey {
    /// Verify a share against the commitments:
    /// `x_i·B == Σ_j i^j·C_j` (verifiable secret sharing).
    pub fn verify_share(&self, secret: &ShareSecret) -> bool {
        let mut expect = EdwardsPoint::identity();
        for (j, c_hex) in self.commitments.iter().enumerate() {
            let c = match decompress_hex(c_hex) {
                Some(p) => p,
                None => return false,
            };
            expect += c * Scalar::from((secret.index as u64).pow(j as u32));
        }
        let actual = ED25519_BASEPOINT_POINT * secret.scalar;
        expect.compress() == actual.compress()
    }

    pub fn group_point(&self) -> Option<EdwardsPoint> {
        decompress_hex(&self.group_pub)
    }
}

/// Trusted-dealer ceremony output.
pub struct DealerOutput {
    pub public: ThresholdPublicKey,
    pub secrets: Vec<ShareSecret>,
}

/// Run the trusted-dealer ceremony: generate the group key and n
/// verifiable shares at threshold t.
///
/// The dealer secret `a_0` exists only inside this function's stack
/// frame (and inside the returned `secrets`, zeroized on drop). In
/// production the dealer is a one-time offline ceremony machine —
/// the same operational posture as the dc-vdf modulus ceremony.
pub fn dealer_keygen(
    rng: &mut (impl RngCore + rand_core::CryptoRng),
    params: ThresholdParams,
) -> Result<DealerOutput, MeshError> {
    params.validate()?;
    let mut coeffs: Vec<Scalar> = (0..params.threshold).map(|_| Scalar::random(rng)).collect();
    let group_pub = (ED25519_BASEPOINT_POINT * coeffs[0])
        .compress()
        .to_bytes_hex();

    let mut secrets = Vec::with_capacity(params.participants as usize);
    let mut shares = Vec::with_capacity(params.participants as usize);
    for i in 1..=params.participants {
        // x_i = p(i) = Σ_j a_j · i^j
        let mut x_i = Scalar::ZERO;
        for (j, a) in coeffs.iter().enumerate() {
            x_i += a * Scalar::from((i as u64).pow(j as u32));
        }
        shares.push(SharePublic {
            index: i,
            share_pub: (ED25519_BASEPOINT_POINT * x_i).compress().to_bytes_hex(),
        });
        secrets.push(ShareSecret {
            index: i,
            scalar: x_i,
        });
    }
    let commitments: Vec<String> = coeffs
        .iter()
        .map(|a| (ED25519_BASEPOINT_POINT * a).compress().to_bytes_hex())
        .collect();
    coeffs.zeroize();
    Ok(DealerOutput {
        public: ThresholdPublicKey {
            params,
            group_pub,
            shares,
            commitments,
        },
        secrets,
    })
}

// ---------------------------------------------------------------------------
// Signing session
// ---------------------------------------------------------------------------

/// Round-1 broadcast from one signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoundOneCommitment {
    pub signer: u16,
    /// D_i (hex).
    pub d_commit: String,
    /// E_i (hex).
    pub e_commit: String,
}

/// Round-2 response from one signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoundTwoShare {
    pub signer: u16,
    /// z_i (32-byte scalar, hex).
    pub z_share: String,
}

/// The aggregate FROST2 signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FrostSignature {
    /// R (hex compressed point).
    pub r_point: String,
    /// z (hex scalar).
    pub z_scalar: String,
    /// Participant indices that produced this signature.
    pub participants: Vec<u16>,
}

impl FrostSignature {
    /// Verify under a group public key and message.
    pub fn verify(&self, group_pub: &ThresholdPublicKey, message: &[u8]) -> bool {
        let (Some(y), Some(r), Some(z)) = (
            decompress_hex(&group_pub.group_pub),
            decompress_hex(&self.r_point),
            hex_scalar(&self.z_scalar),
        ) else {
            return false;
        };
        let c = challenge(&r, &y, message);
        let lhs = ED25519_BASEPOINT_POINT * z;
        let rhs = r + y * c;
        if lhs.compress() != rhs.compress() {
            return false;
        }
        // Participants must be a valid threshold subset of the issued
        // shares — a signature from unknown indices is meaningless.
        let distinct: std::collections::HashSet<u16> = self.participants.iter().copied().collect();
        if distinct.len() != self.participants.len() {
            return false; // duplicate participants — invalid session
        }
        if (distinct.len() as u16) < group_pub.params.threshold {
            return false; // below-threshold signing set
        }
        // When the share list is known (ceremony material present),
        // participants must all be issued shares. Standalone
        // verification (no share list) relies on the threshold count.
        let issued: std::collections::HashSet<u16> =
            group_pub.shares.iter().map(|s| s.index).collect();
        issued.is_empty() || distinct.iter().all(|i| issued.contains(i))
    }
}

/// One signer's local session state.
pub struct SignerSession {
    secret: ShareSecret,
    d_nonce: Scalar,
    e_nonce: Scalar,
    published: Option<RoundOneCommitment>,
}

/// The coordinator-side session (any node; typically the speaker).
pub struct CoordinatorSession {
    pub params: ThresholdParams,
    pub group_pub: ThresholdPublicKey,
    pub commitments: Vec<RoundOneCommitment>,
    pub message: Vec<u8>,
}

impl CoordinatorSession {
    /// Open a signing round over `message` once `t` round-1
    /// commitments have arrived.
    pub fn new(
        group_pub: ThresholdPublicKey,
        participants: &[u16],
        message: &[u8],
    ) -> Result<Self, MeshError> {
        group_pub.params.validate()?;
        let distinct: std::collections::BTreeSet<u16> = participants.iter().copied().collect();
        if (distinct.len() as u16) < group_pub.params.threshold {
            return Err(MeshError::Threshold(format!(
                "{} participants < threshold {}",
                distinct.len(),
                group_pub.params.threshold
            )));
        }
        Ok(Self {
            params: group_pub.params,
            group_pub,
            commitments: Vec::new(),
            message: message.to_vec(),
        })
    }

    /// Ingest one round-1 commitment.
    pub fn ingest_commitment(&mut self, c: RoundOneCommitment) {
        if !self.commitments.iter().any(|x| x.signer == c.signer) {
            self.commitments.push(c);
        }
    }

    /// The participant indices present in this round.
    pub fn participants(&self) -> Vec<u16> {
        let mut p: Vec<u16> = self.commitments.iter().map(|c| c.signer).collect();
        p.sort_unstable();
        p
    }

    /// Aggregate round-2 shares into the final signature.
    pub fn aggregate(&self, shares: &[RoundTwoShare]) -> Result<FrostSignature, MeshError> {
        let parts = self.participants();
        if (parts.len() as u16) < self.params.threshold {
            return Err(MeshError::Threshold("not enough commitments".into()));
        }
        let by_signer: std::collections::HashMap<u16, &RoundTwoShare> =
            shares.iter().map(|s| (s.signer, s)).collect();
        // FROST2 signers embed their own Lagrange coefficient in the
        // share (z_i = d_i + ρ·e_i + λ_i·x_i·c): the aggregator ONLY
        // sums. Re-applying λ_i here would double it and break the
        // verification equation.
        let mut z = Scalar::ZERO;
        for &i in &parts {
            let share = by_signer
                .get(&i)
                .ok_or_else(|| MeshError::Threshold(format!("missing z-share for signer {i}")))?;
            let Some(z_i) = hex_scalar(&share.z_share) else {
                return Err(MeshError::Threshold(format!("bad z-share hex for {i}")));
            };
            z += z_i;
        }
        // R = Π(D_i · E_i^ρ)
        let rho = self.rho();
        let mut r = EdwardsPoint::identity();
        for c in &self.commitments {
            let (Some(d), Some(e)) = (decompress_hex(&c.d_commit), decompress_hex(&c.e_commit))
            else {
                return Err(MeshError::Threshold("bad commitment encoding".into()));
            };
            r += d + e * rho;
        }
        Ok(FrostSignature {
            r_point: r.compress().to_bytes_hex(),
            z_scalar: z.to_bytes().iter().map(|b| format!("{b:02x}")).collect(),
            participants: parts,
        })
    }

    /// ρ = H(DST_RHO ∥ group ∥ m ∥ sorted commitments).
    fn rho(&self) -> Scalar {
        let mut h = Sha512::new();
        h.update(DST_RHO);
        h.update(self.group_pub.group_pub.as_bytes());
        h.update(&self.message);
        let mut sorted = self.commitments.clone();
        sorted.sort_by_key(|c| c.signer);
        for c in &sorted {
            h.update(c.signer.to_be_bytes());
            h.update(c.d_commit.as_bytes());
            h.update(c.e_commit.as_bytes());
        }
        let mut wide = [0u8; 64];
        wide.copy_from_slice(h.finalize().as_slice());
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

impl SignerSession {
    /// Round 1: pick nonces, produce the commitment. Uses OS entropy —
    /// nonce reuse in Schnorr leaks the share, so nonces are drawn
    /// fresh per session and never stored beyond it.
    pub fn round1(secret: ShareSecret) -> Self {
        let mut rng = OsRng;
        Self::round1_with_rng(secret, &mut rng)
    }

    /// Round 1 over a caller-supplied RNG: the deterministic drill
    /// path (`dc mesh simulate`, CI replay — `MeshNodeConfig::
    /// seal_determinism`). Production code MUST use [`Self::round1`]:
    /// deriving Schnorr nonces from a low-entropy or replayed source
    /// is a share-leak vector, so this constructor exists solely for
    /// byte-identical simulation replay.
    pub fn round1_with_rng(
        secret: ShareSecret,
        rng: &mut (impl RngCore + rand_core::CryptoRng),
    ) -> Self {
        let d = Scalar::random(rng);
        let e = Scalar::random(rng);
        Self {
            secret,
            d_nonce: d,
            e_nonce: e,
            published: None,
        }
    }

    pub fn secret(&self) -> &ShareSecret {
        &self.secret
    }

    /// The public round-1 message to send.
    pub fn commitment(&mut self) -> RoundOneCommitment {
        if let Some(c) = &self.published {
            return c.clone();
        }
        let c = RoundOneCommitment {
            signer: self.secret.index,
            d_commit: (ED25519_BASEPOINT_POINT * self.d_nonce)
                .compress()
                .to_bytes_hex(),
            e_commit: (ED25519_BASEPOINT_POINT * self.e_nonce)
                .compress()
                .to_bytes_hex(),
        };
        self.published = Some(c.clone());
        c
    }

    /// Round 2: respond with `z_i = d_i + ρ·e_i + λ_i·x_i·c`.
    pub fn round2(&self, coordinator: &CoordinatorSession) -> Result<RoundTwoShare, MeshError> {
        let parts = coordinator.participants();
        let rho = coordinator.rho();
        // Defensive local recompute of R over ALL commitments: the
        // challenge must bind to the full commitment set, never to a
        // coordinator-supplied digest.
        let y = coordinator
            .group_pub
            .group_point()
            .ok_or_else(|| MeshError::Threshold("bad group key".into()))?;
        // Recompute R over ALL commitments to derive the challenge.
        let mut r_all = EdwardsPoint::identity();
        let mut sorted = coordinator.commitments.clone();
        sorted.sort_by_key(|c| c.signer);
        for c in &sorted {
            let (Some(d), Some(e)) = (decompress_hex(&c.d_commit), decompress_hex(&c.e_commit))
            else {
                return Err(MeshError::Threshold("bad commitment".into()));
            };
            r_all += d + e * rho;
        }
        let c_challenge = challenge(&r_all, &y, &coordinator.message);
        let lambda = lagrange_at_zero(self.secret.index, &parts);
        let z_i = self.d_nonce + rho * self.e_nonce + lambda * self.secret.scalar * c_challenge;
        Ok(RoundTwoShare {
            signer: self.secret.index,
            z_share: z_i.to_bytes().iter().map(|b| format!("{b:02x}")).collect(),
        })
    }
}

// ---------------------------------------------------------------------------
// ML-DSA t-of-n seal layer
// ---------------------------------------------------------------------------

/// One ML-DSA seal entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MlDsaSealEntry {
    /// Signer node id (hex Ed25519 pk — membership identity).
    pub node: String,
    /// Signature over the transcript (hex).
    pub signature: String,
}

/// The post-quantum t-of-n layer: t distinct ML-DSA-44 signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MlDsaSeal {
    pub threshold: u16,
    pub entries: Vec<MlDsaSealEntry>,
}

impl MlDsaSeal {
    /// Verify the seal: `threshold` entries, each valid under the
    /// matching membership ML-DSA key, all from DISTINCT nodes.
    pub fn verify(
        &self,
        membership_pks: &std::collections::HashMap<String, Vec<u8>>,
        message: &[u8],
    ) -> bool {
        let mut seen = std::collections::HashSet::new();
        let mut good = 0u16;
        for e in &self.entries {
            if !seen.insert(e.node.clone()) {
                continue; // duplicate node — count once
            }
            let Some(pk_bytes) = membership_pks.get(&e.node) else {
                continue;
            };
            let Some(pk) = MlDsa44PublicKey::from_bytes(pk_bytes) else {
                continue;
            };
            let Ok(sig_bytes) = hex::decode(&e.signature) else {
                continue;
            };
            if let Some(sig) = MlDsa44Signature::from_bytes(&sig_bytes)
                && pk.verify(message, &sig)
            {
                good += 1;
            }
        }
        good >= self.threshold && self.threshold >= 2
    }
}

// ---------------------------------------------------------------------------
// Scalar/point helpers
// ---------------------------------------------------------------------------

/// c = H(DST_CHALLENGE ∥ R ∥ Y ∥ m) reduced mod l (wide reduction).
fn challenge(r: &EdwardsPoint, y: &EdwardsPoint, message: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(DST_CHALLENGE);
    h.update(r.compress().as_bytes());
    h.update(y.compress().as_bytes());
    h.update(message);
    let mut wide = [0u8; 64];
    h.finalize_into(wide.as_mut_slice().into());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Lagrange coefficient at zero for signer `i` over participant set P.
///
/// λ_i = Π_{j∈P, j≠i} j·(j-i)^{-1}   (evaluation of L_i(0) at x_k = k).
///
/// The sign matters: for j < i the factor (j-i) is negative and the
/// coefficient flips — e.g. λ_2 over {1, 2} is -1, not +1.
fn lagrange_at_zero(i: u16, participants: &[u16]) -> Scalar {
    let mut acc = Scalar::ONE;
    for &j in participants {
        if j == i {
            continue;
        }
        let diff = j as i64 - i as i64;
        let mut term = Scalar::from(j as u64) * Scalar::from(diff.unsigned_abs()).invert();
        if diff < 0 {
            term = -term;
        }
        acc *= term;
    }
    acc
}

trait CompressedHex {
    /// Hex of the compressed point (protocol wire form).
    fn to_bytes_hex(&self) -> String;
}

impl CompressedHex for CompressedEdwardsY {
    fn to_bytes_hex(&self) -> String {
        self.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn decompress_hex(h: &str) -> Option<EdwardsPoint> {
    let bytes = hex::decode(h).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    CompressedEdwardsY::from_slice(&arr).ok()?.decompress()
}

fn hex_scalar(h: &str) -> Option<Scalar> {
    let bytes = hex::decode(h).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Scalar::from_bytes_mod_order(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dc_pq::MlDsa44KeyPair;

    /// Deterministic RNG for reproducible tests. Marked CryptoRng so
    /// dalek's Scalar::random accepts it (nonce quality in tests is
    /// irrelevant; production paths use OsRng).
    struct Det(u64);
    impl rand_core::CryptoRng for Det {}
    impl RngCore for Det {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn keyset(t: u16, n: u16) -> DealerOutput {
        dealer_keygen(
            &mut Det(42),
            ThresholdParams {
                threshold: t,
                participants: n,
            },
        )
        .expect("keygen")
    }

    #[test]
    fn shares_verify_against_commitments() {
        let out = keyset(3, 5);
        for s in &out.secrets {
            assert!(
                out.public.verify_share(s),
                "share {} must verify against commitments",
                s.index
            );
        }
    }

    #[test]
    fn corrupted_share_fails() {
        let out = keyset(2, 4);
        let bad = ShareSecret {
            index: 1,
            scalar: Scalar::from(123456789u64),
        };
        assert!(!out.public.verify_share(&bad));
    }

    #[test]
    fn full_frost2_sign_and_verify() {
        let out = keyset(3, 5);
        let pk = out.public.clone();
        let msg = b"decommission-block-hash";

        // Signers 1, 2, 4 participate (3 of 5).
        let mut sessions: Vec<SignerSession> = [1u16, 2, 4]
            .into_iter()
            .map(|i| {
                SignerSession::round1(out.secrets.iter().find(|s| s.index == i).unwrap().clone())
            })
            .collect();

        let mut coord = CoordinatorSession::new(pk.clone(), &[1, 2, 4], msg).expect("coord");
        for s in &mut sessions {
            coord.ingest_commitment(s.commitment());
        }

        let shares: Vec<RoundTwoShare> = sessions
            .iter()
            .map(|s| s.round2(&coord).expect("r2"))
            .collect();
        let sig = coord.aggregate(&shares).expect("aggregate");
        assert!(sig.verify(&pk, msg), "aggregate signature must verify");

        // Wrong message fails.
        assert!(!sig.verify(&pk, b"other"));
        // Below-threshold participant list fails.
        let mut thin = sig.clone();
        thin.participants = vec![1, 2];
        assert!(!thin.verify(&pk, msg));
    }

    #[test]
    fn one_share_short_of_threshold_fails() {
        let out = keyset(3, 5);
        let pk = out.public.clone();
        let msg = b"m";
        // Round-1 sessions for a 2-of-3 signing set: opened only to
        // prove the coordinator refuses below-threshold sets (the
        // sessions themselves are never consumed).
        let _sessions: Vec<SignerSession> = [1u16, 2]
            .into_iter()
            .map(|i| {
                SignerSession::round1(out.secrets.iter().find(|s| s.index == i).unwrap().clone())
            })
            .collect();
        // The coordinator refuses to even OPEN a below-threshold session:
        // a 2-of-3 signing set cannot produce a valid aggregate.
        let err = CoordinatorSession::new(pk, &[1, 2], msg);
        assert!(matches!(err, Err(MeshError::Threshold(_))));
    }

    #[test]
    fn tampered_z_share_fails() {
        let out = keyset(2, 3);
        let pk = out.public.clone();
        let msg = b"m";
        let mut sessions: Vec<SignerSession> = [1u16, 3]
            .into_iter()
            .map(|i| {
                SignerSession::round1(out.secrets.iter().find(|s| s.index == i).unwrap().clone())
            })
            .collect();
        let mut coord = CoordinatorSession::new(pk.clone(), &[1, 3], msg).expect("coord");
        for s in &mut sessions {
            coord.ingest_commitment(s.commitment());
        }
        let mut shares: Vec<RoundTwoShare> = sessions
            .iter()
            .map(|s| s.round2(&coord).expect("r2"))
            .collect();
        shares[0].z_share = "01".repeat(32);
        let sig = coord.aggregate(&shares).expect("aggregate");
        assert!(!sig.verify(&pk, msg), "forged share must break the math");
    }

    #[test]
    fn params_validate() {
        assert!(
            ThresholdParams {
                threshold: 1,
                participants: 5
            }
            .validate()
            .is_err()
        );
        assert!(
            ThresholdParams {
                threshold: 6,
                participants: 5
            }
            .validate()
            .is_err()
        );
        assert!(
            ThresholdParams {
                threshold: 3,
                participants: 5
            }
            .validate()
            .is_ok()
        );
        let p = ThresholdParams::default_for(7);
        assert_eq!(p.threshold, 5); // 7 - f(=2)
        assert_eq!(p.participants, 7);
    }

    #[test]
    fn ml_dsa_seal_verifies() {
        let kp1 = MlDsa44KeyPair::from_seed(&[1u8; 32]);
        let kp2 = MlDsa44KeyPair::from_seed(&[2u8; 32]);
        let msg = b"transcript";
        let mut pks = std::collections::HashMap::new();
        pks.insert("nodeA".to_string(), kp1.public_key_bytes().to_vec());
        pks.insert("nodeB".to_string(), kp2.public_key_bytes().to_vec());
        let seal = MlDsaSeal {
            threshold: 2,
            entries: vec![
                MlDsaSealEntry {
                    node: "nodeA".into(),
                    signature: hex::encode(kp1.sign(msg).as_bytes()),
                },
                MlDsaSealEntry {
                    node: "nodeB".into(),
                    signature: hex::encode(kp2.sign(msg).as_bytes()),
                },
            ],
        };
        assert!(seal.verify(&pks, msg));
        let mut bad = seal.clone();
        bad.entries[0].node = "nodeC".into();
        assert!(!bad.verify(&pks, msg));
        let mut dup = seal.clone();
        dup.entries[1].node = "nodeA".into();
        dup.entries[1].signature = hex::encode(kp1.sign(msg).as_bytes());
        assert!(!dup.verify(&pks, msg), "duplicates do not reach threshold");
    }
}
