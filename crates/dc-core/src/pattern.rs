use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PrngScheme {
    ChaCha20WindowV1,
}

/// Wipe-pass derivation scheme for VDF-woven sanitization (v0.12.0,
/// Miracle 1). The plan declares the WEAVE (a commitment to the puzzle
/// parameters); the per-pass keystream key is the VDF state materialized
/// by the executor between passes and recorded (with its Wesolowski
/// proof) in the certificate's `vdf` evidence section.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VdfWeaveScheme {
    /// Per-pass key = BLAKE3(state_i || pass_index); window keystream is
    /// ChaCha20WindowV1 over that key. States advance by exactly
    /// `steps_per_pass` sequential modular squarings.
    WesolowskiRsaUfoV1,
}

impl std::fmt::Display for PrngScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChaCha20WindowV1 => write!(f, "chacha20-window-v1"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Pattern {
    Zero,
    Fixed {
        byte: u8,
    },
    /// Repeating little-endian 4-byte word (e.g. 0x92492492 -> [0x92,0x49,0x24,0x92]).
    /// Required by MFM/RLL-era legacy passes such as Gutmann; trailing
    /// partial windows are filled with the leading sub-word.
    FixedWord {
        #[serde(with = "hex_serde_4")]
        bytes: [u8; 4],
    },
    DeterministicRandom {
        scheme: PrngScheme,
        #[serde(with = "hex_serde")]
        seed: [u8; 32],
    },
    /// VDF-woven pass (v0.12.0, Miracle 1): the bytes written to media
    /// during this pass are keyed by an intermediate state of a
    /// time-lock puzzle chain, so the physical write traffic itself
    /// proves a sequential-squaring wall-clock lower bound. The
    /// `seed_commitment` binds the puzzle (modulus + challenge); the
    /// materialized state seed is supplied by the executor (write
    /// path) or read from the certificate's `vdf` evidence (verify
    /// path) via `create_vdf_pattern_source`.
    VdfWoven {
        scheme: VdfWeaveScheme,
        #[serde(with = "hex_serde")]
        seed_commitment: [u8; 32],
    },
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if vec.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes hex, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

mod hex_serde_4 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 4], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 4], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if vec.len() != 4 {
            return Err(serde::de::Error::custom(format!(
                "expected 4 bytes hex, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternDescriptor {
    pub name: String,
    pub pattern: Pattern,
    pub description: String,
}

pub trait PatternSource: Send + Sync {
    /// Fill `buf` with pattern bytes for window `w`. MUST be pure:
    /// identical (w, buf.len()) -> identical bytes, on any machine, forever.
    fn fill(&self, w: u64, buf: &mut [u8]);

    /// Machine-readable descriptor embedded in plan, journal, and cert.
    fn descriptor(&self) -> PatternDescriptor;

    /// Fixed/zero patterns are window-invariant -> engine can use ONE buffer
    /// for the entire pass. PRNG patterns are not.
    fn window_invariant(&self) -> bool;
}

pub struct ZeroPattern;

impl PatternSource for ZeroPattern {
    fn fill(&self, _w: u64, buf: &mut [u8]) {
        buf.fill(0);
    }

    fn descriptor(&self) -> PatternDescriptor {
        PatternDescriptor {
            name: "Zero".to_string(),
            pattern: Pattern::Zero,
            description: "All zero bytes (0x00)".to_string(),
        }
    }

    fn window_invariant(&self) -> bool {
        true
    }
}

pub struct FixedPattern {
    pub byte: u8,
}

impl PatternSource for FixedPattern {
    fn fill(&self, _w: u64, buf: &mut [u8]) {
        buf.fill(self.byte);
    }

    fn descriptor(&self) -> PatternDescriptor {
        PatternDescriptor {
            name: format!("Fixed(0x{:02X})", self.byte),
            pattern: Pattern::Fixed { byte: self.byte },
            description: format!("Repeating byte 0x{:02X}", self.byte),
        }
    }

    fn window_invariant(&self) -> bool {
        true
    }
}

pub struct FixedWordPattern {
    pub bytes: [u8; 4],
}

impl PatternSource for FixedWordPattern {
    fn fill(&self, _w: u64, buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.bytes[i & 3];
        }
    }

    fn descriptor(&self) -> PatternDescriptor {
        PatternDescriptor {
            name: format!("FixedWord(0x{})", hex::encode(self.bytes)),
            pattern: Pattern::FixedWord { bytes: self.bytes },
            description: format!("Repeating 4-byte word {}", hex::encode(self.bytes)),
        }
    }

    fn window_invariant(&self) -> bool {
        true
    }
}

pub struct ChaCha20Pattern {
    pub seed: [u8; 32],
}

impl ChaCha20Pattern {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn generate_random_seed() -> Result<[u8; 32], getrandom::Error> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)?;
        Ok(seed)
    }
}

impl PatternSource for ChaCha20Pattern {
    fn fill(&self, w: u64, buf: &mut [u8]) {
        // §7: Nonce is 12 bytes: nonce[0..8] = window_index as u64 LE, nonce[8..12] = 0x00000000
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&w.to_le_bytes());
        nonce[8..12].copy_from_slice(&[0, 0, 0, 0]);

        buf.fill(0);
        let mut cipher = ChaCha20::new((&self.seed).into(), (&nonce).into());
        cipher.apply_keystream(buf);
    }

    fn descriptor(&self) -> PatternDescriptor {
        PatternDescriptor {
            name: "ChaCha20WindowV1".to_string(),
            pattern: Pattern::DeterministicRandom {
                scheme: PrngScheme::ChaCha20WindowV1,
                seed: self.seed,
            },
            description: format!(
                "Deterministic CSPRNG (ChaCha20WindowV1, seed: {})",
                hex::encode(self.seed)
            ),
        }
    }

    fn window_invariant(&self) -> bool {
        false
    }
}

/// Materialized VDF weave pass source (v0.12.0, Miracle 1).
///
/// Pure WITHIN an instance: `fill` is a pure function of (window, len)
/// for the fixed `state_seed` the instance was constructed with. The
/// state seed itself is the sequential-squaring VDF output for the
/// pass — produced between passes by the executor (each state costing
/// `steps_per_pass` provable non-parallelizable squarings since the
/// previous one) or re-derived by an auditor from the certificate's
/// per-pass states and Wesolowski proofs.
pub struct VdfWeavePattern {
    pub scheme: VdfWeaveScheme,
    pub seed_commitment: [u8; 32],
    /// Pass index this source is bound to.
    pub pass_index: u8,
    /// BLAKE3(state_i || pass_index) — the actual 32-byte ChaCha20 key.
    pub state_seed: [u8; 32],
}

impl PatternSource for VdfWeavePattern {
    fn fill(&self, w: u64, buf: &mut [u8]) {
        // Same keystream geometry as ChaCha20WindowV1 so read-back
        // verification shares one tested code path — only the key
        // derivation differs (it comes from the VDF chain).
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&w.to_le_bytes());
        nonce[8..12].copy_from_slice(&[0, 0, 0, 0]);

        buf.fill(0);
        let mut cipher = ChaCha20::new((&self.state_seed).into(), (&nonce).into());
        cipher.apply_keystream(buf);
    }

    fn descriptor(&self) -> PatternDescriptor {
        PatternDescriptor {
            name: format!(
                "VdfWeaveV1(pass {}, seed-fp {})",
                self.pass_index,
                &hex::encode(self.state_seed)[..16]
            ),
            pattern: Pattern::VdfWoven {
                scheme: self.scheme,
                seed_commitment: self.seed_commitment,
            },
            description: format!(
                "VDF-woven pass — ChaCha20 keystream keyed by time-lock state {}",
                hex::encode(self.state_seed)
            ),
        }
    }

    fn window_invariant(&self) -> bool {
        false
    }
}

/// Derive the 32-byte ChaCha20 key for pass `pass_index` from the
/// materialized VDF state bytes (canonical big-endian modulus-width).
/// Used identically by the writer and the verifier, so both sides
/// always agree on the on-media bytes.
pub fn vdf_pass_seed(state_bytes: &[u8], pass_index: u8) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"dc-vdf/weave/v1");
    h.update(state_bytes);
    h.update(&[pass_index]);
    *h.finalize().as_bytes()
}

/// Construct a materialized weave source for one pass.
pub fn create_vdf_pattern_source(
    scheme: VdfWeaveScheme,
    seed_commitment: [u8; 32],
    pass_index: u8,
    state_bytes: &[u8],
) -> Box<dyn PatternSource> {
    Box::new(VdfWeavePattern {
        scheme,
        seed_commitment,
        pass_index,
        state_seed: vdf_pass_seed(state_bytes, pass_index),
    })
}

pub fn create_pattern_source(pattern: &Pattern) -> Box<dyn PatternSource> {
    match pattern {
        Pattern::Zero => Box::new(ZeroPattern),
        Pattern::Fixed { byte } => Box::new(FixedPattern { byte: *byte }),
        Pattern::FixedWord { bytes } => Box::new(FixedWordPattern { bytes: *bytes }),
        Pattern::DeterministicRandom { scheme, seed } => match scheme {
            PrngScheme::ChaCha20WindowV1 => Box::new(ChaCha20Pattern::new(*seed)),
        },
        // A VdfWoven pattern is a WEAVE DECLARATION, not a materialized
        // source: the state seed only exists after the executor advanced
        // the time-lock chain (or an auditor replays it from the
        // certificate evidence). Reaching this arm means an unmaterialized
        // plan leaked into a generic path — fail loudly instead of
        // writing attacker-predictable bytes to media. The executor and
        // verifier construct weave sources exclusively through
        // `create_vdf_pattern_source`, and every CLI path that compiles or
        // consumes VdfWoven plans validates this first.
        Pattern::VdfWoven { .. } => panic!(
            "VdfWoven patterns must be materialized with create_vdf_pattern_source() \
             (VDF state from the executor's lock or the certificate's vdf evidence)"
        ),
    }
}
