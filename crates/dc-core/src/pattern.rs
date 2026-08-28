use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PrngScheme {
    ChaCha20WindowV1,
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
    DeterministicRandom {
        scheme: PrngScheme,
        #[serde(with = "hex_serde")]
        seed: [u8; 32],
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

pub fn create_pattern_source(pattern: &Pattern) -> Box<dyn PatternSource> {
    match pattern {
        Pattern::Zero => Box::new(ZeroPattern),
        Pattern::Fixed { byte } => Box::new(FixedPattern { byte: *byte }),
        Pattern::DeterministicRandom { scheme, seed } => match scheme {
            PrngScheme::ChaCha20WindowV1 => Box::new(ChaCha20Pattern::new(*seed)),
        },
    }
}
