use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawBlob<T> {
    pub decoded: T,
    pub raw: Vec<u8>,
    pub blake3: String,
}

impl<T> RawBlob<T> {
    pub fn new(decoded: T, raw: &[u8]) -> Self {
        let blake3 = blake3::hash(raw).to_hex().to_string();
        Self {
            decoded,
            raw: raw.to_vec(),
            blake3,
        }
    }
}
