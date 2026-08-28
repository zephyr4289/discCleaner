pub struct Truncator;

impl Truncator {
    /// Pure truncation of journal bytes at offset `o`.
    pub fn truncate(bytes: &[u8], offset: usize) -> Vec<u8> {
        let o = offset.min(bytes.len());
        bytes[..o].to_vec()
    }

    /// Truncate at `offset` and append `zero_len` zero bytes (Δ91 zero-tail model).
    pub fn zero_tail(bytes: &[u8], offset: usize, zero_len: usize) -> Vec<u8> {
        let mut out = Self::truncate(bytes, offset);
        out.extend(std::iter::repeat(0u8).take(zero_len));
        out
    }

    /// Truncate at `offset` and append arbitrary garbage bytes.
    pub fn garbage_tail(bytes: &[u8], offset: usize, garbage: &[u8]) -> Vec<u8> {
        let mut out = Self::truncate(bytes, offset);
        out.extend_from_slice(garbage);
        out
    }
}
