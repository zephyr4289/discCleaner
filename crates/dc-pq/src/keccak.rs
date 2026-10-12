//! FIPS 202 Keccak — the hash foundation of ML-DSA.
//!
//! Implements the Keccak-f[1600] permutation, SHA3-256 and the SHAKE256
//! extendable-output function entirely from the published specification:
//!
//! * round constants and rho rotation offsets are the FIPS 202 Tables
//!   2/3 values and are pinned by known-answer tests below;
//! * SHA3-256 uses rate 136 bytes and domain padding byte `0x06`;
//! * SHAKE256 uses rate 136 bytes and domain padding byte `0x1F`.
//!
//! ML-DSA consumes only [`Shake256`] (64-byte outputs for the internal
//! hash calls, arbitrary-length squeezes for the expansion functions).

// ---------------------------------------------------------------------------
// Keccak-f[1600]
// ---------------------------------------------------------------------------

/// FIPS 202 Table 2 — round constants for the 24 rounds of iota.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// FIPS 202 Table 3 — rho rotation offsets, indexed `RHO[x][y]`.
const RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// The Keccak-f[1600] permutation over a 5x5 lane state.
///
/// State layout: `a[x + 5*y]` is lane (x, y), matching the specification's
/// indexing (x = column, y = row).
pub fn keccak_f1600(a: &mut [u64; 25]) {
    for &rc in RC.iter() {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }

        // rho + pi:  B[y, (2x + 3y) mod 5] = rot(A[x, y], RHO[x][y])
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let dst = y + 5 * ((2 * x + 3 * y) % 5);
                b[dst] = a[x + 5 * y].rotate_left(RHO[x][y]);
            }
        }

        // chi
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // iota
        a[0] ^= rc;
    }
}

// ---------------------------------------------------------------------------
// Sponge
// ---------------------------------------------------------------------------

/// Keccak sponge with a byte-rate of 136 (1088-bit rate / 512-bit capacity —
/// the parameterization shared by SHA3-256 and SHAKE256).
const RATE: usize = 136;

/// Incremental sponge driver. Handles arbitrary absorb/squeeze patterns
/// required by ML-DSA's expansion functions (which squeeze unbounded streams
/// while rejection-sampling).
pub struct KeccakSponge {
    state: [u64; 25],
    /// Bytes of the current rate block already absorbed (absorbing phase)
    /// or already squeezed out (squeezing phase).
    pos: usize,
    squeezing: bool,
}

impl Default for KeccakSponge {
    fn default() -> Self {
        Self::new()
    }
}

impl KeccakSponge {
    pub fn new() -> Self {
        KeccakSponge {
            state: [0u64; 25],
            pos: 0,
            squeezing: false,
        }
    }

    fn xor_byte(&mut self, offset: usize, byte: u8) {
        // Little-endian lane packing (FIPS 202 §3.1.2).
        let lane = offset / 8;
        let shift = 8 * (offset % 8);
        self.state[lane] ^= (byte as u64) << shift;
    }

    fn byte_at(&self, offset: usize) -> u8 {
        let lane = offset / 8;
        let shift = 8 * (offset % 8);
        ((self.state[lane] >> shift) & 0xFF) as u8
    }

    fn permute(&mut self) {
        keccak_f1600(&mut self.state);
    }

    /// Absorb message bytes (may be called repeatedly before finalization).
    /// The domain separation byte is applied once, at padding time
    /// ([`Self::finalize_xof`]).
    pub fn absorb(&mut self, data: &[u8]) {
        assert!(
            !self.squeezing,
            "dc-pq bug: absorb after squeeze — ML-DSA never does this"
        );
        let mut i = 0;
        while i < data.len() {
            let take = core::cmp::min(RATE - self.pos, data.len() - i);
            for k in 0..take {
                self.xor_byte(self.pos + k, data[i + k]);
            }
            self.pos += take;
            i += take;
            if self.pos == RATE {
                self.permute();
                self.pos = 0;
            }
        }
    }

    /// Apply the multi-rate padding at the current position and enter the
    /// squeezing phase.
    pub fn finalize_xof(&mut self, domain: u8) {
        assert!(!self.squeezing, "double finalize");
        // pad10*1 with the domain byte: data || 0x06/0x1F ... || 0x80.
        self.xor_byte(self.pos, domain);
        self.xor_byte(RATE - 1, 0x80);
        self.permute();
        self.pos = 0;
        self.squeezing = true;
    }

    /// Squeeze `out.len()` bytes (advances across rate blocks as needed).
    pub fn squeeze(&mut self, out: &mut [u8]) {
        assert!(self.squeezing, "squeeze before finalize");
        let mut i = 0;
        while i < out.len() {
            let take = core::cmp::min(RATE - self.pos, out.len() - i);
            for k in 0..take {
                out[i + k] = self.byte_at(self.pos + k);
            }
            self.pos += take;
            i += take;
            if self.pos == RATE {
                self.permute();
                self.pos = 0;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fixed-output digests / XOF used by ML-DSA
// ---------------------------------------------------------------------------

/// SHA3-256 (FIPS 202) — included as an independent known-answer anchor for
/// the Keccak core; ML-DSA itself uses only SHAKE256.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sponge = KeccakSponge::new();
    sponge.absorb(data);
    sponge.finalize_xof(0x06);
    let mut out = [0u8; 32];
    sponge.squeeze(&mut out);
    out
}

/// SHAKE256 convenience: absorb `input`, squeeze `out.len()` bytes.
pub fn shake256(input: &[u8], out: &mut [u8]) {
    let mut sponge = KeccakSponge::new();
    sponge.absorb(input);
    sponge.finalize_xof(0x1F);
    sponge.squeeze(out);
}

/// Stateful SHAKE256 XOF: absorb once, then squeeze incrementally in
/// arbitrarily-sized pieces (used by the ML-DSA expansion functions, which
/// consume unbounded streams while rejection-sampling).
pub struct Shake256 {
    sponge: KeccakSponge,
}

impl Shake256 {
    /// Build the XOF over the exact byte concatenation of the given inputs.
    /// ML-DSA hashes are always a concatenation of named fields, so taking
    /// `&[&[u8]]` here documents the domain layout at every call site.
    pub fn new(parts: &[&[u8]]) -> Self {
        let mut sponge = KeccakSponge::new();
        for p in parts {
            sponge.absorb(p);
        }
        sponge.finalize_xof(0x1F);
        Shake256 { sponge }
    }

    /// Squeeze the next `out.len()` bytes from the stream.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.sponge.squeeze(out);
    }
}

// ---------------------------------------------------------------------------
// Known-answer tests (FIPS 202 example vectors)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// SHA3-256("") — the canonical empty-string KAT.
    #[test]
    fn kat_sha3_256_empty() {
        assert_eq!(
            hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    /// SHA3-256("abc").
    #[test]
    fn kat_sha3_256_abc() {
        assert_eq!(
            hex(&sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    /// SHA3-256 of a 200-byte message — forces a multi-block absorb path
    /// (200 > rate 136) plus padding within a partial block. Vector from
    /// the FIPS 202 / NIST SHA-3 sample files (msg length 1600 bits).
    #[test]
    fn kat_sha3_256_200_bytes() {
        let msg = [0xA3u8; 200];
        assert_eq!(
            hex(&sha3_256(&msg)),
            "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"
        );
    }

    /// SHAKE256("", 32) — first 32 bytes of the empty-message XOF.
    #[test]
    fn kat_shake256_empty_32() {
        let mut out = [0u8; 32];
        shake256(b"", &mut out);
        assert_eq!(
            hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    /// Incremental squeezing must equal one-shot squeezing.
    #[test]
    fn shake256_incremental_equals_oneshot() {
        let mut one = [0u8; 300]; // > 2 rate blocks
        shake256(b"incremental-consistency", &mut one);

        let mut xof = Shake256::new(&[b"incremental-consistency"]);
        let mut inc = [0u8; 300];
        let mut done = 0;
        while done < inc.len() {
            let chunk = core::cmp::min(37, inc.len() - done); // awkward size on purpose
            xof.squeeze(&mut inc[done..done + chunk]);
            done += chunk;
        }
        assert_eq!(one, inc);
    }

    /// Two distinct Shake256 instances with identical input agree.
    #[test]
    fn shake256_streams_are_deterministic() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        shake256(b"two instances", &mut a);
        shake256(b"two instances", &mut b);
        assert_eq!(a, b);
    }
}
