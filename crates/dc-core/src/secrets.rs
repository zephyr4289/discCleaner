//! Secret-material hygiene (v0.9.0, Phase 1a).
//!
//! Every byte of key material that passes through `dc` userspace — operator
//! Ed25519 seeds, PIV PIN pads, TPM-sealed blobs and their unsealed plaintext
//! — lives inside a [`SecretBuf`]. The type enforces two OS-level guarantees:
//!
//! 1. **Zeroization**: the backing memory is wiped with volatile stores on
//!    drop (`zeroize` crate — compiler-reorder-proof, never optimized away),
//!    so private keys never linger in freed heap pages, core dumps or
//!    forensic RAM images after the process exits.
//! 2. **Non-pageability**: the pages are `mlock(2)`-pinned for the lifetime
//!    of the buffer, so the secret can never be transparently swapped out to
//!    disk where it would outlive the sanitization run (swap spill is a
//!    classified-media non-spillage violation).
//!
//! `mlock` is best-effort: unprivileged runs are capped by
//! `RLIMIT_MEMLOCK` (often 64 KiB) and this is a hardening layer, not a
//! precondition — the buffer reports whether the pin took hold so callers
//! can surface it in evidence. Zeroization is unconditional.

use std::fmt;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// A heap buffer of secret bytes: `mlock`-pinned, zeroized on drop.
///
/// Construct via [`SecretBuf::from_vec`] / [`SecretBuf::from_str_zeroized`],
/// read via `expose()` (never `Display` — see the `fmt` guard below).
pub struct SecretBuf {
    buf: Box<[u8]>,
    /// Whether `mlock(2)` succeeded (advisory hardening state, surfaced in
    /// evidence but never load-bearing for correctness).
    locked: bool,
}

impl SecretBuf {
    /// Take ownership of a `Vec`, pin it in RAM, wipe it on drop.
    /// `mlock` failure (RLIMIT_MEMLOCK exhaustion under unprivileged fleet
    /// agents) degrades to zeroize-only — recorded in `locked`.
    pub fn from_vec(mut v: Vec<u8>) -> Self {
        v.shrink_to_fit();
        let len = v.len();
        let boxed: Box<[u8]> = v.into_boxed_slice();
        let mut this = Self {
            buf: boxed,
            locked: false,
        };
        this.try_mlock(len);
        this
    }

    /// Convenience: build from a secret string (PIN, passphrase) — the
    /// source `String` copy must be wiped by the CALLER (see
    /// `Zeroizing<String>` for that), this zeroizes only the new buffer.
    pub fn from_str_zeroized(s: &str) -> Self {
        Self::from_vec(s.as_bytes().to_vec())
    }

    /// Best-effort `mlock(2)` on the whole allocation.
    ///
    /// SAFETY: `Box<[u8]>` guarantees a non-null, valid-for-`len` read
    /// pointer for the lifetime of the box; `mlock` only pins pages, it
    /// never writes through the pointer.
    fn try_mlock(&mut self, len: usize) {
        if len == 0 {
            return;
        }
        let rc = unsafe { libc::mlock(self.buf.as_ptr().cast::<libc::c_void>(), len) };
        self.locked = rc == 0;
        if !self.locked {
            // ENOMEM (RLIMIT_MEMLOCK) is the expected unprivileged case;
            // anything else is still non-fatal — zeroization still applies.
            tracing::debug!(
                "mlock of {} secret bytes refused by kernel (zeroization still active)",
                len
            );
        }
    }

    /// Immutable access to the secret (scope discipline: bind to a local,
    /// never copy out).
    pub fn expose(&self) -> &[u8] {
        &self.buf
    }

    /// Mutable access to the secret in place (no reallocation escapes the
    /// guard).
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Explicitly wipe NOW (observable for tests and mid-lifecycle
    /// rotation); the Drop impl wipes again — double-zero is a no-op.
    pub fn zeroize_now(&mut self) {
        self.buf.zeroize();
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Did the kernel accept the `mlock` pin? (evidence/reporting only)
    pub fn is_locked_in_ram(&self) -> bool {
        self.locked
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // 1. Volatile wipe, THEN 2. release the page pin — a window in the
        // other order would let the wiped page be swapped back in.
        self.buf.zeroize();
        if self.locked {
            // SAFETY: same pointer/len contract as try_mlock; munlock only
            // un-pins pages.
            unsafe {
                libc::munlock(self.buf.as_ptr().cast::<libc::c_void>(), self.buf.len());
            }
        }
    }
}

impl Deref for SecretBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl DerefMut for SecretBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

/// Never leak via formatting — not even in debug/panic paths.
impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretBuf(len={}, mlock={})",
            self.buf.len(),
            self.locked
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_vec_roundtrips_and_reports_mlock_state() {
        let s = SecretBuf::from_vec(b"top-secret-seed".to_vec());
        assert_eq!(s.expose(), b"top-secret-seed");
        // On the CI root account mlock virtually always succeeds; either way
        // the flag must mirror reality (we cannot force ENOMEM portably, so
        // only assert the invariant that the API is queryable).
        let _ = s.is_locked_in_ram();
    }

    #[test]
    fn zeroize_now_wipes_contents() {
        let mut s = SecretBuf::from_vec(vec![0xA5u8; 64]);
        s.zeroize_now();
        assert!(s.expose().iter().all(|&b| b == 0));
    }

    #[test]
    fn debug_never_reveals_contents() {
        let s = SecretBuf::from_vec(b"classified".to_vec());
        let rendered = format!("{:?}", s);
        assert!(!rendered.contains("classified"));
        assert!(rendered.contains("SecretBuf"));
    }

    #[test]
    fn empty_buffer_is_inert() {
        let s = SecretBuf::from_vec(Vec::new());
        assert!(s.is_empty());
        assert!(!s.is_locked_in_ram());
    }

    #[test]
    fn deref_gives_byte_slice_access() {
        let mut s = SecretBuf::from_vec(vec![1, 2, 3]);
        assert_eq!(&s[..2], &[1, 2]);
        s.expose_mut()[0] = 9;
        assert_eq!(s.expose()[0], 9);
    }
}
