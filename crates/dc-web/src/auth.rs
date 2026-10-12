//! Bearer-token authentication for the dashboard API.

use std::time::Duration;

/// Token entropy: 32 bytes (256 bits) hex-encoded for display.
pub const AUTH_TOKEN_BYTES: usize = 32;

pub struct TokenAuth {
    token: String,
}

impl TokenAuth {
    /// Generate a fresh 256-bit token from the OS CSPRNG.
    pub fn generate() -> Result<Self, dc_core::DcError> {
        let mut bytes = [0u8; AUTH_TOKEN_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|e| dc_core::DcError::Rng(e.to_string()))?;
        Ok(TokenAuth {
            token: hex::encode(bytes),
        })
    }

    /// Adopt an operator-supplied token (from `--token` or `--token-file`).
    /// Refuses weak tokens: the dashboard gates destructive operations.
    pub fn from_str_token(token: &str) -> Result<Self, dc_core::DcError> {
        if token.len() < 32 {
            return Err(dc_core::DcError::Usage(format!(
                "dashboard token must be at least 32 characters, got {} — \
                 generate one with: openssl rand -hex 32",
                token.len()
            )));
        }
        Ok(TokenAuth {
            token: token.to_string(),
        })
    }

    /// Read the token from a 0600-mode file (token files must not be
    /// world-readable — same discipline as key files).
    pub fn from_file(path: &std::path::Path) -> Result<Self, dc_core::DcError> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(dc_core::DcError::Usage(format!(
                "REFUSING_WORLD_READABLE_TOKEN_FILE: '{}' has mode {:o}",
                path.display(),
                mode
            )));
        }
        let content = std::fs::read_to_string(path)?;
        Self::from_str_token(content.trim())
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Constant-time token comparison: no early exit, so an attacker cannot
    /// time-search the token prefix byte by byte.
    pub fn check(&self, presented: &str) -> bool {
        constant_time_eq(self.token.as_bytes(), presented.as_bytes())
    }
}

/// Constant-time equality over byte slices of any length: the length itself
/// is mixed into the accumulator, and the comparison walks the maximum of
/// both lengths.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max = a.len().max(b.len());
    let mut acc: u8 = ((a.len() ^ b.len()) & 0xFF) as u8;
    for i in 0..max {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        acc |= x ^ y;
    }
    acc == 0
}

/// How long an unauthenticated peer's connection may linger before the
/// server closes it (auth failures get no slow-loris window).
pub const AUTH_FAILURE_CLOSE: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_generate_and_check() {
        let auth = TokenAuth::generate().expect("rng");
        assert_eq!(auth.token().len(), 64, "hex of 32 bytes");
        assert!(auth.check(auth.token()));
        assert!(!auth.check(&auth.token()[..63]));
        assert!(!auth.check("0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn weak_tokens_refused() {
        assert!(TokenAuth::from_str_token("short").is_err());
        assert!(TokenAuth::from_str_token("01234567890123456789012345678901").is_ok());
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
