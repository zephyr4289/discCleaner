use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampToken {
    pub gen_time_utc: u64,
    pub accuracy_seconds: u32,
    pub tsa_identity: String,
    pub imprint_hash: String,
    pub echoed_nonce: String,
}

pub struct TsaMock {
    pub tsa_name: String,
}

impl TsaMock {
    pub fn new(name: &str) -> Self {
        Self {
            tsa_name: name.to_string(),
        }
    }

    /// Issue an RFC 3161 timestamp token with nonce echo and declared accuracy (Δ424, Δ428).
    pub fn issue_token(
        &self,
        doc_hash: &str,
        nonce: &str,
        timestamp_utc: u64,
        accuracy_sec: u32,
    ) -> TimestampToken {
        TimestampToken {
            gen_time_utc: timestamp_utc,
            accuracy_seconds: accuracy_sec,
            tsa_identity: self.tsa_name.clone(),
            imprint_hash: doc_hash.to_string(),
            echoed_nonce: nonce.to_string(),
        }
    }

    /// Verify timestamp token 100% offline against historical root validity window (Δ426, Δ427).
    pub fn verify_token_offline(
        token: &TimestampToken,
        expected_doc_hash: &str,
        expected_nonce: &str,
        root_expiry_utc: u64,
    ) -> Result<String, &'static str> {
        // 1. Nonce Echo Replay Defense (Δ428)
        if token.echoed_nonce != expected_nonce {
            return Err("REPLAY_DETECTED_NONCE_MISMATCH");
        }

        // 2. Document Imprint Binding (Δ425)
        if token.imprint_hash != expected_doc_hash {
            return Err("WRONG_DOCUMENT_IMPRINT_MISMATCH");
        }

        // 3. Historical Validity: Was the root active when the token was issued? (Δ427)
        if token.gen_time_utc > root_expiry_utc {
            return Err("ROOT_EXPIRED_PRIOR_TO_TOKEN_ISSUANCE");
        }

        // 4. Render vocabulary: existed at-or-before T ± A (Δ424)
        Ok(format!(
            "anchored: existed at-or-before {} ±{}s by TSA {}",
            token.gen_time_utc, token.accuracy_seconds, token.tsa_identity
        ))
    }
}
