//! AWS Signature Version 4 — request signing for the EC2 query API.
//!
//! Implements the canonical request / string-to-sign / signing-key ladder
//! exactly as specified (AWS General Reference, "Signature Version 4 signing
//! process"), pinned by the worked example from the AWS documentation.

use crate::hmac::{hmac_sha256, sha256_hex};
use dc_core::DcError;

/// Static AWS credentials (instance-profile / environment-resolved).
#[derive(Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl AwsCredentials {
    /// Resolve credentials from the standard environment variables
    /// (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN).
    pub fn from_env() -> Option<Self> {
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
        let session_token = std::env::var("AWS_SESSION_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        Some(AwsCredentials {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }
}

impl zeroize::Zeroize for AwsCredentials {
    fn zeroize(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

/// One signed request description.
pub struct SigV4Request<'a> {
    pub method: &'a str,
    pub host: &'a str,
    /// URI path, already percent-encoded per SigV4 rules ("/" stays "/").
    pub canonical_uri: &'a str,
    /// Query pairs; will be sorted and canonically encoded.
    pub query: &'a [(String, String)],
    /// Extra headers included in the signature (host and x-amz-* are added
    /// automatically when relevant).
    pub amz_date: &'a str, // YYYYMMDDTHHMMSSZ
    pub region: &'a str,
    pub service: &'a str,
    pub payload: &'a [u8],
    pub session_token: Option<&'a str>,
}

/// Percent-encode per the SigV4 rules: unreserved characters are
/// `A-Z a-z 0-9 - _ . ~`; everything else becomes `%XX` (uppercase hex).
pub fn aws_uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the canonical query string: sort by key then value, encode both.
pub fn canonical_query_string(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query.to_vec();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", aws_uri_encode(&k, true), aws_uri_encode(&v, true)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Sign the request, returning (canonical_headers_and_list, authorization).
pub fn sign(
    creds: &AwsCredentials,
    req: &SigV4Request,
) -> Result<(Vec<(String, String)>, String), DcError> {
    // --- canonical headers: host, x-amz-date, (x-amz-security-token) ---
    let mut headers: Vec<(String, String)> = vec![
        ("host".to_string(), req.host.to_string()),
        ("x-amz-date".to_string(), req.amz_date.to_string()),
    ];
    if let Some(token) = req.session_token {
        headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v))
        .collect();
    let signed_headers: String = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let payload_hash = sha256_hex(req.payload);
    headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        req.canonical_uri,
        canonical_query_string(req.query),
        canonical_headers,
        signed_headers,
        payload_hash,
    );

    // --- string to sign ---
    let date = &req.amz_date[..8];
    let credential_scope = format!("{}/{}/{}/aws4_request", date, req.region, req.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        req.amz_date,
        credential_scope,
        sha256_hex(canonical_request.as_bytes()),
    );

    // --- signing key ladder ---
    let k_date = hmac_sha256(
        format!("AWS4{}", creds.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, req.region.as_bytes());
    let k_service = hmac_sha256(&k_region, req.service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        creds.access_key_id, credential_scope, signed_headers, signature
    );

    headers.push(("authorization".to_string(), authorization));
    Ok((headers, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end signing against a vector computed independently (Python
    /// hmac/hashlib, different codebase): EC2 DescribeVolumes with a session
    /// token. The signing-key ladder alone is additionally pinned by the
    /// published AWS documentation constant c4afb1cc... (kSigning for the
    /// classic 2015-08-30 us-east-1/iam example key).
    #[test]
    fn independent_ec2_describe_volumes_vector() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: Some("IQoJb3EXAMPLETOKEN123//==".to_string()),
        };
        let req = SigV4Request {
            method: "GET",
            host: "ec2.eu-central-1.amazonaws.com",
            canonical_uri: "/",
            query: &[
                ("Action".to_string(), "DescribeVolumes".to_string()),
                ("Version".to_string(), "2016-11-15".to_string()),
                ("VolumeId.1".to_string(), "vol-0abc123DEF".to_string()),
            ],
            amz_date: "20261012T093000Z",
            region: "eu-central-1",
            service: "ec2",
            payload: b"",
            session_token: creds.session_token.as_deref(),
        };
        let (_headers, signature) = sign(&creds, &req).expect("sign");
        assert_eq!(
            signature,
            "f775813851ea466deb06d02f753ac6a0a31e1b8efaeb01d8710634d515c13ca0"
        );
    }

    /// The published AWS documentation derivation constant: the signing key
    /// for the classic example (2015-08-30 / us-east-1 / iam /
    /// wJalrXUtnFEMI...EXAMPLEKEY) is c4afb1cc5771d871763a393e44b703571b5
    /// 5cc28424d1a5e86da6ed3c154a4b9.
    #[test]
    fn aws_documentation_signing_key_ladder() {
        let k_date = hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20150830");
        let k_region = hmac_sha256(&k_date, b"us-east-1");
        let k_service = hmac_sha256(&k_region, b"iam");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        assert_eq!(
            hex::encode(k_signing),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn uri_encoding_rules() {
        assert_eq!(aws_uri_encode("a/b", false), "a/b");
        assert_eq!(aws_uri_encode("a/b", true), "a%2Fb");
        assert_eq!(aws_uri_encode("太空", true), "%E5%A4%AA%E7%A9%BA");
        assert_eq!(aws_uri_encode("AZaz09-_.~", true), "AZaz09-_.~");
        assert_eq!(aws_uri_encode("a b", true), "a%20b");
    }
}
