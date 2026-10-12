//! EC2 Instance Metadata Service v2 — identity and credentials discovery
//! over the link-local endpoint (169.254.169.254), with the session-token
//! handshake that IMDSv2 mandates.

use dc_core::DcError;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const IMDS_HOST: &str = "169.254.169.254";
const IMDS_TIMEOUT: Duration = Duration::from_secs(2);

/// Instance identity facts needed to drive an attach→sanitize→detach
/// lifecycle against *this* EC2 instance.
#[derive(Debug, Clone)]
pub struct InstanceIdentity {
    pub instance_id: String,
    pub region: String,
    pub availability_zone: String,
    pub account_id: String,
}

/// A minimal IMDSv2 client over plain HTTP (the service is link-local
/// plaintext by design; hop limit 1 keeps it non-routable).
pub struct ImdsClient {
    token: String,
}

impl ImdsClient {
    /// Perform the IMDSv2 token handshake (PUT /latest/api/token).
    pub fn connect() -> Result<Self, DcError> {
        let token = plain_http(
            "PUT",
            "/latest/api/token",
            &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
            b"",
        )?;
        if token.status != 200 {
            return Err(DcError::Internal(format!(
                "IMDSv2 token request refused: HTTP {} — is this really an EC2 instance?",
                token.status
            )));
        }
        Ok(ImdsClient {
            token: token.body_str(),
        })
    }

    fn get(&self, path: &str) -> Result<String, DcError> {
        let resp = plain_http(
            "GET",
            path,
            &[("X-aws-ec2-metadata-token", &self.token)],
            b"",
        )?;
        if resp.status != 200 {
            return Err(DcError::Internal(format!(
                "IMDS GET {path}: HTTP {}",
                resp.status
            )));
        }
        Ok(resp.body_str().trim().to_string())
    }

    /// Full instance identity: instance-id, region, AZ and account id
    /// (from the instance-identity document, a JSON blob with exactly the
    /// fields we need).
    pub fn instance_identity(&self) -> Result<InstanceIdentity, DcError> {
        let instance_id = self.get("/latest/meta-data/instance-id")?;
        let az = self.get("/latest/meta-data/placement/availability-zone")?;
        let region = self.get("/latest/meta-data/placement/region")?;
        let doc = self.get("/latest/dynamic/instance-identity/document")?;
        let account_id = json_field(&doc, "accountId").ok_or_else(|| {
            DcError::Internal("instance-identity document: no accountId".to_string())
        })?;
        Ok(InstanceIdentity {
            instance_id,
            region,
            availability_zone: az,
            account_id,
        })
    }

    /// Instance-profile credentials (for instances launched with an IAM
    /// role — the recommended deployment: no long-lived keys on disk).
    pub fn instance_profile_credentials(&self) -> Result<crate::sigv4::AwsCredentials, DcError> {
        let role = self.get("/latest/meta-data/iam/security-credentials/")?;
        let doc = self.get(&format!(
            "/latest/meta-data/iam/security-credentials/{role}"
        ))?;
        let access = json_field(&doc, "AccessKeyId")
            .ok_or_else(|| DcError::Internal("credentials document: no AccessKeyId".to_string()))?;
        let secret = json_field(&doc, "SecretAccessKey").ok_or_else(|| {
            DcError::Internal("credentials document: no SecretAccessKey".to_string())
        })?;
        let token = json_field(&doc, "Token");
        Ok(crate::sigv4::AwsCredentials {
            access_key_id: access,
            secret_access_key: secret,
            session_token: token,
        })
    }
}

/// Field extractor for the tiny, well-formed JSON documents IMDS returns
/// (instance-identity / credential docs). Not a general JSON parser —
/// by design: the surface parsed here is attacker-controlled only in
///sofar as the link-local IMDS is, and a scanner keeps it strict.
fn json_field(doc: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let start = doc.find(&needle)? + needle.len();
    let rest = &doc[start..];
    let colon = rest.find(':')?;
    let rest = &rest[colon + 1..];
    let rest = rest.trim_start();
    let value = rest.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(value[..end].to_string())
}

/// One plain-HTTP/1.1 request to the IMDS endpoint (Connection: close).
fn plain_http(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    _body: &[u8],
) -> Result<crate::transport::TransportResponse, DcError> {
    let mut stream = TcpStream::connect(IMDS_HOST)?;
    stream.set_read_timeout(Some(IMDS_TIMEOUT))?;
    stream.set_write_timeout(Some(IMDS_TIMEOUT))?;

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {IMDS_HOST}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);

    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| DcError::Internal("IMDS: malformed response".to_string()))?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok(crate::transport::TransportResponse {
        status,
        body: body.into_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_field_extraction() {
        let doc = r#"{"accountId":"123456789012","region":"eu-west-1"}"#;
        assert_eq!(
            json_field(doc, "accountId").as_deref(),
            Some("123456789012")
        );
        assert_eq!(json_field(doc, "region").as_deref(), Some("eu-west-1"));
        assert_eq!(json_field(doc, "missing"), None);
        // The extractor must not be confused by nested or absent values.
        assert_eq!(json_field(r#"{"x":1}"#, "x"), None);
    }

    #[test]
    fn imds_credentials_parse() {
        let doc = r#"{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"SECRET","Token":"TOKEN==","Expiration":"2026-10-12T12:00:00Z"}"#;
        assert_eq!(
            json_field(doc, "AccessKeyId").as_deref(),
            Some("ASIAEXAMPLE")
        );
        assert_eq!(
            json_field(doc, "SecretAccessKey").as_deref(),
            Some("SECRET")
        );
        assert_eq!(json_field(doc, "Token").as_deref(), Some("TOKEN=="));
    }
}
