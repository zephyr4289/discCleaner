//! HTTP transport abstraction for cloud API calls.
//!
//! EC2 endpoints are HTTPS-only. The default build of `dc-cloud` carries
//! zero TLS dependencies (the musl appliance must stay dependency-free);
//! real-account operations enable the `cloud-tls` feature which provides
//! [`UreqTransport`] over rustls. Tests and `--provider mock` drills use
//! [`MockTransport`] with canned AWS responses.

use dc_core::DcError;

pub struct TransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl TransportResponse {
    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Pluggable HTTPS transport.
pub trait CloudTransport: Send + Sync {
    /// `method`, absolute `https://` URL, headers, body.
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<TransportResponse, DcError>;
}

/// Production transport behind `--features cloud-tls`.
#[cfg(feature = "cloud-tls")]
pub struct UreqTransport {
    agent: ureq::Agent,
}

#[cfg(feature = "cloud-tls")]
impl UreqTransport {
    pub fn new() -> Self {
        UreqTransport {
            agent: ureq::AgentBuilder::new().build(),
        }
    }
}

#[cfg(feature = "cloud-tls")]
impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "cloud-tls")]
impl CloudTransport for UreqTransport {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<TransportResponse, DcError> {
        let mut req = self.agent.request(method, url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let result = if body.is_empty() {
            req.call()
        } else {
            req.send_bytes(body)
        };
        match result {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.into_string().unwrap_or_default().into_bytes();
                Ok(TransportResponse { status, body })
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default().into_bytes();
                Ok(TransportResponse { status: code, body })
            }
            Err(e) => Err(DcError::Internal(format!("cloud transport: {e}"))),
        }
    }
}

/// Scripted transport for tests and offline drills: pops one queued
/// response per request and records every request it saw.
pub struct MockTransport {
    responses: std::sync::Mutex<Vec<TransportResponse>>,
    pub seen: std::sync::Mutex<Vec<RecordedRequest>>,
}

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl MockTransport {
    pub fn new() -> Self {
        MockTransport {
            responses: std::sync::Mutex::new(Vec::new()),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Queue a response (FIFO).
    pub fn enqueue(&self, status: u16, body: &str) {
        self.responses
            .lock()
            .expect("mock lock")
            .push(TransportResponse {
                status,
                body: body.as_bytes().to_vec(),
            });
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.seen.lock().expect("mock lock").clone()
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudTransport for MockTransport {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<TransportResponse, DcError> {
        self.seen.lock().expect("mock lock").push(RecordedRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: headers.to_vec(),
            body: String::from_utf8_lossy(body).into_owned(),
        });
        self.responses
            .lock()
            .expect("mock lock")
            .pop()
            .ok_or_else(|| DcError::Internal("mock transport: no queued response".to_string()))
    }
}
