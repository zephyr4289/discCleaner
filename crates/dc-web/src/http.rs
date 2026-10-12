//! Minimal HTTP/1.1 — just enough server-side surface for the dashboard:
//! request-line + header parsing, Content-Length bodies, percent-decoding
//! and response writing with keep-alive support. No chunked encoding
//! (clients do not send it for our endpoints), no compression, no CGI.

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Hard caps — a hostile or buggy client must not be able to wedge the
/// appliance: header block and body are bounded, and socket reads are
/// deadline-guarded by the server loop.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// Percent-decoded path, query string removed (e.g. `/api/v1/jobs`).
    pub path: String,
    /// Raw query pairs (percent-decoded values).
    pub query: HashMap<String, String>,
    /// Header names lowercased.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    /// Bearer token from the `Authorization` header.
    pub fn bearer_token(&self) -> Option<&str> {
        let auth = self.header("authorization")?;
        auth.strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
    }

    /// Token from either the Authorization header or `?token=` (SSE paths —
    /// EventSource cannot set request headers).
    pub fn any_token(&self) -> Option<&str> {
        if let Some(t) = self.bearer_token() {
            return Some(t);
        }
        self.query.get("token").map(|s| s.as_str())
    }
}

#[derive(Debug)]
pub enum ParseError {
    /// Peer closed / timed out before a full request arrived.
    ConnectionClosed,
    Malformed(String),
    TooLarge(&'static str),
}

/// Read and parse one HTTP/1.1 request from the stream.
pub fn parse_request(
    reader: &mut BufReader<TcpStream>,
    read_timeout: Duration,
) -> Result<(Request, bool), ParseError> {
    let sock = reader.get_ref();
    sock.set_read_timeout(Some(read_timeout))
        .map_err(|e| ParseError::Malformed(e.to_string()))?;

    // --- request line ---
    let mut line = String::new();
    let n = read_limited_line(reader, &mut line)?;
    if n == 0 {
        return Err(ParseError::ConnectionClosed);
    }
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ParseError::Malformed("no method".into()))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| ParseError::Malformed("no target".into()))?
        .to_string();
    let version = parts.next().unwrap_or("HTTP/1.1");

    // --- headers ---
    let mut headers = HashMap::new();
    let mut total = line.len();
    loop {
        let mut h = String::new();
        let n = read_limited_line(reader, &mut h)?;
        if n == 0 {
            return Err(ParseError::ConnectionClosed);
        }
        total += n;
        if total > MAX_HEADER_BYTES {
            return Err(ParseError::TooLarge("header block"));
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((name, value)) = h.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    // --- body ---
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(ParseError::TooLarge("body"));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|_| ParseError::ConnectionClosed)?;
    }

    // Keep-alive: HTTP/1.1 default, unless the client asked to close.
    let keep_alive = !version.eq_ignore_ascii_case("HTTP/1.0")
        && !headers
            .get("connection")
            .is_some_and(|c| c.to_ascii_lowercase().contains("close"));

    // --- path + query ---
    let (raw_path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target.as_str(), None),
    };
    let path = percent_decode(raw_path);
    let mut query = HashMap::new();
    if let Some(q) = raw_query {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            query.insert(percent_decode(k), percent_decode(v));
        }
    }

    Ok((
        Request {
            method,
            path,
            query,
            headers,
            body,
        },
        keep_alive,
    ))
}

/// Read one `\n`-terminated line with a hard byte cap.
fn read_limited_line(
    reader: &mut BufReader<TcpStream>,
    out: &mut String,
) -> Result<usize, ParseError> {
    let mut buf = Vec::with_capacity(128);
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() > MAX_HEADER_BYTES {
                    return Err(ParseError::TooLarge("line"));
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(ParseError::ConnectionClosed);
            }
            Err(_) => return Err(ParseError::ConnectionClosed),
        }
    }
    let n = buf.len();
    out.push_str(&String::from_utf8_lossy(&buf));
    Ok(n)
}

/// Percent-decode a URL component (`+` is NOT treated as space outside
/// form bodies; our query parser handles form encoding separately).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() + 1 && i + 2 < bytes.len() + 1 => {
                if let (Some(h), Some(l)) = (
                    bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16)),
                    bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16)),
                ) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// SSE responses stream indefinitely — suppress Content-Length.
    pub stream: bool,
    /// Extra headers (e.g. `Location`), appended verbatim.
    pub extra_headers: Vec<(String, String)>,
}

impl Response {
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Response {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value).unwrap_or_default(),
            stream: false,
            extra_headers: vec![],
        }
    }

    pub fn json_raw(status: u16, body: Vec<u8>) -> Self {
        Response {
            status,
            content_type: "application/json",
            body,
            stream: false,
            extra_headers: vec![],
        }
    }

    pub fn text(status: u16, body: &str) -> Self {
        Response {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes().to_vec(),
            stream: false,
            extra_headers: vec![],
        }
    }

    pub fn html(status: u16, body: &[u8]) -> Self {
        Response {
            status,
            content_type: "text/html; charset=utf-8",
            body: body.to_vec(),
            stream: false,
            extra_headers: vec![],
        }
    }

    /// Begin an SSE stream (no Content-Length, `Cache-Control: no-store`).
    pub fn event_stream() -> Self {
        Response {
            status: 200,
            content_type: "text/event-stream",
            body: Vec::new(),
            stream: true,
            extra_headers: vec![
                ("Cache-Control".to_string(), "no-store".to_string()),
                ("X-Accel-Buffering".to_string(), "no".to_string()),
            ],
        }
    }

    pub fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            413 => "Payload Too Large",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Status",
        }
    }

    /// Serialize the response head + body to the stream.
    pub fn write_to(&self, out: &mut TcpStream, keep_alive: bool) -> std::io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n",
            self.status,
            Self::status_text(self.status),
            self.content_type,
        );
        if !self.stream {
            head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        for (k, v) in &self.extra_headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(if keep_alive && !self.stream {
            "Connection: keep-alive\r\n\r\n"
        } else {
            "Connection: close\r\n\r\n"
        });
        out.write_all(head.as_bytes())?;
        if !self.body.is_empty() {
            out.write_all(&self.body)?;
        }
        out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("/api/v1/jobs%20list"), "/api/v1/jobs list");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("truncated%2"), "truncated%2");
        assert_eq!(percent_decode("plain"), "plain");
    }
}
