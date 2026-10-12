//! End-to-end dashboard tests over a real loopback socket: routing,
//! authentication, JSON API shape and the SSE stream.

use dc_web::api::{
    ApiError, CertificateSummary, ControlPlane, DeviceSnapshot, DeviceStatus, JobSnapshot,
    JobState, StartJobRequest, SystemInfo,
};
use dc_web::auth::TokenAuth;
use dc_web::server::{ServerConfig, serve};
use dc_web::sse::Broker;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct MockPlane {
    starts: AtomicU64,
    last_job: Mutex<Option<StartJobRequest>>,
}

impl ControlPlane for MockPlane {
    fn system(&self) -> SystemInfo {
        SystemInfo {
            hostname: "appliance-01".into(),
            version: "0.10.0".into(),
            mode: "appliance".into(),
            uptime_secs: 42,
            engine: "io_uring".into(),
            guardian_locks_active: 2,
            post_quantum_ready: true,
        }
    }

    fn devices(&self) -> Vec<DeviceSnapshot> {
        vec![DeviceSnapshot {
            id: "sda".into(),
            node: "sda".into(),
            dev_path: "/dev/sda".into(),
            transport: "ata".into(),
            model: Some("WDC TEST".into()),
            serial: Some("SN-1".into()),
            capacity_bytes: 512_000_000_000,
            status: DeviceStatus::Idle,
            supported_profiles: vec!["nist-clear".into(), "dod-5220-22m".into()],
            protected: false,
            protection_reason: None,
        }]
    }

    fn jobs(&self) -> Vec<JobSnapshot> {
        vec![JobSnapshot {
            id: "j-1234".into(),
            device: "sda".into(),
            dev_path: "/dev/sda".into(),
            profile: "nist-clear".into(),
            started_utc: "2026-10-12T00:00:00Z".into(),
            state: JobState::Completed,
            progress_pct: Some(100),
            current_pass: Some(1),
            total_passes: Some(1),
            throughput_mib_s: Some(512.0),
            certificate: Some("cert-1".into()),
            exit_code: Some(0),
            error: None,
            log_lines: 10,
        }]
    }

    fn start_job(&self, req: StartJobRequest) -> Result<String, ApiError> {
        if req.confirm.as_deref() != Some("ERASE") {
            return Err(ApiError::bad_request("confirmation phrase required"));
        }
        if req.device == "sdb" {
            return Err(ApiError::conflict("device already sanitizing"));
        }
        self.starts.fetch_add(1, Ordering::SeqCst);
        *self.last_job.lock().unwrap() = Some(req);
        Ok("j-9999".into())
    }

    fn cancel_job(&self, job_id: &str) -> Result<(), ApiError> {
        if job_id == "j-1234" {
            Ok(())
        } else {
            Err(ApiError::not_found("job"))
        }
    }

    fn certificates(&self) -> Vec<CertificateSummary> {
        vec![CertificateSummary {
            id: "cert-1".into(),
            created_utc: "2026-10-12T00:10:00Z".into(),
            device_serial: Some("SN-1".into()),
            dev_path: "/dev/sda".into(),
            profile: "nist-clear".into(),
            verified: Some(true),
            signature_algs: vec!["Ed25519".into(), "ML-DSA-44".into()],
            cloud_provider: None,
            cloud_volume_id: None,
            file_blake3: "abc123".into(),
            path: "/var/lib/diskcleaner/certs/cert-1.cert.json".into(),
        }]
    }

    fn certificate(&self, cert_id: &str) -> Option<serde_json::Value> {
        (cert_id == "cert-1").then(|| serde_json::json!({ "schema": "dc.cert/v2", "id": cert_id }))
    }
}

fn spawn_server() -> (SocketAddr, String, Arc<MockPlane>, Arc<Broker>) {
    let plane = Arc::new(MockPlane {
        starts: AtomicU64::new(0),
        last_job: Mutex::new(None),
    });
    let broker = Arc::new(Broker::new());
    let auth =
        TokenAuth::from_str_token("integration-test-token-0123456789abcdef0").expect("token");
    let token = auth.token().to_string();
    let addr = spawn_server_on(plane.clone(), broker.clone(), auth);
    (addr, token, plane, broker)
}

fn spawn_server_on(plane: Arc<MockPlane>, broker: Arc<Broker>, auth: TokenAuth) -> SocketAddr {
    // Ephemeral port: bind port 0, read back the address, hand it to serve().
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let addr = probe.local_addr().expect("probe addr");
    drop(probe);
    std::thread::Builder::new()
        .name("dc-web-test-server".into())
        .spawn(move || {
            let _ = serve(plane, broker, ServerConfig { bind: addr, auth });
        })
        .expect("spawn server");
    // Wait for the listener to come up (the probe port may be briefly
    // unavailable after close).
    for _ in 0..100 {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return addr;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    addr
}

fn request(addr: SocketAddr, raw: &str) -> (u16, String) {
    let mut sock = TcpStream::connect(addr).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    sock.write_all(raw.as_bytes()).expect("write");
    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

#[test]
fn full_api_surface_over_the_wire() {
    let (addr, token, plane, _broker) = spawn_server();

    // Dashboard shell + health: no auth required.
    let (status, body) = request(
        addr,
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert!(body.starts_with("<!DOCTYPE html>"), "dashboard shell");
    let (status, body) = request(
        addr,
        "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!((status, body.as_str()), (200, "ok"));

    // API without token -> 401.
    let (status, _) = request(
        addr,
        "GET /api/v1/system HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 401, "unauthenticated API must be rejected");

    // Wrong token -> 401.
    let (status, _) = request(
        addr,
        "GET /api/v1/system HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer wrong\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 401);

    // Correct token -> system payload.
    let (status, body) = request(
        addr,
        &format!(
            "GET /api/v1/system HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(status, 200);
    assert!(body.contains("\"hostname\":\"appliance-01\""));
    assert!(body.contains("\"post_quantum_ready\":true"));

    // Devices, jobs, certificates.
    for (path, needle) in [
        ("/api/v1/devices", "WDC TEST"),
        ("/api/v1/jobs", "j-1234"),
        ("/api/v1/certificates", "ML-DSA-44"),
    ] {
        let (status, body) = request(
            addr,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
            ),
        );
        assert_eq!(status, 200, "{path}");
        assert!(body.contains(needle), "{path}: {body}");
    }

    // Certificate detail.
    let (status, body) = request(
        addr,
        &format!(
            "GET /api/v1/certificates/cert-1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(status, 200);
    assert!(body.contains("dc.cert/v2"));
    let (status, _) = request(
        addr,
        &format!(
            "GET /api/v1/certificates/nope HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(status, 404);

    // POST a job without the arm phrase -> 400; with it -> 202.
    let bad = r#"{"device":"sda","profile":"nist-clear"}"#;
    let (status, _) = request(
        addr,
        &format!(
            "POST /api/v1/jobs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            bad.len(),
            bad
        ),
    );
    assert_eq!(status, 400, "missing ERASE confirmation must be refused");

    let good = r#"{"device":"sda","profile":"dod-5220-22m","confirm":"ERASE","label":"tr"}"#;
    let (status, body) = request(
        addr,
        &format!(
            "POST /api/v1/jobs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            good.len(),
            good
        ),
    );
    assert_eq!(status, 202);
    assert!(body.contains("j-9999"));
    assert_eq!(plane.starts.load(Ordering::SeqCst), 1);

    // Job cancel.
    let (status, _) = request(
        addr,
        &format!(
            "POST /api/v1/jobs/j-1234/cancel HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(status, 200);

    // Unknown route -> 404.
    let (status, _) = request(
        addr,
        &format!(
            "GET /api/v1/nonsense HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(status, 404);
}

#[test]
fn sse_stream_delivers_published_events() {
    let plane = Arc::new(MockPlane {
        starts: AtomicU64::new(0),
        last_job: Mutex::new(None),
    });
    let broker = Arc::new(Broker::new());
    let auth = TokenAuth::from_str_token("sse-test-token-0123456789abcdef0").expect("token");
    let token = auth.token().to_string();
    let addr = spawn_server_on(plane, broker.clone(), auth);

    // Subscribe via ?token= (EventSource-compatible path).
    let mut sock = TcpStream::connect(addr).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let req = format!(
        "GET /api/v1/events?token={token} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    );
    sock.write_all(req.as_bytes()).expect("write request");

    // Publish repeatedly until the server thread has subscribed the topic
    // (avoids the subscribe/publish race under test-parallel load) and the
    // frame has been read.
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");
    let mut collected = String::new();
    for _ in 0..50 {
        broker.publish_json(
            "fleet",
            "job.started",
            &serde_json::json!({"job_id": "j-1", "message": "wipe armed"}),
        );
        let mut buf = [0u8; 4096];
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                collected.push_str(&String::from_utf8_lossy(&buf[..n]));
                if collected.contains("event: job.started") {
                    break;
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    assert!(
        collected.starts_with("HTTP/1.1 200"),
        "sse head: {collected}"
    );
    assert!(collected.contains("text/event-stream"), "content type");
    assert!(collected.contains(": connected"), "initial comment frame");
    assert!(collected.contains("event: job.started"), "published event");
    assert!(collected.contains("wipe armed"), "event payload");

    // SSE without token -> 401 (not an event-stream).
    let (status, _) = request(
        addr,
        "GET /api/v1/events HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 401);
}
