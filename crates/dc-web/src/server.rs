//! Connection handling and routing.

use crate::api::{ApiError, ControlPlane, StartJobRequest};
use crate::assets;
use crate::auth::TokenAuth;
use crate::http::{ParseError, Request, Response, parse_request, percent_decode};
use crate::sse::{Broker, KEEPALIVE};
use std::io::BufReader;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Read timeout for request heads: an idle keep-alive connection is
/// allowed to linger this long between requests before being reaped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 64;

pub struct ServerConfig {
    pub bind: std::net::SocketAddr,
    pub auth: TokenAuth,
}

/// Run the dashboard server until the process is terminated.
pub fn serve(
    control_plane: Arc<dyn ControlPlane>,
    broker: Arc<Broker>,
    cfg: ServerConfig,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(cfg.bind)?;
    let shown = if cfg.auth.token().len() > 16 {
        format!(
            "{}…{}",
            &cfg.auth.token()[..8],
            &cfg.auth.token()[cfg.auth.token().len() - 4..]
        )
    } else {
        cfg.auth.token().to_string()
    };
    eprintln!(
        "[DASHBOARD] listening on http://{} (token: {shown})",
        cfg.bind
    );
    eprintln!("[DASHBOARD] open the URL above and paste the operator token when prompted");

    let live = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if live.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            // Shed load rather than queue: the appliance engine comes first.
            eprintln!("[DASHBOARD] shedding connection from {peer}: at MAX_CONNECTIONS");
            continue;
        }
        live.fetch_add(1, Ordering::SeqCst);
        let cp = Arc::clone(&control_plane);
        let broker = Arc::clone(&broker);
        let auth_token = cfg.auth.token().to_string();
        let live = Arc::clone(&live);
        std::thread::Builder::new()
            .name("dc-web-conn".to_string())
            .spawn(move || {
                let _guard = ConnGuard(&live);
                handle_connection(stream, cp, broker, &auth_token);
            })
            .ok();
    }
}

struct ConnGuard<'a>(&'a AtomicUsize);

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handle_connection(
    stream: TcpStream,
    cp: Arc<dyn ControlPlane>,
    broker: Arc<Broker>,
    token: &str,
) {
    let write_half = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let mut out = write_half;

    loop {
        let (req, keep_alive) = match parse_request(&mut reader, IDLE_TIMEOUT) {
            Ok(r) => r,
            Err(ParseError::ConnectionClosed) => return,
            Err(ParseError::TooLarge(what)) => {
                let resp = Response::json(
                    413,
                    &ApiError::new("TOO_LARGE", format!("request {what} exceeds limit")).to_json(),
                );
                let _ = resp.write_to(&mut out, false);
                return;
            }
            Err(ParseError::Malformed(m)) => {
                let resp = Response::json(
                    400,
                    &ApiError::new("BAD_REQUEST", format!("malformed request: {m}")).to_json(),
                );
                let _ = resp.write_to(&mut out, false);
                return;
            }
        };

        let resp = route(&req, cp.as_ref(), token);

        if resp.stream {
            // SSE: write the head, then pump frames until the client leaves.
            if resp.write_to(&mut out, false).is_err() {
                return;
            }
            if let Err(e) = pump_sse(&req, &mut out, &broker) {
                let _ = std::io::Write::write_all(
                    &mut out,
                    format!("event: error\ndata: {e}\n\n").as_bytes(),
                );
            }
            return;
        }

        if resp.write_to(&mut out, keep_alive).is_err() {
            return;
        }
        if !keep_alive {
            return;
        }
    }
}

/// Stream SSE frames for a subscription until the receiver drains, the
/// client disconnects, or a write fails.
fn pump_sse(req: &Request, out: &mut TcpStream, broker: &Broker) -> std::io::Result<()> {
    let topic = if req.path == "/api/v1/events" {
        "fleet".to_string()
    } else {
        // /api/v1/jobs/{id}/events -> job:{id}
        match req
            .path
            .strip_prefix("/api/v1/jobs/")
            .and_then(|rest| rest.strip_suffix("/events"))
        {
            Some(id) => format!("job:{}", percent_decode(id)),
            None => "fleet".to_string(),
        }
    };
    let rx = broker.subscribe(&topic);
    // Tell the client we are live before the first event.
    std::io::Write::write_all(out, b": connected\n\n")?;
    std::io::Write::flush(out)?;
    loop {
        match rx.recv_timeout(KEEPALIVE) {
            Ok(frame) => {
                std::io::Write::write_all(out, frame.render().as_bytes())?;
                std::io::Write::flush(out)?;
            }
            Err(_) => {
                // timeout -> keepalive comment keeps middleboxes from
                // closing the stream; also detects dead sockets.
                std::io::Write::write_all(out, b": keepalive\n\n")?;
                std::io::Write::flush(out)?;
            }
        }
    }
}

fn route(req: &Request, cp: &dyn ControlPlane, token: &str) -> Response {
    // Unauthenticated surfaces: the dashboard shell itself, health probes.
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => return Response::html(200, assets::DASHBOARD_HTML),
        ("GET", "/healthz") => return Response::text(200, "ok"),
        _ => {}
    }

    // Everything under /api/* requires the token (header or ?token= for SSE).
    let authorized = req.any_token().is_some_and(|presented| {
        // constant-time compare against the server token
        ct_check(token.as_bytes(), presented.as_bytes())
    });
    if !authorized {
        return Response::json(401, &ApiError::unauthorized().to_json());
    }

    let path = req.path.as_str();
    let method = req.method.as_str();

    match (method, path) {
        ("GET", "/api/v1/system") => serde_json::to_value(cp.system())
            .map(|v| Response::json(200, &v))
            .unwrap_or_else(|_| {
                Response::json(500, &ApiError::internal("serialize system").to_json())
            }),

        ("GET", "/api/v1/devices") => serde_json::to_value(cp.devices())
            .map(|v| Response::json(200, &v))
            .unwrap_or_else(|_| {
                Response::json(500, &ApiError::internal("serialize devices").to_json())
            }),

        ("GET", "/api/v1/jobs") => serde_json::to_value(cp.jobs())
            .map(|v| Response::json(200, &v))
            .unwrap_or_else(|_| {
                Response::json(500, &ApiError::internal("serialize jobs").to_json())
            }),

        ("POST", "/api/v1/jobs") => {
            let parsed: Result<StartJobRequest, _> = serde_json::from_slice(&req.body);
            match parsed {
                Ok(job_req) => match cp.start_job(job_req) {
                    Ok(job_id) => Response::json(202, &serde_json::json!({ "job_id": job_id })),
                    Err(e) => Response::json(e.status(), &e.to_json()),
                },
                Err(e) => Response::json(
                    400,
                    &ApiError::bad_request(format!("invalid job request: {e}")).to_json(),
                ),
            }
        }

        ("GET", "/api/v1/events") => Response::event_stream(),

        ("GET", "/api/v1/certificates") => serde_json::to_value(cp.certificates())
            .map(|v| Response::json(200, &v))
            .unwrap_or_else(|_| {
                Response::json(500, &ApiError::internal("serialize certificates").to_json())
            }),

        _ => {
            // Path-parameterized routes.
            if let Some(rest) = path.strip_prefix("/api/v1/jobs/") {
                if let Some(_id) = rest.strip_suffix("/events") {
                    // SSE subscription handled by the stream path
                    return Response::event_stream();
                }
                if let Some(id) = rest.strip_suffix("/cancel")
                    && method == "POST"
                {
                    let decoded = percent_decode(id);
                    return match cp.cancel_job(&decoded) {
                        Ok(()) => Response::json(200, &serde_json::json!({ "cancelled": decoded })),
                        Err(e) => Response::json(e.status(), &e.to_json()),
                    };
                }
                if method == "GET" {
                    let decoded = percent_decode(rest);
                    if let Some(job) = cp.jobs().into_iter().find(|j| j.id == decoded) {
                        return serde_json::to_value(job)
                            .map(|v| Response::json(200, &v))
                            .unwrap_or_else(|_| {
                                Response::json(500, &ApiError::internal("serialize job").to_json())
                            });
                    }
                    return Response::json(404, &ApiError::not_found("job").to_json());
                }
            }
            if let Some(rest) = path.strip_prefix("/api/v1/certificates/")
                && method == "GET"
            {
                let decoded = percent_decode(rest);
                return match cp.certificate(&decoded) {
                    Some(json) => {
                        let body = serde_json::json!({ "id": decoded, "json": json });
                        Response::json(200, &body)
                    }
                    None => Response::json(404, &ApiError::not_found("certificate").to_json()),
                };
            }
            Response::json(404, &ApiError::not_found("route").to_json())
        }
    }
}

fn ct_check(a: &[u8], b: &[u8]) -> bool {
    let max = a.len().max(b.len());
    let mut acc: u8 = ((a.len() ^ b.len()) & 0xFF) as u8;
    for i in 0..max {
        acc |= a.get(i).unwrap_or(&0) ^ b.get(i).unwrap_or(&0);
    }
    acc == 0
}
