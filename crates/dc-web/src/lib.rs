//! `dc-web` — the visual operator dashboard (v0.10.0, Frontier 1).
//!
//! Field technicians and data-center e-waste triage operators need an
//! intuitive way to monitor and execute wipes across multi-drive bays
//! without memorizing CLI syntax. `dc serve` exposes exactly that: a
//! local, zero-external-dependency embedded HTTP server with:
//!
//! * a **REST control plane** (`/api/v1/...`) over a trait the CLI
//!   implements against the real engine (`ControlPlane`),
//! * **Server-Sent Events** streams for live job progress and the audit
//!   log (no WebSocket handshake, no protocol upgrade machinery — SSE is
//!   plain HTTP, which keeps the server tiny and appliance-friendly),
//! * an **embedded single-file dashboard** (`assets/index.html`) — no CDN,
//!   no external fonts, no build step; it renders on an air-gapped appliance
//!   ISO exactly as it renders on a workstation,
//! * **bearer-token authentication**: a 256-bit token generated at startup
//!   (or supplied via `--token` / `--token-file`), compared in constant
//!   time; the server binds to 127.0.0.1 by default and refuses remote
//!   binds without an explicit `--listen` + token.
//!
//! # Threat model and deployment posture
//!
//! The dashboard is an OPERATIONS surface, not an Internet surface:
//!
//! 1. Default bind `127.0.0.1:8087` — reachable only from the appliance
//!    console / an SSH tunnel.
//! 2. Remote binds require a token; the token travels as `Authorization:
//!    Bearer <token>` on API calls and as `?token=` on the SSE endpoints
//!    (EventSource cannot set headers — documented caveat: put the
//!    appliance behind TLS via a reverse proxy when exposing it off-host).
//! 3. Read endpoints are unauthenticated-free but WRITE endpoints
//!    (POST/DELETE) always demand the token.
//! 4. The dashboard never accepts raw device writes — every wipe goes
//!    through the same `dc execute` engine, journals, Guardian locks and
//!    certificate chain as the CLI (defence in depth: the web layer adds
//!    zero new privileged code paths).

pub mod api;
pub mod assets;
pub mod auth;
pub mod http;
pub mod server;
pub mod sse;

pub use api::{
    ApiError, CertificateSummary, ControlPlane, DeviceSnapshot, DeviceStatus, JobSnapshot,
    JobState, StartJobRequest, SystemInfo,
};
pub use auth::{AUTH_TOKEN_BYTES, TokenAuth};
pub use server::{ServerConfig, serve};
pub use sse::{Broker, EventFrame};
