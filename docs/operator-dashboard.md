# Operator Dashboard (`dc serve`)

> v0.10.0 · Frontier 1 — Visual Interface

The `dc serve` command runs a **local, zero-external-dependency web dashboard** on the
appliance ISO or a headless server: field technicians and data-center e-waste triage
operators can monitor and execute wipes across multi-drive bays without memorizing CLI
syntax, while every operation still flows through the certified engine.

```
$ dc serve start                       # binds 127.0.0.1:8087, generates a token
[DASHBOARD] listening on http://127.0.0.1:8087 (token: 9f3ab2c1…77e0)
[DASHBOARD] open the URL above and paste the operator token when prompted

$ dc serve start --listen 127.0.0.1:8443 --token-file /etc/diskcleaner/dashboard.token
$ dc serve start --cert-dir /var/lib/diskcleaner/certs
```

On an SSH tunnel: `ssh -L 8087:127.0.0.1:8087 appliance` then open `http://localhost:8087`.

## Architecture

```
┌──────────────────────────┐      ┌──────────────────────────────┐
│  assets/index.html       │◄─────│ dc-web (embedded, no CDN)    │
│  single-file SPA         │      │  http.rs   HTTP/1.1 parser   │
│  dark ops theme, no JS   │      │  sse.rs    event broker      │
│  frameworks, no CDN      │      │  auth.rs   bearer tokens     │
└────────────▲─────────────┘      │  server.rs routing + limits  │
             │ REST + SSE         └──────────┬───────────────────┘
             │                               │ ControlPlane trait
┌────────────┴─────────────┐      ┌──────────▼───────────────────┐
│ Browser (technician)     │      │ dc-cli::serve::OpsPlane       │
└──────────────────────────┘      │  devices: InventoryScanner   │
                                  │  jobs:     `dc execute` child │
                                  │  certs:    cert dir scanner   │
                                  └──────────────────────────────┘
```

**Why SSE and not WebSockets?** Server-Sent Events is plain HTTP with a
`text/event-stream` content type: no `Upgrade:` handshake, no frame masking, no
protocol state machine. The entire live-data path is ~100 lines of Rust, it
traverses reverse proxies and SSH tunnels unchanged, and the browser API
(`EventSource`) auto-reconnects. A wipe dashboard needs server→client push only —
client→server actions go through ordinary POSTs. For an appliance that must boot from
a 15 MB ISO, that simplicity is the design.

**Why an embedded SPA?** The dashboard HTML/CSS/JS is a single file compiled into the
binary (`include_str!`). No CDN, no external fonts, no telemetry — it renders on an
air-gapped appliance exactly as on a workstation. A property test enforces this
(`dashboard_embeds_and_is_self_contained` fails the build if an `http://`,
`https://`, `<script src=` or `<link` ever appears in the asset).

## REST API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | — | Dashboard shell |
| GET | `/healthz` | — | Liveness probe |
| GET | `/api/v1/system` | Bearer | Version, mode, uptime, Guardian lock count, PQ readiness |
| GET | `/api/v1/devices` | Bearer | Device inventory with protection state + supported profiles |
| GET | `/api/v1/jobs` | Bearer | Sanitization job list |
| POST | `/api/v1/jobs` | Bearer | Start a job: `{device, profile, label?, serial_confirm?, confirm: "ERASE"}` |
| GET | `/api/v1/jobs/{id}` | Bearer | Single job |
| POST | `/api/v1/jobs/{id}/cancel` | Bearer | Cancel a running job (SIGKILL to the engine child) |
| GET | `/api/v1/jobs/{id}/events` | `?token=` | Per-job SSE stream |
| GET | `/api/v1/events` | `?token=` | Global SSE stream (`job.*`, `device.updated`, `log`) |
| GET | `/api/v1/certificates` | Bearer | Certificate list (signature algs incl. ML-DSA-44, cloud provider) |
| GET | `/api/v1/certificates/{id}` | Bearer | Full certificate JSON |

Errors are structured: `{"error": {"code": "NOT_FOUND", "message": "…"}}` with proper
status codes. SSE frames follow the wire format `event: <name>\ndata: <json>\n\n`
with `: keepalive` comments every 15 s.

## Security posture

1. **Bind.** Default `127.0.0.1:8087`. A non-loopback `--listen` prints a loud
   warning: the token becomes a network credential — terminate TLS with a reverse
   proxy before exposing the dashboard beyond the maintenance network.
2. **Auth.** All `/api/*` endpoints require a bearer token: 256-bit generated at
   startup, or `--token` (≥ 32 chars), or `--token-file` (mode 0600 enforced).
   Comparison is constant-time. GET/SSE accept `?token=` because `EventSource`
   cannot set headers — documented caveat: reverse-proxy access logs then see the
   token, another reason to stay on loopback/TLS.
3. **Write arming.** POST `/api/v1/jobs` requires `confirm: "ERASE"` server-side
   (the UI also enforces the typed phrase); protected devices (root/system disks,
   the Guardian classification) are refused with 409 — they need the CLI's explicit
   `--allow-system-discipline` path.
4. **No new privileged paths.** Every wipe the dashboard starts is a child process
   running the actual `dc execute` binary — journals, Guardian locks, Guardian
   serial confirmation, certificates and hybrid signing all included. The web layer
   adds zero new privileged code.
5. **Resource discipline.** 16 KiB header cap, 64 KiB body cap, 64 concurrent
   connections, 30 s idle read timeout, SSE keepalives, stalled SSE consumers are
   dropped (bounded queues) rather than allowed to back-pressure the engine.

## Fleet composition

`dc serve` composes with the v0.9.0 fleet JSON mode: job children run with `--json`,
so the dashboard's state transitions are derived from the same `dc.fleet/v1`
envelopes Ansible/SaltStack/K8s DaemonSets harvest — one execution model, two
surfaces.
