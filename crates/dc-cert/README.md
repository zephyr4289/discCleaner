# dc-cert — Certificates, Two-Person Integrity, Key Lifecycle

`dc-cert` produces and verifies the **Certificate of Sanitization** and
enforces the two-person-integrity (2PI) authorization gate.

## Certificate model

`SanitizationCertificate` is JCS-canonicalized (RFC 8785), BLAKE3-hashed,
and Ed25519-signed over the canonical unsigned payload. Verification
(`verify_raw_cert_file`) is deliberately strict:

- strict JSON pre-scan (BOM rejected, duplicate keys rejected, depth ≤ 32)
- schema pinning (`diskcleaner-cert/1`; forward versions refused)
- `#[serde(deny_unknown_fields)]` on the certificate structs — unknown
  forward fields are **rejected**, never silently ignored (Δ169)
- signature must verify over the canonical bytes
- coherence: embedded fingerprint must equal BLAKE3(pubkey)
- anchor evaluation: integrity-only vs authenticated (`--fingerprint`,
  `--trusted-keys`, `--require-anchor`)

## Two-person integrity (dualauth.rs)

`AuthorizationSet` carries real Ed25519 countersignatures over
domain-separated messages (`DC-2PI1-APPROVE-PLAN ∥ plan_hash`). The
historical implementation "signed" by hashing public strings together —
forgeable by anyone without a key (`REG-DUALAUTH-FORGERY`). Verification now
requires: plan-hash binding, a valid signature per entry, fingerprint-key
coherence, and — under 2PI policy — **distinct keys** (one officer signing
twice is not two-person control). Plan approvals can never validate as fleet
manifest approvals (separate domains).

## Key lifecycle (keyring.rs, signer.rs, keystore.rs)

- `KeyringRegistry`: bilateral rotation (old key superseded at T —
  signatures at-or-after T are `SUSPECT_SUPERSEDED_KEY`,
  `REG-KEYRING-SUPERSEDED`), revocation semantics, activation windows
- `OperatorKeyPair`: keyfiles are written 0600 and **refused on load when
  group/other-readable** (`REG-KEYFILE-PERMS`); secrets zeroize on drop

## Module map

- `cert.rs` — certificate + strict verification driver
- `dualauth.rs` — 2PI countersignatures (see `dc-cli`'s `approve` command)
- `keyring.rs` / `keystore.rs` — key inventories and signing-site registry
- `project.rs` / `project2.rs` — pure journal→certificate projection
  (zero generation clock: every fact projects from journal records)
- `schema2.rs` — v2 certificate schema vocabulary
- `zone_attest.rs` — cross-version capacity attestation
- `package.rs` — evidence package manifests

## Testing

`cargo test -p dc-cert --lib` — 11 unit tests (forgery rejection, domain
separation, fingerprint spoofing, temporal key semantics, keyfile modes,
strict parser). Integration: `g6_cert_audit_matrix`, `t9_cert_matrix`,
`m2_4_custody_matrix`.

## v0.5.0 — hardware purge evidence & health snapshots

`SanitizationCertificate` gained three optional, signature-covered fields
(serde `default` — old certificates remain loadable and verifiable):

- `purge: Option<PurgeCertificateEvidence>` — executed mechanism,
  controller-rejected fallbacks, completion provenance
  (`sanitize-status-log` / `blocking-format-return`), progress permille,
  read-back expectation, controller device.
- `health_pre` / `health_post: Option<HealthSnapshotEvidence>` — SMART/health
  wear counters captured around the run; diverging counters evidence the
  certificate names the same physical drive end-to-end.

`render_summary()` prints the purge evidence line and health deltas for
`dc purge` certificates.
