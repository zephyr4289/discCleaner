# discCleaner — Architecture

discCleaner is a military-grade storage sanitization suite implementing
NIST SP 800-88 Rev 1, IEEE 2883-2022, and DoD media sanitization standards
with deterministic cryptographic verification and tamper-evident audit
trails.

## The layer law

```
            ┌──────────────────────────────────────────────┐
 operator → │ dc-cli (surface: prompts, exit codes, gates) │
            └──────────────┬───────────────────────────────┘
                           │ depends on
     ┌─────────────┬───────┴──────┬──────────────┐
     ▼             ▼              ▼              ▼
  dc-probe       dc-io         dc-cert        dc-nvme/ata/
  (Guardian:     (engines,     (certs, 2PI,   scsi/mmc/opal
   is it safe?)   permits)       keyrings)     (hardware purge)
     │             │              │              │
     └──────┬──────┴──────┬───────┴──────┬───────┘
            ▼             ▼              ▼
         dc-core ──── dc-verify ──── dc-hw
     (plans/journals/  (read-back      (protocol codecs,
      FSM/identity)     verification)   pure functions)
            │
            ▼
      dc-testkit  ← integration suites import this; PRODUCTION CRATES NEVER
                    IMPORT IT (layering law, enforced by REG-MMC-LAYERING)
```

**Dependency direction is a security property.** Trust flows down: the CLI
gates everything; the Guardian decides; engines only write with a
permit minted by the FSM in dc-core; codecs are pure; the testkit is the
adversary and stays out of release binaries.


## The v0.11.0 frontiers (ZK, CXL, formal)

Three new layers extend the evidence chain without weakening the layer law:

* **`dc-zk`** — a self-contained Groth16 ZK-SNARK stack over BLS12-381
  (Montgomery fields → 2-6-12 tower → ate pairing → R1CS → Poseidon →
  compliance circuit → receipts). Zero external cryptographic
  dependencies; every constant regenerated programmatically from ground
  truth and pinned by tests. Consumed by `dc zk` and the `SanitizationCertificate.zk`
  statement extension.
* **`dc-cxl`** — CXL 2.0/3.0 Type 3 memory-device sanitization: sysfs/DVSEC
  discovery, Memory Device Mailbox protocol engine over a `MailboxBackend`
  trait (production volatile-MMIO backend + full mock simulator), sanitize
  (0x4400) / secure-erase (0x4401), and the signature-covered
  `SanitizationCertificate.cxl` evidence extension.
* **`dc-verify-formal`** — formal layer: always-on exhaustive state-merged
  model checking of the real FSM (INV-1/2/3 run in every
  `cargo test --workspace`), a verified-abstraction refinement check for the
  window accounting, and `#[cfg(kani)]` bounded symbolic proofs (FSM guards,
  SecretBuf zeroization, v0.12.0: Montgomery CIOS exactness + sonar pairwise
  bit stability). Proof artifacts land in `proofs/`.
* **`dc-vdf`** — Cryptographic Proof-of-Erasure (v0.12.0, Miracle 1): a
  pure-Rust Wesolowski VDF over a safe-prime RSA unknown-order group
  (fixed-limb CIOS Montgomery arithmetic, fused streaming division+modexp
  prover, Fermat-shortcut verifier, zeroized-factor ceremony) and the
  executor's time-lock weave — overwrite passes keyed by chain states, so
  certificates carry a wall-clock lower bound independent of system clocks.
* **`dc-sonar`** — acoustic hardware fingerprinting (v0.12.0, Miracle 2):
  challenge-driven seek micro-stepping probes, IIO/hwmon telemetry capture,
  hand-written radix-2 FFT feature extraction and a pairwise-ordering
  fuzzy extractor — the physical-chassis PUF behind `--puf-guard`.
* **`dc-baremetal`** — Ghost Boot (v0.12.0, Miracle 3): a no_std
  pure-Rust UEFI payload (~25 KB) that boots straight into Ring 0 and
  sanitizes PCIe-attached storage with no kernel, no drivers and no OS.
  Every hardware state machine (PCI/AHCI/NVMe/ACPI) runs in CI against a
  register-accurate simulated bus (`hal::SimBus`).

## The evidence chain

1. `dc plan` compiles a typed `SanitizationPlan` and hashes its JCS form.
2. Two officers countersign the plan hash (`dc approve`).
3. `dc execute` re-runs the Guardian, checks the approval set, arms
   (O_EXCL + flock on the disk **and every partition**), opens a
   hash-chained journal.
4. Every window write is checkpointed; verification reads back 100% of LBAs
   and streams BLAKE3 over what the media actually contains.
5. The certificate embeds plan hash, journal chain head, stream hash, and
   an Ed25519 signature over the canonical form.
6. A third party holding only the seed and geometry can re-derive the
   stream digest from `docs/reproduction/chacha20-window-v1.txt` — the
   cleanroom reproduction contract (A2 Moat).

## Execution model

- **Windows**: the device is covered in fixed windows (default 2 MiB);
  every write, checkpoint, and verify artifact is window-addressed.
- **FSM typestate**: destructive writes require a `WritePermit`; states
  cannot be skipped.
- **Crash safety**: the journal is fsynced per record; torn tails are
  recoverable; zero-tails are corruption.
- **Signals**: SIGINT/SIGTERM set a global cancel; engines drain at the
  next window boundary and journal an `Interrupted` record; `dc resume`
  continues from the frontier. Post-verification signals complete under
  the victory-lap rule.

## Where to look

| I want to... | Start in |
|---|---|
| understand safety gates | `crates/dc-probe/src/guardian.rs` |
| trace evidence | `crates/dc-core/src/journal.rs`, `audit.rs` |
| verify a wipe | `crates/dc-verify/src/verifier.rs` |
| add a protocol | `crates/dc-hw/src/*_codec.rs` + its client crate |
| run tests | `python3 tests/run_tests.py` (lit-style) |

See `docs/SECURITY.md` for the threat model and
`docs/TESTING.md` for the test architecture.
