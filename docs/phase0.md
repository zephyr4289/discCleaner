Locked. Phase 0 is where this project wins or dies, so let's spec it like flight software: **invariants first, state machines explicit, every design decision reversible-but-documented.** Below is the complete engineering spec — workspace, domain model, FSM, guardian rules, I/O engine internals, journal binary format, verification scheme, cert schema, invariants, test matrix, and milestone slicing. This is written to be *implemented directly*.

---

# Phase 0 Engineering Specification — `diskcleaner` Foundation

## 0. Design Contract (non-negotiable scope)

**IN:** device inventory + guardian, whole-disk logical overwrite (zero / fixed byte / deterministic-random), BLKZEROOUT fast path, io_uring engine + sync fallback, flush-before-verify, full verification, crash-resumable journal, Ed25519-signed certificate, hash-chained audit log, CLI.

**OUT (deferred, but trait-shaped-for):** NVMe/ATA/SCSI ioctl passthrough (Phase 1), SMART health (Phase 1), stratified sampling, PDF/A, RFC 3161, TUI, Opal, partitions-as-targets, zoned/SMR write model.

**Acceptance (measurable, restated):**
- A1: Wipe + full verify of 1 TiB at ≥ device line speed (within 10% of `fio` O_DIRECT QD128 comparison).
- A2: Cert is independently reproducible: third party re-derives the PRNG pass and stream hash from cert contents alone.
- A3: Correct refusal (with reason code + audit entry) for: mounted, system-disk, swap, LVM-holder, md-member, dm-holder, multipath, zoned, loop.
- A4: `kill -9` mid-pass → resume → full verify passes. `dm-error` fault at 50% → clean FAILED state → repair → resume → completes.

---

## 1. Workspace & Runtime Decisions

Phase 0 gets **six crates, not nine.** Crates split along *deployment* seams, not academic ones — NVMe/ATA/SCSI crates arrive in Phase 1 when there's code to put in them.

```
diskcleaner/
├── Cargo.toml                  # [workspace], resolver = "2"
├── crates/
│   ├── dc-core/                # domain model, plan, FSM, orchestrator, journal, chain, errors
│   ├── dc-probe/               # sysfs/mountinfo/udev-db inventory, layer-stack, guardian
│   ├── dc-io/                  # Engine trait, io_uring engine, sync engine, buffer pool, patterns
│   ├── dc-verify/              # verification engine, reorder hashing, entropy diagnostics
│   ├── dc-cert/                # JCS canonicalization, Ed25519, cert render, audit log
│   └── dc-cli/                 # clap binary, progress, wiring
```

**Runtime doctrine (decided now, permanent):**

| Decision | Choice | Rationale |
|---|---|---|
| Async runtime | **None. No tokio.** | One reactor thread per device owning one `io_uring` ring. Rings are single-owner; async adds nothing but stack traces. Channels: `std::sync::mpsc` + atomics. |
| C dependencies | **Zero** (libc via rustix only) | musl static binary, boot-ISO-ready from day one. No `libudev` — sysfs + `/run/udev/data` + `/proc` only. No OpenSSL. |
| Serialization | serde + `serde_json`, canonical via `serde_jcs` | JCS (RFC 8785) for everything signed/hashed. |
| Unsafe policy | `unsafe` only in `dc-io` (ioctl/uring), each block justified in a `// SAFETY:` comment | Forensic code goes to court; reviewers must be able to audit unsafe in one file tree. |
| Clocks | Wall clock (UTC ISO-8601) **plus** monotonic durations, both in cert | Wall clocks jump; NTP disputes must not invalidate durations. |

**Dependency manifest (complete — additions are review-gated):**

| Crate | Use |
|---|---|
| `rustix` | io_uring, ioctls, flock, O_DIRECT, signalfd-ish, fs sync |
| `clap` (derive) | CLI |
| `serde`, `serde_json`, `serde_jcs` | plan / journal / cert |
| `blake3` | all hashing (journal chain, plan hash, stream hash, key fingerprints) |
| `sha2` | optional dual-hash (`--sha256`, off by default — SHA-256 @ ~1 GB/s would bottleneck 7 GB/s verify) |
| `ed25519-dalek` | signing |
| `chacha20` (RustCrypto) | deterministic pattern generation |
| `getrandom` | seed harvest |
| `thiserror`, `tracing` (+ subscriber) | errors, structured logs |
| `indicatif` | Phase 0 progress (ratatui is Phase 2) |
| dev: `proptest`, `tempfile`, `assert_cmd` | tests |

---

## 2. Domain Model (`dc-core`)

The four types everything else orbits:

```rust
/// Stable identity: survives USB re-enumeration (device unplugged/replugged).
/// Compared at plan time, arm time, and every checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StableIdentity {
    pub model: Option<String>,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub size_bytes: u64,
    pub bus: BusType,               // Nvme | Sata | Sas | Usb | Mmc | Virtio | Loop | File | Unknown
}

/// Kernel identity: what the *open fd* actually is (fstat st_rdev major:minor).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelIdentity { pub major: u32, pub minor: u32 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub stable: StableIdentity,
    pub kernel: KernelIdentity,
    pub kernel_name: String,            // "sdb", "nvme0n1"
    pub dev_path: String,               // resolved path at open time (informational only)
    pub logical_block_size: u32,        // BLKSSZGET
    pub physical_block_size: u32,       // BLKPBSZGET
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Pattern {
    Zero,                                        // engine may take BLKZEROOUT fast path
    Fixed { byte: u8 },                          // 0x55 / 0xAA / 0xFF …
    DeterministicRandom { scheme: PrngScheme, seed: [u8; 32] },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum PrngScheme { ChaCha20WindowV1 }   // exact construction: §7 — this string goes in the cert
```

**Pattern sources are pure functions of window index:**

```rust
pub trait PatternSource: Send + Sync {
    /// Fill `buf` with pattern bytes for window `w`. MUST be pure:
    /// identical (w, buf.len()) → identical bytes, on any machine, forever.
    /// This single property is what makes full verification O(1) memory.
    fn fill(&self, w: u64, buf: &mut [u8]);

    /// Machine-readable descriptor embedded in plan, journal, and cert.
    fn descriptor(&self) -> PatternDescriptor;

    /// Fixed/zero patterns are window-invariant → engine can use ONE buffer
    /// for the entire pass (§6.2). PRNG patterns are not.
    fn window_invariant(&self) -> bool;
}
```

Verification never stores expected data — it *re-derives* it from `PatternSource`. That's the whole verification memory model: **the expected image of a 20 TB drive is 32 bytes of seed + a scheme string.**

---

## 3. The Sanitization Plan (first-class object)

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationPlan {
    pub plan_schema: &'static str,        // "dc-plan/1"
    pub target: StableIdentity,           // NOT a path — paths are resolved at arm time
    pub mechanism: Mechanism,             // Phase 0: LogicalOverwrite only
    pub verification: VerifyLevel,        // Full | None
    pub window_bytes: u64,                // default 2 MiB
    pub fast_path: FastPathPolicy,        // PreferWriteZeroes | ForbidWriteZeroes
    pub legacy_note: Option<String>,      // honesty label, §profiles
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Mechanism {
    LogicalOverwrite { passes: Vec<Pass> },
    // Phase 1 lands here: NvmeSanitize{..}, AtaSecurityErase{..}, SanitizeCryptoErase{..}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pass { pub pattern: Pattern, pub label: String }
```

**Plan hash — the spine of the whole audit story:**

```text
plan_hash = hex( BLAKE3( JCS( serde_json(plan) ) ) )
```

Rules:
- `plan_hash` covers: target stable identity, mechanism, **all pattern descriptors including the PRNG seed**, verification level, window size, fast-path policy. The seed being hash-committed *before execution* kills any "you picked the seed after the fact" attack — the journal header commits the hash at `t₀`.
- Excluded: estimates, timestamps, display strings. The plan hash is *pure procedure*.
- On **resume**, the seed is read from the journal's embedded plan — never regenerated.

**Profiles (Phase 0 ships exactly three):**

| Profile | Passes | Verify | Label in plan/cert |
|---|---|---|---|
| `clear-zero` (default) | `Zero` ×1 | Full | "NIST SP 800-88 Clear (logical overwrite)" |
| `clear-random` | `DeterministicRandom` ×1 | Full | "NIST SP 800-88 Clear (logical overwrite, CSPRNG)" |
| `legacy-dod3` | `Fixed{0xFF}` → `Fixed{0x00}` → `DeterministicRandom` | Full | `legacy_note: "Legacy contractual pattern. Not recommended for flash media; NIST SP 800-88 §2.4 / DoD 5220.22-M superseded. Provided for contractual compliance only."` |

`dc plan --target X --profile legacy-dod3` prints that legacy note in the confirmation prompt. The tool never *silently* pretends folklore is science — that's a legal feature, and it costs us one string.

---

## 4. Orchestrator FSM

Runtime state machine, exhaustively matched, transition table executable as a unit test:

```rust
pub enum State {
    Probed,
    PlanCompiled { plan: SanitizationPlan, plan_hash: [u8; 32] },
    PlanApproved { /* plan + confirmation transcript */ },
    Armed,                                   // fd open, flock held, identity verified, journal open
    Executing { pass: u8, next_window: u64 },
    Flushing { pass: u8 },
    Verifying,
    Certified,
    // Terminal:
    Aborted, Failed { code: ErrorCode, detail: String },
    Interrupted { resumable: true },         // exits process; resume re-enters via journal replay
}
```

| From | Event | Guard | To | Journal record |
|---|---|---|---|---|
| PlanCompiled | `Approve` | displayed hash == recomputed hash; serial typed matches | PlanApproved | `Header` (plan JSON + plan_hash) |
| PlanApproved | `Arm` | guardian verdict == Pass **or** recorded override; `fstat(fd).st_rdev` → KernelIdentity ∈ target; `flock(EX\|NB)` on disk + all partitions | Armed | `Armed` |
| Armed | `BeginPass` | — | Executing{p,0} | `BeginPass` |
| Executing | checkpoint (every 512 MiB or 5 s) | identity re-verify OK (§5.3) | Executing | `RangeCommit` + fdatasync(journal) |
| Executing | last window written | — | Flushing | `EndPass` |
| Flushing | flush ack | device flush OK | Executing{p+1} ∨ Verifying | `Flushed` |
| Verifying | done | mismatches == 0 ∨ `--accept-mismatch` (cert annotated) | Certified | `Verify` + `Completed` |
| any | SIGINT/SIGTERM | drain ring → checkpoint | Interrupted | `Interrupted` |
| any | EIO / identity drift / journal corrupt | — | Failed | `Failed` |

Two rules worth carving in stone:

- **R1 (write gate):** no write, zero-range, or flush ioctl may be issued unless `state == Executing|Flushing` and the last identity verification is ≤ 1 checkpoint old. Enforced by the engine taking a `WritePermit` handle that only the Executing state can mint.
- **R2 (journal lag):** journal commits *after* CQEs confirm writes — the journal may lag media, never lead it. Crash between write-completion and commit ⇒ we re-write ≤ 1 checkpoint of windows. Overwrite is idempotent; this is safe by construction.

---

## 5. Guardian (`dc-probe`)

### 5.1 Decision table

Pure sysfs/proc parsing, zero udev library, zero superblock *writes*; superblock sniffing is read-only 4 KiB reads.

| # | Check | Source | Verdict |
|---|---|---|---|
| 1 | Target is whole disk, not partition | sysfs | REFUSE `NOT_WHOLE_DISK` |
| 2 | Zoned device (SMR host-managed/aware) | `/sys/block/X/queue/zoned != none` | REFUSE `ZONED` (sequential-write model — Phase 3) |
| 3 | RAM-backed (zram/brd) | sysfs | REFUSE `RAM_BACKED` |
| 4 | Read-only | `BLKROGET` | REFUSE `READ_ONLY` |
| 5 | Native NVMe multipath path (`nvmeXcYnZ` naming) | kernel_name | REFUSE `MULTIPATH_PATH` |
| 6 | Any partition of target mounted | `/proc/self/mountinfo` maj:min match | REFUSE `MOUNTED` |
| 7 | Active swap on target | `/proc/swaps` | REFUSE `SWAP_ACTIVE` |
| 8 | System disk (holds `/`, `/boot`, `/boot/efi`, `/usr`, `/var`) | mountinfo | REFUSE `SYSTEM_DISK` — overridable (§5.2) |
| 9 | Partitions have holders (active LVM PV, dm-crypt, md) | `/sys/block/X/X*/holders/` | REFUSE `HAS_HOLDERS` |
| 10 | md membership | `/proc/mdstat` | REFUSE `MD_MEMBER` |
| 11 | Inactive LVM PV / md member / stale swap sig | udev db `E:ID_FS_TYPE` from `/run/udev/data/b8:M:m`, fallback 4 KiB superblock sniff (`LABELONE`+`LVM2`, md magic, swap magic) | REFUSE `LVM_PV` / `MD_MEMBER` / `STALE_SWAP` |
| 12 | LUKS container (inactive) | sniff `LUKS\xba\xbe` | WARN `CRYPTO_CONTAINER` (proceed requires `--yes`) |
| 13 | Loop device | sysfs | REFUSE `LOOP` unless `--allow-loop` |
| 14 | Size sanity (< 1 MiB or 0) | `BLKGETSIZE64` | REFUSE `SIZE_ANOMALY` |
| 15 | Concurrent claim | `flock(LOCK_EX\|LOCK_NB)` on disk fd **and** every partition fd | REFUSE `BUSY` |

Locking the *partition* fds too is deliberate: LVM/blkid lock partitions, not whole disks. If we only locked the disk, `pvmove` could start mid-wipe.

### 5.2 Override protocol

`SYSTEM_DISK` (and only it) is overridable, in two steps:
1. `--allow-system-disk` flag, **and**
2. Interactive typed entry of the drive's full serial number — or non-interactive `--serial-confirm <SERIAL>` which must byte-match (fleet scripting path).

The override event, flag, and matched serial go into the journal and the cert. No override is silent.

### 5.3 Identity binding & re-verification (TOCTOU kill chain)

The threat: plan compiled against `/dev/sdb` (Drive A), operator swaps cables, `/dev/sdb` is now Drive B, execution wipes the wrong drive.

1. **Open once, never by path again.** At `Arm`: open the resolved path `O_RDWR|O_DIRECT`, then `fstat` the fd → `(major, minor)`. All subsequent I/O and ioctls use this fd. If the device vanishes, the fd errors (`ENODEV`) — it cannot silently redirect.
2. **Stable-identity check at Arm:** sysfs `/sys/dev/block/<maj>:<min>/` serial/wwn/model/size must equal `plan.target`. Any mismatch → REFUSE `IDENTITY_DRIFT`.
3. **Checkpoint re-verification:** every journal checkpoint, re-read `/sys/dev/block/<maj>:<min>/serial` (cheap) and compare. Drift mid-run → `Failed(IDentityDrift)`, journal records it. Rationale: catches iSCSI/NVMe-oF path shenanigans and operator hot-swaps.

---

## 6. I/O Engine (`dc-io`)

### 6.1 Capability probe (all read-only, zero destructive probing)

```
size            ← ioctl(BLKGETSIZE64)
lbs / pbs       ← ioctl(BLKSSZGET / BLKPBSZGET)
write-zeroes    ← /sys/block/X/queue/write_zeroes_max_bytes (>0 ⇒ BLKZEROOUT available)
```

We never "test" BLKZEROOUT by issuing it — a 1-sector probe is still a write. sysfs tells us.

```rust
pub trait Engine: Send {
    fn caps(&self) -> &EngineCaps;
    /// Overwrite [from,to) with pattern. Calls `progress` per checkpoint.
    /// Honors cancel token: drains ring, returns where it stopped.
    fn write_pass(&mut self, pat: &dyn PatternSource, span: LbaSpan,
                  prog: &mut dyn FnMut(EngineProgress)) -> Result<PassOutcome, DcError>;
    /// Fast path zero fill (BLKZEROOUT chunks), or falls back to write_pass(Zero).
    fn zero_pass(&mut self, span: LbaSpan, /*…*/) -> Result<PassOutcome, DcError>;
    /// Sequential read + per-window check + in-order stream hashing (§6.4).
    fn read_verify(&mut self, pat: &dyn PatternSource, span: LbaSpan,
                   sink: &mut dyn VerifySink) -> Result<(), DcError>;
    fn flush(&mut self) -> Result<(), DcError>;   // io_uring FSYNC / fsync fallback
    fn cancel(&self);
}
```

Two implementations: `UringEngine` (kernel ≥ 5.1, probed at runtime) and `SyncEngine` (`pwritev` loop, O_DIRECT, compat path — ancient kernels/VMs). Same trait, same tests run against both (loop devices support `losetup --direct-io=on`, so CI covers both paths).

### 6.2 The three write loops

**(a) Window-invariant patterns (Zero, Fixed) — the one-buffer trick:**
Fill buffer #0 once. Submit up to QD SQEs, *all referencing buffer #0*, each with a different window offset. On each CQE, resubmit the next window. Memory traffic per byte written: **zero**. Pattern fill cost: one 2 MiB fill per pass. Throughput is purely device-bound. (Multiple in-flight SQEs aliasing one buffer is safe because the buffer is immutable and these are writes, never reads.)

**(b) Deterministic-random pass — pipelined generation:**

```
┌──────────── gen threads (min(4, ncpu)) ────────────┐
│  ChaCha20 keystream: key=seed, nonce=window_index   │
│  ~1–3 GB/s/core SIMD                                │
└──────────────┬──────────────────────────────────────┘
               ▼  staging ring (SPSC)
┌──────────── engine thread ──────────────────────────┐
│ free buffer? ← take prefilled window w              │
│ submit WRITE(w) → ring (QD 64–128)                  │
│ CQE(w) → release buffer to gen pool                 │
└─────────────────────────────────────────────────────┘
```

Because each window's keystream depends only on `(seed, window_index)`, **completion order is irrelevant** — a buffer holding window 7124 is correct no matter when it lands. No ordering state, no resync. If generation can't keep pace (Gen5), effective QD self-throttles via the free list — the system degrades gracefully instead of stalling.

**(c) Zero fast path — BLKZEROOUT:**
`ioctl(BLKZEROOUT, {start, len})` in 2 GiB chunks → kernel translates to NVMe WRITE ZEROES / SCSI WRITE SAME. Zero host↔device data transfer; controller writes zeros at media speed. Caveats engineered around: it's synchronous and uncancellable mid-call (chunking bounds the blast radius to 2 GiB); `--no-write-zeroes` exists because some auditors require observable write traffic — the cert records which path ran (`fast_path_used: true/false`). Verification treats both identically (read-back must be zeros either way).

**Defaults:** window 2 MiB · pool 64 × 2 MiB = 128 MiB · QD 64. All tunable (`--window-kib --pool-mib --qd`). Buffers are `mmap`-anonymous, page-aligned, `madvise(MADV_HUGEPAGE)`; every window length/offset is a multiple of lbs; final short window handled by truncation.

### 6.3 Flush-before-verify (non-negotiable)

After the last window of each pass and **before any verification read**: engine issues FSYNC on the device fd (→ NVMe FLUSH / ATA FLUSH CACHE EXT). Without this, read-back can be satisfied from the device's volatile write cache and "verify" a wipe that hit nothing. Most tools skip this; ours doesn't.

### 6.4 Verification read loop — pool-as-reorder-buffer

Reads complete out of order; the stream hash must be **in LBA order**. Design:

```
submit READ(w) for w in window ring…
CQE(w) → ① per-window check (order-independent):
             memcmp(buf, expected(w))   // expected regenerated into scratch
         ② park (w, buf) in pending: BTreeMap<u64, Buf>
drain: while pending.contains(next_expected):
             stream_hasher.update(buf)  // BLAKE3 in-order, streaming
             release buf → free list
backpressure: if pending.len() > pool/2 → pause submissions
```

NVMe returns large sequential reads nearly in order, so `pending` stays tiny and the map is cheap. Result: a true sequential BLAKE3 (and optional SHA-256) over the entire read-back — the standard `blake3` digest any auditor can recompute with `b3sum` after re-reading the drive — with zero extra memory beyond the existing pool.

---

## 7. `ChaCha20WindowV1` — the reproducibility contract

This exact text ships **verbatim inside every certificate**. It is the spec a third party implements to re-derive our random pass:

```text
scheme: chacha20-window-v1
window: W bytes (from plan.window_bytes, default 2097152)
key:    the 32-byte `seed` from the plan (BLAKE3-hash-committed at t0 via plan_hash)
nonce:  12 bytes, little-endian: nonce[0..8] = window_index as u64 LE,
        nonce[8..12] = 0x00000000
blocks: ChaCha20 keystream starting at counter 0, advanced 1 per 64-byte block,
        generated over the full window W (last window of the drive may be
        shorter: keystream is truncated 
Here you go — sections 7 through the end, exactly as written:

---

## 7. `ChaCha20WindowV1` — the reproducibility contract

This exact text ships **verbatim inside every certificate**. It is the spec a third party implements to re-derive our random pass:

```text
scheme: chacha20-window-v1
window: W bytes (from plan.window_bytes, default 2097152)
key:    the 32-byte `seed` from the plan (BLAKE3-hash-committed at t0 via plan_hash)
nonce:  12 bytes, little-endian: nonce[0..8] = window_index as u64 LE,
        nonce[8..12] = 0x00000000
blocks: ChaCha20 keystream starting at counter 0, advanced 1 per 64-byte block,
        generated over the full window W (last window of the drive may be
        shorter: keystream is truncated to remaining length, never re-keyed)
data:   keystream XOR zero-buffer == keystream
```

Reproducibility test (CI, golden vectors): fixed seed `B3*32` style test seeds, window 0/1/last, pin first 64 bytes of each as hex at implementation time; forever after, any change to generation or verification breaks CI loudly. A2 acceptance = an independent reimplementation from this paragraph alone matches our cert's stream hash on a test image.

---

## 8. Journal (`dc-core::journal`)

Append-only, hash-chained, one file per operation: `<serial|anon>-<UTC timestamp>.dcj`.

**Framing:** `magic "DCJ1" | u32 record_len | record (compact JSON) | [u8;32] record_hash`
`record_hash = BLAKE3(record_bytes || prev_hash)`; each record embeds `prev_hash`; header's `prev_hash = [0;32]`. Chain head = last record's hash → embedded in cert. Tampering with any byte anywhere breaks every subsequent hash — cheap, brutal, court-friendly.

**Records (v1):**

```rust
pub enum JournalRecord {
    Header      { plan: SanitizationPlan, plan_hash: String, identity: DeviceIdentity,
                  tool: ToolBuild, argv_hash: String, started_utc: String },
    Armed       { overrides: Vec<String>, locks_held: Vec<String>, at: String },
    BeginPass   { pass: u8, pattern: PatternDescriptor, window_bytes: u64 },
    RangeCommit { pass: u8, first_window: u64, num_windows: u64 },
    EndPass     { pass: u8 },
    Flushed     { pass: u8 },
    Verify      { level: String, windows_checked: u64, mismatch_count: u64,
                  first_mismatch_lbas: Vec<u64>, stream_hash_blake3: String,
                  stream_hash_sha256: Option<String>, fast_path_used: bool },
    Interrupted { at: String, hint: String },
    Resumed     { at: String, from_pass: u8, from_window: u64 },
    Failed      { code: String, detail: String },
    Aborted     { at: String },
    Completed   { at: String, duration_mono_ms: u64 },
}
```

**Checkpoint policy:** `RangeCommit` every 512 MiB or 5 s (whichever first) + `fdatasync` of the journal fd; directory fsync at creation. Worst-case replay loss on `kill -9`: one checkpoint of re-write (idempotent, R2).

**Resume algorithm** (`dc resume --journal X`):
1. Parse every record; verify chain end-to-end. **Invalid chain ⇒ refuse to resume**, error `JOURNAL_CORRUPT` + audit entry. Tamper evidence *working as intended* — the operator starts a new journal, and the broken one is preserved as evidence.
2. Reconstruct: last pass state, committed window coverage, whether flush/verify happened.
3. Re-Arm from scratch: full guardian re-run, identity re-bind to a fresh fd (the old fd died with the process), compare stable identity against journal's `Header.plan.target`.
4. Emit `Resumed`, continue. Crash between write and commit ⇒ re-write ≤ 1 checkpoint of windows — harmless.

---

## 9. Verification Engine (`dc-verify`)

```rust
pub enum VerifyLevel { Full, None }   // Stratified arrives Phase 2; None is stamped loudly on the cert

pub struct VerificationReport {
    pub level: VerifyLevel,
    pub windows_checked: u64,
    pub mismatch_count: u64,
    pub first_mismatch_lbas: Vec<u64>,     // capped at 64 entries
    pub stream_hash_blake3: String,        // in-LBA-order digest of full read-back
    pub stream_hash_sha256: Option<String>,
    pub entropy: Option<EntropyDiag>,      // random passes only: per-window Shannon + χ²(dof=255)
}

pub struct EntropyDiag { pub h_min: f64, pub h_mean: f64, pub h_max: f64,
                         pub chi2_max: f64, pub windows: u64 }
```

Per-window semantics (matching my earlier correction of the entropy trap):

| Pattern | Per-window check |
|---|---|
| Zero / Fixed | exact `memcmp` against regenerated block |
| DeterministicRandom | regenerate window keystream → exact `memcmp` |
| — | Shannon + χ² computed as *diagnostics only*, recorded for the cert's entropy section; never a pass/fail oracle |

Verification failure → `Failed`, journal `Failed` record. `--accept-mismatch` allows issuing a **certificate of attempted sanitization** explicitly marked `verification: FAILED (N mismatches)` — labs need this for dying media, and an honest failure cert beats a fake success cert every day of the week.

---

## 10. Certificate (`dc-cert`)

```jsonc
{
  "schema": "diskcleaner-cert/1",
  "tool":        { "name": "diskcleaner", "version": "0.1.0",
                   "build_hash": "<reproducible-build BLAKE3>", "target_triple": "x86_64-unknown-linux-musl" },
  "verification_scheme_doc": "<§7 text verbatim>",
  "plan":        { "<full plan JSON>", "plan_hash": "…" },
  "device":      { "<DeviceIdentity>", "health": null },
  "execution":   { "started_utc": "…", "finished_utc": "…", "duration_mono_ms": 0,
                   "interruptions": [ { "at_utc": "…", "resumed_utc": "…" } ],
                   "passes": [ { "index": 0, "pattern": "…", "fast_path_used": false,
                                 "windows_written": 0, "throughput_mib_s": 0.0 } ] },
  "verification":{ "level": "Full", "stream_hash_blake3": "…", "stream_hash_sha256": null,
                   "windows_checked": 0, "mismatch_count": 0, "entropy": { "h_min": 7.9999, "…": 0 } },
  "journal":     { "path": "…", "chain_head": "…", "record_count": 0 },
  "operator":    { "key_fingerprint_blake3": "…", "public_key_ed25519": "…" },
  "signature":   { "alg": "Ed25519", "value": "<base64>" }
}
```

- **Signature:** Ed25519 over `serde_jcs` (RFC 8785) canonicalization of everything above `signature`. JCS, not raw serde_json — serializer field-order changes across versions would break old certs otherwise. `dc cert verify <file>` re-validates; any tampered byte fails.
- **Reproducibility story (A2):** given this file, a third party with any ChaCha20 implementation can re-derive every random window's bytes, and — with drive read access — recompute the full BLAKE3 stream hash and compare. The cert is not a claim; it's a *recipe*.
- Key handling Phase 0: Ed25519 keyfile (`--key`), fingerprint = BLAKE3(pubkey). PKCS#11/YubiKey slot already reserved in the `operator` struct for Phase 2.
- Output: `<serial>-<ts>.cert.json` + human text summary (PDF/A is Phase 2).

**Audit log** (separate, always, even for refusals that never open a journal): append-only `audit-chain.log`, same hash-chain framing, one line-record per invocation: `timestamp | argv_hash | target | outcome(refusal code | plan_hash | journal id)`. Guardian refusals are forensically interesting events too.

---

## 11. Error Taxonomy & Exit Codes

```rust
pub enum DcError {
    Guardian(GuardianRefusal { code: &'static str, detail: String, hint: String }),
    IdentityDrift { expected: StableIdentity, observed: StableIdentity },
    Io { op: &'static str, errno: i32, at_lba: Option<u64> },
    JournalCorrupt { record_index: u64, reason: String },
    VerificationFailed { mismatches: u64, sample: Vec<u64> },
    Interrupted { completed_through: Option<(u8, u64)> },
    OperatorAbort, CertSigning(String), Usage(String),
}
```

| Exit code | Meaning |
|---|---|
| 0 | Certified clean |
| 2 | Guardian refusal |
| 3 | Interrupted (resumable) |
| 4 | Verification failed |
| 5 | I/O failure |
| 6 | Journal corrupt / chain invalid |
| 7 | Identity drift |
| 8 | Usage |

Stable exit codes from day one — fleet orchestration depends on them.

---

## 12. CLI Surface (Phase 0, complete)

```
dc list                                   # inventory table (read-only, always safe)
dc plan    --target /dev/nvme0n1 [--profile clear-zero] [--qd … --pool-mib … --no-write-zeroes]
                                          # prints plan + plan_hash (dry-run by default)
dc execute --target … --profile … [--key /path/key] [--allow-system-disk [--serial-confirm S]]
                                          # confirm (type serial) → run → cert
dc resume  --journal <file> [--key …]
dc verify  --journal <file>               # standalone re-verification of a wiped drive
dc cert    show|verify <file>
```

Signals: SIGINT/SIGTERM blocked in worker threads, consumed by a watcher thread → graceful drain → checkpoint → `Interrupted` (exit 3). SIGKILL is handled by the journal's existence — that's the entire reason it exists.

---

## 13. Invariants (each maps to a test)

- **INV1 — Write gate:** no write/zero/flush ioctl outside `Executing|Flushing` with fresh identity check. (Test: FSM unit tests assert only `WritePermit` path reaches engine.)
- **INV2 — Journal lag:** a `RangeCommit` is only emitted after CQEs for all its windows. (Test: inject CQE failure, assert no commit.)
- **INV3 — Chain integrity:** cert `chain_head` == BLAKE3 over journal file. (Test: T9.)
- **INV4 — Plan hash recomputable:** `plan_hash` in cert == BLAKE3(JCS(plan JSON in cert)). (Test: T9b.)
- **INV5 — PRNG reproducibility:** golden vectors + independent reimplementation cross-check. (Test: T8.)
- **INV6 — Zero external processes:** no `std::process` anywhere; CI greps the workspace, plus an integration test runs the binary under a seccomp filter denying `execve`.
- **INV7 — Dual clock:** every duration is monotonic; every instant is UTC ISO-8601; both recorded.

---

## 14. Test Matrix → CI Gates

| ID | Setup | Action | Expect |
|---|---|---|---|
| T1 | loop 1 GiB, `--direct-io=on` | `clear-zero` full run | exit 0; read-back via second fd all zeros; stream hash correct |
| T2 | `dm-error` @ 50% | wipe | exit 5; journal `Failed`; repair map → `dc resume` → exit 0 |
| T3 | `kill -9` mid-pass | loop 1 GiB | journal valid; resume completes; verify passes (A4) |
| T4 | loop, one partition mounted | wipe | exit 2 `MOUNTED`; audit-chain entry exists |
| T5 | loop → PV in active VG | wipe | exit 2 `HAS_HOLDERS` |
| T6 | flip one byte in journal | resume | exit 6 `JOURNAL_CORRUPT`; original file preserved |
| T7 | plan on sdA, swap to sdB | execute | exit 7 `IDENTITY_DRIFT`; zero writes issued |
| T8 | golden PRNG vectors | — | pinned hex matches (A2) |
| T9 | tamper cert byte / reorder JSON keys | `dc cert verify` | fails; untouched cert passes across serializer versions |
| T10 | NVMe bare-metal (self-hosted runner) | 1 TiB `clear-random` | ≥ 90% of `fio` O_DIRECT QD128 throughput (A1) |
| T11 | SIGINT mid-pass | — | exit 3, checkpointed, resumable |
| T12 | proptest: journal truncation at every byte offset | resume | always `JOURNAL_CORRUPT` or clean replay — never a wrong continuation |

CI needs **root** (loop/dm devices): self-hosted runner or rootful container with `/dev` mapped; plus one bare-metal box with a real NVMe drive for T10 — the throughput claim is only real if it's measured on silicon. Gates on every PR: fmt, clippy `-D warnings`, `cargo-deny` (license + advisories + **ban list**: `openssl-sys`, `libudev-sys`, `tokio`), unit+integration, INV6 seccomp test. Fuzzing (cargo-fuzz) targets: mountinfo parser, journal replay, sysfs parsers.

---

## 15. Milestones (PR-sized, each with Definition of Done)

| | Deliverable | DoD |
|---|---|---|
| **M0.1** | Workspace + `dc-probe` inventory + full guardian table + audit log + `dc list` | T4, T5, refusal-path audit entries |
| **M0.2** | `SyncEngine` + zero/fixed/PRNG write + flush + confirmation UX + journal (write-only) | T1 passes on sync path |
| **M0.3** | `UringEngine` (all three loops §6.2) + BLKZEROOUT fast path + progress | T10 hits ≥90% fio |
| **M0.4** | Checkpointing + resume + `dm-error` harness + signal handling | T2, T3, T11, T12 |
| **M0.5** | `dc-verify`: exact-match, PRNG re-derive, reorder hashing, entropy diag, `--accept-mismatch` | T8; verify 1 TiB end-to-end |
| **M0.6** | Cert + JCS signing + `dc cert verify` + reproducible-build hash embedding + docs + exit codes | T9, INV4/INV5 demo, release binary musl-static |

Six weeks of runway, each week shippable, and at M0.6 you have something no open-source tool currently offers: **a resumable, identity-pinned, journal-backed wipe with deterministic-PRNG full verification and a reproducible signed certificate.** That alone out-classes ShredOS/nwipe before a single NVMe ioctl lands in Phase 1.

---

Two things to lock before M0.1 day one: (1) the golden PRNG vectors get pinned the moment §7 is implemented — they're the root of trust for A2; (2) the journal chain framing code is written once in `dc-core` and *reused* by the audit log — no second implementation to diverge.

Next artifact, say the word: **the actual repo scaffold** — every `Cargo.toml`, module tree with stubbed signatures exactly as specced above, the failing test suite for T1–T12 (red on day one, green by M0.6), and the CI workflow with the deny-list and seccomp gate — or we go deeper on any single subsystem first (my vote: §6.2's engine loop, since every GB/s of headroom there compounds across every future phase).
