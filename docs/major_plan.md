Love the energy — the document is ~80% architecturally correct, and the direct-ioctl / no-external-binaries instinct is exactly right. So instead of re-praising it, I'm going to do what a rival architect would do before this thing gets built: **red-team it, fill the gaps that would get it shredded in a deposition, and force sequencing discipline.** The biggest risk isn't ambition — it's building 9 crates simultaneously and shipping none.

---

## 1. Red-Team: Traps in the Current Plan

**T1 — The eBPF write blocker is a trap. Delete it.**
`io_uring` workers execute I/O *inside the kernel* — they never issue `write()` syscalls, so syscall-level eBPF interception sees nothing. Your write-blocker would be bypassed by the exact I/O engine you're building. Correct design: `BLKROSET` + device-mapper read-only linear table as belt-and-braces, *attempt-verify semantics*, and honest documentation that software write-blocking is best-effort. Real labs use hardware blockers anyway. Ship acquisition mode with the software blocker, don't pretend it's absolute.

**T2 — Multi-pass overwrite on SSDs is *worse* than useless. Make the tool say so.**
Pattern overwrite on flash: (a) burns write endurance, (b) never touches over-provisioned blocks, bad-block remaps, or FTL metadata, and (c) takes 10–100× longer than crypto erase. NIST 800-88 says this explicitly. Keep DoD/BSI patterns in the tool — customers contractually demand them — but label them *"legacy contractual compliance pattern; not recommended for flash media"* in the UI and the certificate. A tool that claims "DoD 5220.22-M compliant" in its marketing gets destroyed under cross-examination (the current manual itself defers to NIST 800-88; the 7-pass pattern is folklore from decades-old NSA guidance). Honest labeling is a *legal feature*.

**T3 — Entropy verification is the wrong instrument for pattern passes.**
`H(X)=0` proves all bytes are *identical* — a drive filled entirely with `0xFF` also scores 0.0 entropy and "passes" a zero-fill audit. Correct verification semantics:

| Pass type | Verification method |
|---|---|
| Fixed pattern (0x00, 0x55, DoD…) | Exact `memcmp` against regenerated expected block per LBA window |
| CSPRNG pass | **Deterministic per-LBA PRNG**: ChaCha20 keystream, key = seed, nonce = LBA. Verify = regenerate & compare. O(1) memory, full-coverage verification of a 20TB drive without storing a byte. Seed goes in the signed cert → entire pass is reproducible by any auditor, forever. |
| Zero-fill / dealloc | Read-back + exact match, plus RZAT (read-zero-after-trim) checks |
| Entropy + χ² (dof=255) | Diagnostic *only*, for random passes and anomaly detection |

This deterministic-PRNG trick is the single highest-value cryptographic design decision in the tool. It makes full verification computationally trivial and gives the cert reproducibility no commercial competitor offers.

**T4 — Sanitize is asynchronous. Screen-scraping died for the right reason; the fix is the Sanitize Status log.**
NVMe sanitize completion is detected by polling **Get Log Page LID 0x81** (Sanitize Status log): `SPROG` gives completion percentage, `SSTAT` gives state (in-progress / completed / failed / global-data-erased flag). This log is *persistent across power cycles* — free evidence for the cert. Same pattern for SCSI: `FORMAT UNIT` with IMMED=1, then poll the progress indication descriptor via REQUEST SENSE. Also handle the ugly states: power loss mid-sanitize can leave a controller locked or in a failed-sanitize state — the tool must surface that honestly, not crash.

**T5 — USB bridges lie. This is where real-world wipes go to die.**
Cheap JMicron/ASMedia/Cypress SAT bridges frequently mangle `ATA PASS-THROUGH(16)`, silently drop HPA/DCO commands, or return success without executing. Never trust the return code alone: verify *effects* independently (IDENTIFY before/after HPA restore, capacity re-read, sanitize-status readback, read-back sampling). Maintain a tested-bridge matrix as a first-class asset — this is Blancco's actual moat, not software.

**T6 — TCG Opal is a project unto itself. Phase it last.**
Full Opal means sessions, ComPacket/Property parsing, the protocol's challenge-response scheme, locking ranges. A mis-issued command can lock a drive permanently. Minimal viable slice: detect Opal via SECURITY PROTOCOL IN (protocol 0x00 supported-list), then PSID Revert — nothing else. Everything later.

**T7 — Freeze-lock reality check.**
There is no `SECURITY UNFREEZE` command. Drives get frozen by BIOS at boot (IDENTIFY word 128, security status). The classic unfreeze is S3 suspend/resume or a link/port reset — the doc gestures at this but the plan must own it explicitly, including the headless-boot-ISO case where the *tool's own boot environment* must never freeze drives in the first place (that's a feature of your boot image: no BIOS freeze on warm path).

**T8 — Opcode nit, and the lesson behind it.**
Dataset Management is opcode `0x09`, not `0x0A` (Format NVM `0x80` and Sanitize `0x84` in your doc are correct). The lesson: every CDB/command encoding needs golden hex-vector unit tests against the spec revision you target, plus differential testing against `nvme-cli`, `sg3_utils`, and `hdparm` during development. Your code goes to court; a bit-flipped field is reasonable doubt.

---

## 2. Missing Subsystems (the gaps that matter more than new features)

**G1 — Crash-resumable wipe journal.** A 20TB multi-pass wipe is a multi-day operation. Journal every completed LBA range per pass (append-only, hash-chained records). On interruption — crash, power loss, Ctrl-C — resume from the journal. Critically: **the cert must disclose any interruption and resume**, with timestamps. Courts forgive interruptions; they don't forgive concealment.

**G2 — Identity re-verification immediately before every destructive command.** USB re-enumeration can swap `/dev/sdX` assignments between selection and execution. Check serial + WWN + kernel device identity *at the moment of the destructive ioctl*, not just at selection time. This is forensic-grade safety; the current plan only fingerprints at selection.

**G3 — Layer-stack resolution.** Traverse sysfs `holders/`, `/proc/mdstat`, udev `ID_FS_TYPE` (LVM2_member, linux_raid_member), dm tables, loop, NVMe-oF. Refuse member devices of active arrays with explicit resolution paths. Self-contained via sysfs/udev — still zero external binaries.

**G4 — Supply chain & reproducible builds.** For a forensic tool this is table stakes, and it's absent from the plan: `--locked` reproducible builds, `cargo-deny`/`cargo-vet`, minimal dep tree, and — critically — **the binary's own hash embedded in every certificate**. "The tool that wiped this drive" must be a specific, reconstructable artifact. Also: never log the ephemeral ATA erase password (generate random per-operation, discard).

**G5 — Testing infrastructure (zero in the plan).** `scsi_debug` kernel module for SAS/SCSI emulation, QEMU's NVMe device model (recent versions emulate Format/Sanitize), loop devices + `dm-error` for fault injection, `cargo-fuzz` on every parser (sysfs, IDENTIFY structs, sense data), golden CDB vectors, differential testing vs. reference tools, and eventually self-hosted bare-metal CI with a drive-and-bridge menagerie. A forensic claim without a test matrix is marketing.

**G6 — Boot ISO.** "No external binaries" implies the real deployment: a static **musl** binary in your own minimal initramfs/ISO — the ShredOS/DBAN slot, which is currently served by a decades-old tool. This is also the environment where the freeze-lock problem (T7) must be solved by construction.

**G7 — Fleet/kiosk mode.** How labs actually run: scan barcode → auto-wipe → auto-cert. Optional two-person integrity (co-signing operator keys) for high-security shops. This is a differentiator commercial tools charge fortunes for.

**G8 — Timestamping beyond signatures.** Ed25519 proves *who*, not *when*. Add **RFC 3161 (TSA) trusted timestamps** to every cert, and an append-only hash-chained local audit log of all operations (not just successes — aborts, failures, refusals).

---

## 3. Architecture Upgrades

**A. The Sanitization Plan is a first-class object.** Probe → compile a plan (device identity, chosen mechanisms with ranked fallbacks, HPA/DCO sequencing, passes, verification level, est. duration) → operator reviews and approves → **plan hash goes into the certificate**. The cert then proves: *this exact procedure was approved and executed on this exact device*. Dry-run mode falls out for free.

**B. Standards as declarative data, not code.** Profiles = JSON documents (mechanism sequences + verification requirements) consumed by a generic executor. When NIST 800-88 Rev.2 finalizes or IEEE 2883 adds mechanisms, it's a config change. Target IEEE 2883-2022 as the forward standard; keep 800-88 for contractual demand.

**C. Strategy matrix (the heart of the engine):**

| Device class | Primary (Purge) | Fallback | Notes |
|---|---|---|---|
| NVMe | Sanitize Crypto Erase | Block Erase → Format NVM SES=2 | Poll LID 0x81; namespace inventory matters |
| SATA SSD | ATA Sanitize (Crypto Scramble) | Security Erase Enhanced | Check word 128 for enhanced-erase support |
| SATA HDD | Security Erase Enhanced | HPA/DCO restore → pattern overwrite | **DCO → HPA → re-read geometry → wipe** (ordering matters) |
| SAS/SCSI | SCSI SANITIZE | FORMAT UNIT IMMED + sense polling | |
| SED | PSID Revert | Native crypto erase | Phase 3 |
| USB-bridged | Delegate via SAT | Raw overwrite | Bridge capability probe (T5) |

**D. The `BLKZEROOUT` / WRITE ZEROES fast path — you're missing this and it's huge.** For zero-fill passes, don't ship data over the bus at all: `ioctl(BLKZEROOUT)` (backed by NVMe Write Zeroes / SCSI WRITE SAME) has the *controller itself* write zeros at media speed. Zero host bandwidth, zero page-cache involvement. Chunk it (~2GB calls) for progress reporting. Same idea opportunistic for SCSI VERIFY with byte-compare (support is spotty — treat as fast path, not assumption).

**E. Flush-before-verify.** With volatile write caches, a read-back can be satisfied from cache, not media. Issue an explicit flush (NVMe FLUSH / ATA FLUSH CACHE EXT) after each pass and before verification reads, or write with FUA. Most wiping tools get this wrong; yours shouldn't.

**F. Concurrency model.** Thread-per-device, each owning a private `io_uring` ring (rings are single-owner by design), QD 64–256, registered buffers. Fixed-pattern passes reuse **one** registered buffer across all SQEs — memory bandwidth for pattern generation drops to zero. Orchestrator + ratatui TUI communicate over channels; SIGINT = graceful checkpoint → journal → "interrupted" state. Also: **detect SMR drives and force sequential writes** — random-order multi-pass on host-managed SMR causes multi-day stalls; this is a real incident class.

The ioctl core, to make "no external binaries" concrete (~what Phase 1 centers on):

```rust
#[repr(C)]
struct NvmePassthruCmd {
    opcode: u8, flags: u8, rsvd1: u16, nsid: u32,
    cdw2: u32, cdw3: u32, metadata: u64, addr: u64, metadata_len: u32,
    data_len: u32, cdw10: u32, /* ... cdw16, timeout_ms */
}
// Sanitize: opcode 0x84, cdw10 = action (crypto-erase/block-erase/overwrite),
// then poll Get Log Page LID 0x81 (SPROG %, SSTAT state) until terminal.
unsafe { ioctl(fd, NVME_IOCTL_ADMIN_CMD, &mut cmd) };
```

---

## 4. Sequencing (the difference between shipping and vaporware)

| Phase | Scope | Acceptance criteria |
|---|---|---|
| **0 — Foundation** (first) | Guardian/safety layer, device inventory + identify, layer-stack resolution, io_uring I/O engine (+ sync fallback for pre-5.1 kernels like RHEL8), zero/pattern wipe, `BLKZEROOUT` fast path, exact-match full verification, deterministic-PRNG verify, JSON cert + Ed25519, journal/resume, CLI | Wipe + fully verify a 1TB drive at line speed; cert reproducible; correctly refuses system/LVM/RAID disks; crash-resume proven with `dm-error` |
| **1 — Native purge** | NVMe (Format SES, Sanitize + status-log polling), ATA via SG_IO (security erase, sanitize, HPA/DCO, freeze handling), bridge matrix v1 | Differential parity vs `nvme-cli`/`hdparm`; sanitize success/abort/fail paths exercised on QEMU + hardware |
| **2 — Ops hardening** | SCSI/SAS, verification levels (Full/Stratified/None — stamped on cert), PDF/A, RFC 3161, TUI, fleet concurrency, thermals monitoring | Fleet of 8 devices concurrently with per-device certs |
| **3 — Frontier** | Opal PSID revert, eMMC/UFS, boot ISO, kiosk + two-person rule | |

**Explicitly deferred (or killed):** acquisition/E01/AFF4 mode (it's a second product — revisit after sanitization is best-in-class), filesystem slack cleaner (scope bomb; also near-meaningingless on SSDs due to wear-leveling — if ever built, honesty-label it), all eBPF anything.

## 5. Open decisions to lock *now*

1. **Licensing** — permissive (MIT/Apache-2.0) crates invite ecosystem reuse and enterprise adoption; GPL on the CLI protects against closed forks. This shapes everything downstream.
2. **Cert canonicalization** — sign RFC 8785 (JCS) canonical JSON, not raw bytes; otherwise serializer changes break signature validation across versions.
3. **Seed disclosure policy** — my recommendation: disclose the CSPRNG seed in the cert (enables auditor reproduction; the data is destroyed anyway).
4. **Minimum kernel target** — 5.10/5.15 LTS with io_uring, sync-O_DIRECT fallback below.
5. **Stack** — `rustix` (ioctls + io_uring), hand-written `#[repr(C)]` command structs with golden-vector tests (not bindgen), `clap`/`ratatui`, `blake3`/`sha2`, `ed25519-dalek`, `x509-cert` + `cryptoki` (PKCS#11/YubiKey), `rand_chacha`, `udev`.

---

Bottom line: your doc has the right skeleton — the wins now are (1) fixing the eight traps, (2) the deterministic-PRNG verification + plan-hash-in-cert combo (that's your defensible-moat feature), and (3) ruthless Phase 0 discipline.

Next concrete deliverable, if you want: I can draft the **Phase 0 crate skeleton** — full trait boundaries (`Transport`, `DeviceIdentity`, `EraseStrategy`, `Verifier`), the Sanitization Plan state machine, and the guardian's interlock rules — so you can start cutting code this week. Which one first?
