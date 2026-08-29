# diskCleaner (`dc`)

[![Version](https://img.shields.io/badge/version-v0.3.1-blue.svg)](https://github.com/zephyr4289/diskCleaner)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/arch-x86__64%20%7C%20aarch64--musl-blueviolet.svg)](https://github.com/zephyr4289/diskCleaner)
[![Standards](https://img.shields.io/badge/standards-NIST%20SP%20800--88%20%7C%20IEEE%202883--2022-orange.svg)](docs/diskCleaner.md)
[![Build](https://img.shields.io/badge/build-static%20%7C%20zero--dependency-success.svg)](https://github.com/zephyr4289/diskCleaner)

**Forensic-grade storage sanitization for Linux — every claim carries its own evidence, verification instructions, and cryptographic proof.**

`dc` is a self-contained, statically linked, zero-dependency storage sanitization suite engineered for NVMe, SATA, SAS/SCSI, USB-bridged (SAT), eMMC/UFS, TCG Opal self-encrypting (SED), and Host-Managed SMR/ZNS storage. It executes **NIST SP 800-88 Rev 1** Clear and Purge operations, issuing cryptographically signed, third-party-verifiable evidence packages that survive crashes, power loss, and adversarial cross-examination.

```
Version       : v0.3.1 (Complete Product Release)
Target Triples: x86_64-unknown-linux-musl · aarch64-unknown-linux-musl
Runtime Deps  : Zero external binaries, zero dynamic libraries
Crates        : 15 modular workspace crates (22,600+ Rust LOC)
Verification  : Ed25519 + RFC 8785 JCS + RFC 3161 TSA + PDF/A-3 Archival Embedding
```

---

## Table of Contents

- [Architectural Overview](#architectural-overview)
- [Data Flow & Lifecycle Model](#data-flow--lifecycle-model)
- [Device Support & Sanitization Matrix](#device-support--sanitization-matrix)
- [Quick Start](#quick-start)
- [The Guardian Safety System](#the-guardian-safety-system)
- [Cryptographic Evidence & Offline Verification](#cryptographic-evidence--offline-verification)
- [Two-Person Integrity & Key Lifecycle](#two-person-integrity--key-lifecycle)
- [Fleet Orchestration](#fleet-orchestration)
- [Standalone Boot Environment](#standalone-boot-environment)
- [Engineering Discipline & Testkit](#engineering-discipline--testkit)
- [Standards & Compliance](#standards--compliance)

---

## Architectural Overview

`diskCleaner` is organized into 15 modular Rust crates with strict unidirectional dependency boundaries. Unsafe code is strictly isolated to low-level ioctl wrappers; all protocol codecs, parsers, and strategy planners are pure, memory-safe, and deterministic.

```mermaid
graph TD
    subgraph "CLI & Presentation Layer"
        CLI["dc-cli<br/>(Operator CLI · Supervisor · PID-1 Init)"]
        TUI["dc-tui<br/>(LBA Heatmap · Phase-True Display)"]
        REP["dc-report<br/>(Deterministic PDF/A-3 Report Writer)"]
    end

    subgraph "Core Orchestration & Evidence"
        CORE["dc-core<br/>(Strategy Compiler · FSM · DCJ1 Journal · DCA1 Audit)"]
        CERT["dc-cert<br/>(cert/1 & cert/2 · Dual-Auth · Keyring · TSA)"]
        VERIFY["dc-verify<br/>(Two-Oracle Verifier · Stream Hash · Entropy)"]
    end

    subgraph "Hardware Probe & Guardian"
        PROBE["dc-probe<br/>(BlockGraph Walk · 17-Rule Guardian · ArmLockSet)"]
    end

    subgraph "I/O Engine & Execution"
        IO["dc-io<br/>(io_uring / Sync · BLKZEROOUT · Zoned Planner)"]
    end

    subgraph "Pure Hardware Codecs"
        HW["dc-hw<br/>(Pure Codecs: NVMe · ATA · SCSI · MMC · Opal)"]
    end

    subgraph "Transport Purge Drivers"
        NVME["dc-nvme<br/>(NVMe Purge Driver)"]
        ATA["dc-ata<br/>(ATA / SAT Driver)"]
        SCSI["dc-scsi<br/>(SCSI / SAS Driver)"]
        MMC["dc-mmc<br/>(eMMC / UFS Driver)"]
        OPAL["dc-opal<br/>(TCG Opal Driver)"]
    end

    CLI --> CORE
    CLI --> PROBE
    CLI --> TUI
    CLI --> REP
    CORE --> CERT
    CORE --> IO
    IO --> HW
    PROBE --> IO
    VERIFY --> CORE
    HW --> NVME
    HW --> ATA
    HW --> SCSI
    HW --> MMC
    HW --> OPAL
```

---

## Data Flow & Lifecycle Model

Every sanitization run transitions through a deterministic, crash-resilient lifecycle. Execution state is committed to a hash-chained binary journal (`DCJ1`) before issuing media writes.

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Operator / Key B
    participant Guardian as Guardian (dc-probe)
    participant Core as Core FSM (dc-core)
    participant Engine as I/O & Drivers (dc-io)
    participant Journal as Journal (DCJ1)
    participant Verifier as Verifier (dc-verify)
    participant Package as Evidence (dc-cert / dc-report)

    Operator->>Guardian: dc check / plan (Target Discovery)
    Guardian->>Guardian: Deep Dependency Walk (LVM/DM/MD/Mounts)
    Guardian-->>Core: Validated BlockGraph + Clean Target
    Core->>Core: Compile Strategy Ladder & Write Model
    Operator->>Core: dc plan approve (Two-Person Countersignature)
    Core->>Guardian: Acquire ArmLockSet (O_EXCL Whole-Disk & Partitions)
    Core->>Journal: Emit Header & Armed Record
    Core->>Engine: Issue Hardware Purge / Zoned Writes
    Engine->>Journal: Commit RangeCommit / SanitizeProgress (INV2)
    Engine-->>Core: Pass Completed (Flush-Before-Verify)
    Core->>Verifier: Execute Two-Oracle Verification
    Verifier->>Verifier: Oracle 1: Read Media vs Keystream Recipe<br/>Oracle 2: Hash Read-Back vs Journaled Digest
    Verifier-->>Core: Verification Report (Verified / Grades)
    Core->>Journal: Emit Completed Record & Seal Chain
    Core->>Package: Project dc-cert/2 + PDF/A-3 Archival Report + dc-evidence/1
    Package-->>Operator: Cryptographically Signed Evidence Package
```

---

## Device Support & Sanitization Matrix

| Device Class | Primary Firmware Purge | Secondary Fallback | Clear Overwrite | NIST SP 800-88 Grade |
| :--- | :--- | :--- | :--- | :--- |
| **NVMe SSD** | Sanitize Crypto Erase / Block Erase | Format NVM (CES / SES) | `ChaCha20WindowV1` / Zero | **Purge** / Clear |
| **SATA SSD** | ATA Sanitize Crypto Scramble | Enhanced Security Erase | `ChaCha20WindowV1` / Zero | **Purge** / Clear |
| **SATA HDD** | Enhanced Security Erase (DCO/HPA restored) | Security Erase | Multi-Pass DoD / Overwrite | **Purge** / Clear |
| **SAS / SCSI** | SCSI SANITIZE (Crypto / Block) | FORMAT UNIT (Format-Grade) | `ChaCha20WindowV1` / Zero | **Purge** / Clear |
| **USB-Bridged** | SAT Pass-Through (Runtime Probed) | Capability-Probed Overwrite | Verified Logical Overwrite | **Purge** / Clear |
| **eMMC / UFS** | Native Sanitize / Secure Purge | Secure Trim / Trim Erase | User Area Overwrite (RPMB Gated)| **Purge** / Clear |
| **Locked SED** | TCG Opal 2.0 PSID Crypt-Revert | Factory Revert | N/A (PSID unlocks unreadable media)| **Purge** |
| **SMR / ZNS** | Zoned Sequential Discipline + Resets | Zone-Attested Coverage | Sequential Stream Overwrite | **Purge** / Clear |

---

## Quick Start

### 1. Build the Static Binary
```bash
# Clean musl static build (no dynamic dependencies)
cargo build --release --target x86_64-unknown-linux-musl
```

### 2. Reconnaissance & Safety Audit
```bash
# List all system block devices with advisory classification
dc list

# Check target safety against the 17-precedence Guardian (Read-Only)
dc check --target /dev/nvme0n1
```

### 3. Strategy Compilation
```bash
# Compile a deterministic sanitization plan committed by plan_hash
dc plan --target /dev/nvme0n1 --strategy purge --out plan.json
```

### 4. Two-Person Approval & Execution
```bash
# Second operator countersigns the plan (Pre-Arm Dual-Auth)
dc plan approve --plan plan.json --key /path/to/officer.key --out plan.approved.json

# Execute with operator key and interactive serial confirmation
dc execute --plan plan.approved.json --key /path/to/operator.key
```

### 5. Crash Recovery & Resumption
```bash
# Resume an interrupted wipe across crashes, power loss, or reboots
dc resume --journal /var/log/dc/run.dcj
```

### 6. Evidence Inspection & Verification
```bash
# Offline verification of signed certificate and journal chain
dc cert verify cert.json --journal run.dcj

# Generate deterministic archival PDF/A-3 report with embedded JSON
dc report --cert cert.json --out report.pdf
```

---

## The Guardian Safety System

The Guardian enforces a mathematical guarantee: **no target will be modified if it contains live system dependencies or ambiguous identity.**

```mermaid
flowchart TD
    Target["Target Device (/dev/sdX, /dev/nvmeXn1)"] --> S0["1. Size Anomaly Check"]
    S0 --> S1["2. Whole-Disk vs Partition Check"]
    S1 --> S2["3. System Disk Check (/proc/self/mountinfo)"]
    S2 --> S3["4. Deep Dependency Walk (BlockGraph)"]
    
    subgraph "BlockGraph Traversal"
        S3 --> LVM["LVM Physical Volumes (PV/VG/LV)"]
        S3 --> CRYPT["dm-crypt / LUKS Mappings"]
        S3 --> MD["MD Software RAID Members"]
        S3 --> NVME_NS["NVMe Multi-Namespace Containment"]
    end

    LVM --> Gate{"Any Live Edge or Mount?"}
    CRYPT --> Gate
    MD --> Gate
    NVME_NS --> Gate

    Gate -- Yes --> Refuse["REFUSAL (Exit Code 2)<br/>Machine-Readable DangerPath Emitted"]
    Gate -- No --> Arm["Acquire ArmLockSet<br/>O_EXCL on Disk + All Partition Nodes"]
    Arm --> Proceed["Proceed to Execution"]
```

---

## Cryptographic Evidence & Offline Verification

All evidence emitted by `diskCleaner` is **independently verifiable without using `dc`**:

1. **RFC 8785 Canonical JSON (JCS):** All certificates (`dc-cert/1` and `dc-cert/2`) are canonicalized under RFC 8785 to ensure identical hashing regardless of whitespace or key ordering.
2. **Ed25519 Signatures (RFC 8032):** Digital signatures can be checked with any standard OpenSSL command:
   ```bash
   openssl dgst -sha512 -verify pubkey.pem -signature cert.sig canonical_cert.json
   ```
3. **Deterministic Keystream Recipe (`ChaCha20WindowV1`):** Every random pass derives its stream via `ChaCha20(key = seed, nonce = window_index)`. Third parties can regenerate and verify any sector of a 20 TB drive with $O(1)$ memory overhead.
4. **RFC 3161 TSA Timestamp Anchors:** Anchors provide verifiable proof that evidence existed *at-or-before* time $T$.
5. **PDF/A-3 Archival Embedding:** Reports embed the raw signed JSON, token sidecars, and keyring references directly inside the PDF document attachments.

---

## Two-Person Integrity & Key Lifecycle

```mermaid
graph LR
    KeyA["Operator Key A<br/>(Initiator / Hardware Token)"] --> AuthSet["AuthorizationSet<br/>(Binds plan_hash)"]
    KeyB["Officer Key B<br/>(Approver / Hardware Token)"] --> AuthSet
    AuthSet --> Custody{"Derived Custody"}
    Custody -- Both Hardware Tokens --> HW["separate-hardware"]
    Custody -- Keyfiles Present --> SF["shared-filesystem"]
    HW --> Arm["Arm & Execute"]
    SF --> Arm
```

* **Pre-Arm Gating:** Single-operator execution is strictly refused with `AUTHORIZATION_INCOMPLETE` when policy requires dual integrity.
* **Bilateral Key Rotation:** `dc-keyring/1` links old key supersession and new key activation at identical timestamp $T$.
* **At-or-After Revocation:** Revoked keys preserve historical pre-revocation evidence while marking post-revocation signatures as `SUSPECT_REVOKED_KEY`.

---

## Fleet Orchestration

The fleet supervisor orchestrates multi-drive bulk sanitization using a **process-per-device** isolation model.

```mermaid
graph TD
    Supervisor["Fleet Supervisor (Thin Process Coordinator)"]
    Manifest["Batch Manifest (dc-batch/1)<br/>Committed Identity & Plan Hash"]
    Audit["Machine-Wide Audit Log (DCA1)"]

    Supervisor --> Manifest
    Supervisor -->|Spawn & Monitor| C1["Child 1 (/dev/nvme0n1)<br/>dc execute"]
    Supervisor -->|Spawn & Monitor| C2["Child 2 (/dev/nvme1n1)<br/>dc execute"]
    Supervisor -->|Spawn & Monitor| C3["Child N (/dev/sda)<br/>dc execute"]

    C1 --> J1["Journal 1"]
    C2 --> J2["Journal 2"]
    C3 --> JN["Journal N"]

    J1 --> Audit
    J2 --> Audit
    JN --> Audit

    Supervisor --> Report["Fleet Batch Report (Merkle Aggregation)"]
```

* **Supervisor Ignorance Law:** The supervisor knows processes, pipes, and signals, but carries zero device-specific driver code.
* **Independent Child Drains:** Children handle signals locally and drain in-flight writes to disk independently ($P == C$).
* **Seam Verification:** The supervisor asserts that `constructed_argv_hash == child_journal_argv_hash`.

---

## Standalone Boot Environment

`diskCleaner` ships a self-contained bare-metal boot ISO:
* **PID-1 Architecture:** `dc` boots directly as `/init` with no shell (`/bin/sh`), no initramfs scripts, and zero daemon dependencies.
* **Self-Protection:** The boot medium (`BOOT_MEDIUM`) and active evidence sink (`EVIDENCE_SINK`) are protected by non-overridable Guardian rows.
* **Persistent Evidence Sink:** Probes and verifies evidence sinks before arming any destructive operation.
* **Hardware Unfreeze:** Executes RTC/S3 suspend dances to clear SATA BIOS freeze locks safely.

---

## Engineering Discipline & Testkit

The system is tested against an exhaustive verification lattice:
* **23 Red-Team Test Rigs (T1–T23):** Covering fault injection, crash recovery, Guardian trees, PRNG cleanroom, Opal SEDs, USB bridges, and Zoned SMR.
* **16 Founding Ceremonies:** Minting immutable golden vectors, certificates, and test corpora with documented provenance.
* **3 CI Lanes:** Pure (unprivileged mock suite), Root (loopback, null_blk, and kernel devices), and Scheduled (bare-metal silicon menagerie).
* **Reproducibility Triangle:** Proves `{x86-env-1, x86-cross-2, arm-native}` produce 100% byte-identical release binaries.
* **Dual Implementations:** Every cryptographic verifier, parser, and journal oracle is independently implemented in `dc-testkit` to eliminate self-judging bias.

---

## Standards & Compliance

* **NIST SP 800-88 Rev 1:** Guidelines for Media Sanitization (Clear, Purge, and Destroy).
* **IEEE 2883-2022:** Standard for Sanitizing Storage.
* **DoD 5220.22-M:** National Industrial Security Program Operating Manual (Legacy multi-pass overwrite).
* **RFC 8785 (JCS):** JSON Canonicalization Scheme.
* **RFC 8032:** Edwards-Curve Digital Signature Algorithm (Ed25519).
* **RFC 3161:** Internet X.509 Public Key Infrastructure Time-Stamp Protocol.
* **ISO 19005-3 (PDF/A-3):** Archival Document Format with Embedded Verifiable Payloads.

---

## License

Licensed under either of:
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
