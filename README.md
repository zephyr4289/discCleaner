# diskCleaner (`dc`)

> **Military-Grade Storage Sanitization & Forensic Verification Suite**
> Engineered strictly according to **NIST SP 800-88 Rev 1**, **IEEE 2883-2022**, and **DoD 5220.22-M** standards with deterministic cryptographic verification and tamper-evident audit logs.

---

## Architectural Overview

`diskcleaner` is built as a modular 6-crate Rust workspace designed for bare-metal, initramfs, and CI-driven forensic deployments without external runtime binary dependencies.

```
diskcleaner/
├── crates/
│   ├── dc-core/       # Domain models, SanitizationPlan, FSM, Hash-Chained Journal (DCJ1), AuditLog
│   ├── dc-probe/      # Sysfs/proc inventory scanner, Layer-Stack resolver, 15-Rule Guardian
│   ├── dc-io/         # Engine trait, UringEngine (io_uring), SyncEngine (O_DIRECT), Pinned Buffer Pool
│   ├── dc-verify/     # StreamVerifier, Shannon Entropy (H) & Chi-Square (χ²) diagnostics, BLAKE3/SHA256
│   ├── dc-cert/       # SanitizationCertificate (RFC 8785 JCS Canonicalization + Ed25519 signing)
│   └── dc-cli/        # High-performance CLI binary (diskcleaner / dc)
```

---

## Key Systems Engineering Features

### 1. Incorruptible Hardware Guardian (15-Rule Matrix)
- **Zero Accidental Wipes:** Intercepts mounted partitions (`/proc/self/mountinfo`), active swap (`/proc/swaps`), LVM physical volumes, dm-crypt containers, and software RAID members (`/proc/mdstat`).
- **TOCTOU Elimination:** Opens target block devices once via `(major, minor)` and holds exclusive `flock(LOCK_EX | LOCK_NB)` across both the drive and all child partition nodes.
- **Two-Step System Disk Override:** Refuses active OS disks (`/`, `/boot`, `/usr`) unless explicitly unlocked with `--allow-system-disk --serial-confirm <SERIAL>`.

### 2. High-Throughput I/O Engine (`io_uring` + Direct I/O)
- **Page-Aligned Memory Pooling:** 4096-byte page-locked memory allocations pinned with `libc::mlock` and `MADV_HUGEPAGE`.
- **Zero-Allocation Fixed Passes:** Reuses a single immutable registered 2 MiB memory buffer across all Submission Queue Entries (SQEs) for zero host memory traffic.
- **`BLKZEROOUT` Fast Path:** Offloads zeroing directly to storage controllers at physical NAND/platter line speed.

### 3. Defensible Cryptographic Verification (`ChaCha20WindowV1`)
- **Deterministic-Random PRNG Verification:** Overwrites sectors with a deterministic ChaCha20 keystream (`key = seed`, `nonce = window_index`).
- **$O(1)$ Memory Full Verification:** Third-party auditors can mathematically verify any sector of a 20 TB drive with zero storage overhead by re-deriving the keystream.
- **Tamper-Evident Journaling (`DCJ1`):** Every window commit is hash-chained (`record_hash = BLAKE3(record || prev_hash)`).

### 4. Tamper-Proof Digital Certificates
- Formatted as canonical JSON under **RFC 8785 (JCS)**.
- Cryptographically signed with **Ed25519** digital signatures.

---

## CLI Usage

### 1. Inventory Device Scan (Read-Only)
```bash
dc list
```

### 2. Generate Sanitization Plan (Dry Run)
```bash
dc plan --target /dev/nvme0n1 --profile clear-zero
```

### 3. Execute Certified Sanitization Pass
```bash
# Interactive confirmation via drive serial number entry:
sudo dc execute --target /dev/nvme0n1 --profile clear-zero --out-dir /var/log/sanitization

# Scripted execution with explicit key and serial confirmation:
sudo dc execute --target /dev/nvme0n1 --profile clear-random --key /path/to/operator.key --serial-confirm "S6B0NJ0W102938X"
```

### 4. Inspect & Verify Certificate Signature
```bash
dc cert verify /var/log/sanitization/S6B0NJ0W102938X-2026-08-28.cert.json
```

### 5. Generate Operator Ed25519 Signing Keypair
```bash
dc keygen --out operator.key
```

---

## Standards Compliance

- **NIST SP 800-88 Rev 1:** Clear (Logical Overwrite), Purge (Firmware Erase readiness)
- **IEEE 2883-2022:** Standard for Sanitizing Storage
- **DoD 5220.22-M:** 3-Pass Overwrite with Legacy Compliance Note
- **RFC 8785 (JCS):** JSON Canonicalization Scheme for Digital Signatures
