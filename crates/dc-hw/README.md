# dc-hw — Pure Hardware Protocol Codecs (NVMe / ATA-SAT / SCSI)

`dc-hw` translates between Rust types and the wire formats of the storage
protocols used for purges. It is **pure**: no syscalls, no devices, no
globals — only encode/decode functions over byte buffers, plus the spec
citations that justify every bit position.

## Why encoding correctness is a safety property

A wrong CDB byte does not merely fail — it can hang a target (e.g. FORMAT
UNIT with FMTDATA=1 obligates a parameter list nobody sends), silently
misreport completion (sanitize progress), or mis-frame an ATA command so the
HBA waits on a data phase that never comes. Every encoder here is paired
with a unit test that pins its bit layout.

## Module map

- `nvme_codec.rs` — Format NVM (SES occupies CDW10 bits 10:09 — verified
  against QEMU's NVMe emulation and the Linux kernel), Sanitize, Get Log
  Page 0x81, identify controller/namespace, SMART/health decoding
- `ata_codec.rs` — IDENTIFY DEVICE decoding (word 128 security status,
  NUL-and-space padded string handling) and SAT ATA PASS-THROUGH(16) with
  **explicit `SatTransferClass` framing** (`None` / `DataIn` / `DataOut`).
  SECURITY ERASE PREPARE/UNIT/FREEZE LOCK encoders are provided as non-data
  commands — the historical single-framing encoder claimed PIO data-in
  transfers for everything, which is how non-data commands hang HBAs.
- `scsi_codec.rs` — SANITIZE, FORMAT UNIT (FMTDATA never set without a
  parameter list), REQUEST SENSE, fixed/descriptor sense decoding with
  SKSV progress (round-half-up permille).
- `tables.rs` — spec citation constants (SPC-4, SBC-3, NVMe Base, ATA8-ACS).
- `raw.rs` — `RawBlob<T>`: decoded value + raw bytes + BLAKE3, for keeping
  the original evidence next to every interpretation.

## Testing

`cargo test -p dc-hw --lib` — 12 unit tests pinning SAT protocol codes,
SECURITY ERASE opcodes (0xF3/0xF4/0xF5) and the enhanced-erase FEATURES bit,
NUL-padded ATA strings, SES bit positions, sanitize-progress rounding
(SPROG=0xFFFF → 1000 permille, not 999), and FMTDATA/IMMED layout.

## Dependency policy

serde/serde_json/thiserror/hex/blake3 only. No libc, no I/O — codecs are
pure functions and stay that way.
