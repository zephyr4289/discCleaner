# CXL Type 3 Memory Sanitization (`dc cxl`)

> v0.11.0 · Frontier 2 — CXL 2.0/3.0 Memory Device Mailbox, PCIe 5.0/6.0

Modern hyperscaler AI clusters and enterprise in-memory databases (SAP HANA,
LLM inference caches) hold secrets in **CXL Type 3 Persistent Memory and
Memory Expanders** sitting directly on the PCIe bus. When a server reboots or
is reassigned, sensitive weights and database pages linger in non-volatile
CXL RAM. Neither `dd` nor standard NVMe commands can touch this memory —
it is not a block device; its lifecycle is governed by the **CXL Memory Device
Mailbox**.

```
$ dc cxl list
MEMDEV   PCI BDF             MEDIA SIZE  REGISTER BLOCK
mem0     0000:41:00.0           256 GiB  /sys/bus/pci/devices/0000:41:00.0/resource1

$ dc cxl sanitize mem0 --evidence-out cxl-evidence.json
command:        sanitize (opcode 0x4400)
device:         mem0
serial:         4d4f434b43584c31...
return code:    0x0000 (Success)
media verified: 64 windows sampled, all zero: true
progress:       187 samples, completed in 41203 ms
regs pre-hash:  349d65e9ba1de7b0...
evidence:       cxl-evidence.json

$ dc cxl erase mem0          # foreground cryptographic erase (0x4401)
```

## Command set

| subcommand | opcode | semantics |
|------------|--------|-----------|
| `dc cxl list` | — | enumerate `/sys/bus/cxl/devices/mem*` with PCI context |
| `dc cxl status mem0` | 0x4000 / 0x4500 | Identify + security state report |
| `dc cxl sanitize mem0` | **0x4400** | background overwrite of ALL media (NIST SP 800-88 Purge-equivalent for CXL media) |
| `dc cxl erase mem0` | **0x4401** | foreground cryptographic erase of user data |

Every subcommand takes `--mock` to run against the built-in Type 3 simulator
(operator drills, CI — the same discipline as the TPM and fabric layers).

## Evidence: what lands in the certificate

The `CxlSanitizeEvidence` extension (signature-covered like every other
certificate field) binds:

* **the executing hardware** — SHA-256 of the device register block observed
  before and after the command (component register hashes), plus the Identify
  payload digest and serial;
* **the command** — opcode, final mailbox return code, and the full
  background progress telemetry (elapsed-ms / percent-complete samples);
* **the post-condition** — a deterministic sampled read-back of the mapped
  media (up to 64 × 4-KiB windows evenly spaced, plus a full digest for
  media ≤ 1 MiB) proving the observable all-zero post-condition.

## Register layout governance

Every hardware offset lives in `crates/dc-cxl/src/regs.rs` with its
specification citation (mailbox at device-register-block offset 0x8880;
Command register opcode [15:0] / payload length [40:32]; Status bit 0 = busy
with the return code at [31:16] — a layout choice that keeps odd return codes
like 0x0b unambiguous; Background Command Status percent at [23:16]).
If a future CXL revision moves a register, `regs.rs` is the single
correction point — the protocol engine is layout-agnostic.

## Discovery path

1. `/sys/bus/cxl/devices/mem*/devtype` = `cxl_mem_device` (kernel cxl_mem
   driver).
2. The memdev's `device` symlink resolves the backing PCI function (BDF).
3. The PCI config space is parsed for the **CXL DVSEC** (PCIe extended
   capability 0x23, vendor 0x1E98) — DVSEC ID 0 carries the Register Block
   Locator (BAR index + offset of the device register block).
4. The register block is mmap'd from the BAR's sysfs `resourceN` file and all
   mailbox traffic runs through volatile MMIO accessors.

## Verification posture

The mock device simulates the full protocol — including background progress
telemetry and a fault-injection mode (`sanitize_leaves_media`) where the
device *claims* success but leaves data behind: the sampled read-back must
catch it, and a test pins that it does. The production MMIO path currently
reports media verification through the controller's sanitize status plus the
sampled read-back where a mapped media window exists (HDM-decoded region
integration is the natural follow-up for devices that expose it).
