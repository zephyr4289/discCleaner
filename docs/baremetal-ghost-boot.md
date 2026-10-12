# Ghost Boot — Bare-Metal Ring-0 Sanitization Payload
## (v0.12.0, Miracle 3 — `dc-baremetal`)

Even the leanest live Linux ISO is bloated: kernel, systemd or busybox,
kernel drivers, ACPI tables, rootfs mounts. If the target has corrupt
memory, bad firmware or an obscure bootloader bug, Linux will not
boot — and the wipe fails.

**Ghost Boot is a 100% pure-Rust bare-metal UEFI payload**: no kernel,
no drivers, no OS, no glibc. Release build: **~25 KB** (the budget was
300 KB).

## Build & deploy

```text
dc baremetal build                      # cargo build --target x86_64-unknown-uefi --features efi
dc baremetal deploy --device /dev/sdX   # copy to EFI/BOOT/BOOTX64.EFI on FAT32
# or directly:
scripts/build-ghost.sh
```

Boot the stick on any x86-64 UEFI machine. The payload runs and powers
the machine off (ACPI S5).

## What executes

1. **UEFI handoff** (`uefi.rs`): Graphics Output Protocol framebuffer,
   ACPI 2.0 RSDP from the configuration table, a 2 MiB
   AllocateMaxAddress DMA window below 4 GiB, `ExitBootServices`.
2. **PCIe scan** (`pci.rs`): config space via I/O ports 0xCF8/0xCFC,
   storage classes only (AHCI 01:06:01, NVMe 01:08:02), bus mastering
   enabled per function, BAR decode (32/64-bit, size probe).
3. **NVMe** (`nvme.rs`): full controller bring-up — admin queues,
   Identify, I/O queue pair, then **Format NVM with cryptographic
   erase** (the controller-side purge) **plus** a ChaCha20(RDRAND)
   full-namespace pattern pass via Write DMA.
4. **AHCI** (`ahci.rs`): HBA reset/enable, port spin-up + signature
   detect, command list/FIS setup, full-band 48-bit WRITE DMA EXT
   pattern passes.
5. **Framebuffer console** (`fb.rs`): 8×16 bitmap font, per-device
   progress bars. No font driver, no text mode — raw pixels.
6. **ACPI S5** (`acpi.rs`): RSDP → XSDT → FADT walk; PM1a
   SLP_TYP|SLP_EN write. No acpid, no userspace.

## Why shipping this is safe

* **Every hardware state machine is CI-tested.** All register access
  flows through two traits (`hal::PortIo`, `hal::Mmio`). The same
  driver code that toggles a real HBA's doorbell runs in CI against
  `hal::SimBus` — a register-accurate simulated bus with PCI
  config emulation, NVMe CC.EN→CSTS.RDY and doorbell→completion
  reactions, and AHCI write-1-to-clear interrupt semantics.
* **The payload never executes code from the target's disks.**
* **Entropy without an OS**: RDRAND (re-looped per the SDM) with a
  disclosed TSC fallback for CPUs lacking the instruction.
* The UEFI target build (`cargo check --target x86_64-unknown-uefi
  --features efi`) is part of the release checklist; the bin target
  is feature-gated so hosted CI never needs the toolchain.

## Documented v1 limitations

* SATA capacity discovery uses a 2^32-sector (≈2 TiB) write ceiling
  rather than IDENTIFY-parse sizing (v2: IDENTIFY DEVICE geometry).
* PCIe scan covers bus 0 (the root complex devices of every standard
  server); multi-bus enumeration behind bridges is v2.
* The payload renders and powers off; it does not yet produce a
  signed certificate artifact (no operator key ceremony exists in a
  kernel-less environment) — the on-screen summary + QR export is the
  v2 roadmap (reusing the dc-photon QR encoder).
