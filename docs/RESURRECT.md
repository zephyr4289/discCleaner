# dc-resurrect — Forensic Autonomous Self-Assembling Kernel for Dead / Damaged Silicon

> v0.15.0. Resurrect **bricked** drives over the debug pins that
> survive — raw JTAG, SWD and vendor UART Boot-ROMs — inject a
> RAM-resident pure-Rust micro-firmware nucleus straight into
> controller SRAM, take over the raw NAND controller from inside
> the chip, execute die-level erase, and prove it — no $100k
> industrial shredder.

## The myth

*"The drive is bricked, shred it."* Every sanitization tool in
existence — including everything else in `dc` — assumes the
drive's firmware and main controller are alive and answering
PCIe/SATA handshakes. In the real world, half the decommissioned
drives in data centers and military bases are **dead**:

* the SPI flash firmware corrupted during a brownout,
* the controller's ARM Cortex-R4 crashed into a HardFault loop,
* the PCB power path has a blown TVS diode,
* or the vendor's debug bridges are locked.

Because nothing answers on the bus, the operator's only sanctioned
option is the industrial shredder — ~$975 a drive, a queue, and an
audit trail that says "destroyed, trust us". dc-resurrect is the
alternative: it talks to the corpse over the pins that survive,
erases the silicon from the inside, and emits a Merkle proof that
every block is gone.

## The weapon stack

### 1. Failure taxonomy and routing (`failure.rs`)

| Class | Cause | Resurrection route |
|-------|-------|---------------------|
| A | firmware corruption, BROM strapped in | UART Boot-ROM download |
| B | Cortex-R4 HardFault / lockup loop | SWD (ADIv5) halt + MEM-AP SRAM writes |
| C | blown TVS diode / dead rails | rig bench power, then A |
| D | vendor debug lockdown | IEEE 1149.1 EXTEST pin takeover of the NAND bus |
| X | beyond debug silicon | physical destruction (honest failure) |

The scan phase probes UART / SWD / JTAG in order, applies bench
power if the rails are dead, and classifies with evidence lines
that end up in the mission log.

### 2. Bit-level debug transports

* **JTAG (IEEE 1149.1)** — the full 16-state TAP controller,
  chain discovery by IDCODE scan, LSB-first IR/DR shifting, and
  35-bit DPACC/APACC transactions with posted reads through
  RDBUFF. IR-preserving routes keep EXTEST sessions alive between
  scans.
* **SWD (ADIv5)** — request packets with parity, OK/WAIT/FAULT
  acks with retry and sticky-fault clear, posted AP reads,
  turnarounds as first-class link events, line reset (≥50 highs),
  and the JTAG↔SWD switch magic `0xE79E` in both directions.
* **UART Boot-ROM** — auto-baud, magic HELLO with CRC16-XMODEM
  echo, HMAC-SHA256 challenge/response for vendors that gate the
  shell (Phison model), CRC-checked chunked download with NAK
  retry, memory PEEK/POKE, JUMP, and nucleus heartbeat frames.
* **MEM-AP** — power-up handshake, bank select, CSW/TAR/DRW with
  1 KiB auto-increment windows.

### 3. The self-assembling nucleus (`payload/`)

No static binary ships. At injection time the host emits 16-bit
**Thumb instructions** (the portable subset every ARM7TDMI,
Cortex-R and Cortex-M core decodes) from a library of code
fragments, patches **literal pools** and **label fixups** against
the actual controller profile *and* the ONFI geometry the stage-1
probe discovered **on the drive**, and links the fragments through
a host-patched HLP_\* table (a tiny PLT) plus a VARS parameter
block — one position-fixed SRAM image with a SHA-256 manifest.

* **Stage 1** is a ~100-instruction probe that talks to NAND die 0
  over the controller's register block and pulls READ-ID plus the
  ONFI parameter page into an SRAM mailbox.
* **Stage 2** is the autonomous erase kernel: it builds its own
  CRC-32 table in SRAM, erases every block of every die, retries
  marginal blocks up to three times, verifies pages read back as
  `0xFF` while streaming a CRC-32 of the readback, writes one
  attestation record per block into the mailbox, heartbeats
  progress, and parks in WFI. The operator may disconnect after
  injection.

### 4. The reference core (`sim/`)

The simulator implements a **reference Thumb interpreter** that
fetches and decodes the real machine code from simulated SRAM —
the payload is not interpreted abstractly; if the assembler emits
garbage, the reference core HardFaults exactly like the silicon
would. The full-scale Class A mission runs **54.7 million real
instructions** through it. The device side (TAP state machine, SWD
decoder, BROM shell, DP/AP register file with locked-AP FAULT
model, NAND controller with R/nB timing and DQ hold) is simulated
at the same granularity the hardware sees — the same engine bits
that would talk to a real brick over an FTDI rig.

Class D is the endgame: when the debug ports fault and even the
JTAG-DP feeds junk, the TAP and its boundary-scan register still
answer — so the rig drives CLE/ALE/nCE/nWE/nRE/DQ[7:0] directly
through the BSR, no CPU required, erase and verify included.

## The certificate

One Merkle leaf per addressed block, **no gaps**: every block of
every die appears exactly once — erased (with CRC-32 of the
verified page stream), skipped (factory bad marker re-read after
erase setup), failed after retries, or the whole die reported as
ID-mismatched. SHA-256 over canonical records, duplicate-last on
odd levels, sampled inclusion proofs, all serialized into a
human-readable `.drz` file that the CLI verifies offline. The
trust anchor is the SHA-256 of the injected payload recorded in
the file: *the kernel whose hash is printed here ran, and it
attested every block of this geometry*. Reviewing the nucleus is
reviewing the proof.

## Rig honesty

The `hal` module defines the transport traits (`JtagLink`,
`SwdLink`, `UartLink`, `RigPower`); an FT232H-class adapter in
MPSSE mode or a `gpiod` character device is the real-hardware
bring-up point. This release ships the bit-level simulator so the
entire stack — including the injected machine code — is exercised
end-to-end on a desk. Known modeling deltas: IDCODE/DPIDR use
public ARM reference constants (the profile database is the
override point); the BROM grammar is the modeled superset (vendors
differ in incantation, not concept); on SWD WAIT during a write
data phase the model terminates the packet while the DP spec has
the host complete the phase — the FTDI driver owns that policy on
real hardware.

## Threat model

Authorized data-at-rest destruction on hardware you own or are
contracted to decommission. The adversary is post-decommission
forensics on the NAND die itself; the defense is physical
erase of every block with per-block attestation. The proof file
cannot attest silicon the rig never reached — Class X failures
are reported as failures, never papered over. Erasure is
irreversible; the `.drz` receipt is the only thing you get to
keep.
