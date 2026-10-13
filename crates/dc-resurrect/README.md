# dc-resurrect

**Forensic Autonomous Self-Assembling Kernel for Dead / Damaged Silicon** — PR16 of the `discCleaner` suite.

Every sanitization tool in existence — including everything else in `dc` — assumes the drive's firmware and main controller are alive and answering PCIe/SATA handshakes. In the real world, half the decommissioned drives in data centers and military bases are **bricked**:

- the SPI flash firmware corrupted during a brownout,
- the controller's internal ARM Cortex-R4 crashed into a HardFault loop,
- the PCB power path has a blown TVS diode,
- or the vendor's debug bridges are locked.

Because the controller is dead, sysadmins have no choice but to feed the drive into an industrial shredder. **dc-resurrect is the alternative**: it speaks to the corpse over the pins that survive — raw JTAG, SWD and the UART Boot-ROMs that Marvell, Silicon Motion, Phison and Samsung mask into their silicon — injects a microscopic, *self-assembled*, RAM-resident Rust nucleus into the controller's SRAM, takes over the raw NAND flash controller from the inside of the chip, executes physical die-level erase, verifies every block, and emits a Merkle-proof-of-erasure receipt. Shredder quote avoided: ~$975/drive.

```
scan     -> what answers on UART / SWD / JTAG? (bench power if Class C)
triage   -> failure class + resurrection route
assemble -> stage-1 probe nucleus; run it; parse the REAL ONFI geometry
           from the drive itself; stage-2 kernel assembled FOR that silicon
inject   -> BROM download or MEM-AP writes, then JUMP
execute  -> autonomous kernel: erase, retry marginal blocks, verify
           pages read back erased, CRC-32 attestations, heartbeat, park
collect  -> mailbox readback over the same debug link
prove    -> one Merkle leaf per block, no gaps; .drz receipt; offline verify
```

## Failure taxonomy and routes

| Class | Cause | Route |
|-------|-------|-------|
| A | firmware corruption, BROM strapped in | UART Boot-ROM download |
| B | Cortex-R4 HardFault / lockup loop | SWD (ADIv5) halt + MEM-AP SRAM writes |
| C | blown TVS diode / dead rails | rig bench power, then A |
| D | vendor debug lockdown | IEEE 1149.1 EXTEST pin takeover of the NAND bus |
| X | beyond debug silicon | physical destruction (honest failure) |

Class D is the endgame: when the debug ports fault and even the JTAG-DP feeds junk, the TAP and its boundary-scan register still answer — so the rig drives CLE/ALE/nCE/nWE/nRE/DQ[7:0] directly through the BSR, no CPU required. Every command byte costs two BSR shifts and every data byte three; the cost model prints the wall-clock estimate. It works on a corpse. It is also the reason the injection routes exist — the in-silicon kernel does the same work orders of magnitude faster.

## The self-assembling nucleus

No static binary ships. At injection time the host:

1. emits a handful of well-understood 16-bit **Thumb instructions** (the portable subset every ARM7TDMI, Cortex-R and Cortex-M core decodes) from a nucleus library of code fragments;
2. patches **literal pools** and **label fixups** against the actual controller profile, the ONFI geometry the stage-1 probe discovered *on the drive*, and the chosen verify strategy — geometry becomes instruction immediates;
3. links the fragments through a host-patched **HLP_\* table** (a tiny PLT) plus a VARS parameter block, producing one position-fixed SRAM image with a SHA-256 manifest.

Stage 1 is a ~100-instruction probe that talks to NAND die 0 over the controller's register block and pulls the READ-ID word plus the ONFI parameter page into an SRAM mailbox. Stage 2 is the autonomous erase kernel: it builds its own CRC-32 table in SRAM (no host tables), erases every block of every die, retries marginal blocks up to three times, verifies pages read back as `0xFF` while streaming a CRC-32 of the readback, writes one attestation record per block into the mailbox, heartbeats progress over the UART register when one exists, and parks in a WFI loop. No host babysitting: the operator may disconnect after injection.

The `sim/` module contains a **reference Thumb core** that fetches and decodes the real machine code from simulated SRAM — the payload is not interpreted abstractly. If the assembler emits garbage, that core HardFaults exactly like the silicon would: the same disease this tool exists to cure. The full-scale Class A mission runs 54.7 million real instructions through it.

## Proof of erasure

One Merkle leaf per addressed block, **no gaps**: every block of every die appears exactly once — erased (with CRC-32 of the verified page stream), skipped (factory bad marker re-read after erase setup), failed after retries, or the whole die reported as ID-mismatched. SHA-256 over canonical records, duplicate-last on odd levels, sampled inclusion proofs, all serialized into a human-readable `.drz` file:

```
$ dc-resurrect verify proof-class-a.drz
PROOF OK
  controller   : marvell-88ss1077
  merkle root  : f749290a6f6540e1...
  leaves       : 1024 rehashed, preimages verified
  inclusions   : 8 verified
  blocks       : 1024 total / 1020 erased / 4 skipped / 0 failed
  payload sha  : 56dc7d748b6a102a...
```

Trust model, stated plainly: the root of trust is the SHA-256 of the injected payload recorded in the file. The proof demonstrates *the kernel whose hash is printed here ran, and it attested every block of this geometry*. Reviewing the nucleus is reviewing the proof.

## Transports, implemented at bit level

- **JTAG (IEEE 1149.1)**: full 16-state TAP controller, chain discovery by IDCODE scan, IR/DR shifting LSB-first, and the 35-bit DPACC/APACC transactions of the ARM JTAG-DP with posted reads through RDBUFF.
- **SWD (ADIv5)**: request packets with parity, OK/WAIT/FAULT acks, posted AP reads, turnarounds as first-class events, line-reset detection (≥50 high clocks), and the JTAG↔SWD switch magic `0xE79E` — including the TLR path back to JTAG.
- **UART Boot-ROM**: auto-baud, magic HELLO with CRC16-XMODEM echo, HMAC-SHA256 challenge/response for vendors that gate the shell (Phison model), CRC-checked chunked download, memory PEEK/POKE, JUMP, and nucleus heartbeat telemetry frames.
- **MEM-AP**: power-up handshake, bank-select, CSW/TAR/DRW with auto-increment windows.

The simulator implements the *device* side of each protocol at the same granularity the hardware sees — the same engine bits that would talk to a real brick over an FTDI rig. Scenarios make the drive *usefully dead* before resurrection: brownout-corrupted firmware, HardFault lockup with the strap not asserted, dead rails until bench power, and vendor debug lock (SWD AP faults, JTAG-DP junk, EXTEST still alive). The NAND model carries seeded forensic-looking data, factory bad blocks, and marginal blocks that fail erase once or twice before succeeding — the decade-old-drive wear pattern.

## Usage

```
dc-resurrect demo [--scenario firmware|hardfault|tvn|lockdown] [--vendor NAME]
                  [--verify off|sampled|full] [--seed HEX] [--stuck DIE:BLOCK]
                  [--out proof.drz] [--compact]
                  [--blocks N] [--ppb N] [--bytes N] [--luns N]
dc-resurrect verify <proof.drz>
dc-resurrect inspect-payload        assemble + disassemble the nucleus
dc-resurrect vendors                list built-in controller profiles
```

Example — resurrect a hardfault-locked SM2262EN:

```
$ dc-resurrect demo --scenario hardfault --vendor siliconmotion-sm2262en
[SCAN]  SWD DPIDR 0x2ba01477 — debug port alive
[SCAN]  MEM-AP IDR 0x24770011 — memory access port open
[TRIAGE] B — core fault / lockup (debug port alive) — route: SWD (ARM ADIv5)
[SWD]    core halted (was fault-looped) — taking SRAM
[INJECT] stage-1 probe: 4224 B into SRAM via MEM-AP, core released
[PROBE]  READ-ID 0x3294de98 | ONFI: 2048 B/page, 64 ppb, 512 blk/LUN, 2 LUN
[INJECT] stage-2 kernel: 8192 B — autonomous erase begins
[EXEC]  park: 1024 total | 1020 erased | 4 skipped | 0 failed
[PROOF] verify: OK (1024 leaves rehashed, 8 inclusion proofs checked)
[RIG]   chip resurrected: 1020 erased / 4 skipped-bad / 0 failed
```

## Rig hardware (real-world bring-up)

The `hal` module defines three transport traits (`JtagLink`, `SwdLink`, `UartLink`) plus `RigPower` for Class C bench power. An FT232H-class adapter in MPSSE mode or a `gpiod` character device implements them; this build ships the bit-level simulator so the entire stack — including the injected machine code — is exercised end-to-end on a desk. Vendor profiles (SRAM windows, NAND controller MMIO blocks, BROM grammar, BSR length) come from `vendors/*.toml` (TOML-lite, editable on the bench) with four built-in reference families:

| Profile | Core | Transports | BROM auth |
|---------|------|-----------|-----------|
| marvell-88ss1077 | Cortex-R4 | JTAG + BROM UART | no |
| siliconmotion-sm2262en | Cortex-R5 ×2 | SWD + JTAG + BROM | no |
| phison-ps5012 | Cortex-R5 | SWD + JTAG + BROM | **yes** (HMAC challenge) |
| samsung-pascal | Cortex-R4 ×3 | JTAG + BROM | no |

## Modeling-gap ledger (honesty section)

The simulator is a *reference model*, and these are the deltas between it and bench reality:

- IDCODE/DPIDR values use public ARM JTAG-DP/SW-DP reference constants; production parts vary by family and fuse lot. The profile database is the override point.
- The JTAG-DP 35-bit scan packing follows the modeled convention (request bits LSB-first, then data); ADIv5-conformant, but verify against the target TRM before relying on it with a live brick.
- The BROM grammar (autobaud byte, magic, auth, chunking) is the modeled superset — each vendor's actual shell differs in incantation, not in concept.
- On SWD WAIT during a *write* data phase, this model terminates the packet; the DP spec has the host complete the phase. The FTDI driver owns that policy on real hardware.
- The reference core implements exactly the nucleus ISA subset; a payload opcode outside it HardFaults (correctly).

## Status

```
cargo test    # 55 tests: 41 unit + 8 end-to-end missions + 6 protocol
```

All four failure classes complete at full scale (1024 blocks, 2 dies): erase, marginal-block retry, sampled/full page verification, Merkle proof generation and offline verification, tamper rejection, stuck-block accounting, and post-mission medium checks (every non-bad page reads back `0xFF`).

## Legal

For authorized data-at-rest destruction on hardware you own or are contracted to decommission. Erasure is irreversible; the proof file is the only thing you get to keep.
