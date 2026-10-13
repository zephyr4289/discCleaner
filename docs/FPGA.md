# dc-fpga — Ghost Silicon: the RISC-V Open-Silicon Root of Destruction

> v0.13.0, Frontier 3. A pure-Rust `no_std` payload for open RISC-V
> softcores that intercepts storage lanes, sanitizes autonomously,
> and burns a **physical eFuse** on completion.

## The trust problem

Every software stack in this workspace — including the 24 KB Ghost
Boot — ultimately executes on proprietary silicon: x86 CPUs with
Intel ME / AMD PSP, ARM cores with TrustZone ROM, Ring -2/-3
microcode nobody outside the vendor has read. A decommission proof
that bottoms out in "trust the chip vendor" is a proof with a hole
in it.

## The answer: open silicon

Ghost Silicon is a **Hardware Security Interceptor**: a small
open-silicon device (RISC-V softcore on an open FPGA —
[NEORV32](https://github.com/stnolink/neorv32),
[VexRiscv](https://github.com/SpinalHDL/VexRiscv) — or an open BMC
service processor) that sits **directly on the target's PCIe/SATA
storage lanes**. It gates every transaction and runs the
sanitization state machine autonomously: no host CPU, no host OS,
no host firmware in the trust chain. The entire netlist is public
and reproducible from vendor-neutral toolchains.

## The state machine

```text
SELF-TEST ─▶ ENUMERATE ─▶ AWAIT-ARM ─▶ SANITIZE ─▶ VERIFY ─▶ CERTIFY ─▶ SEAL ─▶ HALT
     │            │            │            │           │          │
     └────────────┴────────────┴────────────┴───────────┴──────────┴──▶ FAULT
                                                        (never burns COMPLETE)
```

| State | What happens |
|-------|--------------|
| **SELF-TEST** | Register-path integrity, fuse-word sanity (an already-sealed board refuses to run), lane-present plausibility |
| **ENUMERATE** | Passive IDENTIFY per lane — the inventory the run is accountable for |
| **AWAIT-ARM** | Operator consent: the physical ARM button latches a magic register; **there is no software path** to it |
| **SANITIZE** | Gate every present lane (host held in electrical idle), block-erase the full window set, apply the final pattern |
| **VERIFY** | Full readback per lane; any residue word or read failure blocks completion |
| **CERTIFY** | FNV-1a word-chain transcript digest over every lane's verified readback |
| **SEAL** | Burn per-target fuses + VERIFIED + COMPLETE, latch the lane gate closed |
| **FAULT** | Burn ONLY the fault fuse and latch: bricked for storage reuse, readable as *failed — inspect* |

## The eFuse bank

One-way metal links — microscopically visible, forgeable by no
software on any die, confirmable decades later with a microscope,
powered or not.

| bits | meaning |
|------|---------|
| 0..=27 | per-target completion fuse (one per enumerated lane) |
| 28 | FAULT — the run ended in the fault path |
| 29 | VERIFIED — self-verification passed |
| 30 | COMPLETE — the root of destruction ran to the end |
| 31 | reserved (never burnable) |

`completed = COMPLETE ∧ ¬FAULT`: a board that faulted — even if
buggy code blew both — never reads as done.

## The lane gate

```text
BYPASS  traffic flows host ↔ target untouched (normal operation)
GATED   the payload drives the target directly; the host side is
        held in hot-reset / electrical idle — it cannot observe
        or inject anything
LATCHED one-way after completion: every write transaction is
        refused at the gate; the read-only audit path stays up
```

## The payload

~5 KB (`--profile ghost`: opt-level=z, LTO, panic=abort,
codegen-units=1), `riscv32imc-unknown-none-elf`, zero dependencies
— core + compiler_builtins only, exactly like Ghost Boot. Naked
`_start` sets SP over a 16 KiB boot stack, calls `rust_main`, parks
in `wfi` after the terminal state.

```console
$ rustup target add riscv32imc-unknown-none-elf
$ cargo build -p dc-fpga --target riscv32imc-unknown-none-elf \
              --profile ghost --features silicon
$ ls -l target/riscv32imc-unknown-none-elf/ghost/dc-ghost-silicon
```

Board map (port by overriding the constants in
`src/bin/ghost_silicon.rs`): interceptor MMIO bank at
`0x4000_0000`, UART16550-compatible console at `0x4001_0000`.

## CI: every state machine tested against SimBoard

All register access flows through the `Mmio` trait — the identical
code drives a real SoC (via `RealMmio`) and the deterministic
`SimBoard` virtual softcore in unit tests: gate refusals (ungated
commands rejected, latched writes refused forever), fuse one-way
semantics, happy-path seals, fault paths (tampered target, missing
target, disarmed board), pattern verification, transcript
determinism and content-binding.

```console
$ dc fpga simulate --lanes 3
[FPGA] SELF-TEST → ... → SEAL → HALT
[FPGA] eFuse word         : 0x60000007
[FPGA] ROOT OF DESTRUCTION COMPLETE — silicon-level proof burned
```

## Threat model

1. **Host-side malware / compromised OS** — the target host is
   hostile from the first clock; the gate holds it in electrical
   idle and the payload has no code-loading interface at all.
2. **Closed Ring -2/-3 microcode** — none executes on an open RTL
   softcore.
3. **Premature completion claims** — the COMPLETE fuse burns only
   after every enumerated target passed readback verification.
4. **Re-use of a "wiped" board** — LATCHED refuses every later
   write; the blown-fuse board remains auditable but never quietly
   re-serviceable as clean storage.
