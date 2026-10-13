# dc-wear — Silicon-Level Analog Flash Degradation Analysis & Charge Bleed

> v0.13.0, Frontier 2. Prove the flash **physically** underwent
> high-voltage erasure — evidence the controller cannot fake with
> silent remaps.

## The doubt

After a 3-pass NIST 800-88 Clear, an auditor asks: *"did the flash
controller ACTUALLY erase the cells — or did it silently remap bad
blocks, keep the original charge states, and tell the software what
it wanted to hear?"* Software readback cannot answer: the FTL owns
the mapping, and a firmware lie is invisible to a lie detector that
runs on top of the same firmware.

dc-wear measures the **physics** instead of the firmware.

## The evidence stack

### 1. Fowler-Nordheim tunneling ledger (`tunnel.rs`)

NAND erasure raises the substrate to ~+20 V and electrons leave
the floating gate by quantum tunneling through the ~7–8 nm oxide:

```text
J = A_FN · F² · exp(−B_FN / F)     A_FN = 1.25e-6 A·cm⁻²·(MV/cm)⁻², B_FN = 253 MV/cm
Q_inj = Σ_pulses J(F_p) · t_p       [C/cm² — the oxide endurance metric]
```

Every real erase pulse injects charge THROUGH the dielectric. An
FTL that books erasures without pulses books zero charge — the
ledger cannot be satisfied by bookkeeping alone, because wearing
the oxide and erasing the cell are the **same current**.

**Calibration note (documented, not hidden):** the per-cell electron
count is anchored to the textbook SLC erase window (~2.5×10³
electrons per standard 10.5 MV/cm / 1 ms pulse) because the
effective tunnel area per cell is process-secret. The area-side
`Q_inj` ledger stays first-principles. The **charge-bleed
consistency check** divides the ledger's supplied charge by the
charge the observed ΔVth implies (`ΔQ = C_fg·ΔVth`); a ratio < 1.0
means the observed shift cannot be explained by the campaign's
pulses — physically impossible for an honest run, so the
certificate refuses.

### 2. Threshold-voltage shift (`vth.rs`)

Trapped charge screens the floating gate: the erased-Vth population
walks positive and smears. The wear law:

```text
ΔVth(N) = ΔV₀ · N^α        ΔV₀ = 40 mV, α = 0.35 (tunnel-oxide trapping)
σ(N)    = σ₀ · (1 + w·√N)  widening
```

Per-cell Vth is not directly visible to software, but the
controller's own **read-retry** compensation is: retries per 1 000
reads map monotonically to distribution overlap, and the estimator
inverts that to a ΔVth and an implied P/E cycle count.

### 3. Program-latency statistics (`latency.rs`)

Worn cells need more ISPP steps and erase-verify retries. The host
measures operation timing at nanosecond resolution; the Welch-t
separation between a fresh baseline and the stressed population is
a wear signature the FTL cannot hide without faking its own
wall-clock. Sub-microsecond variance growth (CV) is tracked
explicitly.

### 4. RBER power law (`ber.rs`)

```text
RBER(N) = r₀ + a·(N/N_end)^b      r₀ = 1e-6, a = 3e-4, b = 2, N_end = 100k
```

Fresh-looking RBER on a supposedly cycled channel is FTL-shortcut
evidence; `looks_fresh(errors, bits)` applies a sample-size-aware
band over the floor.

## The Silicon Wear Certificate

Per channel, three verdicts:

1. **F-N charge present** — non-zero injected charge integral;
2. **Charge-bleed consistency** — observed ΔVth covered by the
   ledger (`supplied/needed ≥ 1`);
3. **Statistical stress signature** — latency separation ≥ 3σ
   (Welch t) *or* retry-implied cycles ≥ 50.

And one fleet-level assertion: **100 % channel coverage.** A
single silently-retired die (controller remap lie) fails the whole
certificate. Integrity and coverage are separate questions: an
honest *failure* still verifies as a document — the auditor sees
exactly which channels lacked evidence.

The body is BLAKE3-digest-bound (`dc-wear-cert/1`); any field flip
breaks verification. Sign the digest with the existing hybrid
Ed25519 + ML-DSA machinery for the full chain of custody.

## Operation

```console
$ dc wear simulate --device-id SN-XYZ --cycles 3000 --out wear-cert.json
ch | dies | pulses | Q_inj min | dVth max | cons. min | t min | cycles | verdict
 0 |    4 |  12000 | 1.42e-14 |    0.345 |    3483.3 |  40.9 |    369 | PASS
 ...
[WEAR] SILICON WEAR CERTIFICATE: VERIFIED

$ dc wear verify --cert wear-cert.json
[WEAR] VERIFIED — digest covers the body, verdicts recompute, coverage closes
```

## Real-device backends

The measurement interface is the `NandProbe` trait
(erase/program pulse → latency + verify errors + retries). The
deterministic `SimNand` physics backend powers CI and `dc wear
simulate`; real backends implement the same contract over
dc-nvme/dc-ata passthrough timing and vendor log pages — the
campaign arithmetic is identical either way.

## Testing

32 tests: FN law shape and anchors, ledger linearity, consistency
bounds (absurd shifts refused, untouched channels refused), wear-law
round-trip, retry-rate monotonicity, RBER round-trip, freshness
band, campaign coverage, worn-vs-fresh statistics, certificate
assembly/tamper/missing-channel/round-trip/determinism.
