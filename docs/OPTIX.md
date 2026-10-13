# dc-optix — Sub-Surface Optical Disk Laser Photobleaching & Phase-Change Destruction

> v0.14.0, Breakthrough 3. Turn a commodity optical drive into a
> **self-contained physical incinerator** for WORM media — no
> shredders, no furnaces, evidence in the tray.

## The myth

*"WORM media (Archival Blu-Ray, M-DISC, CD-R, DVD-R) can only be
destroyed by physical shredding or incineration."* The recording
layer — organic dye, inorganic phase-change alloy, glassy carbon —
is chemically unmodifiable through standard OS write commands.
But it is a thin film sitting a few hundred microns from a
precision-stabilized laser: the drive's **own optical pickup**.

## The weapon stack

### 1. MMC vendor diagnostics (`mmc.rs`)

The raw command channel (ATAPI / SCSI MMC via SG_IO — abstracted
behind the [`MmcTransport`] trait; the simulation records the
stream for the certificate):

```text
DISABLE_OPC      stop run-time laser power calibration from
                 clamping the diode back to write levels
LASER_OVERDRIVE  PWM duty → 100% continuous wave,
                 diode current → the vendor absolute-maximum shelf
PARK_VELOCITY    pin the CLV servo at the spindle floor
FOCUS_OFFSET     static defocus into the substrate gap (deep-layer
                 media coupling)
WRITE_LONG       the burn pass, zone by zone
```

WRITE_LONG **requires the fully armed state** — an unconfigured
drive refuses the pass. Out-of-envelope parameters (current past
the vendor shelf, CLV below the spindle stall, focus past the
actuator range) are rejected at the transport.

### 2. The dose model (`opu.rs`)

The CLV servo holds the beam's linear velocity constant across the
spiral (`v = ω(r)·r`). Energy per unit track length:

```text
E/L = P / v        dose = gain_current × duty × focus_coupling × (v_w / v)
```

— maximized at **low** velocity and **high** power: the exact
inverse of the drive's write strategy. The default campaign (28 mW
CW at 1.2 m/s against a 10 mW / 4.917 m/s write strategy) delivers
an **11.5× energy gain** per unit track length.

### 3. Media physics (`layer.rs`)

Per-cell reflectivity state with media-specific destruction modes
(dose in normalized units: 1.0 = one nominal write pulse per cell):

| medium | mode | threshold |
|---|---|---|
| organic dye (CD-R, DVD-R) | photobleach to saturation | 1.0 |
| phase-change alloy (BD-R, DVD±RW) | melt & quench to amorphous | 2.5 |
| glassy carbon (M-DISC) | ablation / carbonization | 6.0 |

M-DISC is the point of the exercise: the "stone" layer marketed as
surviving a millennium — and shredding — needs ablation-class dose.
Only the overdriven parked-CW beam delivers it.

### 4. The spiral engine (`anneal.rs`)

Write-long passes over the **full spiral** (lead-in → lead-out)
with along-track thermal spreading (kernel `[0.12, 0.76, 0.12]` —
the hot spot bleeds into its neighbours, physics in our favour).
Coverage is accounted per cell: every cell's accumulated dose must
cross the media threshold.

### 5. Readback verification (`rfeeye.rs`)

The forensics-lab read path, with a best-case quiet instrument
(σ = 1% of full-scale return):

- **RF eye pattern** — eye height `I₀·(R_max − R_min)`; a destroyed
  layer is a flat line: eye closed to the noise floor.
- **Push-pull tracking** — the quadrature-photodiode groove error
  signal, decaying with the thermally slumped groove walls.
- **Jitter** — with contrast gone the slicer fires on pure noise.
- **Read recovery** — the known-format discriminator lands at
  chance (50%).

## The certificate

Per zone: minimum cell dose (must cross the media threshold), eye
height, residual ΔR/R modulation. Overall: 100% spiral coverage,
worst modulation below 0.05, push-pull below 15% of fresh, read
recovery at 50% ± 5%. The command-stream digest binds the exact
weaponization sequence. BLAKE3 over the canonical body; `verify()`
recomputes every verdict from the raw statistics.

```text
dc optix simulate --disc-id MD-0001 --media glassy-carbon --out optix-cert.json
dc optix verify --cert optix-cert.json
```

## Threat model

1. **Forensic readback** — calibrated drive re-read: modulation
   flat, every channel bit reads as noise, recovery at chance.
2. **Microscopy recovery** — polished cross-sections hunting
   surviving mark trains: per-cell dose coverage leaves no
   survivors (the coverage denominator is the cell, not the zone).
3. **Certificate forgery / replay** — BLAKE3 digest, verdict
   recomputation, signable via the dc-cert hybrid machinery.

## Integration honesty

This release ships the physics engine, the command protocol and
the verification instruments; the hardware backend rides the
per-OEM vendor diagnostic tables through the [`MmcTransport`]
trait (SG_IO passthrough over dc-scsi). Drive families differ in
their diagnostic blocks and interlocks — the envelope checks model
the documented shelves of the common families.
