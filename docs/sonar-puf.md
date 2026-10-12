# Sonar Acoustic Fingerprinting — Counterfeit-Drive & Rogue-Swap Defense
## (v0.12.0, Miracle 2 — `dc-sonar`)

Counterfeit SSDs and refurbished HDDs in global supply chains routinely
carry **flashed serial numbers and spoofed firmware WWNs**. You think
you wiped "Drive Serial #12345" — but a rogue swap took place, and the
real classified drive left the bay while a decoy took its place. Serial
numbers live in firmware; firmware can be rewritten. **Physics
cannot.**

Every mechanical drive arm, spindle motor and even the piezoelectric
capacitors on an SSD circuit board carry unique microscopic physical
imperfections that resonate at distinct acoustic and vibrational
harmonics. `dc-sonar` turns the drive itself into a challenge–response
**Physical Unclonable Function (PUF)**.

## The Pulse

A probe is a deterministic, challenge-derived I/O score
(`dc_sonar::SeekScore`): alternating short reads between
pseudo-random LBA islands with settle delays in the 200 µs–3 ms band.
On HDDs the arm's servo transients ring the chassis at its natural
frequencies; on SSDs, clustered read bursts excite
controller/PCB power-delivery resonances. The score is derived from
`SHA-256(challenge ‖ domain ‖ step)` — an auditor can regenerate the
exact LBA script from the recorded challenge and geometry.

## The Pickup

High-rate telemetry sampling from OUTSIDE the drive — none of these
channels can be influenced by drive firmware:

* **IIO accelerometers** (`/sys/bus/iio/devices`, polled
  `in_accel_{x,y,z}_raw`): 1–8 kHz effective — the acoustic band
  where spindle fundamentals (~60–150 Hz) and actuator servo
  resonances (~100–800 Hz) live.
* **hwmon channels** (temperature/voltage/fan): 1–10 Hz, an
  independent physical observer via regulator/load transients.

## The Fingerprint

`dc_sonar::signal` (hand-written radix-2 FFT, zero dependencies —
KAT-tested against a direct DFT reference) extracts per-channel
harmonic peaks (parabolic-interpolated), spectral centroid, spread,
flatness and RMS over the 20 Hz–2 kHz analysis band.

The fuzzy extractor uses the **pairwise-ordering construction**
(`sonar-puf/pairwise-order-v1`): a bit is `value(A) > value(B)` for two
same-type features whose observed gap dwarfs their observed
dispersions (`reliability = gap/(σA+σB) ≥ 3`). Such bits flip with
probability ≈ Φ(−reliability) — negligible — and the helper data
(feature ids + gaps + enrolled bits) discloses only internal orderings
that cloning the electronics does not reproduce. Verification scores
the Hamming distance against a 12.5% tolerance with a floor of 4.

Cloning the firmware leaves the chassis resonance — and therefore the
fingerprint — different. That is the point.

## Operations

```text
# enroll the physical chassis (K capture cycles):
dc sonar enroll --target /dev/sda --out sonar-enrollment.json

# verify any time later (fresh challenge — recorded responses are
# useless against a different challenge):
dc sonar verify --target /dev/sda --enrollment sonar-enrollment.json

# guard a wipe (pre + mid + post chassis checks, fail-closed):
dc execute --target /dev/sda --profile nist-clear \
           --puf-guard sonar-enrollment.json
```

The certificate's `sonar` section carries the enrolled fingerprint
digest, the telemetry sources, and every guard verification with its
Hamming score. A mid-wipe mismatch aborts certification with
`PUF_MISMATCH` — the rogue-swap detector.

## Honest limitations

* The acoustic channel needs **platform telemetry**: an IIO
  accelerometer (typical on enterprise boards) or hwmon channels.
  Without any telemetry source the guard **refuses** (`PUF_NO_TELEMETRY`)
  — fail-closed by design.
* Peak-index stability assumes magnitude-rank-stable top-K harmonics
  (true for healthy mechanical drives; degraded bearings shift
  rankings — reflected as distance, caught by the tolerance).
* Drills/CI may run against a recorded capture via the debug-only
  `DC_SONAR_REPLAY_CAPTURE` seam (release binaries carry no
  environment-driven path — the `DC_SIGNAL_AT` pattern).
* V1 binds single-physical-unit identity; population-level FAR/FRR
  benchmarking across chassis fleets is the v2 roadmap (the
  synthetic tests bound the construction, not the fleet statistics).
