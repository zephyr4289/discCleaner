# dc-remanence — MFM Anti-Forensics & Remanence Annihilation

> v0.14.0, Breakthrough 1. Drive the guard-band sub-surface
> magnetization **below the Johnson-Nyquist thermal floor** —
> rendering Magnetic Force Microscopy recovery physically
> uninformative.

## The myth

*"Overwriting a sector with zeros destroys the data."* In magnetic
physics it does not. When a write head records a bit, its fringing
field leaks past the nominal track edge into the guard bands,
leaving sub-track magnetization remnants a few nanometres wide
(the "track-edge shoulder"). A state-grade forensics lab with a
Magnetic Force Microscope (or a spin-polarized SEM) scans those
guard bands and reads the hysteresis ghosts of the **previous**
recording — the data survives at the track edges even after a
NIST-grade overwrite of the track core.

dc-remanence quantifies the myth, then destroys it:

```text
naive zero-overwrite of the demo recording : ghost pools at ~+1..+4 dB
                                            → the adversary decides
                                              in 2–5 bits
after the dc-remanence treatment           : certified bound −23..−26 dB
                                            → detection horizon
                                              2–5× the bits on the track
```

## The weapon stack

### 1. Off-track micro-stepping (`microstep.rs`)

The head is stepped off the track centerline in sub-track
increments through the vendor diagnostic command surface (ATA
task-file / SCSI OEM block — the same interfaces service centers
use for head alignment):

```text
ladder: 0%, +15%, −15%, +30%, −30% of track pitch
        at up to +55% write-current overdrive
```

Overdriving the current raises the gap field *and* widens the
write bubble (the field past the pole edge decays exponentially
with a ~6.5 nm falloff; solving `H(edge) = H_c` moves the edge out
logarithmically with current). The union of the ladder's bubbles
must cover 100% of the guard band on both sides — plus the
neighbor's near guard band at ±30% — or the planner refuses
(forensic islands). The executed command stream is digest-bound
in the certificate: the [`MicroStepTransport`] trait is the
integration point for real ATA/SCSI diagnostic backends.

### 2. Curie-dither domain randomization (`curie.rs`)

A high-spatial-frequency alternating-flux write pattern at elevated
current: polarity inverted every 2 cells (maximum transition
density), per-pass random phase, per-cell transition jitter. Each
pass gives every guard-band grain a Néel-Brown thermal switch
attempt toward the *current* polarity:

```text
P_switch(H, H_c) = 1                        H ≥ H_c        (hard switch)
                 = exp(−κ·(1 − H/H_c))      H <  H_c        (thermal)
retention after K passes = (1 − p)^K        κ = 12 (write-dwell activation)
```

The old domain orientation decays geometrically and ends
re-randomized — decoupled from the previous recording. The dense
comb also plants fresh transitions everywhere, destroying the
edge-density forensics (the certificate bounds the correlation
between the old recording's edge-energy sequence and the
post-treatment residual at zero).

### 3. The statistical proof (`prml.rs`)

The adversary model is the **best-case lab**: known plaintext,
perfect tip positioning, multi-column pooling, and a read path
whose only noise is the Johnson-Nyquist floor

```text
σ = sqrt(4·k_B·T·R·B) / full-scale     (320 K, 45 Ω, 300 MHz → σ ≈ 0.0138)
```

Every lateral guard-band column carries an independently noised
copy of the same old-bit sequence (amplitude `a_c` per column), so
the optimal detector accumulates per-bit deflection
`Σ_c a_c²/σ²`. The certificate therefore bounds the **aggregate
noncentrality** `λ = K·Σ_c a_c²/σ̂²` at 99% confidence by inverting
the noncentral-χ² quantile equation — a sign-mixing-safe omnibus
bound. The certified number is the per-bit aggregate SNR
`λ_ub/K`, demanded **< −20 dB**, which also forces the
Neyman-Pearson detection horizon
`(Q⁻¹(10⁻⁶) − Q⁻¹(0.99))² / SNR` beyond the bits the track
physically contains.

Supporting instruments: the PR4 partial-response channel
(`y_k = x_k − x_{k−2} + n_k`) with a 4-state max-log BCJR
soft-decision LLR extractor demonstrates the wiped track reads
back as one constant symbol — no per-bit structure survives.

## The certificate

Per track: guard-band column coverage (100% required), the naive
zero-overwrite baseline ghost (the myth, quantified — detection in
a handful of bits), the post-treatment aggregate SNR bound (the
χ² omnibus), the detection horizon vs. supply, the
transition-forensics correlation, and the main-channel readback
mean. Everything is BLAKE3-digest bound; `verify()` recomputes
every verdict from the raw statistics — tampering with any field
breaks the digest, and re-digesting a lie breaks the arithmetic
recomputation.

```text
dc remanence simulate --device-id SN-XYZ --tracks 4 --out remanence-cert.json
dc remanence verify --cert remanence-cert.json
```

## Calibration honesty

Track geometry (112 nm pitch, 79 nm write element, 6.5 nm fringe
falloff, log-normal coercivity at median 0.62 gap-field units)
models a ~2 500 TPI-class perpendicular recording drive — textbook
thin-film values. The micro-step command tables themselves are
vendor-proprietary; the simulation records the issued command
stream (opcodes `0xD1..0xD3`) so a hardware backend can be
verified against the same digest chain. Lateral resolution (4 nm)
is finer than a real MFM tip resolves — the model is generous
**to the adversary**.

## Threat model

1. **Track-edge ghost (the MFM read)** — covered by the ladder +
   dither; certified below the floor.
2. **Transition-boundary forensics** — the dither comb + the
   edge-energy correlation bound.
3. **Certificate forgery / replay** — BLAKE3 digest, verdict
   recomputation, signable via the dc-cert hybrid
   Ed25519 + ML-DSA machinery.
