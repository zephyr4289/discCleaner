# Sanitization Standards Profile Matrix (v0.5.0)

`dc profiles` renders this table from `dc_core::SanitizationProfile::CATALOG`
at runtime — this document is the frozen reference for procurement and audit
mapping. The catalog is the single source of truth: the CLI profile option
and the plan compiler both consume it, so the table below can never drift
from what executes.

| CLI `--profile`        | Passes | Pass sequence                                   | Verification default | Standard reference | Flash-suitable |
|------------------------|--------|-------------------------------------------------|----------------------|--------------------|-----------------|
| `nist-clear`           | 1      | 0x00                                            | full read-back       | NIST SP 800-88r1 §4.3 (Clear) | yes |
| `nist-clear-random`   | 1      | CSPRNG (ChaCha20-window-v1)                      | full read-back       | NIST SP 800-88r1 §4.3 (Clear) | yes |
| `certin-goi`          | 3      | 0x00 → 0xFF → CSPRNG                            | full read-back       | CERT-In / GoI media sanitisation practice | yes |
| `dod-5220.22m`        | 3      | 0xFF → 0x00 → CSPRNG                            | full read-back       | US DoD 5220.22-M (superseded) | yes |
| `dod-5220.22m-ece`    | 7      | FF/00/CSPRNG/FF/00/CSPRNG/CSPRNG                | full read-back       | US DoD 5220.22-M ECE (superseded) | no |
| `csec-itsg-06`        | 3      | 0x00 → CSPRNG → CSPRNG                          | full read-back       | CSE ITSG-06 (Canada) | yes |
| `bsi-vsitr`           | 7      | 00/FF/00/FF/00/FF/00                            | full read-back       | BSI VSITR (Germany) | yes |
| `schneier`            | 7      | FF, 00, 5× CSPRNG                               | full read-back       | B. Schneier, Applied Cryptography 2nd ed. (1996) | yes |
| `gutmann`             | 35     | 4×R, 27 MFM/RLL words, 4×R                      | full read-back       | P. Gutmann (1996) — legacy | no |

Aliases (script compatibility): `clear-zero` → `nist-clear`,
`clear-random` → `nist-clear-random`, `legacy-dod3` → `dod-5220.22m`.

## Verification levels (`--verify`)

| Flag           | Meaning | Where it is recorded |
|----------------|---------|----------------------|
| `full`         | 100% of user-addressable LBAs read back and compared | plan, journal (`full`), certificate |
| `sample:N`     | Deterministic 1-in-N window sampling (NIST SP 800-88r1 permits sampled verification of the final pass); unsampled windows are never read — the skipped I/O is the wall-clock saving | journal (`sample:N`), certificate (`{"sampled":{"stride":N}}`) |
| `none`         | No read-back (controller-attested purges document their own evidence) | journal (`none`), certificate |

`--verify` cannot override a `--plan` file: the compiled plan's verification
level is part of the plan hash (binding contract).

## Hardware purge (`dc purge`, NVMe)

The NIST SP 800-88 **Purge** action via the controller itself — no overwrite
traffic. The ladder (per attested capabilities) is
Sanitize Crypto Erase → Sanitize Block Erase → Format NVM Crypto Erase,
with completion evidenced by the Sanitize Status Log 0x81 (SSTAT terminal
state) or the blocking Format NVM admin return, plus pre/post SMART-health
snapshots embedded in the signed certificate. Format-NVM crypto-erase
additionally receives a sampled (1-in-64) zero read-back per the ladder's
"Zeros" expectation.
