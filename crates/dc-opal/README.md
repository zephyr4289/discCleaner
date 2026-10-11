# dc-opal — TCG Opal SSC Client (SED Rescue)

`dc-opal` performs state-gated **PSID revert** rescues on self-encrypting
drives: the last-resort mechanism that regenerates the data encryption key
using the physical presence ID printed on the drive label.

## Safety properties

- PSID revert is offered **only for locked intake** (Δ368) — an unlocked
  drive has better options and must not be nuked
- `PsidSecret` zeroizes on drop via volatile writes and its `Debug` impl
  prints only the BLAKE3 hash — the PSID itself can never leak into logs or
  panic messages (Δ367)
- Evidence records the PSID **hash only**, never the secret

## Module map

- `psid.rs` — the zeroizing PSID holder
- `client.rs` — state-gated revert with `OpalRescueSummary`
- `discovery.rs` — Opal SSC type discovery tree

## Testing

`cargo test -p dc-opal --lib` — 2 unit tests (hash stability, Debug leak
refusal, state gating). Integration: `m1_8_opal_client_matrix`, `t19_opal_matrix`.
