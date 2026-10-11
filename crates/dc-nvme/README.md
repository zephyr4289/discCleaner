# dc-nvme — Native NVMe Admin Purge Client

`dc-nvme` executes controller-level purge mechanisms over the NVMe admin
queue, with a **planned fallback ladder** and hard evidence rules.

## The purge ladder

`NvmePurgeClient::execute_purge_ladder()` walks Sanitize Crypto Erase →
Sanitize Block Erase → Format NVM (Crypto Erase), recording every controller
rejection as a `MechanismFallback`. Termination evidence rules:

- **Sanitize paths return `Ok` only on a terminal Sanitize Status Log**
  (SSTAT=Completed). A still-in-progress operation consumes its poll budget
  and returns `SANITIZE_INCOMPLETE` — it never reports completion it did not
  observe (`REG-NVME-FABRICATED-COMPLETION`).
- **Format NVM** completion is evidenced by the blocking (non-IMMED) admin
  return; the summary's `completion_evidence()` records that provenance so
  certificates never claim sanitize-log data that does not exist.
- **Logical overwrite is refused outright**: it is an engine-driven,
  minutes-long write that no admin client can perform; fabricating its
  completion would certify an erase that never ran.

The NSID for Format NVM is derived from the permit's bound target
(`/dev/nvme0n3` → NSID 3), never hardcoded (`REG-NVME-NSID`).

## Module map

- `purge.rs` — the ladder, poll budget, evidence provenance
- `permit.rs` — `PurgePermit` typestate token binding target device+serial
- `transport.rs` — `NvmeAdminTransport` trait + `ErrnoClassifier`, the
  strict kernel-errno taxonomy (Δ268: EFAULT/EINVAL are OUR bugs,
  ETIMEDOUT is ambiguous, unmapped errnos are loud)

## Testing

`cargo test -p dc-nvme --lib` — 6 unit tests (terminal-status requirement,
refusal of fabricated completion, ladder fallback, NSID derivation, errno
taxonomy). Integration: `m1_3_nvme_client_matrix`, `t13_nvme_purge_matrix`.
