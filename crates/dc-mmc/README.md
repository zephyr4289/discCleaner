# dc-mmc — Native eMMC Purge Executor

`dc-mmc` sanitizes eMMC/SD media with partition-scoped honesty: user area,
boot0, boot1, and RPMB have different capabilities, and the certificate must
say exactly what happened — no more, no less.

## Vocabulary

- `access.rs` — `MmcAccessClass` (NativeController vs ReaderMediated):
  the production-owned access vocabulary. **This crate must never depend on
  `dc-testkit`** — the historical inverted dependency put the test kit in
  release binaries (`REG-MMC-LAYERING`, guarded by an integration test)
- `confirm.rs` — `TwoAxisConfirmation`: device-CID × partition-set
  reconciliation; every confirmed partition must be executed and every
  executed partition must have been confirmed (Δ348)
- `permit.rs` — `ConfigTransactionPermit` / `ConfigTxnGuard` for PARTITION_CONFIG
  transactions
- `client.rs` — `MmcPurgeClient` with honest `proof_substrate` provenance
  ("MockTranscribed" vs "SiliconObserved")

PARTITION_CONFIG updates preserve the adjacent BOOT_PARTITION_ENABLE and
BOOT_ACK bits — a wrong RMW would brick boot partitions (tested in
`cargo test -p dc-mmc --lib`).

## Testing

3 unit tests + integration `m1_7_mmc_client_matrix`, `t18_mmc_ufs_matrix`.
