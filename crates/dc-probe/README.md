# dc-probe — Device Discovery, Layer Stacks, and the Guardian

`dc-probe` answers "what is this device, what is stacked on it, and is it
safe to destroy?" It owns the **Guardian**, the 15-rule pre-flight safety
table that stands between an operator's intent and a destructive write.

## The Guardian (guardian.rs)

`Guardian::evaluate()` walks the normative precedence table (§7): size
anomalies, partition-vs-whole-disk classification, RAM-backed devices,
zoned geometry, read-only state, NVMe multipath handles, mounts and system
disks, active swap, device-mapper/LVM holders, active md members, sniffed
storage signatures (LUKS/LVM/swap/RAID), and loop devices. Refusals carry a
stable `code`, operator-facing `detail`, and actionable `hint`.

**Fail-closed arming** (`Guardian::arm_and_lock`): the whole disk and every
child partition are opened `O_RDWR|O_EXCL` and flocked. A partition whose
exclusive open fails (other than ENOENT for a vanished node) refuses to arm
— the historical code silently skipped it (`REG-GUARDIAN-PARTLOCK`).

`is_partition_name()` uses real separator logic: `loop0p1` is a partition,
`loop0` is a whole disk — the 'p' inside the *driver name* is not a
separator (`REG-PARTITION-NAME`).

## Module map

- `inventory.rs` — sysfs/udev probing; `probe_device_or_refuse()` maps a
  missing target to a Guardian refusal (exit 2), not a raw I/O error
- `guardian.rs` — the safety table + exclusive locking
- `layer_stack.rs` — mountinfo parsing, holder detection, write-zeroes
  capability, signature sniffing (bounded reads)
- `classify.rs` / `graph.rs` — topology classification
- `sniff.rs` — bounded signature sniffer (Δ124: never reads unbounded)
- `bootfacts.rs` / `identity.rs` — boot-environment facts, identity helpers

## Testing

`cargo test -p dc-probe --lib` — partition-name matrix and refusal codes.
Integration: `dc-cli/tests/g3_guardian_matrix`, `t4_guardian_matrix`,
`t5_lvm_matrix`, `t6_tamper_matrix`.

## Dependency policy

Read-only probing by design: opens devices `O_RDONLY` until `arm_and_lock`.
Never imports engines or codecs.
