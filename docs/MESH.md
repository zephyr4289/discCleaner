# dc-mesh — Autonomous Multi-Node Consensus & Byzantine Sanitization Swarm

> v0.13.0, Frontier 1. Wipe a 500-node hyperscaler cluster with **no
> central server, no orchestrator, no single point of trust**.

## The problem

Data-center decommissioning leans on centralized orchestrators:
Ansible playbooks, PXE boot servers, a jump box with a for-loop. If
that one machine is compromised — or simply wedged mid-run — rogue
nodes can skip drives and report false success. Every certificate
in the fleet then inherits the trust assumptions of one box. That is
the exact opposite of what a decommission proof needs.

dc-mesh replaces the orchestrator with **the swarm itself**: a
leaderless, peer-to-peer, Byzantine fault-tolerant mesh of `dc`
instances speaking directly over raw L2 Ethernet.

## Protocol

| Layer | Mechanism |
|-------|-----------|
| Transport | Raw Ethernet frames, EtherType `0x88B5` (IEEE local-experimental range). No IP, no ARP, no TCP, no ports. `AF_PACKET` on Linux (`CAP_NET_RAW`). |
| Discovery | Signed broadcast HELLO / HELLO_ACK; membership **freezes** into an epoch roster at `2f+1` peers or after a silence window. |
| Gossip | Epidemic anti-entropy of per-drive `DriveReport` attestations: identity, pattern, verified-window counts, BLAKE3 root over readback evidence. |
| Spot proofs | Witnesses challenge fresh (nonce, LBA window); the wiper must return the bytes on media **right now**; every node recomputes the expected pattern. |
| Consensus | PBFT-family rotating-speaker (deterministic `speaker(view) = H(membership ∥ view)`), PREPARE/COMMIT at `2f+1`, view-change on timeout. |
| Rogue detection | Equivocation, duplicate serials, failed spot-proofs, timeouts → signed accusations; `2f+1` distinct accusers **isolate** a node into the collective ledger. |
| Sealing | **FROST2 threshold Schnorr over Ed25519** (t-of-n aggregate; the group key exists nowhere after the ceremony) **plus an ML-DSA-44 post-quantum t-of-n signature set**. |

### The certificate

The `SwarmCertificate` proves, verifiable offline by anyone with
the membership keys:

* every declared drive was wiped and zero-entropy verified under
  the decided pattern;
* every witness spot-proof challenge passed;
* the quorum reached consensus (`2f+1` committers listed);
* at least `t` distinct threshold shares co-signed the result;
* rogue nodes are **named**, with evidence, and their drives are
  explicitly listed as *not certified*.

### Byzantine actors the drills pin (CI-enforced)

| Actor | Behavior | Detection |
|-------|----------|-----------|
| **Liar** | Claims drives wiped; media untouched | Witness spot-proof recompute fails → `failed_spot_proof` |
| **Silent** | Goes dark mid-run | Report/challenge deadlines → `timeout` |
| **Equivocator** | Two different signed proposals in one view | Both digests recorded **before** validation → `equivocation` |

Local validation refuses to PREPARE any block that omits an
isolation the validator holds (a decision missing a live rogue
verdict is stale by definition), and `seal_set` includes strictly
live members — an isolated node can never wedge the seal.

## Determinism

Drills (`dc mesh simulate`, CI) derive FROST nonces from the run
seed — **byte-identical certificates on replay**. Production
deployments draw nonces from the OS CSPRNG (`round1`); deriving
Schnorr nonces from a replayed source is a share-leak vector, so
the deterministic path is drill-only and marked as such.

## Operation

```console
$ dc mesh simulate --nodes 7 --byzantine 3=liar --out swarm-cert.json
[MESH] converged in 16 ticks (deterministic from seed 42)
[MESH] rogue ledger     : 1 entry
         - node 526ec9..a0b3: failed_spot_proof (5 accusers)
[MESH] FROST2 seal     : t = 5 of 7 (aggregate Ed25519)
[MESH] ML-DSA-44 seal  : 5 of 7 partial signatures (post-quantum)

$ dc mesh verify --cert swarm-cert.json
[MESH] VERIFIED — the cluster's collective signature holds
```

Real segments: `dc mesh` instances on the decommission VLAN with
jumbo frames (MTU ≥ 9000 — ML-DSA-44 partials expand to ≈ 4.8 KB)
and `CAP_NET_RAW` (see `docs/SECURITY.md`).

## Security properties

* **No orchestrator to compromise.** Removing the single point of
  trust is the point of the crate.
* **t-of-n unforgeable certificates.** An attacker must compromise
  a threshold of the physical cluster, not one jump box.
* **Quantum-resistant seal.** The ML-DSA-44 layer survives a
  future adversary with a quantum computer; the Ed25519 layer
  carries classical interoperability.
* **Rogues cannot shrink the quorum retroactively.** Membership is
  frozen; late arrivals are latched, recorded, excluded.

## Testing

45 unit + integration tests: frame round-trips and tamper
detection, discovery freezing, gossip duplicate-serial detection,
spot-proof lie/replay/timeout cases, consensus view rotation and
equivocation flagging, FROST/MuSig2-style threshold arithmetic,
rogue-ledger aggregation, whole-swarm drills (honest, liar,
silent, equivocator), cross-node certificate identity and
deterministic byte-identical replay.
