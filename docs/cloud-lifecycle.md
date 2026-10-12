# Cloud Block-Storage Lifecycle (`dc cloud`)

> v0.10.0 · Frontier 2 — AWS EBS first, Azure/GCP behind the same trait

Cloud-native enterprises retiring AWS EBS volumes need a **verified, automated
attach → sanitize → verify → detach lifecycle** with signed audit receipts that
cryptographically bind the cloud context — Provider, Account ID, Volume ID, KMS Key
ARN, Region/AZ — alongside the usual write-pass verification evidence.

```
$ dc cloud describe --provider aws --volume vol-0abc123def
Volume:       vol-0abc123def
Provider:     aws
Size:         512 GiB
Encrypted:     yes
KMS Key:      arn:aws:kms:eu-west-1:111122223333:key/...
AZ:           eu-west-1a
State:        available

$ dc cloud plan --provider aws --volume vol-0abc123def      # dry: zero API mutations
$ dc cloud wipe  --provider aws --volume vol-0abc123def \
                 --device /dev/sdf --key operator.sk --execute
```

## The lifecycle state machine

```
 describe ──► attach ──► sanitize ──► verify ──► detach ──► receipt (hybrid-signed)
 (read-only)   (API)      (dc execute   (engine      (API)
                            child)       verify)
      │           │            │
      │           │            └── failure ──► rollback-detach ──► error
      │           └── never leaves the sanitizer without a detach
      └── in-use elsewhere: REFUSED (detach it in the console first —
          an explicit, logged decision the operator must make)
```

**The rollback rule:** once `attach` succeeds, *any* later failure still detaches
the volume (phase `rollback-detach` recorded in the receipt). A failed wipe never
leaves a foreign volume dangling on the sanitizer instance.

**Safety rails:**

1. Volumes attach only to the *instance the tool runs on* (identity resolved via
   IMDSv2; never cross-instance).
2. A volume currently attached elsewhere is refused before any mutating call.
3. Destructive phases run only with `--execute` — `plan`/dry-runs perform zero API
   mutations.
4. The receipt binds the engine certificate by **file hash (BLAKE3)** — cloud
   evidence cannot be spliced onto a different wipe's certificate.

## The audit receipt

```json
{
  "schema": "dc.cloud-receipt/v1",
  "cloud": {
    "provider": "aws",
    "account_id": "111122223333",
    "volume_id": "vol-0abc123def",
    "kms_key_arn": "arn:aws:kms:eu-west-1:…",
    "region": "eu-west-1",
    "availability_zone": "eu-west-1a",
    "performed_by_instance": "i-0e8f…",
    "attachment_device": "/dev/sdf"
  },
  "volume": { "size_gib": 512, "encrypted": true, "volume_type": "gp3", … },
  "lifecycle": [ { "phase": "describe", "result": "ok", … }, … ],
  "certificate": { "path": "certificates/…cert.json", "file_blake3": "…" },
  "signature":  { "alg": "Ed25519", "value": "…" },
  "post_quantum": { "alg": "ML-DSA-44", "public_key": "…", "value": "…" }
}
```

Both signature legs cover the same canonical JCS bytes (see
[post-quantum.md](post-quantum.md)); the cloud context is inside the signed
payload, so a receipt cannot be re-targeted to a different volume or account
without breaking both signatures.

## AWS driver internals

- **SigV4** (`dc-cloud/src/sigv4.rs`): canonical request → string-to-sign →
  signing-key ladder, implemented from the specification. Pinned by an
  independently computed vector (Python `hmac`/`hashlib`, a separate codebase) and
  by the published AWS documentation signing-key constant
  (`c4afb1cc5771d871…` for the classic 2015-08-30 us-east-1/iam example).
- **IMDSv2** (`imds.rs`): the token-handshake client for instance identity
  (instance-id, region, AZ, account id from the instance-identity document) and
  instance-profile credentials — the recommended deployment (no long-lived keys
  on the sanitizer).
- **EC2 query API** (`aws.rs`): `DescribeVolumes`, `AttachVolume`, `DetachVolume`
  with strict, allocation-bounded XML field extraction (no XML parser in the
  appliance).
- **Transport** (`transport.rs`): the EC2 endpoint is HTTPS-only; production runs
  enable the `cloud-tls` feature (`ureq`/rustls). The default build carries zero
  TLS dependencies — the musl appliance build stays dependency-free, and mock
  drills work without credentials.

Enable the AWS driver in packaged builds:

```
cargo build -p dc-cli --features cloud-tls
```

Credentials resolve in order: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`
(+ `AWS_SESSION_TOKEN`) environment, then the EC2 instance profile via IMDSv2.

## Provider abstraction

`dc-cloud::CloudDriver` is the whole surface a provider must implement:
`describe_volume`, `attach_volume`, `detach_volume`, `wait_state`,
`cloud_context`. Azure (Managed Disks) and GCP (Persistent Disk) plug in behind
the same trait — `dc cloud providers` reports the current roster:

```
aws     driver    EBS via EC2 query API (SigV4 + IMDSv2; needs cloud-tls)
mock    driver    offline drills: full lifecycle, no cloud calls
azure   planned   Managed Disks (driver trait ready)
gcp     planned   Persistent Disk (driver trait ready)
```

## Mock drills (`--provider mock`)

The mock driver runs the **same state machine** with no cloud at all — operator
training and CI. The test matrix covers: the happy path (with a hybrid-signed
receipt), dry-run (zero mutations), sanitize-failure → rollback-detach, the
attached-elsewhere safety rail, and unknown-volume handling
(`crates/dc-cloud/tests/cloud.rs`).

No AWS credentials are needed to exercise any of this locally — mock test
infrastructure ships in-tree.
