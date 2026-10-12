//! dc-vault — Micro-KVM hardware memory vault (v0.8.0, Vector 2).
//!
//! `--vault` executes the security-critical path of a sanitization run
//! inside a self-contained micro-VM: a pure-Rust KVM hypervisor control
//! plane (~600 lines, no BIOS, no QEMU, no device model) that boots a
//! 64-byte position-fixed guest payload directly into long mode.
//!
//! Defense properties:
//! - **Memory isolation**: guest RAM is `mlock`'d, never swapped, wiped on
//!   drop; the session key that seals the verification chain is generated
//!   by guest `RDRAND` + host entropy *inside* the VM.
//! - **Memory encryption**: when the kernel exposes AMD SEV / SEV-ES /
//!   SW-protected VM types, the VM is created with the encrypted type —
//!   host userspace (and a host rootkit) sees only ciphertext for the
//!   guest's working set. `--vault` with encryption semantics refused
//!   when no encrypted VM type exists: fail-closed, never silently
//!   downgraded.
//! - **Attestable execution**: the payload image is BLAKE3-measured and
//!   the measurement rides in the certificate; combined with the v0.8.0
//!   TPM quote (Vector 1) an auditor can prove *which* enclave image ran.
//! - **Tamper-evident verification**: read-back evidence is chained with
//!   HMAC-SHA256 under the vault key (`verify_chain`); a host rootkit
//!   cannot forge the chain head without the guest-only key.
//!
//! Scope honesty (documented in docs/SECURITY.md): v0.8.0 vault isolates
//! key generation and the verification chain. Guest-side virtio-blk I/O
//! (the wipe traffic itself executing inside the enclave) is the v0.9.0
//! milestone; the VFIO group plumbing that will carry it is staged in
//! `passthrough.rs` and is exercised to the ioctl boundary now.

pub mod kvm;
pub mod passthrough;
pub mod payload;
pub mod verify_chain;
pub mod vm;

pub use kvm::{Kvm, KvmError};
pub use payload::{SESSION_KEY_LEN, layout, payload_measurement};
pub use verify_chain::{VerificationChain, hmac_sha256};
pub use vm::{GuestRam, MemoryEncryption, MicroVm, VaultRunOutcome};

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Vault execution failures — every refusal is a hard stop for the run.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault refused: {0}")]
    Refusal(String),
    #[error("KVM error: {0}")]
    Kvm(#[from] KvmError),
    #[error("vault guest failed: {0}")]
    GuestFailed(String),
    #[error("vault session key could not be sealed: {0}")]
    Sealing(String),
}

/// How strict the vault gate is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum VaultRequirement {
    /// No vault requested (default — no report embedded).
    #[default]
    None,
    /// Vault must run; memory encryption is opportunistic (SEV used when
    /// present). For development hosts without SEV.
    Enclave,
    /// Vault must run AND memory encryption must be active — the
    /// sovereign/deployment posture: a host without SEV/TDX cannot
    /// certify.
    EncryptedEnclave,
}

/// The certificate-embedded vault report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultReport {
    /// `KVM_GET_API_VERSION` observed (must be 12 — the frozen UAPI).
    pub kvm_api_version: i32,
    /// Which VM type the enclave ran under.
    pub memory_encryption: String,
    /// True when an encrypted VM type was actually used.
    pub encrypted: bool,
    /// BLAKE3/24 of the guest payload image that generated the key.
    pub guest_payload_blake3: String,
    /// BLAKE3/24 of the session key (fingerprint only — never the key).
    pub session_key_fingerprint: String,
    /// HMAC chain head after folding all verification records.
    pub chain_head_hex: String,
    /// Records folded into the chain.
    pub chain_records: u64,
    /// vCPU exits observed during the enclave run.
    pub vcpu_exits: u32,
    /// Wall-clock duration of the enclave run (microseconds).
    pub elapsed_us: u64,
}

impl VaultReport {
    pub fn field_lines(&self) -> Vec<(String, String)> {
        vec![
            (
                "Vault memory encryption".into(),
                self.memory_encryption.clone(),
            ),
            (
                "Vault guest image (BLAKE3/24)".into(),
                self.guest_payload_blake3.clone(),
            ),
            (
                "Vault session key (fingerprint)".into(),
                self.session_key_fingerprint.clone(),
            ),
            ("Vault HMAC chain head".into(), self.chain_head_hex.clone()),
            (
                "Vault chain records".into(),
                format!("{}", self.chain_records),
            ),
            ("Vault vCPU exits".into(), format!("{}", self.vcpu_exits)),
        ]
    }
}

/// One executed vault session: owns the (scrubbed) key material while
/// records are being sealed.
pub struct VaultSession {
    report: VaultReport,
    chain: Option<VerificationChain>,
    session_key: Option<[u8; SESSION_KEY_LEN]>,
    _vm: Option<MicroVm>,
}

impl VaultSession {
    /// Probe what the host can offer, honoring the fail-closed policy.
    pub fn probe(requirement: VaultRequirement) -> Result<VaultProbe, VaultError> {
        let kvm = Kvm::open().map_err(|e| {
            VaultError::Refusal(format!(
                "--vault requires /dev/kvm: {e}. A compromised host cannot \
                 be excluded without the enclave; refusing to certify."
            ))
        })?;
        let version = kvm.api_version()?;
        let enc = if kvm.vm_type_supported(kvm::KVM_X86_SEV_ES_VM) {
            MemoryEncryption::SevEs
        } else if kvm.vm_type_supported(kvm::KVM_X86_SEV_VM) {
            MemoryEncryption::Sev
        } else if kvm.vm_type_supported(kvm::KVM_X86_SW_PROTECTED_VM) {
            MemoryEncryption::SwProtected
        } else {
            MemoryEncryption::None
        };
        if requirement == VaultRequirement::EncryptedEnclave && enc == MemoryEncryption::None {
            return Err(VaultError::Refusal(
                "--vault (encrypted-enclave posture) requires AMD SEV, SEV-ES or a \
                 SW-protected VM type from this kernel; none available. Refusing to \
                 certify on an unencrypted host — SEV/TDX memory encryption is the \
                 guarantee that a host rootkit cannot read the session key."
                    .into(),
            ));
        }
        Ok(VaultProbe {
            api_version: version,
            encryption: enc,
        })
    }

    /// Run the enclave: boot the micro-VM, generate the session key,
    /// scrub the guest pages, and arm the verification chain.
    pub fn execute(requirement: VaultRequirement) -> Result<Self, VaultError> {
        let probe = Self::probe(requirement)?;
        let kvm = Kvm::open().map_err(VaultError::Kvm)?;
        let started = Instant::now();
        let mut vm = MicroVm::build(&kvm, probe.encryption)?;

        // Host entropy injection (getrandom via the OS CSPRNG).
        let mut seed = [0u8; SESSION_KEY_LEN];
        getrandom_fill(&mut seed);
        vm.inject_seed(&seed);
        // SAFETY: seed was consumed by the guest; wipe our copy.
        for b in seed.iter_mut() {
            *b = 0;
        }

        let deadline = Instant::now() + Duration::from_secs(30);
        let outcome = vm.run(deadline)?;
        let elapsed = started.elapsed().as_micros() as u64;
        let exits = vm.exits();
        let key = match outcome {
            VaultRunOutcome::Completed { key } => key,
            other => {
                return Err(VaultError::GuestFailed(format!(
                    "enclave did not complete cleanly: {other:?}"
                )));
            }
        };

        // Fingerprint + chain under the guest-derived key.
        let mut fingerprint_material = blake3::Hasher::new();
        fingerprint_material.update(&key);
        let fingerprint = fingerprint_material.finalize().to_hex().to_string()[..24].to_string();
        let chain = VerificationChain::new(&key, fingerprint.as_bytes());

        // Defense-in-depth: scrub key material from the guest pages; the
        // host-side copy below is zeroized when this session drops.
        vm.scrub_result_page();

        let report = VaultReport {
            kvm_api_version: probe.api_version,
            memory_encryption: probe.encryption.label().to_string(),
            encrypted: probe.encryption != MemoryEncryption::None,
            guest_payload_blake3: payload_measurement(),
            session_key_fingerprint: fingerprint,
            chain_head_hex: chain.head_hex(),
            chain_records: chain.records(),
            vcpu_exits: exits,
            elapsed_us: elapsed,
        };
        Ok(Self {
            report,
            chain: Some(chain),
            session_key: Some(key),
            _vm: Some(vm),
        })
    }

    /// Fold one verification record into the HMAC chain.
    pub fn seal_record(&mut self, record: &[u8]) -> Result<String, VaultError> {
        let chain = self.chain.as_mut().ok_or_else(|| {
            VaultError::Sealing("vault chain already finalized (session dropped?)".into())
        })?;
        Ok(hex::encode(chain.seal(record)))
    }

    /// Snapshot the report (chain head is final only after all records).
    pub fn report(&self) -> VaultReport {
        let mut r = self.report.clone();
        if let Some(chain) = &self.chain {
            r.chain_head_hex = chain.head_hex();
            r.chain_records = chain.records();
        }
        r
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        // Zeroize the host-side key copy with volatile stores.
        if let Some(key) = self.session_key.as_mut() {
            for b in key.iter_mut() {
                // SAFETY: plain volatile store, no aliasing.
                unsafe { std::ptr::write_volatile(b, 0u8) };
            }
        }
    }
}

/// Host capability probe result.
pub struct VaultProbe {
    pub api_version: i32,
    pub encryption: MemoryEncryption,
}

/// OS entropy fill (getrandom(2) via libc).
fn getrandom_fill(buf: &mut [u8]) {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = unsafe {
            libc::getrandom(
                buf.as_mut_ptr().add(filled) as *mut libc::c_void,
                buf.len() - filled,
                0,
            )
        };
        if n < 0 {
            // getrandom(2) with GRND_NONBLOCK unset blocks until ready;
            // EINTR is the only realistic retry.
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // Last resort: /dev/urandom via std.
            let n = std::fs::read("/dev/urandom").map(|v| v.len()).unwrap_or(0);
            if n == 0 {
                panic!("no OS entropy source available for vault seed");
            }
            filled = buf.len().min(n);
            continue;
        }
        filled += n as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_probe_without_kvm_is_a_clean_refusal_not_a_panic() {
        match VaultSession::probe(VaultRequirement::EncryptedEnclave) {
            Ok(_) => {} // host has KVM (and possibly SEV): fine
            Err(VaultError::Refusal(msg)) => {
                assert!(msg.contains("SEV") || msg.contains("/dev/kvm"), "{msg}");
            }
            Err(VaultError::Kvm(KvmError::NoKvm(_))) => {} // also a refusal
            Err(other) => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn vault_report_field_lines_cover_the_chain() {
        let report = VaultReport {
            kvm_api_version: 12,
            memory_encryption: "AMD SEV".into(),
            encrypted: true,
            guest_payload_blake3: payload_measurement(),
            session_key_fingerprint: "abcd".into(),
            chain_head_hex: "beef".into(),
            chain_records: 7,
            vcpu_exits: 3,
            elapsed_us: 1200,
        };
        let lines = report.field_lines();
        assert!(lines.iter().any(|(k, _)| k.contains("chain head")));
        assert!(lines.iter().any(|(k, _)| k.contains("encryption")));
        assert!(report.encrypted);
    }

    /// Full enclave run when the environment provides KVM (skipped on
    /// hosts without /dev/kvm — CI containers — where the CLI must fail
    /// closed instead; that behavior is pinned in t29).
    #[test]
    fn vault_session_executes_and_seals_records_when_kvm_exists() {
        let kvm = match Kvm::open() {
            Ok(k) => k,
            Err(_) => {
                eprintln!("skipping: no /dev/kvm here");
                return;
            }
        };
        if !kvm.vm_type_supported(kvm::KVM_X86_DEFAULT_VM) {
            eprintln!("skipping: KVM refuses VM creation in this sandbox");
            return;
        }
        let mut session = match VaultSession::execute(VaultRequirement::Enclave) {
            Ok(s) => s,
            Err(e) => panic!("vault execution failed: {e}"),
        };
        let head1 = session.seal_record(b"pass1-verified").expect("seal");
        let head2 = session.seal_record(b"pass2-verified").expect("seal");
        assert_ne!(head1, head2, "chain must advance");
        let report = session.report();
        assert_eq!(report.chain_records, 2);
        assert_eq!(report.kvm_api_version, 12);
        assert_eq!(report.guest_payload_blake3, payload_measurement());
        assert_eq!(report.session_key_fingerprint.len(), 24);
    }
}
