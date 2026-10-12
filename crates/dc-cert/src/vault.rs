//! Micro-KVM vault execution report (v0.8.0, Vector 2) and the photon
//! bridge manifest (Vector 3) — the certificate-embedded halves of the
//! dc-vault and dc-photon stacks.

use serde::{Deserialize, Serialize};

/// The certificate-embedded vault report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultReportEvidence {
    /// `KVM_GET_API_VERSION` observed (must be 12 — the frozen UAPI).
    pub kvm_api_version: i32,
    /// Which VM type the enclave ran under ("AMD SEV", "AMD SEV-ES",
    /// "SW-protected VM", "none").
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

impl VaultReportEvidence {
    pub fn defense_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.encrypted {
            warnings.push(
                "DEFENSE_WARNING: vault ran WITHOUT memory encryption (no SEV/TDX VM type) — \
                 the session key was generated inside a KVM enclave but a host adversary with \
                 hypervisor access could observe guest RAM. Physical destruction remains the \
                 only unconditional answer on this host class."
                    .into(),
            );
        }
        if self.kvm_api_version != 12 {
            warnings.push(format!(
                "DEFENSE_WARNING: KVM API version {} (expected the frozen 12) — \
                 nonstandard hypervisor, enclave isolation not guaranteed.",
                self.kvm_api_version
            ));
        }
        warnings
    }

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
            (
                "Vault HMAC chain head".into(),
                format!(
                    "{}…",
                    &self.chain_head_hex[..16.min(self.chain_head_hex.len())]
                ),
            ),
            (
                "Vault chain records".into(),
                format!("{}", self.chain_records),
            ),
            ("Vault vCPU exits".into(), format!("{}", self.vcpu_exits)),
        ]
    }
}

/// The photon-bridge manifest (Vector 3): what the receiving auditor needs
/// to validate a captured optical stream against the signed certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhotonManifestEvidence {
    /// BLAKE3 of the streamed payload (hex).
    pub payload_blake3: String,
    /// Truncated stream id (hex).
    pub stream_id: String,
    /// Payload length in bytes.
    pub payload_len: u64,
    /// Fountain block size.
    pub block_size: u32,
    /// Symbols per frame.
    pub symbols_per_frame: u32,
    /// Fountain stream seed (hex) — the out-of-band binding.
    pub stream_seed: String,
    /// QR version ceiling in use.
    pub qr_version_ceiling: u8,
}

impl PhotonManifestEvidence {
    pub fn field_lines(&self) -> Vec<(String, String)> {
        vec![
            ("Photon payload BLAKE3".into(), self.payload_blake3.clone()),
            ("Photon stream id".into(), self.stream_id.clone()),
            (
                "Photon payload bytes".into(),
                format!("{}", self.payload_len),
            ),
            ("Photon block size".into(), format!("{}", self.block_size)),
            (
                "Photon symbols/frame".into(),
                format!("{}", self.symbols_per_frame),
            ),
            ("Photon stream seed".into(), self.stream_seed.clone()),
        ]
    }
}

/// Fabric session evidence (Vector 4): the remote-purge hop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricSessionEvidence {
    /// "tcp" | "rdma" | "fc" | "loop".
    pub transport: String,
    /// Fabric address of the remote subsystem.
    pub traddr: String,
    /// Transport service id (port).
    pub trsvcid: String,
    /// Subsystem NQN.
    pub nqn: String,
    /// Sysfs controller name that appeared (e.g. "nvme4").
    pub ctrl_name: String,
    /// Controller char device used for admin passthrough.
    pub ctrl_char_dev: String,
    /// True when the session ended with an explicit, ACKed DISCONNECT.
    pub disconnected_cleanly: bool,
    /// Session duration (ms) — connect to disconnect.
    pub session_ms: u64,
    /// FC mapping evidence (when the transport is fc).
    pub fc_host_port_name: Option<String>,
}

impl FabricSessionEvidence {
    pub fn defense_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.disconnected_cleanly {
            warnings.push(
                "DEFENSE_WARNING: fabric session did not end with a confirmed DISCONNECT — \
                 the remote subsystem may still hold the controller session open."
                    .into(),
            );
        }
        warnings
    }

    pub fn field_lines(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Fabric transport".into(), self.transport.clone()),
            (
                "Fabric target".into(),
                format!("{}:{}", self.traddr, self.trsvcid),
            ),
            ("Fabric subsystem NQN".into(), self.nqn.clone()),
            ("Fabric controller".into(), self.ctrl_name.clone()),
            ("Fabric char device".into(), self.ctrl_char_dev.clone()),
            ("Fabric session".into(), format!("{} ms", self.session_ms)),
        ];
        if let Some(fc) = &self.fc_host_port_name {
            lines.push(("Fabric FC host WWPN".into(), fc.clone()));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(encrypted: bool) -> VaultReportEvidence {
        VaultReportEvidence {
            kvm_api_version: 12,
            memory_encryption: if encrypted {
                "AMD SEV".into()
            } else {
                "none".into()
            },
            encrypted,
            guest_payload_blake3: "abc123".into(),
            session_key_fingerprint: "def456".into(),
            chain_head_hex: "00".repeat(32),
            chain_records: 5,
            vcpu_exits: 2,
            elapsed_us: 1200,
        }
    }

    #[test]
    fn unencrypted_vault_discloses() {
        assert!(vault(false).defense_warnings().len() == 1);
        assert!(vault(true).defense_warnings().is_empty());
        assert!(
            vault(true)
                .field_lines()
                .iter()
                .any(|(k, _)| k.contains("chain head"))
        );
        let mut v = vault(true);
        v.kvm_api_version = 11;
        assert!(v.defense_warnings().len() == 1);
    }

    #[test]
    fn photon_and_fabric_field_lines() {
        let m = PhotonManifestEvidence {
            payload_blake3: "ab".repeat(32),
            stream_id: "cafebabe".into(),
            payload_len: 20480,
            block_size: 48,
            symbols_per_frame: 3,
            stream_seed: "000000005eed0001".into(),
            qr_version_ceiling: 10,
        };
        assert!(
            m.field_lines()
                .iter()
                .any(|(k, v)| k.contains("BLAKE3") && v.len() == 64)
        );

        let f = FabricSessionEvidence {
            transport: "tcp".into(),
            traddr: "10.0.0.5".into(),
            trsvcid: "4420".into(),
            nqn: "nqn.2014-08.org.example:sub1".into(),
            ctrl_name: "nvme4".into(),
            ctrl_char_dev: "/dev/nvme4".into(),
            disconnected_cleanly: true,
            session_ms: 85000,
            fc_host_port_name: None,
        };
        assert!(f.defense_warnings().is_empty());
        assert!(
            f.field_lines()
                .iter()
                .any(|(k, v)| k.contains("target") && v.contains("10.0.0.5"))
        );
        let mut f2 = f;
        f2.disconnected_cleanly = false;
        assert_eq!(f2.defense_warnings().len(), 1);
    }
}
