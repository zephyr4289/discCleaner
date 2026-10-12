//! dc-tpm — native TPM 2.0 remote-attestation stack (v0.8.0, Vector 1).
//!
//! Zero dynamic linking, zero external tooling: a byte-exact implementation
//! of the TPM 2.0 wire protocol (TCG TPM 2.0 Part 1/2/3) spoken directly to
//! the kernel resource manager (`/dev/tpmrm0`) with poll(2)-deadline
//! discipline. No tpm2-tss, no tpm2-tools, no OpenSSL.
//!
//! What this crate proves, and what the certificate embeds:
//! - **PCR measurements**: SHA-256 extends of the appliance kernel (PCR 8),
//!   initramfs (PCR 9), the running `dc` binary (PCR 10) and the plan
//!   evidence (PCR 11), alongside the platform-firmware PCRs 0-7 already
//!   measured by UEFI (SRTM).
//! - **AIK custody**: a restricted, non-exportable NIST P-256 signing key
//!   created inside the secure element (`RESTRICTED | SIGN | FIXED_TPM |
//!   FIXED_PARENT` attributes are pinned and verified on every provision).
//! - **TPM2_Quote**: an ECDSA-SHA256-signed `TPMS_ATTEST` over PCRs 0-11,
//!   bound to a caller nonce (freshness) and the TPM monotonic clock
//!   (replay guard). Verified locally before it is ever certified, and
//!   re-verifiable offline from the archived raw response.
//!
//! Threat model: a ring-0 kernel rootkit can forge every software artifact
//! in an evidence package, but it cannot make the motherboard's secure
//! element sign a quote over PCRs it did not measure, and it cannot extract
//! the AIK private key to sign a doctored one. The quote is the hardware
//! anchor of the whole certificate.

pub mod attest;
pub mod constants;
pub mod device;
pub mod structures;
pub mod synth;
pub mod wire;

pub use attest::{
    AikHandle, AttestFields, MeasurementReport, QuoteBundle, TpmAttestor, recompute_pcr_digest,
    verify_bundle, verify_quote,
};
pub use constants::{
    AIK_OBJECT_ATTRIBUTES, DC_AIK_PERSISTENT_HANDLE, DC_QUOTE_PCR_MASK, TPM_ALG_ECDSA,
    TPM_ALG_SHA256, TPM_CC_QUOTE, TPM_GENERATED, TPM_ST_ATTEST_QUOTE,
};
pub use device::{TpmError, TpmRmTransport, TpmTransport};
pub use structures::{PcrSelection, PcrSelectionList, QuoteAttestation};

/// Where `dc` looks for the TPM resource manager.
pub const TPM_RM_DEVICE: &str = "/dev/tpmrm0";
