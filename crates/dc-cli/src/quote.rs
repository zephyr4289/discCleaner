//! `dc quote` — TPM 2.0 PCR remote attestation (v0.8.0, Vector 1).
//!
//! `generate`: measure the appliance artifacts (kernel → PCR 8, initramfs
//! → PCR 9, dc binary → PCR 10, evidence tag → PCR 11), then produce a
//! `TPM2_Quote` over PCRs 0-11 signed by the non-exportable AIK. The
//! bundle is verified locally (fail-closed) before it is written.
//!
//! `verify`: re-run the full verification ladder against a saved bundle —
//! the same check an external auditor performs with the archived raw
//! quote response.

use crate::{QuoteArgs, QuoteSubcommands};
use dc_core::DcError;
use dc_tpm::{DC_AIK_PERSISTENT_HANDLE, QuoteBundle, TpmAttestor, TpmRmTransport, verify_bundle};

pub fn cmd_quote(args: QuoteArgs) -> Result<(), DcError> {
    match &args.sub {
        QuoteSubcommands::Generate {
            kernel,
            initramfs,
            binary,
            evidence_tag,
            nonce,
            out,
        } => cmd_generate(&GenerateArgs {
            kernel: kernel.clone(),
            initramfs: initramfs.clone(),
            binary: binary.clone(),
            evidence_tag: evidence_tag.clone().unwrap_or_default(),
            nonce: nonce.clone(),
            out: out.clone(),
        }),
        QuoteSubcommands::Verify { file } => cmd_verify(&VerifyArgs { file: file.clone() }),
    }
}

fn cmd_generate(args: &GenerateArgs) -> Result<(), DcError> {
    let transport =
        TpmRmTransport::open().map_err(|e| DcError::Internal(format!("TPM unavailable: {e}")))?;
    let mut transport = transport;
    let mut attestor = TpmAttestor::new(&mut transport, DC_AIK_PERSISTENT_HANDLE)
        .map_err(|e| DcError::Internal(format!("AIK provisioning failed: {e}")))?;

    // Measure the artifacts into PCRs 8-11 (missing files are skipped and
    // visible as unchanged PCRs in the bundle).
    attestor
        .measure_artifacts(
            args.kernel.as_deref(),
            args.initramfs.as_deref(),
            args.binary.as_deref(),
            args.evidence_tag.as_bytes(),
        )
        .map_err(|e| DcError::Internal(format!("PCR measurement failed: {e}")))?;

    // Nonce: caller-supplied hex, or fresh run-bound entropy.
    let nonce: Vec<u8> = match &args.nonce {
        Some(hexstr) => hex::decode(hexstr).map_err(|e| DcError::Usage(format!("--nonce: {e}")))?,
        None => run_bound_nonce().to_vec(),
    };

    let bundle = attestor
        .generate_quote(&nonce)
        .map_err(|e| DcError::Internal(format!("TPM2_Quote failed or failed verification: {e}")))?;

    let json = serde_json::to_string_pretty(&bundle)
        .map_err(|e| DcError::Internal(format!("serialize bundle: {e}")))?;
    match &args.out {
        Some(path) => std::fs::write(path, &json)
            .map_err(|e| DcError::Internal(format!("write {}: {e}", path.display())))?,
        None => println!("{json}"),
    }
    eprintln!(
        "[ok] TPM2_Quote generated, locally verified, and archived (nonce {}…)",
        &bundle.nonce_hex[..12.min(bundle.nonce_hex.len())]
    );
    Ok(())
}

fn cmd_verify(ver: &VerifyArgs) -> Result<(), DcError> {
    let json = std::fs::read_to_string(&ver.file)
        .map_err(|e| DcError::Usage(format!("read {}: {e}", ver.file.display())))?;
    let bundle: QuoteBundle = serde_json::from_str(&json)
        .map_err(|e| DcError::Usage(format!("parse quote bundle: {e}")))?;
    match verify_bundle(&bundle) {
        Ok(true) => {
            println!("TPM quote VERIFIED:");
            println!("  magic                {}", bundle.attestation.magic_hex);
            println!(
                "  type                 {}",
                bundle.attestation.attest_type_hex
            );
            println!(
                "  PCR digest           {}…",
                &bundle.pcr_digest_hex[..16.min(bundle.pcr_digest_hex.len())]
            );
            println!(
                "  nonce                {}…",
                &bundle.nonce_hex[..16.min(bundle.nonce_hex.len())]
            );
            println!(
                "  clock/reset/restart  {}/{}/{}",
                bundle.tpm_clock, bundle.tpm_reset_count, bundle.tpm_restart_count
            );
            println!(
                "  signature            ECDSA-P256 (AIK x={}…)",
                &bundle.aik_x_hex[..12.min(bundle.aik_x_hex.len())]
            );
            Ok(())
        }
        Ok(false) => Err(DcError::Internal("quote did not verify".into())),
        Err(e) => Err(DcError::Internal(format!("verification FAILED: {e}"))),
    }
}

/// CLI argument surface (constructed by clap in `lib.rs`).
pub struct GenerateArgs {
    pub kernel: Option<std::path::PathBuf>,
    pub initramfs: Option<std::path::PathBuf>,
    pub binary: Option<std::path::PathBuf>,
    pub evidence_tag: String,
    pub nonce: Option<String>,
    pub out: Option<std::path::PathBuf>,
}

pub struct VerifyArgs {
    pub file: std::path::PathBuf,
}

/// Convert a `QuoteBundle` into certificate evidence.
pub fn bundle_to_evidence(bundle: &QuoteBundle) -> dc_cert::TpmAttestationEvidence {
    dc_cert::TpmAttestationEvidence {
        nonce_hex: bundle.nonce_hex.clone(),
        pcr_mask_hex: bundle.pcr_mask_hex.clone(),
        pcr_values_hex: bundle.pcr_values_hex.clone(),
        pcr_digest_hex: bundle.pcr_digest_hex.clone(),
        quote_response_hex: bundle.quote_response_hex.clone(),
        aik_x_hex: bundle.aik_x_hex.clone(),
        aik_y_hex: bundle.aik_y_hex.clone(),
        aik_public_template_hex: bundle.aik_public_template_hex.clone(),
        attestation: dc_cert::AttestationFields {
            magic_hex: bundle.attestation.magic_hex.clone(),
            attest_type_hex: bundle.attestation.attest_type_hex.clone(),
            qualified_signer_hex: bundle.attestation.qualified_signer_hex.clone(),
            firmware_version: bundle.attestation.firmware_version,
            clock_safe: bundle.attestation.clock_safe,
        },
        signature_r_hex: bundle.signature_r_hex.clone(),
        signature_s_hex: bundle.signature_s_hex.clone(),
        tpm_clock: bundle.tpm_clock,
        tpm_reset_count: bundle.tpm_reset_count,
        tpm_restart_count: bundle.tpm_restart_count,
        locally_verified: bundle.locally_verified,
    }
}

/// Opportunistic quote capture for the purge/execute certificate path:
/// returns None (with a stderr note) when the host has no TPM — unless
/// `required`, in which case it is a hard refusal.
pub fn capture_for_certificate(required: bool) -> Result<Option<QuoteBundle>, DcError> {
    let transport = match TpmRmTransport::open() {
        Ok(t) => t,
        Err(e) if !required => {
            eprintln!(
                "[note] no TPM 2.0 device ({e}); certificate continues without hardware attestation"
            );
            return Ok(None);
        }
        Err(e) => {
            return Err(DcError::Internal(format!(
                "--tpm-quote-required: refusing to certify without hardware attestation: {e}"
            )));
        }
    };
    let mut transport = transport;
    let mut attestor = TpmAttestor::new(&mut transport, DC_AIK_PERSISTENT_HANDLE)
        .map_err(|e| DcError::Internal(format!("AIK provisioning failed: {e}")))?;
    let nonce = run_bound_nonce();
    let bundle = attestor
        .generate_quote(&nonce)
        .map_err(|e| DcError::Internal(format!("TPM2_Quote failed: {e}")))?;
    eprintln!("[ok] TPM2_Quote captured and locally verified for the certificate");
    Ok(Some(bundle))
}

/// Fresh, run-bound nonce: BLAKE3(time ‖ pid ‖ clock ticks).
fn run_bound_nonce() -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            .to_le_bytes(),
    );
    h.update(&std::process::id().to_le_bytes());
    h.update(crate::chrono_now_iso().as_bytes());
    h.update(&monotonic_ticks());
    h.finalize().into()
}

fn monotonic_ticks() -> [u8; 8] {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    (start.elapsed().as_nanos() as u64).to_le_bytes()
}
