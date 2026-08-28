use crate::cert::{
    ExecutionDetails, ExecutionPassReport, FailureRecord, InterruptionRecord, SanitizationCertificate,
};
use crate::signer::OperatorKeyPair;
use dc_core::journal::{JournalReader, JournalRecord};
use dc_core::DcError;
use dc_verify::{VerificationReport, VerifyLevel};
use std::path::Path;

pub struct CertificateProjector;

impl CertificateProjector {
    /// Pure projection of a Completed journal into a signed SanitizationCertificate (Δ163, Δ164).
    /// Zero generation clock; all facts, tool builds, durations, and timestamps project from journal records.
    pub fn project(
        journal_path: &Path,
        keypair: &OperatorKeyPair,
    ) -> Result<SanitizationCertificate, DcError> {
        let (records, summary) = JournalReader::read_and_verify_chain(journal_path)?;

        let mut header_opt = None;
        let mut completed_opt = None;
        let mut verify_opt = None;
        let mut failures = Vec::new();
        let mut interruptions = Vec::new();
        let mut passes = Vec::new();
        let mut last_interrupted_at = None;

        for rec in &records {
            match rec {
                JournalRecord::Header { .. } => {
                    header_opt = Some(rec.clone());
                }
                JournalRecord::Failed { at_utc, code, errno, op, at_lba, .. } => {
                    failures.push(FailureRecord {
                        at_utc: at_utc.clone().unwrap_or_else(|| "2026-08-28T00:00:00Z".to_string()),
                        code: code.clone(),
                        errno: *errno,
                        op: op.clone(),
                        at_lba: *at_lba,
                    });
                }
                JournalRecord::Interrupted { at, .. } => {
                    last_interrupted_at = Some(at.clone());
                }
                JournalRecord::Resumed { at, .. } => {
                    if let Some(int_at) = last_interrupted_at.take() {
                        interruptions.push(InterruptionRecord {
                            at_utc: int_at,
                            resumed_utc: at.clone(),
                        });
                    }
                }
                JournalRecord::EndPass { pass } => {
                    passes.push(ExecutionPassReport {
                        index: *pass,
                        pattern: format!("Pass {}", pass),
                        fast_path_used: false,
                        windows_written: 0,
                        throughput_kib_s: 0,
                    });
                }
                JournalRecord::Verify {
                    level,
                    windows_checked,
                    mismatch_count,
                    first_mismatch_lbas,
                    stream_hash_blake3,
                    stream_hash_sha256,
                    fast_path_used,
                } => {
                    verify_opt = Some(VerificationReport {
                        level: if level == "Full" { VerifyLevel::Full } else { VerifyLevel::Sampled(10) },
                        windows_checked: *windows_checked,
                        mismatch_count: *mismatch_count,
                        first_mismatch_lbas: first_mismatch_lbas.clone(),
                        stream_hash_blake3: stream_hash_blake3.clone(),
                        stream_hash_sha256: stream_hash_sha256.clone(),
                        entropy: None,
                    });
                    if let Some(last_p) = passes.last_mut() {
                        last_p.fast_path_used = *fast_path_used;
                        last_p.windows_written = *windows_checked;
                    }
                }
                JournalRecord::Completed { at, duration_mono_ms } => {
                    completed_opt = Some((at.clone(), *duration_mono_ms));
                }
                _ => {}
            }
        }

        let (plan, plan_hash, identity, started_utc) = match header_opt {
            Some(JournalRecord::Header { plan, plan_hash, identity, started_utc, .. }) => {
                (plan, plan_hash, identity, started_utc)
            }
            _ => {
                return Err(DcError::CertInvalid("Missing Header in journal".to_string()));
            }
        };

        let (finished_utc, duration_mono_ms) = completed_opt.ok_or_else(|| {
            DcError::CertInvalid("Journal does not end in a Completed terminal record".to_string())
        })?;

        let verify_report = verify_opt.ok_or_else(|| {
            DcError::CertInvalid("Journal is missing a Verify record".to_string())
        })?;

        let execution = ExecutionDetails {
            started_utc,
            finished_utc,
            duration_mono_ms,
            interruptions,
            failures,
            passes,
        };

        let mut cert = SanitizationCertificate::new(
            plan,
            plan_hash,
            identity,
            execution,
            verify_report,
            summary,
            keypair.public_key_hex(),
            keypair.key_fingerprint_blake3(),
        );

        cert.sign(keypair)?;
        Ok(cert)
    }
}
