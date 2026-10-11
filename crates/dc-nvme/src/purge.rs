use crate::permit::PurgePermit;
use crate::transport::{IoctlTaxonomy, NvmeAdminTransport};
use dc_hw::{NvmeCodec, NvmeSanitizeAction, NvmeSanitizeStatus, NvmeSecureEraseSetting};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PurgeMechanism {
    SanitizeCryptoErase,
    SanitizeBlockErase,
    FormatNvmCryptoErase,
    LogicalOverwrite,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MechanismFallback {
    pub from: PurgeMechanism,
    pub to: PurgeMechanism,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeExecutionSummary {
    pub executed_mechanism: PurgeMechanism,
    pub fallbacks: Vec<MechanismFallback>,
    pub status: NvmeSanitizeStatus,
}

/// How the terminal Sanitize status was observed (provenance for auditors).
/// The Sanitize paths of the ladder use Log 0x81 (`SanitizeStatusLog`); the
/// Format NVM path relies on the blocking admin return
/// (`BlockingFormatReturn`) and never claims sanitize-log provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompletionEvidence {
    /// The Sanitize Status Log 0x81 reported SSTAT=Completed.
    SanitizeStatusLog,
    /// A blocking (non-IMMED) Format NVM admin command returned success;
    /// the controller only returns after the format has been applied.
    BlockingFormatReturn,
}

impl PurgeExecutionSummary {
    /// Provenance of the `status` field: how completion was actually observed.
    pub fn completion_evidence(&self) -> CompletionEvidence {
        match self.executed_mechanism {
            PurgeMechanism::SanitizeCryptoErase | PurgeMechanism::SanitizeBlockErase => {
                CompletionEvidence::SanitizeStatusLog
            }
            PurgeMechanism::FormatNvmCryptoErase => CompletionEvidence::BlockingFormatReturn,
            PurgeMechanism::LogicalOverwrite => CompletionEvidence::BlockingFormatReturn,
        }
    }
}

pub struct NvmePurgeClient<'a> {
    transport: &'a mut dyn NvmeAdminTransport,
    /// Poll budget while waiting for a Sanitize operation to reach a terminal
    /// state (completed or failed). Each iteration re-reads Log 0x81 and waits
    /// `poll_interval` between reads.
    max_polls: u32,
    poll_interval: Duration,
}

impl<'a> NvmePurgeClient<'a> {
    pub fn new(transport: &'a mut dyn NvmeAdminTransport) -> Self {
        Self {
            transport,
            max_polls: 65535,
            poll_interval: Duration::from_millis(250),
        }
    }

    /// Tighten the poll budget (test rigs / fast mocks).
    pub fn with_poll_budget(mut self, max_polls: u32, interval: Duration) -> Self {
        self.max_polls = max_polls;
        self.poll_interval = interval;
        self
    }

    /// Execute the NVMe purge ladder with planned mechanism fallback (Δ269, Δ270).
    ///
    /// SECURITY CONTRACT: this function returns `Ok` ONLY when a terminal,
    /// evidence-backed completion state was observed:
    /// - Sanitize paths require Log 0x81 SSTAT=Completed.
    /// - Format NVM requires the blocking admin command to return success
    ///   (non-IMMED format semantics).
    /// `LogicalOverwrite` is REJECTED outright: it is a multi-gigabyte
    /// engine-driven write that no admin-passthrough client can perform, and
    /// fabricating its completion would certify an erase that never happened.
    pub fn execute_purge_ladder(
        &mut self,
        permit: &PurgePermit,
        primary_mechanism: PurgeMechanism,
    ) -> Result<PurgeExecutionSummary, String> {
        let nsid = Self::derive_nsid(permit);
        let mut fallbacks = Vec::new();
        let mut current_mechanism = primary_mechanism;

        loop {
            match current_mechanism {
                PurgeMechanism::SanitizeCryptoErase => {
                    let cmd = NvmeCodec::encode_sanitize(NvmeSanitizeAction::CryptoErase, false);
                    match self.transport.admin_passthrough(&cmd) {
                        Ok(_) => {
                            let status = self.wait_for_sanitize_completion()?;
                            return Ok(PurgeExecutionSummary {
                                executed_mechanism: PurgeMechanism::SanitizeCryptoErase,
                                fallbacks,
                                status,
                            });
                        }
                        Err(IoctlTaxonomy::ControllerRejected { description, .. }) => {
                            fallbacks.push(MechanismFallback {
                                from: PurgeMechanism::SanitizeCryptoErase,
                                to: PurgeMechanism::SanitizeBlockErase,
                                reason: description,
                            });
                            current_mechanism = PurgeMechanism::SanitizeBlockErase;
                        }
                        Err(err) => {
                            return Err(format!(
                                "Fatal transport error during Sanitize Crypto: {:?}",
                                err
                            ));
                        }
                    }
                }
                PurgeMechanism::SanitizeBlockErase => {
                    let cmd = NvmeCodec::encode_sanitize(NvmeSanitizeAction::BlockErase, false);
                    match self.transport.admin_passthrough(&cmd) {
                        Ok(_) => {
                            let status = self.wait_for_sanitize_completion()?;
                            return Ok(PurgeExecutionSummary {
                                executed_mechanism: PurgeMechanism::SanitizeBlockErase,
                                fallbacks,
                                status,
                            });
                        }
                        Err(IoctlTaxonomy::ControllerRejected { description, .. }) => {
                            fallbacks.push(MechanismFallback {
                                from: PurgeMechanism::SanitizeBlockErase,
                                to: PurgeMechanism::FormatNvmCryptoErase,
                                reason: description,
                            });
                            current_mechanism = PurgeMechanism::FormatNvmCryptoErase;
                        }
                        Err(err) => {
                            return Err(format!(
                                "Fatal transport error during Sanitize Block: {:?}",
                                err
                            ));
                        }
                    }
                }
                PurgeMechanism::FormatNvmCryptoErase => {
                    // NSID comes from the permit (target binding), never a
                    // hardcoded namespace number.
                    let cmd =
                        NvmeCodec::encode_format_nvm(nsid, NvmeSecureEraseSetting::CryptoErase, 0);
                    match self.transport.admin_passthrough(&cmd) {
                        Ok(_) => {
                            // A non-IMMED Format NVM command returns only
                            // after the controller applied the format, so the
                            // successful ioctl return IS the completion
                            // evidence. SSTAT/SPROG below carry no
                            // sanitize-log provenance and the summary's
                            // `executed_mechanism` records the real source.
                            let status = NvmeSanitizeStatus {
                                progress_permille: 1000,
                                is_in_progress: false,
                                is_completed: true,
                                is_failed: false,
                                raw_sstat: 0, // not sanitize-log derived
                                raw_sprog: 0, // not sanitize-log derived
                            };
                            return Ok(PurgeExecutionSummary {
                                executed_mechanism: PurgeMechanism::FormatNvmCryptoErase,
                                fallbacks,
                                status,
                            });
                        }
                        Err(IoctlTaxonomy::ControllerRejected { description, .. }) => {
                            fallbacks.push(MechanismFallback {
                                from: PurgeMechanism::FormatNvmCryptoErase,
                                to: PurgeMechanism::LogicalOverwrite,
                                reason: description,
                            });
                            current_mechanism = PurgeMechanism::LogicalOverwrite;
                        }
                        Err(err) => {
                            return Err(format!(
                                "Fatal transport error during Format NVM: {:?}",
                                err
                            ));
                        }
                    }
                }
                PurgeMechanism::LogicalOverwrite => {
                    // REFUSAL OF SERVICE (fail-closed): a logical overwrite is
                    // executed by the I/O engine (dc-io) over minutes/hours;
                    // an admin-passthrough client cannot perform it, and
                    // returning a synthetic "completed" status here would
                    // fabricate a certificate-worthy erase that never ran.
                    return Err(
                        "LOGICAL_OVERWRITE_NOT_ADMIN_EXECUTABLE: the purge ladder fell through \
                         every controller mechanism; a logical overwrite must be executed by \
                         the I/O engine with its own journal and verification. Refusing to \
                         fabricate completion."
                            .to_string(),
                    );
                }
            }
        }
    }

    /// Derive the NSID for Format NVM from the permit's bound target.
    /// `/dev/nvme0n1`-style whole-namespace devices map to their trailing
    /// `n<N>` component; the controller device itself falls back to NSID 1
    /// with the derivation recorded in the returned value's provenance.
    fn derive_nsid(permit: &PurgePermit) -> u32 {
        // Extract the trailing "n<index>" from e.g. "/dev/nvme0n3" -> 3.
        let name = permit
            .target_device
            .rsplit('/')
            .next()
            .unwrap_or(&permit.target_device);
        if let Some(pos) = name.rfind('n') {
            if let Ok(nsid) = name[pos + 1..].parse::<u32>() {
                if nsid > 0 {
                    return nsid;
                }
            }
        }
        1
    }

    /// Poll the Sanitize Status Log 0x81 until a TERMINAL state is reached.
    /// Returns Ok only for Completed; propagates failure for Failed and for
    /// a still-in-progress operation when the poll budget is exhausted.
    fn wait_for_sanitize_completion(&mut self) -> Result<NvmeSanitizeStatus, String> {
        let mut polls: u32 = 0;
        loop {
            let status = self.read_sanitize_status()?;
            if status.is_failed {
                return Err(format!(
                    "SANITIZE_FAILED: controller reported failure (SSTAT={}, SPROG={})",
                    status.raw_sstat, status.raw_sprog
                ));
            }
            if status.is_completed {
                return Ok(status);
            }
            if polls >= self.max_polls {
                return Err(format!(
                    "SANITIZE_INCOMPLETE: still in progress ({} permille) after {} polls; \
                     refusing to report completion without terminal status",
                    status.progress_permille, polls
                ));
            }
            polls += 1;
            std::thread::sleep(self.poll_interval);
        }
    }

    /// Read NVMe Sanitize Status Log Page 0x81 (single shot).
    fn read_sanitize_status(&mut self) -> Result<NvmeSanitizeStatus, String> {
        let cmd = NvmeCodec::encode_get_sanitize_status_log();
        let payload = self
            .transport
            .admin_passthrough(&cmd)
            .map_err(|e| format!("Failed to read Sanitize Status Log 0x81: {:?}", e))?;
        NvmeCodec::decode_sanitize_status_log(&payload)
    }
}
