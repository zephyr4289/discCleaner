//! `dc-scsi` purge — the SAS/SCSI hardware purge ladder (v0.6.0).
//!
//! Executes firmware-level purges on SAS enterprise drives and SAN arrays
//! over the REAL Linux SG_IO transport:
//!
//! 1. SANITIZE (SPC-4 §6.34, opcode 0x48) — ALWAYS issued with IMMED=1
//!    (the non-blocking law, Δ288: a blocking sanitize wedges the SG_IO
//!    queue behind a firmware operation the operator cannot cancel).
//! 2. REAL-TIME PROGRESS: REQUEST SENSE polls observe sense key 0x02
//!    (NOT READY) / ASC 0x04 with the SKS progress field — the live
//!    firmware percentage auditors ask for.
//! 3. THE LADDER (planned fallback, controller-rejected only):
//!    SANITIZE Crypto Erase -> SANITIZE Block Erase -> FORMAT UNIT
//!    (FMTDATA=0 — no defect-list obligation, Δxxx REG-SCSI-FMTDATA) as
//!    the blocking last resort whose successful return IS completion.
//! 4. Terminal evidence: sanitize completion surfaces as UNIT ATTENTION
//!    0x29/0x00 (POWER ON OR RESET OCCURRED) or NO SENSE; a failed
//!    sanitize surfaces as NOT READY 0x02/ASC 0x31.
//! 5. G-LIST AUDIT: READ DEFECT DATA (10) grown-list header query feeds
//!    the reallocated-sector defense disclosure (v0.6.0,
//!    REG-SMART-GLIST-DISCLOSURE).

use dc_hw::{
    ScsiCodec, ScsiSanitizeServiceAction, ScsiSenseData, SgIoDevice, SG_DXFER_FROM_DEV,
    SG_DXFER_NONE, SG_DXFER_TO_DEV,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// Timeout for the IMMED=1 SANITIZE issue itself (returns immediately).
pub const SANITIZE_ISSUE_TIMEOUT_MS: u32 = 60_000;
/// Timeout for the blocking FORMAT UNIT last resort.
pub const FORMAT_UNIT_TIMEOUT_MS: u32 = 24 * 60 * 60 * 1000;
/// Timeout for REQUEST SENSE / READ DEFECT DATA probes.
pub const PROBE_TIMEOUT_MS: u32 = 30_000;
/// REQUEST SENSE allocation: fixed-format sense with SKS progress needs
/// at least 18 bytes.
pub const REQUEST_SENSE_ALLOC: u8 = 32;

/// ASCQ for "LOGICAL UNIT NOT READY, SANITIZE IN PROGRESS" (SBC).
pub const ASCQ_SANITIZE_IN_PROGRESS: u8 = 0x0B;
/// ASC for "LOGICAL UNIT NOT READY" family.
pub const ASC_LU_NOT_READY: u8 = 0x04;
/// ASC for "LOGICAL UNIT NOT READY, SANITIZE FAILED" family.
pub const ASC_SANITIZE_FAILED: u8 = 0x31;
/// ASC 0x29 / ASCQ 0x00 — POWER ON OR RESET OCCURRED: the UNIT ATTENTION
/// that surfaces when a sanitize completes.
pub const ASC_POWER_ON_RESET: u8 = 0x29;

/// Typestate token authorizing destructive SCSI purge execution (INV11,
/// Δ272) — the SAS mirror of `dc-nvme`'s PurgePermit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScsiPurgePermit {
    pub target_device: String,
    pub target_wwn: String,
    pub authorized_at_utc: u64,
}

impl ScsiPurgePermit {
    pub fn mint(target_device: &str, target_wwn: &str, timestamp_utc: u64) -> Self {
        Self {
            target_device: target_device.to_string(),
            target_wwn: target_wwn.to_string(),
            authorized_at_utc: timestamp_utc,
        }
    }
}

/// Transfer phase of one SCSI exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScsiXfer {
    None,
    FromDev(usize),
    ToDev(Vec<u8>),
}

/// One completed exchange (transport-healthy; CHECK CONDITION is a REPLY).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScsiReply {
    pub status: u8,
    pub sense: Vec<u8>,
    pub data_in: Vec<u8>,
}

impl ScsiReply {
    pub fn good() -> Self {
        Self {
            status: 0x00,
            sense: Vec::new(),
            data_in: Vec::new(),
        }
    }

    pub fn is_good(&self) -> bool {
        self.status == 0x00
    }
}

/// Transport abstraction: production rides SG_IO on the locked block
/// node; test rigs script replies CDB-by-CDB.
pub trait ScsiPurgeTransport: Send {
    fn issue(&mut self, cdb: &[u8], xfer: ScsiXfer, timeout_ms: u32) -> Result<ScsiReply, String>;
}

/// Production transport: SG_IO ioctl on the block device node
/// (character /dev/sg* nodes are refused — Δ330, REG-SCSI-SG-NODE).
pub struct LinuxScsiPurge {
    dev: SgIoDevice,
}

impl LinuxScsiPurge {
    pub fn open(path: &Path) -> Result<Self, String> {
        let dev = SgIoDevice::open_block_node(path).map_err(|e| e.to_string())?;
        Ok(Self { dev })
    }

    pub fn path(&self) -> &str {
        self.dev.path()
    }
}

impl ScsiPurgeTransport for LinuxScsiPurge {
    fn issue(&mut self, cdb: &[u8], xfer: ScsiXfer, timeout_ms: u32) -> Result<ScsiReply, String> {
        let result = match xfer {
            ScsiXfer::None => self
                .dev
                .execute(cdb, SG_DXFER_NONE, &mut [], timeout_ms)
                .map_err(|e| format!("SG_IO transport fault: {}", e))?,
            ScsiXfer::FromDev(n) => {
                let mut buf = vec![0u8; n];
                self.dev
                    .execute(cdb, SG_DXFER_FROM_DEV, &mut buf, timeout_ms)
                    .map_err(|e| format!("SG_IO transport fault: {}", e))?
            }
            ScsiXfer::ToDev(ref payload) => {
                let mut buf = payload.clone();
                self.dev
                    .execute(cdb, SG_DXFER_TO_DEV, &mut buf, timeout_ms)
                    .map_err(|e| format!("SG_IO transport fault: {}", e))?
            }
        };
        Ok(ScsiReply {
            status: result.status,
            sense: result.sense,
            data_in: result.data_in,
        })
    }
}

/// Purge mechanisms of the SCSI ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScsiPurgeMechanism {
    /// SANITIZE Crypto Erase (service action 0x03): the controller
    /// cryptographically erases the media (key destroy).
    SanitizeCryptoErase,
    /// SANITIZE Block Erase (service action 0x02): electrical erase of
    /// all user data blocks.
    SanitizeBlockErase,
    /// FORMAT UNIT (FMTDATA=0): re-initializes the medium; blocking
    /// last resort.
    FormatUnit,
}

impl ScsiPurgeMechanism {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SanitizeCryptoErase => "SCSI Sanitize Crypto Erase",
            Self::SanitizeBlockErase => "SCSI Sanitize Block Erase",
            Self::FormatUnit => "SCSI Format Unit (FMTDATA=0)",
        }
    }

    pub fn nist_class(&self) -> &'static str {
        match self {
            Self::SanitizeCryptoErase | Self::SanitizeBlockErase => "Purge",
            Self::FormatUnit => "Purge",
        }
    }
}

/// How terminal completion was observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScsiCompletionEvidence {
    /// REQUEST SENSE observed a terminal transition: UNIT ATTENTION
    /// 0x29/0x00 after in-progress reporting, or NO SENSE with the
    /// not-ready condition cleared.
    SensePollTerminal,
    /// The blocking (non-IMMED) FORMAT UNIT command returned successfully.
    BlockingFormatReturn,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScsiMechanismFallback {
    pub from: String,
    pub to: String,
    pub reason: String,
}

/// Execution summary mirroring `dc-nvme`'s PurgeExecutionSummary so
/// `dc purge` certificates are transport-uniform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScsiPurgeExecutionSummary {
    pub executed_mechanism: ScsiPurgeMechanism,
    pub fallbacks: Vec<ScsiMechanismFallback>,
    pub completion_evidence: ScsiCompletionEvidence,
    /// Last observed progress in permille (1000 = done).
    pub progress_permille: u16,
    /// Grown-defect (G-List) count queried before the purge (defense
    /// disclosure input; None when the drive does not expose it).
    pub grown_defects_pre: Option<u64>,
    /// Final REQUEST SENSE snapshot at terminal state (audit provenance).
    pub terminal_sense: ScsiSenseData,
}

/// The purge client.
pub struct ScsiPurgeClient<'a> {
    transport: &'a mut dyn ScsiPurgeTransport,
    max_polls: u32,
    poll_interval: Duration,
    progress_sink: Option<Box<dyn FnMut(u16) + 'a>>,
}

impl<'a> ScsiPurgeClient<'a> {
    pub fn new(transport: &'a mut dyn ScsiPurgeTransport) -> Self {
        Self {
            transport,
            max_polls: 24 * 60 * 4, // 24h at 250ms spacing
            poll_interval: Duration::from_millis(250),
            progress_sink: None,
        }
    }

    /// Tighten the poll budget (test rigs / fast mocks).
    pub fn with_poll_budget(mut self, max_polls: u32, interval: Duration) -> Self {
        self.max_polls = max_polls;
        self.poll_interval = interval;
        self
    }

    /// Attach a progress sink for the sanitize poll loop.
    pub fn with_progress_sink(mut self, sink: impl FnMut(u16) + 'a) -> Self {
        self.progress_sink = Some(Box::new(sink));
        self
    }

    // -----------------------------------------------------------------
    // Non-destructive probes
    // -----------------------------------------------------------------

    /// Read the standard INQUIRY identity (vendor / product / firmware
    /// revision) — the SAS firmware attestation probe (v0.7.0, Vector 4).
    pub fn identify(&mut self) -> Result<dc_hw::ScsiInquiryIdentity, String> {
        let cdb = dc_hw::ScsiCodec::encode_inquiry(36);
        let reply = self
            .transport
            .issue(&cdb, ScsiXfer::FromDev(36), PROBE_TIMEOUT_MS)?;
        if !reply.is_good() {
            return Err(format!(
                "INQUIRY failed: SCSI status 0x{:02X}",
                reply.status
            ));
        }
        dc_hw::ScsiCodec::decode_inquiry_identity(&reply.data_in)
    }

    /// Read the drive temperature via LOG SENSE page 0x0D (parameter
    /// 0x0000, current) — the SAS thermal probe (v0.7.0, Vector 2).
    pub fn read_temperature(&mut self) -> Result<dc_hw::thermal::ThermalReading, String> {
        let cdb = dc_hw::ScsiCodec::encode_log_sense_temperature();
        let reply = self
            .transport
            .issue(&cdb, ScsiXfer::FromDev(32), PROBE_TIMEOUT_MS)?;
        if !reply.is_good() {
            return Err(format!(
                "LOG SENSE (0x0D) failed: SCSI status 0x{:02X}",
                reply.status
            ));
        }
        dc_hw::thermal::decode_log_sense_temperature(&reply.data_in)
    }

    /// Query the grown defect (G-List) count via READ DEFECT DATA (10):
    /// a header-only round-trip; count = list length / 8-byte descriptors.
    pub fn read_grown_defects(&mut self) -> Result<u64, String> {
        let cdb = ScsiCodec::encode_read_defect_data(true, 4);
        let reply = self
            .transport
            .issue(&cdb, ScsiXfer::FromDev(4), PROBE_TIMEOUT_MS)?;
        if !reply.is_good() {
            return Err(format!(
                "READ DEFECT DATA failed: SCSI status 0x{:02X}",
                reply.status
            ));
        }
        ScsiCodec::decode_defect_list_count(&reply.data_in)
    }

    /// One REQUEST SENSE round-trip, decoded.
    fn request_sense(&mut self) -> Result<ScsiSenseData, String> {
        let cdb = ScsiCodec::encode_request_sense(REQUEST_SENSE_ALLOC);
        let reply = self.transport.issue(
            &cdb,
            ScsiXfer::FromDev(REQUEST_SENSE_ALLOC as usize),
            PROBE_TIMEOUT_MS,
        )?;
        if reply.sense.is_empty() {
            // NO SENSE at all: the LUN is idle.
            return Ok(ScsiSenseData {
                sense_key: 0x00,
                asc: 0x00,
                ascq: 0x00,
                progress_permille: None,
            });
        }
        ScsiCodec::decode_sense_data(&reply.sense)
    }

    // -----------------------------------------------------------------
    // The ladder
    // -----------------------------------------------------------------

    /// Execute the SCSI purge ladder with planned fallback.
    ///
    /// SECURITY CONTRACT: `Ok` is returned ONLY when a terminal,
    /// evidence-backed completion state was observed (sense-poll terminal
    /// transition for sanitize paths; blocking return for FORMAT UNIT).
    /// Transport faults are fatal; only a controller REJECTION walks the
    /// ladder down.
    pub fn execute_purge_ladder(
        mut self,
        permit: &ScsiPurgePermit,
        requested: Option<ScsiPurgeMechanism>,
    ) -> Result<ScsiPurgeExecutionSummary, String> {
        // G-List audit (best-effort; drives may not expose the list).
        let grown_defects_pre = self.read_grown_defects().ok();

        let mut fallbacks: Vec<ScsiMechanismFallback> = Vec::new();
        let mut current = requested.unwrap_or(ScsiPurgeMechanism::SanitizeCryptoErase);

        loop {
            match current {
                ScsiPurgeMechanism::SanitizeCryptoErase => {
                    match self.run_sanitize(ScsiSanitizeServiceAction::CryptoErase) {
                        Ok((progress, terminal)) => {
                            return Ok(ScsiPurgeExecutionSummary {
                                executed_mechanism: ScsiPurgeMechanism::SanitizeCryptoErase,
                                fallbacks,
                                completion_evidence: ScsiCompletionEvidence::SensePollTerminal,
                                progress_permille: progress,
                                grown_defects_pre,
                                terminal_sense: terminal,
                            });
                        }
                        Err(SanitizeStepOutcome::Rejected(reason)) => {
                            fallbacks.push(ScsiMechanismFallback {
                                from: "SanitizeCryptoErase".into(),
                                to: "SanitizeBlockErase".into(),
                                reason,
                            });
                            current = ScsiPurgeMechanism::SanitizeBlockErase;
                        }
                        Err(SanitizeStepOutcome::Fatal(reason)) => return Err(reason),
                    }
                }
                ScsiPurgeMechanism::SanitizeBlockErase => {
                    match self.run_sanitize(ScsiSanitizeServiceAction::BlockErase) {
                        Ok((progress, terminal)) => {
                            return Ok(ScsiPurgeExecutionSummary {
                                executed_mechanism: ScsiPurgeMechanism::SanitizeBlockErase,
                                fallbacks,
                                completion_evidence: ScsiCompletionEvidence::SensePollTerminal,
                                progress_permille: progress,
                                grown_defects_pre,
                                terminal_sense: terminal,
                            });
                        }
                        Err(SanitizeStepOutcome::Rejected(reason)) => {
                            fallbacks.push(ScsiMechanismFallback {
                                from: "SanitizeBlockErase".into(),
                                to: "FormatUnit".into(),
                                reason,
                            });
                            current = ScsiPurgeMechanism::FormatUnit;
                        }
                        Err(SanitizeStepOutcome::Fatal(reason)) => return Err(reason),
                    }
                }
                ScsiPurgeMechanism::FormatUnit => {
                    // FMTDATA=0 framing (no parameter list obligation);
                    // blocking — the successful return is the evidence.
                    let cdb = ScsiCodec::encode_format_unit(false);
                    let reply = self
                        .transport
                        .issue(&cdb, ScsiXfer::None, FORMAT_UNIT_TIMEOUT_MS)
                        .map_err(|e| {
                            format!(
                                "FORMAT UNIT transport fault on {}: {} — media state \
                                 ambiguous, refusing to certify",
                                permit.target_device, e
                            )
                        })?;
                    if !reply.is_good() {
                        let sense = ScsiCodec::decode_sense_data(&reply.sense)
                            .map(|s| {
                                format!(
                                    "sense 0x{:02X}/0x{:02X}/0x{:02X}",
                                    s.sense_key, s.asc, s.ascq
                                )
                            })
                            .unwrap_or_else(|_| "undecodable sense".to_string());
                        return Err(format!(
                            "SCSI_LADDER_EXHAUSTED: FORMAT UNIT failed ({}) on {}; the \
                             controller rejected every firmware purge — use `dc execute` \
                             for a tool-verified logical overwrite",
                            sense, permit.target_device
                        ));
                    }
                    let terminal = self.request_sense().unwrap_or(ScsiSenseData {
                        sense_key: 0x00,
                        asc: 0x00,
                        ascq: 0x00,
                        progress_permille: None,
                    });
                    return Ok(ScsiPurgeExecutionSummary {
                        executed_mechanism: ScsiPurgeMechanism::FormatUnit,
                        fallbacks,
                        completion_evidence: ScsiCompletionEvidence::BlockingFormatReturn,
                        progress_permille: 1000,
                        grown_defects_pre,
                        terminal_sense: terminal,
                    });
                }
            }
        }
    }

    /// Issue one IMMED=1 SANITIZE and poll REQUEST SENSE to a terminal
    /// state. Progress is read from the sense-key-specific (SKS) field.
    fn run_sanitize(
        &mut self,
        action: ScsiSanitizeServiceAction,
    ) -> Result<(u16, ScsiSenseData), SanitizeStepOutcome> {
        // The non-blocking law (Δ288): sanitize is ALWAYS IMMED=1.
        let cdb = ScsiCodec::encode_sanitize(action, true);
        let reply = self
            .transport
            .issue(&cdb, ScsiXfer::None, SANITIZE_ISSUE_TIMEOUT_MS)
            .map_err(SanitizeStepOutcome::Fatal)?;
        if !reply.is_good() {
            if let Some(reason) = Self::illegal_request_reason(&reply) {
                return Err(SanitizeStepOutcome::Rejected(reason));
            }
            return Err(SanitizeStepOutcome::Fatal(format!(
                "SANITIZE (service action 0x{:02X}) failed at issue: SCSI status 0x{:02X}",
                action as u8, reply.status
            )));
        }

        let mut polls: u32 = 0;
        loop {
            let sense = self.request_sense().map_err(SanitizeStepOutcome::Fatal)?;

            // Terminal: UNIT ATTENTION 0x29/0x00 — the sanitize completion
            // signature (consumed by this read).
            if sense.sense_key == 0x06 && sense.asc == ASC_POWER_ON_RESET {
                return Ok((1000, sense));
            }
            // Terminal: NO SENSE — the not-ready condition cleared.
            if sense.sense_key == 0x00 {
                return Ok((1000, sense));
            }
            // Failed sanitize: NOT READY / ASC 0x31 family.
            if sense.sense_key == 0x02 && sense.asc == ASC_SANITIZE_FAILED {
                return Err(SanitizeStepOutcome::Fatal(format!(
                    "SANITIZE_FAILED: sense 0x{:02X}/0x{:02X}/0x{:02X}",
                    sense.sense_key, sense.asc, sense.ascq
                )));
            }
            // In progress: NOT READY / ASC 0x04 (any ASCQ — 0x0B is the
            // SBC-4 "sanitize in progress" qualifier).
            if sense.sense_key == 0x02 && sense.asc == ASC_LU_NOT_READY {
                let progress = sense.progress_permille.unwrap_or(0);
                if let Some(sink) = self.progress_sink.as_mut() {
                    sink(progress);
                }
                if polls >= self.max_polls {
                    return Err(SanitizeStepOutcome::Fatal(format!(
                        "SANITIZE_INCOMPLETE: still in progress ({} permille) after {} \
                         sense polls; refusing to report completion without terminal state",
                        progress, polls
                    )));
                }
                polls += 1;
                std::thread::sleep(self.poll_interval);
                continue;
            }
            // Anything else is unclassified — fail loud, never certify.
            return Err(SanitizeStepOutcome::Fatal(format!(
                "UNCLASSIFIED_SENSE during sanitize poll: 0x{:02X}/0x{:02X}/0x{:02X}",
                sense.sense_key, sense.asc, sense.ascq
            )));
        }
    }

    fn illegal_request_reason(reply: &ScsiReply) -> Option<String> {
        let (key, asc, ascq) = if reply.sense.len() >= 4 && (reply.sense[0] & 0x7F) == 0x72 {
            (reply.sense[1] & 0x0F, reply.sense[2], reply.sense[3])
        } else if reply.sense.len() >= 14 {
            (reply.sense[2] & 0x0F, reply.sense[12], reply.sense[13])
        } else {
            return None;
        };
        if key == 0x05 {
            Some(format!(
                "controller rejected: ILLEGAL REQUEST (sense 0x{:02X} 0x{:02X} 0x{:02X})",
                key, asc, ascq
            ))
        } else {
            None
        }
    }
}

enum SanitizeStepOutcome {
    /// Controller rejected the operation — ladder walks down.
    Rejected(String),
    /// Terminal failure or ambiguity — abort.
    Fatal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    type MockScsiMatcher = Box<dyn Fn(&[u8]) -> bool + Send>;

    struct MockScsi {
        script: RefCell<Vec<(MockScsiMatcher, ScsiReply)>>,
    }

    impl MockScsi {
        fn new() -> Self {
            Self {
                script: RefCell::new(Vec::new()),
            }
        }

        fn on(&self, matcher: impl Fn(&[u8]) -> bool + Send + 'static, reply: ScsiReply) -> &Self {
            self.script.borrow_mut().push((Box::new(matcher), reply));
            self
        }
    }

    impl ScsiPurgeTransport for MockScsi {
        fn issue(
            &mut self,
            cdb: &[u8],
            _xfer: ScsiXfer,
            _timeout_ms: u32,
        ) -> Result<ScsiReply, String> {
            let next = self.script.borrow_mut().remove(0);
            if !(next.0)(cdb) {
                return Err(format!(
                    "mock mismatch: CDB opcode 0x{:02X} unexpected",
                    cdb[0]
                ));
            }
            Ok(next.1)
        }
    }

    /// Fixed-format sense bytes: key/asc/ascq + SKS progress permille.
    fn fixed_sense(key: u8, asc: u8, ascq: u8, progress: Option<u16>) -> ScsiReply {
        let mut sense = vec![0u8; 18];
        sense[0] = 0x70; // fixed format, current errors
        sense[2] = key;
        if let Some(p) = progress {
            // SKS bit + progress fraction of 0x10000.
            sense[15] = 0x80;
            let raw = (p as u32 * 65536 / 1000) as u16;
            sense[16] = (raw >> 8) as u8;
            sense[17] = raw as u8;
        }
        sense[12] = asc;
        sense[13] = ascq;
        ScsiReply {
            status: 0x02,
            sense,
            data_in: Vec::new(),
        }
    }

    fn permit() -> ScsiPurgePermit {
        ScsiPurgePermit::mint("/dev/sdb", "naa.5000c500b2a12345", 1_700_000_000)
    }

    fn is_sanitize(action: u8, cdb: &[u8]) -> bool {
        cdb[0] == 0x48 && (cdb[1] & 0x1F) == action && (cdb[1] & 0x80) != 0
    }

    fn is_request_sense(cdb: &[u8]) -> bool {
        cdb[0] == 0x03
    }

    fn is_format_unit(cdb: &[u8]) -> bool {
        cdb[0] == 0x04 && (cdb[1] & 0x10) == 0
    }

    fn is_read_defect(cdb: &[u8]) -> bool {
        cdb[0] == 0x37 && (cdb[1] & 0x08) != 0
    }

    #[test]
    fn sanitize_crypto_completes_via_sense_progress_and_unit_attention() {
        let mock = MockScsi::new();
        mock.on(is_read_defect, ScsiReply::good())
            .on(|cdb| is_sanitize(0x03, cdb), ScsiReply::good())
            // 50% progress: NOT READY / ASC 0x04 / ASCQ 0x0B with SKS.
            .on(
                is_request_sense,
                fixed_sense(0x02, 0x04, ASCQ_SANITIZE_IN_PROGRESS, Some(500)),
            )
            // Terminal: UNIT ATTENTION 0x29/0x00.
            .on(
                is_request_sense,
                fixed_sense(0x06, ASC_POWER_ON_RESET, 0x00, None),
            );
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn ScsiPurgeTransport;
        let progress_seen = RefCell::new(Vec::new());
        let sink_seen = &progress_seen;
        let client = ScsiPurgeClient::new(transport)
            .with_poll_budget(8, Duration::from_millis(0))
            .with_progress_sink(move |p| sink_seen.borrow_mut().push(p));
        let summary = client
            .execute_purge_ladder(&permit(), None)
            .expect("sanitize crypto must complete");
        assert_eq!(
            summary.executed_mechanism,
            ScsiPurgeMechanism::SanitizeCryptoErase
        );
        assert_eq!(
            summary.completion_evidence,
            ScsiCompletionEvidence::SensePollTerminal
        );
        assert_eq!(summary.progress_permille, 1000);
        assert_eq!(*progress_seen.borrow(), vec![500], "live progress reported");
        assert_eq!(summary.terminal_sense.asc, ASC_POWER_ON_RESET);
    }

    #[test]
    fn controller_rejection_walks_to_block_erase_then_format_unit() {
        let mock = MockScsi::new();
        let reject_crypto = ScsiReply {
            status: 0x02,
            sense: {
                let mut s = vec![0u8; 14];
                s[0] = 0x70;
                s[2] = 0x05; // ILLEGAL REQUEST
                s[12] = 0x20; // invalid command operation code
                s
            },
            data_in: Vec::new(),
        };
        let reject_block = ScsiReply {
            status: 0x02,
            sense: {
                let mut s = vec![0u8; 14];
                s[0] = 0x70;
                s[2] = 0x05;
                s[12] = 0x24; // invalid field in CDB
                s
            },
            data_in: Vec::new(),
        };
        mock.on(is_read_defect, ScsiReply::good())
            .on(|cdb| is_sanitize(0x03, cdb), reject_crypto)
            .on(|cdb| is_sanitize(0x02, cdb), reject_block)
            // FORMAT UNIT succeeds blocking.
            .on(is_format_unit, ScsiReply::good())
            .on(is_request_sense, fixed_sense(0x00, 0x00, 0x00, None));
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn ScsiPurgeTransport;
        let summary = ScsiPurgeClient::new(transport)
            .execute_purge_ladder(&permit(), None)
            .expect("format unit fallback must complete");
        assert_eq!(summary.executed_mechanism, ScsiPurgeMechanism::FormatUnit);
        assert_eq!(
            summary.completion_evidence,
            ScsiCompletionEvidence::BlockingFormatReturn
        );
        assert_eq!(summary.fallbacks.len(), 2);
        assert_eq!(summary.fallbacks[0].to, "SanitizeBlockErase");
        assert_eq!(summary.fallbacks[1].to, "FormatUnit");
    }

    #[test]
    fn sanitize_failure_is_fatal_not_a_fallback() {
        let mock = MockScsi::new();
        mock.on(is_read_defect, ScsiReply::good())
            .on(|cdb| is_sanitize(0x03, cdb), ScsiReply::good())
            .on(
                is_request_sense,
                fixed_sense(0x02, ASC_SANITIZE_FAILED, 0x00, None),
            );
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn ScsiPurgeTransport;
        let err = ScsiPurgeClient::new(transport)
            .execute_purge_ladder(&permit(), None)
            .expect_err("sanitize failure must abort");
        assert!(err.contains("SANITIZE_FAILED"), "got: {}", err);
    }

    #[test]
    fn grown_defect_probe_counts_glist_entries() {
        let mock = MockScsi::new();
        // Header: defect list length 24 bytes = 3 descriptors of 8 bytes.
        let header = [0x00u8, 0x00, 0x00, 0x18];
        mock.on(
            is_read_defect,
            ScsiReply {
                status: 0x00,
                sense: Vec::new(),
                data_in: header.to_vec(),
            },
        );
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn ScsiPurgeTransport;
        let count = ScsiPurgeClient::new(transport)
            .read_grown_defects()
            .expect("READ DEFECT DATA must parse");
        assert_eq!(count, 3);
    }

    #[test]
    fn no_sense_is_terminal_not_infinite_poll() {
        let mock = MockScsi::new();
        mock.on(is_read_defect, ScsiReply::good())
            .on(|cdb| is_sanitize(0x03, cdb), ScsiReply::good())
            // Immediate NO SENSE: sanitize already done (fast devices).
            .on(is_request_sense, fixed_sense(0x00, 0x00, 0x00, None));
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn ScsiPurgeTransport;
        let summary = ScsiPurgeClient::new(transport)
            .with_poll_budget(2, Duration::from_millis(0))
            .execute_purge_ladder(&permit(), None)
            .expect("NO SENSE must be terminal");
        assert_eq!(summary.progress_permille, 1000);
    }

    #[test]
    fn poll_budget_exhaustion_refuses_completion() {
        let mock = MockScsi::new();
        mock.on(is_read_defect, ScsiReply::good())
            .on(|cdb| is_sanitize(0x03, cdb), ScsiReply::good())
            // Stuck at 40%: three polls budgeted, three served.
            .on(
                is_request_sense,
                fixed_sense(0x02, 0x04, ASCQ_SANITIZE_IN_PROGRESS, Some(400)),
            )
            .on(
                is_request_sense,
                fixed_sense(0x02, 0x04, ASCQ_SANITIZE_IN_PROGRESS, Some(400)),
            )
            .on(
                is_request_sense,
                fixed_sense(0x02, 0x04, ASCQ_SANITIZE_IN_PROGRESS, Some(400)),
            );
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn ScsiPurgeTransport;
        let err = ScsiPurgeClient::new(transport)
            .with_poll_budget(2, Duration::from_millis(0))
            .execute_purge_ladder(&permit(), None)
            .expect_err("exhausted poll budget must refuse completion");
        assert!(err.contains("SANITIZE_INCOMPLETE"), "got: {}", err);
    }
}
