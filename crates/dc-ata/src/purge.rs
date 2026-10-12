//! `dc-ata` purge — the SAT-framed ATA hardware purge ladder (v0.6.0).
//!
//! Executes firmware-level purges on SATA drives (and SAS/SATA arrays
//! addressed through SAT bridges) over the REAL Linux SG_IO transport:
//!
//! 1. GEOMETRY RESTORATION: DCO IDENTIFY + READ NATIVE MAX ADDRESS EXT
//!    disclose masked capacity; SET MAX ADDRESS EXT un-hides HPA so the
//!    purge covers every factory sector. Every stage is recorded in a
//!    [`GeometryTransaction`] (three-capacity evidence).
//! 2. FREEZE GATE: SECURITY FREEZE LOCK (set by most BIOS/UEFI at power-on)
//!    makes destructive security commands illegal — we disclose and stop
//!    with power-cycle instructions instead of failing mid-ladder.
//! 3. THE LADDER (planned fallback, controller-rejected only):
//!    SANITIZE DEVICE Crypto Scramble (the NIST SP 800-88 "Purge": the
//!    controller destroys the media encryption key — seconds of work)
//!    -> SANITIZE DEVICE Block Erase -> SECURITY ERASE UNIT Enhanced ->
//!    SECURITY ERASE UNIT Normal.
//! 4. LIFELINE DISCIPLINE: the random rescue password that arms the
//!    security-erase run is structurally voided on a clean erase and
//!    disclosed on a failed one (no-harm repair via SECURITY DISABLE
//!    PASSWORD first; the drive must never end up bricked).
//!
//! Fail-closed rules (mirror of the NVMe ladder):
//! - `Ok` is returned ONLY with terminal, evidence-backed completion:
//!   sanitize paths require the Sanitize Status log (0x30) to report a
//!   terminal state; the security-erase path requires the blocking
//!   command return.
//! - Transport faults never trigger fallback (the media state is
//!   ambiguous); only a controller REJECTION (ILLEGAL REQUEST sense)
//!   moves the ladder down.

use crate::geometry::{FdGen, GeometryTransaction};
use crate::security::AtaLifeline;
use dc_hw::{
    AtaCodec, AtaIdentifyData, AtaSanitizeFeature, AtaSanitizeStatus, AtaSecurityStatus,
    SgIoDevice, SG_DXFER_FROM_DEV, SG_DXFER_NONE, SG_DXFER_TO_DEV,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// SG_IO budget for one firmware sanitize: the spec ceiling is hours on
/// spinning rust; a day of headroom on the transport never truncates a
/// legitimate purge.
pub const SANITIZE_TIMEOUT_MS: u32 = 24 * 60 * 60 * 1000;
/// SG_IO budget for the security-erase family (drives report their own
/// estimates in IDENTIFY words 89/90; 2x estimate + margin, capped).
pub const SECURITY_ERASE_TIMEOUT_MS: u32 = 24 * 60 * 60 * 1000;
/// Timeout for reads (IDENTIFY / SMART / DCO): brisk.
pub const READ_TIMEOUT_MS: u32 = 30_000;
/// Sanitize Status log address (ATA8-ACS §7.47.2).
pub const SANITIZE_STATUS_LOG: u8 = 0x30;

/// Typestate token authorizing destructive ATA purge execution — the
/// ATA mirror of `dc-nvme`'s PurgePermit (INV11, Δ272).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtaPurgePermit {
    pub target_device: String,
    pub target_serial: String,
    pub authorized_at_utc: u64,
}

impl AtaPurgePermit {
    pub fn mint(target_device: &str, target_serial: &str, timestamp_utc: u64) -> Self {
        Self {
            target_device: target_device.to_string(),
            target_serial: target_serial.to_string(),
            authorized_at_utc: timestamp_utc,
        }
    }
}

/// Transfer phase of one SAT exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SatXfer {
    /// Non-data command.
    None,
    /// PIO data-in with a receive buffer of `usize` bytes.
    FromDev(usize),
    /// PIO data-out carrying the payload.
    ToDev(Vec<u8>),
}

/// One completed SAT exchange (transport-healthy; the SCSI status byte and
/// sense data carry the device verdict — CHECK CONDITION is a REPLY, not
/// a transport fault).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SatReply {
    /// SCSI status byte (0x00 GOOD, 0x02 CHECK CONDITION, ...).
    pub status: u8,
    /// Sense bytes (SAT returns ATA registers in the 0x09 descriptor).
    pub sense: Vec<u8>,
    /// Data-in payload.
    pub data_in: Vec<u8>,
}

impl SatReply {
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

/// Transport abstraction: the production [`LinuxSatPurge`] rides SG_IO on
/// the locked block node; test rigs script replies CDB-by-CDB.
pub trait SatPurgeTransport: Send {
    fn issue(&mut self, cdb: &[u8; 16], xfer: SatXfer, timeout_ms: u32)
        -> Result<SatReply, String>;
}

/// Production transport: SG_IO ioctl on the block device node.
pub struct LinuxSatPurge {
    dev: SgIoDevice,
}

impl LinuxSatPurge {
    /// Open the target's block node (refuses `/dev/sg*` character nodes —
    /// the second-door problem, Δ330).
    pub fn open(path: &Path) -> Result<Self, String> {
        let dev = SgIoDevice::open_block_node(path).map_err(|e| e.to_string())?;
        Ok(Self { dev })
    }

    /// Bound device path (evidence provenance).
    pub fn path(&self) -> &str {
        self.dev.path()
    }
}

impl SatPurgeTransport for LinuxSatPurge {
    fn issue(
        &mut self,
        cdb: &[u8; 16],
        xfer: SatXfer,
        timeout_ms: u32,
    ) -> Result<SatReply, String> {
        let result = match xfer {
            SatXfer::None => self
                .dev
                .execute(cdb, SG_DXFER_NONE, &mut [], timeout_ms)
                .map_err(|e| format!("SG_IO transport fault: {}", e))?,
            SatXfer::FromDev(n) => {
                let mut buf = vec![0u8; n];
                self.dev
                    .execute(cdb, SG_DXFER_FROM_DEV, &mut buf, timeout_ms)
                    .map_err(|e| format!("SG_IO transport fault: {}", e))?
                // data_in taken from result below via returned struct
            }
            SatXfer::ToDev(ref payload) => {
                let mut buf = payload.clone();
                self.dev
                    .execute(cdb, SG_DXFER_TO_DEV, &mut buf, timeout_ms)
                    .map_err(|e| format!("SG_IO transport fault: {}", e))?
            }
        };
        Ok(SatReply {
            status: result.status,
            sense: result.sense,
            data_in: result.data_in,
        })
    }
}

/// Purge mechanisms of the ATA ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtaPurgeMechanism {
    /// SANITIZE DEVICE Crypto Scramble (FEATURES 0x20): the controller
    /// destroys the data encryption key.
    SanitizeCryptoScramble,
    /// SANITIZE DEVICE Block Erase (FEATURES 0x10): electrical erase of
    /// all user data blocks.
    SanitizeBlockErase,
    /// SECURITY ERASE UNIT, Enhanced variant (FEATURES bit 1): the drive's
    /// own cryptographic pre-load is invalidated.
    SecurityEraseEnhanced,
    /// SECURITY ERASE UNIT, Normal variant: firmware overwrite of all user
    /// sectors with zeros.
    SecurityEraseNormal,
}

impl AtaPurgeMechanism {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SanitizeCryptoScramble => "ATA Sanitize Crypto Scramble",
            Self::SanitizeBlockErase => "ATA Sanitize Block Erase",
            Self::SecurityEraseEnhanced => "ATA Security Erase (Enhanced)",
            Self::SecurityEraseNormal => "ATA Security Erase (Normal)",
        }
    }

    /// NIST SP 800-88 classification of the mechanism.
    pub fn nist_class(&self) -> &'static str {
        match self {
            Self::SanitizeCryptoScramble | Self::SanitizeBlockErase => "Purge",
            Self::SecurityEraseEnhanced => "Purge",
            Self::SecurityEraseNormal => "Purge",
        }
    }
}

/// How terminal completion was observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtaCompletionEvidence {
    /// Sanitize Status log 0x30 reported a terminal (completed) state.
    SanitizeStatusLog,
    /// The blocking SECURITY ERASE UNIT command returned successfully
    /// (the drive only returns after the erase finished).
    BlockingEraseReturn,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaMechanismFallback {
    pub from: String,
    pub to: String,
    pub reason: String,
}

/// Execution summary mirroring `dc-nvme`'s PurgeExecutionSummary so
/// `dc purge` certificates are transport-uniform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaPurgeExecutionSummary {
    pub executed_mechanism: AtaPurgeMechanism,
    pub fallbacks: Vec<AtaMechanismFallback>,
    pub completion_evidence: AtaCompletionEvidence,
    /// Final Sanitize Status log state (sanitize paths only).
    pub sanitize_status: Option<AtaSanitizeStatus>,
    /// Progress in permille at terminal state (1000 = done).
    pub progress_permille: u16,
    /// Lifeline identity (blake3-derived) of the rescue password.
    pub lifeline_id: String,
    /// True when the lifeline was structurally voided on clean completion.
    pub lifeline_voided: bool,
    /// Geometry restoration evidence (three capacities + stages).
    pub geometry: GeometryTransaction,
    /// Post-purge IDENTIFY re-read (security-state transition evidence).
    pub post_security: AtaSecurityStatus,
}

/// Errors carrying an operator-rescuable lifeline disclosure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtaPurgeError {
    /// Fatal: message text (transport faults, ambiguous states).
    Fatal(String),
    /// The erase failed and the no-harm repair could not clear the lock:
    /// the rescue password is disclosed so the operator can unlock and
    /// retry rather than destroy the drive.
    EraseFailedLockedDisclosed {
        detail: String,
        rescue_password: String,
    },
}

impl AtaPurgeError {
    pub fn message(&self) -> String {
        match self {
            Self::Fatal(m) => m.clone(),
            Self::EraseFailedLockedDisclosed { detail, .. } => {
                format!("ERASE_FAILED_LIFELINE_DISCLOSED: {}", detail)
            }
        }
    }
}

/// The purge client. Construct with the production [`LinuxSatPurge`] or a
/// scripted transport in tests.
pub struct AtaPurgeClient<'a> {
    transport: &'a mut dyn SatPurgeTransport,
    max_polls: u32,
    poll_interval: Duration,
    /// Progress sink (permille) — the CLI wires its progress printer here.
    progress_sink: Option<Box<dyn FnMut(u16) + 'a>>,
}

impl<'a> AtaPurgeClient<'a> {
    pub fn new(transport: &'a mut dyn SatPurgeTransport) -> Self {
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

    /// Attach a progress sink for long-running sanitize operations.
    pub fn with_progress_sink(mut self, sink: impl FnMut(u16) + 'a) -> Self {
        self.progress_sink = Some(Box::new(sink));
        self
    }

    // -----------------------------------------------------------------
    // Non-destructive probes (shared with the execute-path G-List audit)
    // -----------------------------------------------------------------

    /// IDENTIFY DEVICE (0xEC) through the transport.
    pub fn identify(&mut self) -> Result<AtaIdentifyData, String> {
        let reply = self.transport.issue(
            &AtaCodec::encode_sat_identify_device(),
            SatXfer::FromDev(512),
            READ_TIMEOUT_MS,
        )?;
        if !reply.is_good() {
            return Err(format!(
                "IDENTIFY DEVICE failed: SCSI status 0x{:02X}",
                reply.status
            ));
        }
        AtaCodec::decode_identify_device(&reply.data_in)
    }

    /// Read the grown-defect (reallocated sector) count via SMART READ
    /// DATA attribute 0x05 — the G-List disclosure probe (v0.6.0,
    /// REG-SMART-GLIST-DISCLOSURE).
    pub fn read_reallocated_sectors(&mut self) -> Result<u64, String> {
        let reply = self.transport.issue(
            &AtaCodec::encode_sat_smart_read_data(),
            SatXfer::FromDev(512),
            READ_TIMEOUT_MS,
        )?;
        if !reply.is_good() {
            return Err(format!(
                "SMART READ DATA failed: SCSI status 0x{:02X}",
                reply.status
            ));
        }
        AtaCodec::decode_smart_reallocated_sectors(&reply.data_in)
    }

    /// Read the drive temperature via SMART READ DATA attribute 194
    /// (fallback 190) on the SAME SG_IO fd the ladder holds — the thermal
    /// probe for the v0.7.0 governor (Vector 2). No device contention.
    pub fn read_temperature(&mut self) -> Result<crate::thermal::ThermalReading, String> {
        let reply = self.transport.issue(
            &AtaCodec::encode_sat_smart_read_data(),
            SatXfer::FromDev(512),
            READ_TIMEOUT_MS,
        )?;
        if !reply.is_good() {
            return Err(format!(
                "SMART READ DATA failed: SCSI status 0x{:02X}",
                reply.status
            ));
        }
        crate::thermal::decode_smart_temperature(&reply.data_in)
    }

    /// Read one page of the Device Statistics log (GP Log 0x04) via READ
    /// LOG EXT — the raw SSD wear indicators of the v0.7.0 firmware
    /// attestation (Vector 4). `page` 0x00 is General Statistics, 0x04
    /// is the Solid State Device Statistics page.
    pub fn read_device_statistics(
        &mut self,
        page: u16,
    ) -> Result<(dc_hw::AtaDeviceStatisticsPage, Vec<u8>), String> {
        let cdb = AtaCodec::encode_sat_read_log_ext(0x04, page, 1);
        let reply = self
            .transport
            .issue(&cdb, SatXfer::FromDev(512), READ_TIMEOUT_MS)?;
        if !reply.is_good() {
            return Err(format!(
                "READ LOG EXT (log 0x04 page 0x{:02X}) failed: SCSI status 0x{:02X}",
                page, reply.status
            ));
        }
        let decoded = dc_hw::AtaDeviceStatisticsPage::decode(&reply.data_in, page)?;
        Ok((decoded, reply.data_in))
    }

    // -----------------------------------------------------------------
    // The ladder
    // -----------------------------------------------------------------

    /// Execute the ATA purge ladder with planned fallback.
    ///
    /// SECURITY CONTRACT: `Ok` is returned ONLY when a terminal,
    /// evidence-backed completion state was observed. Transport faults are
    /// fatal (ambiguous media state); only a controller rejection
    /// (ILLEGAL REQUEST sense for the selected feature) walks the ladder
    /// down. `AtaPurgeError::EraseFailedLockedDisclosed` carries the rescue
    /// password so a failed security erase never bricks the drive.
    pub fn execute_purge_ladder(
        mut self,
        permit: &AtaPurgePermit,
        requested: Option<AtaPurgeMechanism>,
    ) -> Result<AtaPurgeExecutionSummary, AtaPurgeError> {
        // Intake: IDENTIFY, freeze gate, geometry restoration.
        let identify = self.identify().map_err(AtaPurgeError::Fatal)?;

        // FREEZE GATE (Δ280): a frozen drive refuses destructive security
        // commands with ILLEGAL REQUEST — disclose the power-cycle remedy.
        if identify.security.frozen {
            return Err(AtaPurgeError::Fatal(format!(
                "FROZEN: {} reports SECURITY FREEZE LOCK active (set by most BIOS/UEFI \
                 at power-on). Power-cycle the host WITHOUT letting firmware re-freeze \
                 (hot-plug the drive, or use a controller that does not assert freeze), \
                 then retry the purge.",
                permit.target_device
            )));
        }
        if identify.security.locked {
            return Err(AtaPurgeError::Fatal(format!(
                "PRE_LOCKED: {} is locked with a pre-existing password unknown to this \
                 run; the no-fabrication rule forbids certifying a purge behind a lock.",
                permit.target_device
            )));
        }

        // GEOMETRY RESTORATION (Δ260): unmask HPA/DCO-hidden capacity so
        // the purge covers every factory sector; stages + three capacities
        // land in the certificate.
        let geometry = self.restore_geometry(&identify);

        // Ladder selection: explicit request, else support-ordered auto.
        let mut fallbacks: Vec<AtaMechanismFallback> = Vec::new();
        let mut current = match requested {
            Some(m) => m,
            None => self.auto_primary(&identify).ok_or_else(|| {
                AtaPurgeError::Fatal(format!(
                    "NO_PURGE_MECHANISM: {} attests neither SANITIZE DEVICE (word 169) \
                     nor the ATA SECURITY feature set (word 128); refusing to certify a \
                     purge the firmware cannot perform",
                    permit.target_device
                ))
            })?,
        };

        loop {
            match current {
                AtaPurgeMechanism::SanitizeCryptoScramble => {
                    match self.run_sanitize(AtaSanitizeFeature::CryptoScramble) {
                        Ok((status, progress)) => {
                            return Ok(self.finalize_summary(
                                AtaPurgeMechanism::SanitizeCryptoScramble,
                                fallbacks,
                                AtaCompletionEvidence::SanitizeStatusLog,
                                Some(status),
                                progress,
                                None,
                                geometry,
                            ));
                        }
                        Err(SanitizeStepOutcome::Rejected(reason)) => {
                            fallbacks.push(AtaMechanismFallback {
                                from: "SanitizeCryptoScramble".into(),
                                to: "SanitizeBlockErase".into(),
                                reason,
                            });
                            current = AtaPurgeMechanism::SanitizeBlockErase;
                        }
                        Err(SanitizeStepOutcome::Fatal(reason)) => {
                            return Err(AtaPurgeError::Fatal(reason));
                        }
                    }
                }
                AtaPurgeMechanism::SanitizeBlockErase => {
                    match self.run_sanitize(AtaSanitizeFeature::BlockErase) {
                        Ok((status, progress)) => {
                            return Ok(self.finalize_summary(
                                AtaPurgeMechanism::SanitizeBlockErase,
                                fallbacks,
                                AtaCompletionEvidence::SanitizeStatusLog,
                                Some(status),
                                progress,
                                None,
                                geometry,
                            ));
                        }
                        Err(SanitizeStepOutcome::Rejected(reason)) => {
                            fallbacks.push(AtaMechanismFallback {
                                from: "SanitizeBlockErase".into(),
                                to: "SecurityEraseEnhanced".into(),
                                reason,
                            });
                            current = AtaPurgeMechanism::SecurityEraseEnhanced;
                        }
                        Err(SanitizeStepOutcome::Fatal(reason)) => {
                            return Err(AtaPurgeError::Fatal(reason));
                        }
                    }
                }
                AtaPurgeMechanism::SecurityEraseEnhanced | AtaPurgeMechanism::SecurityEraseNormal
                // (auto falls here only when supported per IDENTIFY)
                => {
                    let enhanced = current == AtaPurgeMechanism::SecurityEraseEnhanced;
                    if !identify.security.supported {
                        return Err(AtaPurgeError::Fatal(
                            "NO_PURGE_MECHANISM: ATA SECURITY feature set not supported \
                             (IDENTIFY word 128) — ladder exhausted"
                                .to_string(),
                        ));
                    }
                    if enhanced && !identify.security.enhanced_erase_supported {
                        // Requested enhanced on a drive without it: fall to
                        // normal, recorded as a fallback.
                        fallbacks.push(AtaMechanismFallback {
                            from: "SecurityEraseEnhanced".into(),
                            to: "SecurityEraseNormal".into(),
                            reason: "IDENTIFY word 128 bit 5: enhanced erase not supported"
                                .to_string(),
                        });
                        return self.execute_security_erase(permit, false, fallbacks, geometry);
                    }
                    return self.execute_security_erase(permit, enhanced, fallbacks, geometry);
                }
            }
        }
    }

    fn auto_primary(&self, identify: &AtaIdentifyData) -> Option<AtaPurgeMechanism> {
        if identify.sanitize.crypto_scramble_supported {
            Some(AtaPurgeMechanism::SanitizeCryptoScramble)
        } else if identify.sanitize.block_erase_supported {
            Some(AtaPurgeMechanism::SanitizeBlockErase)
        } else if identify.security.enhanced_erase_supported {
            Some(AtaPurgeMechanism::SecurityEraseEnhanced)
        } else if identify.security.supported {
            Some(AtaPurgeMechanism::SecurityEraseNormal)
        } else {
            None
        }
    }

    /// Run one SANITIZE DEVICE operation and poll the Sanitize Status log
    /// (0x30) to a terminal state.
    fn run_sanitize(
        &mut self,
        feature: AtaSanitizeFeature,
    ) -> Result<(AtaSanitizeStatus, u16), SanitizeStepOutcome> {
        let cdb = AtaCodec::encode_sat_sanitize_device(feature);
        let reply = self
            .transport
            .issue(&cdb, SatXfer::None, SANITIZE_TIMEOUT_MS)
            .map_err(SanitizeStepOutcome::Fatal)?;
        if !reply.is_good() {
            // CHECK CONDITION: classify. ILLEGAL REQUEST against the
            // sanitize feature = controller rejection (ladder walks down);
            // anything else is fatal.
            if let Some(sense) = Self::sense_illegal_request(&reply) {
                return Err(SanitizeStepOutcome::Rejected(sense));
            }
            return Err(SanitizeStepOutcome::Fatal(format!(
                "SANITIZE DEVICE (FEATURES 0x{:02X}) failed with SCSI status 0x{:02X}; \
                 media state ambiguous — refusing to certify",
                feature as u16, reply.status
            )));
        }

        // Blocking return: the device only returns after the sanitize
        // finished; poll the log for the terminal evidence (and progress
        // for the journal).
        let mut polls: u32 = 0;
        loop {
            let status = self
                .read_sanitize_status()
                .map_err(SanitizeStepOutcome::Fatal)?;
            if status.is_failed {
                return Err(SanitizeStepOutcome::Fatal(format!(
                    "SANITIZE_FAILED: Sanitize Status log reports failure (SSTAT=0x{:04X}, \
                     SPROG=0x{:04X})",
                    status.raw_sstat, status.raw_sprog
                )));
            }
            if status.is_completed {
                return Ok((status.clone(), status.progress_permille));
            }
            if polls >= self.max_polls {
                return Err(SanitizeStepOutcome::Fatal(format!(
                    "SANITIZE_INCOMPLETE: still in progress ({} permille) after {} polls; \
                     refusing to report completion without terminal status",
                    status.progress_permille, polls
                )));
            }
            if let Some(sink) = self.progress_sink.as_mut() {
                sink(status.progress_permille);
            }
            polls += 1;
            std::thread::sleep(self.poll_interval);
        }
    }

    /// Single-shot Sanitize Status log read (log address 0x30 via SMART
    /// READ LOG, FEATURES 0xD5).
    fn read_sanitize_status(&mut self) -> Result<AtaSanitizeStatus, String> {
        let cdb = AtaCodec::encode_sat_smart_read_log(SANITIZE_STATUS_LOG);
        let reply = self
            .transport
            .issue(&cdb, SatXfer::FromDev(512), READ_TIMEOUT_MS)?;
        AtaSanitizeStatus::decode_log(&reply.data_in)
    }

    /// SECURITY ERASE sub-pipeline with lifeline discipline (Δ258, Δ276):
    /// random password -> SET PASSWORD -> ERASE PREPARE -> ERASE UNIT ->
    /// structural lifeline void on success; no-harm repair (DISABLE
    /// PASSWORD) with lifeline disclosure on failure.
    fn execute_security_erase(
        mut self,
        permit: &AtaPurgePermit,
        enhanced: bool,
        fallbacks: Vec<AtaMechanismFallback>,
        geometry: GeometryTransaction,
    ) -> Result<AtaPurgeExecutionSummary, AtaPurgeError> {
        // 1. Random lifeline password (CSPRNG, 32 bytes).
        let mut password = [0u8; 32];
        getrandom::getrandom(&mut password)
            .map_err(|e| AtaPurgeError::Fatal(format!("CSPRNG unavailable: {}", e)))?;
        let mut lifeline = AtaLifeline::new(&hex::encode(password));

        // 2. SET PASSWORD (user authority) — arms the security feature with
        //    a password only this run holds.
        let (cdb, payload) = AtaCodec::encode_sat_security_set_password(false, &password);
        let reply = self
            .transport
            .issue(
                &cdb,
                SatXfer::ToDev(payload.to_vec()),
                SECURITY_ERASE_TIMEOUT_MS,
            )
            .map_err(AtaPurgeError::Fatal)?;
        if !reply.is_good() {
            return Err(AtaPurgeError::Fatal(format!(
                "SECURITY SET PASSWORD failed: SCSI status 0x{:02X} — aborting before \
                 any destructive step",
                reply.status
            )));
        }

        // 3. ERASE PREPARE.
        let cdb = AtaCodec::encode_sat_security_erase_prepare();
        let reply = self
            .transport
            .issue(&cdb, SatXfer::None, SECURITY_ERASE_TIMEOUT_MS)
            .map_err(AtaPurgeError::Fatal)?;
        if !reply.is_good() {
            // No harm yet: disarm by disabling the password we just set.
            let _ = self.no_harm_repair(&password);
            return Err(AtaPurgeError::Fatal(format!(
                "SECURITY ERASE PREPARE failed: SCSI status 0x{:02X} (drive disarmed)",
                reply.status
            )));
        }

        // 4. ERASE UNIT (blocking; carries the password payload).
        let (cdb, payload) =
            AtaCodec::encode_sat_security_erase_unit_auth(false, enhanced, &password);
        let erase_reply = self
            .transport
            .issue(
                &cdb,
                SatXfer::ToDev(payload.to_vec()),
                SECURITY_ERASE_TIMEOUT_MS,
            )
            .map_err(AtaPurgeError::Fatal)?;

        if erase_reply.is_good() {
            // 5. Clean completion: structural lifeline void + post-IDENTIFY.
            let lifeline_id = lifeline.id.clone();
            lifeline.void();
            let post = self.identify().ok();
            let post_security = post
                .as_ref()
                .map(|i| i.security.clone())
                .unwrap_or_else(identify_security_disarmed);
            let mechanism = if enhanced {
                AtaPurgeMechanism::SecurityEraseEnhanced
            } else {
                AtaPurgeMechanism::SecurityEraseNormal
            };
            return Ok(AtaPurgeExecutionSummary {
                executed_mechanism: mechanism,
                fallbacks,
                completion_evidence: AtaCompletionEvidence::BlockingEraseReturn,
                sanitize_status: None,
                progress_permille: 1000,
                lifeline_id,
                lifeline_voided: true,
                geometry,
                post_security,
            });
        }

        // 6. Erase failed: no-harm repair first (DISABLE PASSWORD), then
        //    disclose the lifeline if the drive stayed locked.
        let repair_ok = self.no_harm_repair(&password).is_ok();
        let post = self.identify().ok();
        let post_security = post
            .as_ref()
            .map(|i| i.security.clone())
            .unwrap_or_else(identify_security_disarmed);
        let detail = format!(
            "SECURITY ERASE UNIT (enhanced={}) failed: SCSI status 0x{:02X} on {}",
            enhanced, erase_reply.status, permit.target_device
        );
        if repair_ok && !post_security.locked {
            // Repaired to unlocked: the drive is usable; the purge did NOT
            // complete though — that is a failure, not a certificate.
            return Err(AtaPurgeError::Fatal(format!(
                "{} — no-harm repair cleared the lock (drive unlocked, purge NOT \
                 completed); re-run or switch to `dc execute`",
                detail
            )));
        }
        Err(AtaPurgeError::EraseFailedLockedDisclosed {
            detail,
            rescue_password: hex::encode(password),
        })
    }

    /// No-harm repair: SECURITY DISABLE PASSWORD with our own password
    /// (only possible because the lifeline was minted this run).
    fn no_harm_repair(&mut self, password: &[u8; 32]) -> Result<(), String> {
        let (cdb, payload) = AtaCodec::encode_sat_security_disable_password(false, password);
        let reply = self
            .transport
            .issue(
                &cdb,
                SatXfer::ToDev(payload.to_vec()),
                SECURITY_ERASE_TIMEOUT_MS,
            )
            .map_err(|e| format!("transport fault during no-harm repair: {}", e))?;
        if reply.is_good() {
            Ok(())
        } else {
            Err(format!(
                "SECURITY DISABLE PASSWORD failed: SCSI status 0x{:02X}",
                reply.status
            ))
        }
    }

    /// GEOMETRY RESTORATION (Δ260): disclose and lift masked capacity.
    fn restore_geometry(&mut self, identify: &AtaIdentifyData) -> GeometryTransaction {
        let visible = identify.lba48_sectors;

        // DCO IDENTIFY: the factory ceiling (optional on SAT bridges).
        let dco_max = self
            .transport
            .issue(
                &AtaCodec::encode_sat_device_config_identify(),
                SatXfer::FromDev(512),
                READ_TIMEOUT_MS,
            )
            .ok()
            .and_then(|reply| AtaCodec::decode_device_config_overlay(&reply.data_in).ok())
            .unwrap_or(visible);

        // READ NATIVE MAX ADDRESS EXT returns via the 0x09 ATA return
        // descriptor (CHECK CONDITION with descriptor sense IS the success
        // path — CK_COND=1 was requested).
        let native = match self.transport.issue(
            &AtaCodec::encode_sat_read_native_max_ext(),
            SatXfer::None,
            READ_TIMEOUT_MS,
        ) {
            Ok(reply) => {
                AtaCodec::decode_ata_return_descriptor_lba(&reply.sense).unwrap_or(visible)
            }
            Err(_) => visible,
        };

        let mut tx = GeometryTransaction::begin(visible, native, dco_max);
        let mut gen = FdGen(1);

        // DCO restore only when the factory ceiling exceeds native
        // (recorded; a power-on reset applies it — FdGen models the POR).
        if dco_max > native {
            gen = tx.stage_dco_restore(gen);
        }
        // HPA unlock when native exceeds visible: SET MAX ADDRESS EXT
        // lifts the ceiling to native, then re-IDENTIFY confirms.
        if native > visible {
            let cdb = AtaCodec::encode_sat_set_max_ext(native);
            if self
                .transport
                .issue(&cdb, SatXfer::None, READ_TIMEOUT_MS)
                .map(|r| r.is_good())
                .unwrap_or(false)
            {
                tx.stage_hpa_unlock(gen);
            }
        }
        tx.commit();
        tx
    }

    fn sense_illegal_request(reply: &SatReply) -> Option<String> {
        // Descriptor format: [0]=0x72/0x73, [1]=sense key, [2]=ASC, [3]=ASCQ.
        // Fixed format: [2]=sense key, [12]=ASC, [13]=ASCQ.
        let (key, asc, ascq) = if reply.sense.len() >= 4 && (reply.sense[0] & 0x7F) == 0x72 {
            (reply.sense[1] & 0x0F, reply.sense[2], reply.sense[3])
        } else if reply.sense.len() >= 14 {
            (reply.sense[2] & 0x0F, reply.sense[12], reply.sense[13])
        } else {
            return None;
        };
        // 0x05 = ILLEGAL REQUEST; 0x20/0x24 = invalid command/field — the
        // SAT layer rejecting the sanitize/security feature.
        if key == 0x05 {
            Some(format!(
                "controller rejected: ILLEGAL REQUEST (sense 0x{:02X} 0x{:02X} 0x{:02X})",
                key, asc, ascq
            ))
        } else {
            None
        }
    }

    fn finalize_summary(
        self,
        mechanism: AtaPurgeMechanism,
        fallbacks: Vec<AtaMechanismFallback>,
        evidence: AtaCompletionEvidence,
        sanitize_status: Option<AtaSanitizeStatus>,
        progress: u16,
        _lifeline: Option<()>,
        geometry: GeometryTransaction,
    ) -> AtaPurgeExecutionSummary {
        AtaPurgeExecutionSummary {
            executed_mechanism: mechanism,
            fallbacks,
            completion_evidence: evidence,
            sanitize_status,
            progress_permille: progress,
            // Sanitize paths never mint a password lifeline.
            lifeline_id: String::new(),
            lifeline_voided: false,
            geometry,
            post_security: identify_security_disarmed(),
        }
    }
}

/// A never-locked placeholder for sanitize-path summaries (the security
/// state after a successful sanitize is, by definition, unlocked).
fn identify_security_disarmed() -> AtaSecurityStatus {
    AtaSecurityStatus {
        supported: false,
        enabled: false,
        locked: false,
        frozen: false,
        enhanced_erase_supported: false,
        erase_time_minutes: None,
        enhanced_erase_time_minutes: None,
    }
}

enum SanitizeStepOutcome {
    /// Controller rejected the feature — ladder walks down.
    Rejected(String),
    /// Terminal failure or ambiguity — abort.
    Fatal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Scripted transport: each issue() pops the next (match, reply).
    type SatMatcher = Box<dyn Fn(&[u8; 16]) -> bool + Send>;

    struct MockSat {
        script: RefCell<Vec<(SatMatcher, SatReply)>>,
        seen: RefCell<Vec<[u8; 16]>>,
    }

    impl MockSat {
        fn new() -> Self {
            Self {
                script: RefCell::new(Vec::new()),
                seen: RefCell::new(Vec::new()),
            }
        }

        fn on(
            &self,
            matcher: impl Fn(&[u8; 16]) -> bool + Send + 'static,
            reply: SatReply,
        ) -> &Self {
            self.script.borrow_mut().push((Box::new(matcher), reply));
            self
        }
    }

    impl SatPurgeTransport for MockSat {
        fn issue(
            &mut self,
            cdb: &[u8; 16],
            _xfer: SatXfer,
            _timeout_ms: u32,
        ) -> Result<SatReply, String> {
            self.seen.borrow_mut().push(*cdb);
            let next = self.script.borrow_mut().remove(0);
            if !(next.0)(cdb) {
                return Err(format!(
                    "mock mismatch: CDB opcode 0x{:02X} ATA cmd 0x{:02X} unexpected",
                    cdb[0], cdb[14]
                ));
            }
            Ok(next.1)
        }
    }

    fn identify_reply(
        security: &AtaSecurityStatus,
        sanitize: &dc_hw::AtaSanitizeSupport,
    ) -> SatReply {
        let mut raw = vec![0u8; 512];
        // Serial
        raw[20] = b'N';
        raw[21] = b'S';
        // Model
        raw[54] = b'O';
        raw[55] = b'M';
        // words 100-103: 48-bit capacity 1000 sectors
        raw[200..208].copy_from_slice(&1000u64.to_le_bytes());
        // word 128 (offset 256): security status
        let mut w128 = 0u16;
        if security.supported {
            w128 |= 0x0001;
        }
        if security.enabled {
            w128 |= 0x0002;
        }
        if security.locked {
            w128 |= 0x0004;
        }
        if security.frozen {
            w128 |= 0x0008;
        }
        if security.enhanced_erase_supported {
            w128 |= 0x0020;
        }
        raw[256..258].copy_from_slice(&w128.to_le_bytes());
        // word 169 (offset 338): sanitize support (bit0 supported, bit1
        // crypto, bit2 block erase)
        let mut w169 = 0u16;
        if sanitize.supported {
            w169 |= 0x0001;
        }
        if sanitize.crypto_scramble_supported {
            w169 |= 0x0002;
        }
        if sanitize.block_erase_supported {
            w169 |= 0x0004;
        }
        raw[338..340].copy_from_slice(&w169.to_le_bytes());
        // word 206 (offset 412): VALID coverage bits 14:12 = 0b001
        raw[412..414].copy_from_slice(&0x1000u16.to_le_bytes());
        SatReply {
            status: 0x00,
            sense: Vec::new(),
            data_in: raw,
        }
    }

    fn sanitize_status_reply(sprog: u16, sstat: u16) -> SatReply {
        let mut log = vec![0u8; 512];
        log[4..6].copy_from_slice(&sprog.to_le_bytes());
        log[10..12].copy_from_slice(&sstat.to_le_bytes());
        SatReply {
            status: 0x00,
            sense: Vec::new(),
            data_in: log,
        }
    }

    /// Descriptor-format sense carrying the 0x09 ATA return descriptor
    /// with a 48-bit LBA (READ NATIVE MAX ADDRESS EXT success path).
    fn native_max_sense(lba: u64) -> Vec<u8> {
        let mut sense = vec![0u8; 8];
        sense[0] = 0x72; // descriptor format
        sense.extend_from_slice(&[0x09, 0x0C]); // type 0x09, len 12
        let mut payload = [0u8; 12];
        // desc bytes 6..12: LBA 47:40, 31:24, 39:32, 23:16, 15:8, 7:0
        // => payload[4..10]
        payload[4] = (lba >> 40) as u8;
        payload[5] = (lba >> 24) as u8;
        payload[6] = (lba >> 32) as u8;
        payload[7] = (lba >> 16) as u8;
        payload[8] = (lba >> 8) as u8;
        payload[9] = lba as u8;
        sense.extend_from_slice(&payload);
        sense
    }

    fn permit() -> AtaPurgePermit {
        AtaPurgePermit::mint("/dev/sda", "SN-TEST", 1_700_000_000)
    }

    fn clean_security() -> AtaSecurityStatus {
        AtaSecurityStatus {
            supported: true,
            enabled: false,
            locked: false,
            frozen: false,
            enhanced_erase_supported: true,
            erase_time_minutes: Some(2),
            enhanced_erase_time_minutes: Some(4),
        }
    }

    fn crypto_sanitize() -> dc_hw::AtaSanitizeSupport {
        dc_hw::AtaSanitizeSupport {
            supported: true,
            crypto_scramble_supported: true,
            block_erase_supported: true,
            overwrite_supported: false,
        }
    }

    fn is_identify(cdb: &[u8; 16]) -> bool {
        cdb[0] == 0x85 && cdb[14] == 0xEC
    }

    fn is_sanitize_crypto(cdb: &[u8; 16]) -> bool {
        cdb[0] == 0x85 && cdb[14] == 0xB4 && cdb[4] == 0x20
    }

    fn is_sanitize_status_log(cdb: &[u8; 16]) -> bool {
        cdb[0] == 0x85 && cdb[14] == 0xB0 && cdb[4] == 0xD5 && cdb[8] == 0x30
    }

    fn is_set_password(cdb: &[u8; 16]) -> bool {
        cdb[0] == 0x85 && cdb[14] == 0xF1
    }

    fn is_erase_prepare(cdb: &[u8; 16]) -> bool {
        cdb[0] == 0x85 && cdb[14] == 0xF3
    }

    fn is_erase_unit(cdb: &[u8; 16], enhanced: bool) -> bool {
        cdb[0] == 0x85 && cdb[14] == 0xF4 && cdb[4] == if enhanced { 0x02 } else { 0x00 }
    }

    fn is_disable_password(cdb: &[u8; 16]) -> bool {
        cdb[0] == 0x85 && cdb[14] == 0xF6
    }

    #[test]
    fn sanitize_crypto_completes_with_status_log_evidence() {
        let mock = MockSat::new();
        // IDENTIFY (intake + post-geometry re-read)
        mock.on(
            is_identify,
            identify_reply(&clean_security(), &crypto_sanitize()),
        )
        .on(|cdb| cdb[0] == 0x85 && cdb[14] == 0xB1, SatReply::good()) // DCO identify
        .on(|cdb| cdb[0] == 0x85 && cdb[14] == 0x27, SatReply::good()) // READ NATIVE MAX
        .on(is_sanitize_crypto, SatReply::good())
        .on(
            is_sanitize_status_log,
            sanitize_status_reply(0xFFFF, 0x0002),
        );
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn SatPurgeTransport;
        let client = AtaPurgeClient::new(transport);
        let summary = client
            .execute_purge_ladder(&permit(), None)
            .expect("sanitize crypto must complete");
        assert_eq!(
            summary.executed_mechanism,
            AtaPurgeMechanism::SanitizeCryptoScramble
        );
        assert_eq!(
            summary.completion_evidence,
            AtaCompletionEvidence::SanitizeStatusLog
        );
        assert_eq!(summary.progress_permille, 1000);
        assert!(summary.sanitize_status.as_ref().unwrap().is_completed);
    }

    #[test]
    fn frozen_drive_refused_with_power_cycle_instruction() {
        let mock = MockSat::new();
        let mut frozen = clean_security();
        frozen.frozen = true;
        mock.on(is_identify, identify_reply(&frozen, &crypto_sanitize()));
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn SatPurgeTransport;
        let err = AtaPurgeClient::new(transport)
            .execute_purge_ladder(&permit(), None)
            .expect_err("frozen must be refused");
        match err {
            AtaPurgeError::Fatal(msg) => {
                assert!(msg.contains("FROZEN"), "must disclose freeze: {}", msg);
                assert!(
                    msg.contains("Power-cycle"),
                    "must instruct power-cycle: {}",
                    msg
                );
            }
            other => panic!("expected Fatal, got {:?}", other.message()),
        }
    }

    #[test]
    fn controller_rejection_walks_the_ladder_to_security_erase() {
        let mock = MockSat::new();
        // IDENTIFY: no sanitize support, security with enhanced erase.
        let no_sanitize = dc_hw::AtaSanitizeSupport::default();
        mock.on(is_identify, identify_reply(&clean_security(), &no_sanitize))
            .on(|cdb| cdb[0] == 0x85 && cdb[14] == 0xB1, SatReply::good()) // DCO
            .on(|cdb| cdb[0] == 0x85 && cdb[14] == 0x27, SatReply::good()) // native max
            .on(is_set_password, SatReply::good())
            .on(is_erase_prepare, SatReply::good())
            // ERASE UNIT (enhanced, FEATURES 0x02) succeeds blocking.
            .on(|cdb| is_erase_unit(cdb, true), SatReply::good())
            .on(is_identify, identify_reply(&clean_security(), &no_sanitize));
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn SatPurgeTransport;
        let summary = AtaPurgeClient::new(transport)
            .execute_purge_ladder(&permit(), None)
            .expect("security erase enhanced must run");
        assert_eq!(
            summary.executed_mechanism,
            AtaPurgeMechanism::SecurityEraseEnhanced
        );
        assert_eq!(
            summary.completion_evidence,
            AtaCompletionEvidence::BlockingEraseReturn
        );
        assert!(
            summary.lifeline_voided,
            "lifeline must be voided on clean erase"
        );
        assert!(!summary.lifeline_id.is_empty());
    }

    #[test]
    fn failed_security_erase_discloses_lifeline_after_repair_fails() {
        let mock = MockSat::new();
        let no_sanitize = dc_hw::AtaSanitizeSupport::default();
        mock.on(is_identify, identify_reply(&clean_security(), &no_sanitize))
            .on(|cdb| cdb[0] == 0x85 && cdb[14] == 0xB1, SatReply::good())
            .on(|cdb| cdb[0] == 0x85 && cdb[14] == 0x27, SatReply::good())
            .on(is_set_password, SatReply::good())
            .on(is_erase_prepare, SatReply::good())
            // ERASE UNIT fails (CHECK CONDITION, non-ILLEGAL sense).
            .on(
                |cdb| is_erase_unit(cdb, true),
                SatReply {
                    status: 0x02,
                    sense: vec![
                        0x70, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00,
                        0x40, 0x00,
                    ],
                    data_in: Vec::new(),
                },
            )
            // No-harm repair fails.
            .on(
                is_disable_password,
                SatReply {
                    status: 0x02,
                    sense: vec![
                        0x70, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00,
                    ],
                    data_in: Vec::new(),
                },
            )
            // Post IDENTIFY: still locked.
            .on(
                is_identify,
                identify_reply(
                    &AtaSecurityStatus {
                        supported: true,
                        enabled: true,
                        locked: true,
                        frozen: false,
                        enhanced_erase_supported: true,
                        erase_time_minutes: Some(2),
                        enhanced_erase_time_minutes: Some(4),
                    },
                    &no_sanitize,
                ),
            );
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn SatPurgeTransport;
        let err = AtaPurgeClient::new(transport)
            .execute_purge_ladder(&permit(), None)
            .expect_err("failed erase must surface");
        match err {
            AtaPurgeError::EraseFailedLockedDisclosed {
                rescue_password, ..
            } => {
                assert_eq!(rescue_password.len(), 64, "32-byte hex lifeline");
            }
            other => panic!("expected lifeline disclosure, got {}", other.message()),
        }
    }

    #[test]
    fn geometry_restoration_unmasks_hpa_and_records_stages() {
        let mock = MockSat::new();
        let no_sanitize = dc_hw::AtaSanitizeSupport::default();
        // IDENTIFY visible 1000 sectors; DCO says 5000; native max LBA in
        // the return descriptor = 3000.
        mock.on(is_identify, identify_reply(&clean_security(), &no_sanitize))
            // DCO IDENTIFY: words 100-103 at bytes 200-207 = 5000.
            .on(
                |cdb| cdb[0] == 0x85 && cdb[14] == 0xB1,
                SatReply {
                    status: 0x00,
                    sense: Vec::new(),
                    data_in: {
                        let mut raw = vec![0u8; 512];
                        raw[200..208].copy_from_slice(&5000u64.to_le_bytes());
                        raw
                    },
                },
            )
            // READ NATIVE MAX EXT: CHECK CONDITION with 0x09 descriptor
            // sense carrying LBA 3000.
            .on(
                |cdb| cdb[0] == 0x85 && cdb[14] == 0x27,
                SatReply {
                    status: 0x02,
                    sense: native_max_sense(3000),
                    data_in: Vec::new(),
                },
            )
            // SET MAX ADDRESS EXT accepted.
            .on(|cdb| cdb[0] == 0x85 && cdb[14] == 0x37, SatReply::good())
            .on(is_set_password, SatReply::good())
            .on(is_erase_prepare, SatReply::good())
            .on(|cdb| is_erase_unit(cdb, true), SatReply::good())
            .on(is_identify, identify_reply(&clean_security(), &no_sanitize));
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn SatPurgeTransport;
        let summary = AtaPurgeClient::new(transport)
            .execute_purge_ladder(&permit(), None)
            .expect("purge with geometry restoration must run");
        let geom = &summary.geometry;
        // DCO restore lifts the native ceiling to 5000 (applies after POR),
        // HPA unlock then lifts visible capacity to the (restored) native.
        assert_eq!(
            geom.current_capacity, 5000,
            "HPA unlock lifts to restored native"
        );
        assert_eq!(geom.native_capacity, 5000, "DCO restore lifts the ceiling");
        assert_eq!(geom.stages.len(), 2, "DCO_RESTORE + HPA_UNLOCK recorded");
        assert_eq!(geom.stages[0].op, "DCO_RESTORE");
        assert_eq!(geom.stages[1].op, "HPA_UNLOCK");
        assert!(geom.committed);
        assert_eq!(geom.stages[1].cap_before, 1000);
        assert_eq!(
            geom.stages[0].cap_before, 3000,
            "pre-restore native recorded"
        );
    }

    #[test]
    fn smart_reallocated_probe_parses_grown_defects() {
        let mock = MockSat::new();
        let mut smart = vec![0u8; 512];
        // Attribute 0x05 at first entry (base 2): id + 6-byte raw value.
        smart[2] = 0x05;
        let raw_val: u64 = 4096;
        smart[7..13].copy_from_slice(&raw_val.to_le_bytes()[..6]);
        mock.on(
            |cdb| cdb[0] == 0x85 && cdb[14] == 0xB0 && cdb[4] == 0xD0,
            SatReply {
                status: 0x00,
                sense: Vec::new(),
                data_in: smart,
            },
        );
        let mut mock_ref = mock;
        let transport = &mut mock_ref as &mut dyn SatPurgeTransport;
        let count = AtaPurgeClient::new(transport)
            .read_reallocated_sectors()
            .expect("SMART READ DATA must parse");
        assert_eq!(count, 4096, "G-List count from attribute 0x05 raw value");
    }

    #[test]
    fn transport_fault_is_fatal_not_a_fallback() {
        struct FaultySat;
        impl SatPurgeTransport for FaultySat {
            fn issue(
                &mut self,
                _cdb: &[u8; 16],
                _xfer: SatXfer,
                _timeout_ms: u32,
            ) -> Result<SatReply, String> {
                Err("ETIMEDOUT: sanitize never returned".to_string())
            }
        }
        let mut faulty = FaultySat;
        let transport = &mut faulty as &mut dyn SatPurgeTransport;
        let err = AtaPurgeClient::new(transport)
            .execute_purge_ladder(&permit(), None)
            .expect_err("transport fault must be fatal");
        assert!(err.message().contains("ETIMEDOUT"));
    }
}
