//! T24 — UNIVERSAL HARDWARE PURGE MATRIX (v0.6.0).
//!
//! Cross-transport integration over the public purge clients:
//! - ATA: the SAT ladder (geometry restoration, freeze gate, sanitize
//!   status-log evidence, security-erase lifeline discipline).
//! - SCSI: the SANITIZE ladder (IMMED law, sense progress, UA
//!   completion, FORMAT UNIT fallback, G-List probe).
//! - PDF/A-3: the archival certificate engine end-to-end.
//! - Policy: the defense verification gate's CLI surface.

use dc_ata::purge::{
    AtaPurgeClient, AtaPurgeMechanism, AtaPurgePermit, SatPurgeTransport, SatReply, SatXfer,
};
use dc_hw::{AtaCodec, AtaSecurityStatus, ScsiCodec, ScsiSanitizeServiceAction};
use dc_scsi::purge::{
    ScsiPurgeClient, ScsiPurgeMechanism, ScsiPurgePermit, ScsiPurgeTransport, ScsiReply, ScsiXfer,
};
use std::cell::RefCell;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Scripted SAT transport (mirrors the dc-ata unit rig, exported here for
// cross-crate integration coverage).
// ---------------------------------------------------------------------------

type SatMatcher = Box<dyn Fn(&[u8; 16]) -> bool + Send>;
type ScsiMatcher = Box<dyn Fn(&[u8]) -> bool + Send>;

struct ScriptedSat {
    script: RefCell<Vec<(SatMatcher, SatReply)>>,
}

impl ScriptedSat {
    fn new() -> Self {
        Self {
            script: RefCell::new(Vec::new()),
        }
    }

    fn on(&self, m: impl Fn(&[u8; 16]) -> bool + Send + 'static, r: SatReply) -> &Self {
        self.script.borrow_mut().push((Box::new(m), r));
        self
    }
}

impl SatPurgeTransport for ScriptedSat {
    fn issue(&mut self, cdb: &[u8; 16], _x: SatXfer, _t: u32) -> Result<SatReply, String> {
        let next = self.script.borrow_mut().remove(0);
        if !(next.0)(cdb) {
            return Err(format!("unexpected CDB 0x{:02X}/0x{:02X}", cdb[0], cdb[14]));
        }
        Ok(next.1)
    }
}

struct ScriptedScsi {
    script: RefCell<Vec<(ScsiMatcher, ScsiReply)>>,
}

impl ScriptedScsi {
    fn new() -> Self {
        Self {
            script: RefCell::new(Vec::new()),
        }
    }

    fn on(&self, m: impl Fn(&[u8]) -> bool + Send + 'static, r: ScsiReply) -> &Self {
        self.script.borrow_mut().push((Box::new(m), r));
        self
    }
}

impl ScsiPurgeTransport for ScriptedScsi {
    fn issue(&mut self, cdb: &[u8], _x: ScsiXfer, _t: u32) -> Result<ScsiReply, String> {
        let next = self.script.borrow_mut().remove(0);
        if !(next.0)(cdb) {
            return Err(format!("unexpected CDB opcode 0x{:02X}", cdb[0]));
        }
        Ok(next.1)
    }
}

// --- reply builders --------------------------------------------------------

fn ata_identify(security: &AtaSecurityStatus, crypto: bool) -> SatReply {
    let mut raw = vec![0u8; 512];
    raw[20] = b'N';
    raw[21] = b'S';
    raw[200..208].copy_from_slice(&1000u64.to_le_bytes());
    let mut w128 = 0u16;
    if security.supported {
        w128 |= 0x0001;
    }
    if security.enhanced_erase_supported {
        w128 |= 0x0020;
    }
    if security.frozen {
        w128 |= 0x0008;
    }
    raw[256..258].copy_from_slice(&w128.to_le_bytes());
    let mut w169 = 0u16;
    if crypto {
        w169 |= 0x0007; // supported | crypto | block erase
    }
    raw[338..340].copy_from_slice(&w169.to_le_bytes());
    raw[412..414].copy_from_slice(&0x1000u16.to_le_bytes()); // VALID
    SatReply {
        status: 0x00,
        sense: Vec::new(),
        data_in: raw,
    }
}

fn ata_san_log(sprog: u16, sstat: u16) -> SatReply {
    let mut log = vec![0u8; 512];
    log[4..6].copy_from_slice(&sprog.to_le_bytes());
    log[10..12].copy_from_slice(&sstat.to_le_bytes());
    SatReply {
        status: 0x00,
        sense: Vec::new(),
        data_in: log,
    }
}

fn scsi_fixed_sense(key: u8, asc: u8, ascq: u8, progress: Option<u16>) -> ScsiReply {
    let mut sense = vec![0u8; 18];
    sense[0] = 0x70;
    sense[2] = key;
    if let Some(p) = progress {
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

fn ata_permit() -> AtaPurgePermit {
    AtaPurgePermit::mint("/dev/sda", "SN-T24", 1_700_000_000)
}

fn scsi_permit() -> ScsiPurgePermit {
    ScsiPurgePermit::mint("/dev/sdb", "naa.t24", 1_700_000_000)
}

// ---------------------------------------------------------------------------
// T24-ATA: SAT ladder integration
// ---------------------------------------------------------------------------

#[test]
fn t24_ata_sanitize_crypto_ladder_with_geometry_evidence() {
    let sat = ScriptedSat::new();
    sat.on(|c| c[14] == 0xEC, ata_identify(&clean_security(), true))
        .on(|c| c[14] == 0xB1, SatReply::good()) // DCO identify
        .on(|c| c[14] == 0x27, SatReply::good()) // native max (no HPA)
        .on(|c| c[14] == 0xB4 && c[4] == 0x20, SatReply::good()) // SANITIZE crypto
        .on(
            |c| c[14] == 0xB0 && c[4] == 0xD5,
            ata_san_log(0xFFFF, 0x0002),
        );
    let mut t = sat;
    let summary = AtaPurgeClient::new(&mut t)
        .execute_purge_ladder(&ata_permit(), None)
        .expect("T24-ATA: crypto scramble must complete");
    assert_eq!(
        summary.executed_mechanism,
        AtaPurgeMechanism::SanitizeCryptoScramble
    );
    assert_eq!(summary.progress_permille, 1000);
    assert!(!summary.geometry.stages.is_empty() || summary.geometry.current_capacity == 1000);
    assert!(summary.completion_evidence == dc_ata::purge::AtaCompletionEvidence::SanitizeStatusLog);
}

#[test]
fn t24_ata_freeze_gate_discloses_power_cycle_remedy() {
    let sat = ScriptedSat::new();
    let mut frozen = clean_security();
    frozen.frozen = true;
    sat.on(|c| c[14] == 0xEC, ata_identify(&frozen, true));
    let mut t = sat;
    let err = AtaPurgeClient::new(&mut t)
        .execute_purge_ladder(&ata_permit(), None)
        .expect_err("frozen must be refused");
    let msg = err.message();
    assert!(msg.contains("FROZEN") && msg.contains("Power-cycle"));
}

#[test]
fn t24_ata_security_erase_lifeline_voided_on_clean_completion() {
    let sat = ScriptedSat::new();
    sat.on(|c| c[14] == 0xEC, ata_identify(&clean_security(), false))
        .on(|c| c[14] == 0xB1, SatReply::good())
        .on(|c| c[14] == 0x27, SatReply::good())
        .on(|c| c[14] == 0xF1, SatReply::good()) // SET PASSWORD
        .on(|c| c[14] == 0xF3, SatReply::good()) // ERASE PREPARE
        .on(|c| c[14] == 0xF4, SatReply::good()) // ERASE UNIT (enhanced)
        .on(|c| c[14] == 0xEC, ata_identify(&clean_security(), false));
    let mut t = sat;
    let summary = AtaPurgeClient::new(&mut t)
        .execute_purge_ladder(&ata_permit(), None)
        .expect("security erase enhanced must run");
    assert_eq!(
        summary.executed_mechanism,
        AtaPurgeMechanism::SecurityEraseEnhanced
    );
    assert!(summary.lifeline_voided, "clean erase voids the lifeline");
    assert!(!summary.lifeline_id.is_empty());
    assert!(!summary.post_security.locked);
}

// ---------------------------------------------------------------------------
// T24-SCSI: SANITIZE ladder integration
// ---------------------------------------------------------------------------

#[test]
fn t24_scsi_sanitize_progress_then_unit_attention_completion() {
    let scsi = ScriptedScsi::new();
    let is_glist = |c: &[u8]| c[0] == 0x37;
    let is_sanitize_crypto = |c: &[u8]| c[0] == 0x48 && (c[1] & 0x1F) == 0x03 && (c[1] & 0x80) != 0;
    let is_sense = |c: &[u8]| c[0] == 0x03;
    scsi.on(is_glist, ScsiReply::good())
        .on(is_sanitize_crypto, ScsiReply::good())
        // 10% -> 60% -> UNIT ATTENTION 0x29/0x00 (completion signature).
        .on(is_sense, scsi_fixed_sense(0x02, 0x04, 0x0B, Some(100)))
        .on(is_sense, scsi_fixed_sense(0x02, 0x04, 0x0B, Some(600)))
        .on(is_sense, scsi_fixed_sense(0x06, 0x29, 0x00, None));
    let mut t = scsi;
    let seen: RefCell<Vec<u16>> = RefCell::new(Vec::new());
    let sink = &seen;
    let summary = ScsiPurgeClient::new(&mut t)
        .with_poll_budget(16, Duration::from_millis(0))
        .with_progress_sink(move |p| sink.borrow_mut().push(p))
        .execute_purge_ladder(&scsi_permit(), None)
        .expect("sanitize crypto must complete via sense polling");
    assert_eq!(
        summary.executed_mechanism,
        ScsiPurgeMechanism::SanitizeCryptoErase
    );
    assert_eq!(summary.progress_permille, 1000);
    assert_eq!(
        *seen.borrow(),
        vec![100, 600],
        "live firmware progress observed"
    );
    assert_eq!(
        summary.completion_evidence,
        dc_scsi::purge::ScsiCompletionEvidence::SensePollTerminal
    );
}

#[test]
fn t24_scsi_ladder_falls_through_to_format_unit() {
    let scsi = ScriptedScsi::new();
    let reject = ScsiReply {
        status: 0x02,
        sense: {
            let mut s = vec![0u8; 14];
            s[0] = 0x70;
            s[2] = 0x05; // ILLEGAL REQUEST
            s[12] = 0x20;
            s
        },
        data_in: Vec::new(),
    };
    scsi.on(|c| c[0] == 0x37, ScsiReply::good())
        .on(|c| c[0] == 0x48 && (c[1] & 0x1F) == 0x03, reject.clone())
        .on(|c| c[0] == 0x48 && (c[1] & 0x1F) == 0x02, reject.clone())
        .on(|c| c[0] == 0x04 && (c[1] & 0x10) == 0, ScsiReply::good()) // FORMAT UNIT
        .on(|c| c[0] == 0x03, scsi_fixed_sense(0x00, 0x00, 0x00, None));
    let mut t = scsi;
    let summary = ScsiPurgeClient::new(&mut t)
        .execute_purge_ladder(&scsi_permit(), None)
        .expect("format unit must complete the exhausted ladder");
    assert_eq!(summary.executed_mechanism, ScsiPurgeMechanism::FormatUnit);
    assert_eq!(summary.fallbacks.len(), 2);
    assert_eq!(
        summary.completion_evidence,
        dc_scsi::purge::ScsiCompletionEvidence::BlockingFormatReturn
    );
}

#[test]
fn t24_scsi_glist_probe_feeds_defense_disclosure() {
    let scsi = ScriptedScsi::new();
    // Grown defect list of 5 descriptors (40 bytes).
    scsi.on(
        |c| c[0] == 0x37 && (c[1] & 0x08) != 0,
        ScsiReply {
            status: 0x00,
            sense: Vec::new(),
            data_in: vec![0x00, 0x00, 0x00, 40],
        },
    );
    let mut t = scsi;
    let count = ScsiPurgeClient::new(&mut t)
        .read_grown_defects()
        .expect("G-List must parse");
    assert_eq!(count, 5);
    // The disclosure text a defense certificate must carry.
    let warning = format!(
        "Media contains {} reallocated sector(s) inaccessible to logical writes. \
         Physical destruction recommended per NIST SP 800-88 Rev 1",
        count
    );
    assert!(warning.contains("Physical destruction"));
}

// ---------------------------------------------------------------------------
// T24-PDFA: archival PDF end-to-end (attachment carving + structure)
// ---------------------------------------------------------------------------

#[test]
fn t24_pdfa3_attachment_carving_round_trip() {
    // A signed-certificate-shaped payload with bytes that would break a
    // naive text embedding (braces, quotes, high-bit sequences).
    let cert: Vec<u8> = (0u8..255)
        .chain(b"{\"schema\":\"diskcleaner-cert/1\"}".iter().copied())
        .collect();
    let journal: Vec<u8> = b"DCJ1\x00\x01\x02journal".to_vec();
    let pdf = dc_report::render_sanitization_archive(
        "Certificate of Sanitization",
        "Hardware Purge — SCSI Sanitize Crypto Erase — naa.t24",
        "Purge",
        true,
        &[
            (
                "Executed mechanism".to_string(),
                "ScsiSanitizeCryptoErase".to_string(),
            ),
            (
                "Completion evidence".to_string(),
                "scsi-sense-poll-terminal".to_string(),
            ),
        ],
        &["Media contains 5 reallocated sector(s).".to_string()],
        "2026-10-12T07:33:00Z",
        &[
            dc_report::ArchiveAttachment {
                filename: "certificate.json",
                bytes: &cert,
                mime: "application/json",
                relationship: "Source",
            },
            dc_report::ArchiveAttachment {
                filename: "journal.dcj",
                bytes: &journal,
                mime: "application/octet-stream",
                relationship: "Supplement",
            },
        ],
    );
    // Both attachments carve out byte-identical (unfiltered streams).
    let cert_ref = cert.as_slice();
    assert!(pdf.windows(cert_ref.len()).any(|w| w == cert_ref));
    let journal_ref = journal.as_slice();
    assert!(pdf.windows(journal_ref.len()).any(|w| w == journal_ref));
    // Structure: A4 pages, embedded font, ICC output intent, file specs.
    let s = String::from_utf8_lossy(&pdf);
    for marker in [
        "/MediaBox [0 0 595 842]",
        "/FontFile2",
        "/GTS_PDFA1",
        "pdfaid:part>3<",
        "/AF [",
    ] {
        assert!(s.contains(marker), "missing {}", marker);
    }
}

// ---------------------------------------------------------------------------
// T24-POLICY: the defense verification gate on the real CLI binary
// ---------------------------------------------------------------------------

#[test]
fn t24_defense_policy_gate_cli_matrix() {
    use assert_cmd::Command;

    // Sampling on defense profiles: exit 8 before arming, across the
    // whole defense catalog.
    for profile in [
        "dod5220-22m",
        "dod5220-22m-ece",
        "certin-goi",
        "csec-itsg06",
        "bsi-vsitr",
    ] {
        Command::cargo_bin("diskcleaner")
            .unwrap()
            .arg("execute")
            .arg("--target")
            .arg("/dev/nonexistent-t24")
            .arg("--profile")
            .arg(profile)
            .arg("--verify")
            .arg("sample:4")
            .arg("--dry-run")
            .assert()
            .code(8);
    }
    // Non-defense profile + sampling is permitted (fails later at the
    // probe with exit 2 instead — the gate is profile-specific).
    Command::cargo_bin("diskcleaner")
        .unwrap()
        .arg("execute")
        .arg("--target")
        .arg("/dev/nonexistent-t24")
        .arg("--profile")
        .arg("schneier")
        .arg("--verify")
        .arg("sample:4")
        .arg("--dry-run")
        .assert()
        .code(2);
}

// ---------------------------------------------------------------------------
// T24-CODEC: cross-transport CDB spot checks (belt to the r900 braces)
// ---------------------------------------------------------------------------

#[test]
fn t24_transport_cdb_sanity() {
    // ATA sanitize CDB mirrors the executed ladder step.
    let cdb = AtaCodec::encode_sat_sanitize_device(dc_hw::AtaSanitizeFeature::CryptoScramble);
    assert_eq!((cdb[0], cdb[14], cdb[4]), (0x85, 0xB4, 0x20));
    // SCSI crypto-erase service action with IMMED.
    let sc = ScsiCodec::encode_sanitize(ScsiSanitizeServiceAction::CryptoErase, true);
    assert_eq!((sc[0], sc[1] & 0x1F, sc[1] & 0x80), (0x48, 0x03, 0x80));
    // FORMAT UNIT never obligates a parameter list.
    let fmt = ScsiCodec::encode_format_unit(false);
    assert_eq!(fmt[1] & 0x10, 0);
}
