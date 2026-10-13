//! The mission pipeline: scan, triage, resurrect, attest.
//!
//! ```text
//! scan     -> what answers on UART / SWD / JTAG? (bench power if Class C)
//! triage   -> failure class + route
//! assemble -> stage-1 probe nucleus; run it; parse real ONFI geometry;
//!             stage-2 erase kernel assembled FOR that geometry
//! inject   -> BROM download or MEM-AP writes, then JUMP
//! execute  -> autonomous kernel: erase, retry marginal blocks, verify,
//!             CRC-32 attestations, heartbeat, park
//! collect  -> mailbox readback over the same debug link
//! prove    -> Merkle tree over one leaf per block; .drz proof; verify
//! ```

use std::path::PathBuf;

use crate::attest::{BlockRecord, BlockStats, ErasureProof, ST_ERASED};
use crate::bitbang::{BitBangNand, estimate_seconds};
use crate::dp::MemAp;
use crate::failure::{FailureClass, TriageReport};
use crate::hal::{RigPower, Transport, UartLink};
use crate::jtag::JtagEngine;
use crate::nand::NandGeometry;
use crate::payload::{self, MB_SUM_DONE, MB_SUM_MAGIC, PayloadParams, Stage, VerifyMode, layout};
use crate::sim::{ScenarioKind, SimLink, demo_geometry};
use crate::swd::SwdEngine;
use crate::uart_brom::{BromChannel, HB_DONE, HB_PROGRESS};
use crate::vendors::ControllerProfile;

/// Bench quote we beat (industrial shredder, per-drive service fee).
pub const SHREDDER_QUOTE_USD: u64 = 975;

#[derive(Clone, Debug)]
pub struct MissionConfig {
    pub scenario: ScenarioKind,
    pub vendor: Option<String>,
    pub verify: VerifyMode,
    pub seed: u64,
    pub geometry: Option<NandGeometry>,
    pub stuck: Option<(usize, u32)>,
    pub proof_path: PathBuf,
    pub full_records: bool,
}

impl Default for MissionConfig {
    fn default() -> Self {
        MissionConfig {
            scenario: ScenarioKind::FirmwareCorrupt,
            vendor: None,
            verify: VerifyMode::Sampled,
            seed: 0x5EED_C0DE,
            geometry: None,
            stuck: None,
            proof_path: PathBuf::from("proof.drz"),
            full_records: true,
        }
    }
}

pub struct BitBangStats {
    pub shifts: u64,
    pub seconds_at_1mhz: f64,
}

pub struct MissionReport {
    pub class: FailureClass,
    pub profile: ControllerProfile,
    pub transport: Transport,
    pub stats: BlockStats,
    pub geometry: NandGeometry,
    pub proof_path: PathBuf,
    pub core_instructions: u64,
    pub bitbang: Option<BitBangStats>,
    pub log: Vec<String>,
}

/// Which profile the rig brings to the bench by default per scenario.
fn default_profile(scenario: ScenarioKind) -> ControllerProfile {
    match scenario {
        // Marvell 88SS1077: the Cortex-R4 brick with a generous BROM.
        ScenarioKind::FirmwareCorrupt | ScenarioKind::PowerPathTvn => {
            ControllerProfile::builtin_by_name("marvell-88ss1077").unwrap()
        }
        // Silicon Motion SM2262EN: SWD bonded out, so the debug-port route
        // is exercisable; also the lockdown victim.
        ScenarioKind::HardFaultLockup | ScenarioKind::DebugLockdown => {
            ControllerProfile::builtin_by_name("siliconmotion-sm2262en").unwrap()
        }
    }
}

/// Probe-phase parameters (geometry-independent by construction).
fn probe_params(profile: &ControllerProfile) -> PayloadParams {
    PayloadParams {
        load_base: profile.sram_base,
        nand_mmio: profile.nand_mmio,
        dbg_mmio: profile.dbg_mmio,
        uart_mmio: Some(profile.uart_mmio),
        geometry: demo_geometry(), // unused by the probe code itself
        verify: VerifyMode::Off,
        read_id_word: 0,
    }
}

fn kernel_params(
    profile: &ControllerProfile,
    geometry: NandGeometry,
    verify: VerifyMode,
    read_id_word: u32,
) -> PayloadParams {
    PayloadParams {
        load_base: profile.sram_base,
        nand_mmio: profile.nand_mmio,
        dbg_mmio: profile.dbg_mmio,
        uart_mmio: Some(profile.uart_mmio),
        geometry,
        verify,
        read_id_word,
    }
}

/// What the kernel left in the mailbox.
struct Mailbox {
    records: Vec<BlockRecord>,
    summary: Option<[u32; 6]>,
}

fn parse_mailbox(words: &[u32]) -> Mailbox {
    let mut records = Vec::new();
    let mut summary = None;
    let mut i = 0;
    while i + 1 < words.len() {
        match words[i] {
            x if x == crate::payload::MB_REC_MAGIC && i + 5 <= words.len() => {
                records.push(BlockRecord::from_mailbox(
                    words[i + 1],
                    words[i + 2],
                    words[i + 3],
                    words[i + 4],
                ));
                i += 5;
            }
            x if x == MB_SUM_MAGIC && i + 6 <= words.len() => {
                summary = Some([
                    words[i],
                    words[i + 1],
                    words[i + 2],
                    words[i + 3],
                    words[i + 4],
                    words[i + 5],
                ]);
                break;
            }
            _ => break,
        }
    }
    Mailbox { records, summary }
}

/// The pin-level path on full-size geometry runs with verification off
/// (the cost model explains why); small geometries keep the requested mode.
fn effective_verify(cfg: &MissionConfig, geometry: &NandGeometry) -> VerifyMode {
    if cfg.scenario == ScenarioKind::DebugLockdown && geometry.total_blocks() > 64 {
        VerifyMode::Off
    } else {
        cfg.verify
    }
}

/// One full resurrection mission against the simulated dead drive.
pub fn run(cfg: &MissionConfig, log: &mut Vec<String>) -> Result<MissionReport, String> {
    let profile = match &cfg.vendor {
        Some(name) => ControllerProfile::builtin_by_name(name)
            .ok_or_else(|| format!("unknown vendor profile: {name}"))?,
        None => default_profile(cfg.scenario),
    };
    let board_geometry = cfg.geometry.unwrap_or_else(demo_geometry);
    let mut link = SimLink::build(
        cfg.scenario,
        profile.clone(),
        board_geometry,
        cfg.seed,
        cfg.stuck,
    );
    log.push(format!(
        "[RIG]   link: sim (bit-level) | scenario: {} | seed {:#x} | target profile: {} ({})",
        cfg.scenario.name(),
        cfg.seed,
        profile.name,
        profile.core
    ));
    log.push(format!(
        "[RIG]   NAND {}+{} B/page | {} ppb | {} blk/LUN | {} LUN | {} bytes",
        board_geometry.bytes_per_page,
        board_geometry.spare_bytes,
        board_geometry.pages_per_block,
        board_geometry.blocks_per_lun,
        board_geometry.luns,
        board_geometry.capacity()
    ));

    // ---------------- scan ----------------
    let mut bench_power_applied = false;
    let mut brom_alive = false;
    link.write_byte(profile.brom.sync)
        .map_err(|e| e.to_string())?;
    match link.read_byte_timeout(50).map_err(|e| e.to_string())? {
        Some(b) if b == profile.brom.ack => {
            brom_alive = true;
            log.push(format!(
                "[SCAN]  UART @{} baud: auto-baud ACK {:#04x} — BROM ALIVE",
                profile.brom.baud, b
            ));
        }
        _ => {
            if !link.target.rails_alive {
                log.push("[SCAN]  no life on any bus — checking power path...".to_string());
                log.push("[SCAN]  blown TVS diode, rails dead: applying external bench 5V/3.3V (current-limited)".to_string());
                link.rig_apply_power().map_err(|e| e.to_string())?;
                bench_power_applied = true;
                log.push("[SCAN]  bench power good. Re-scanning...".to_string());
                link.write_byte(profile.brom.sync)
                    .map_err(|e| e.to_string())?;
                if let Some(b) = link.read_byte_timeout(50).map_err(|e| e.to_string())?
                    && b == profile.brom.ack
                {
                    brom_alive = true;
                    log.push("[SCAN]  UART BROM answers after re-power — the silicon is fine, the PCB was the corpse.".to_string());
                }
            } else {
                log.push("[SCAN]  UART silent — no BROM strap (or locked shell).".to_string());
            }
        }
    }

    // SWD probe: DPIDR then a MEM-AP IDR attempt (locked silicon faults here).
    let mut swd_usable = false;
    let mut swd_locked = false;
    {
        let mut swd = SwdEngine::new(link);
        match swd.connect() {
            Ok(dpidr) => {
                log.push(format!(
                    "[SCAN]  SWD DPIDR {:#010x} — debug port alive",
                    dpidr
                ));
                let mut ap = MemAp::new(&mut swd, 0);
                match ap.power_up().and_then(|_| ap.idr()) {
                    Ok(idr) => {
                        swd_usable = true;
                        log.push(format!(
                            "[SCAN]  MEM-AP IDR {:#010x} — memory access port open",
                            idr
                        ));
                    }
                    Err(_) => {
                        swd_locked = true;
                        log.push(
                            "[SCAN]  MEM-AP access FAULTS — vendor debug lock engaged.".to_string(),
                        );
                    }
                }
                let _ = swd_locked; // surfaced through the Class D triage below
            }
            Err(_) => {
                log.push("[SCAN]  SWD: no debug port (or silicon dark).".to_string());
            }
        }
        link = swd.into_inner();
    }

    // JTAG chain scan (returns us to JTAG mode via TLR if SWD probed first).
    let taps = {
        let mut jeng = JtagEngine::new(link);
        let taps = jeng.scan_chain(2048, 32);
        link = jeng.into_inner();
        taps
    };
    if !taps.is_empty() {
        log.push(format!(
            "[SCAN]  JTAG chain: {} TAP(s): {}",
            taps.len(),
            taps.iter()
                .map(|t| format!("IDCODE {:#010x}", t.idcode))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    } else {
        log.push("[SCAN]  JTAG: no TAP on the chain.".to_string());
    }

    // ---------------- triage ----------------
    let mut triage = TriageReport::new(if bench_power_applied {
        FailureClass::C_PowerPath
    } else if brom_alive {
        FailureClass::A_FirmwareCorruption
    } else if swd_usable {
        FailureClass::B_CoreFault
    } else if !taps.is_empty() {
        FailureClass::D_DebugLockdown
    } else {
        FailureClass::X_Unrecoverable
    });
    if bench_power_applied {
        triage.evidence("power rails dead until bench supply; TVS diode bypassed");
    }
    if !brom_alive {
        triage.evidence("BROM UART silent (strap not asserted or vendor lock)");
    }
    if triage.class == FailureClass::B_CoreFault {
        triage.evidence("core faulted at boot; debug port responsive — RAM takeover viable");
    }
    if triage.class == FailureClass::D_DebugLockdown {
        triage
            .evidence("SWD AP faults, JTAG-DP returns junk — boundary-scan pin takeover required");
    }
    log.push(format!(
        "[TRIAGE] {} — route: {}",
        triage.class.name(),
        triage.class.route().name()
    ));
    for e in &triage.evidence {
        log.push(format!("        · {e}"));
    }
    if triage.class == FailureClass::X_Unrecoverable {
        return Err("silicon beyond debug access — physical destruction still required".into());
    }

    // ---------------- resurrect ----------------
    let RouteOut {
        link,
        records,
        geometry,
        bitbang,
    } = match triage.class {
        FailureClass::A_FirmwareCorruption | FailureClass::C_PowerPath => {
            run_via_brom(link, &profile, cfg, log)?
        }
        FailureClass::B_CoreFault => run_via_swd(link, &profile, cfg, log)?,
        FailureClass::D_DebugLockdown => {
            run_via_bitbang(link, &profile, &board_geometry, cfg, log)?
        }
        FailureClass::X_Unrecoverable => unreachable!(),
    };

    // ---------------- prove ----------------
    let core_instructions = link.target.core.executed;
    let stats = BlockStats::from_records(&records, geometry.total_blocks());
    if !stats.complete(&geometry) {
        return Err(format!(
            "mailbox accounting incomplete: erased {} + skipped {} + failed {} (+die-fail {} x {}) != total {}",
            stats.erased,
            stats.skipped_bad,
            stats.failed,
            stats.die_id_fail,
            geometry.blocks_per_lun,
            stats.total
        ));
    }
    let payload_sha = *last_kernel_sha();
    let payload_len = last_kernel_len();
    let payload_crc = last_kernel_crc();
    let proof = ErasureProof::build(
        cfg.scenario.name(),
        &profile,
        Stage::Kernel,
        payload_sha.unwrap_or([0u8; 32]),
        payload_len.unwrap_or(0),
        payload_crc.unwrap_or(0),
        geometry,
        effective_verify(cfg, &geometry),
        records,
        cfg.seed,
        core_instructions,
    );
    proof
        .write_file(&cfg.proof_path, cfg.full_records)
        .map_err(|e| e.to_string())?;
    log.push(format!(
        "[PROOF] merkle root {}",
        crate::sha256::hex(&proof.merkle_root)
    ));
    log.push(format!(
        "[PROOF] leaves {} / {} — complete block coverage | written: {}",
        proof.stats().erased
            + proof.stats().skipped_bad
            + proof.stats().failed
            + proof.stats().die_id_fail,
        stats.total,
        cfg.proof_path.display()
    ));
    match ErasureProof::verify_file(&cfg.proof_path) {
        Ok(rep) => {
            log.push(format!(
                "[PROOF] verify: OK ({} leaves rehashed, {} inclusion proofs checked, payload sha {}…)",
                rep.leaves_checked,
                rep.inclusions_checked,
                &crate::sha256::hex(&rep.payload_sha256)[..16]
            ));
        }
        Err(e) => return Err(format!("proof failed verification: {e}")),
    }
    log.push(format!(
        "[RIG]   chip resurrected: {} erased / {} skipped-bad / {} failed — shredder quote avoided: ${}",
        stats.erased, stats.skipped_bad, stats.failed, SHREDDER_QUOTE_USD
    ));

    Ok(MissionReport {
        class: triage.class,
        profile,
        transport: triage.class.route(),
        stats,
        geometry,
        proof_path: cfg.proof_path.clone(),
        core_instructions,
        bitbang,
        log: std::mem::take(log),
    })
}

// ---------------------------------------------------------------------------
// Route 1: UART Boot-ROM download
// ---------------------------------------------------------------------------

fn run_via_brom(
    link: SimLink,
    profile: &ControllerProfile,
    cfg: &MissionConfig,
    log: &mut Vec<String>,
) -> Result<RouteOut, String> {
    let mut link = link;
    let records;
    let geometry;
    {
        let params = profile.brom.clone();
        let mut ch = BromChannel::new(&mut link, params);
        ch.open().map_err(|e| format!("BROM open failed: {e}"))?;
        log.push(
            "[BROM]   auto-baud + HELLO verified (CRC16 echo) — vendor shell authenticated"
                .to_string(),
        );

        // ---- stage 1: the probe
        let p1 = payload::assemble_probe(&probe_params(profile));
        log.push(format!(
            "[ASM]   stage-1 probe nucleus: {} B, sha256 {}…",
            p1.blob.len(),
            &crate::sha256::hex(&p1.manifest.blob_sha256)[..16]
        ));
        ch.download(&p1.blob, p1.manifest.load_base)
            .map_err(|e| format!("probe download failed: {e}"))?;
        ch.jump(p1.manifest.entry)
            .map_err(|e| format!("probe jump failed: {e}"))?;
        wait_heartbeat(&mut ch, log, "probe")?;
        log.push("[PROBE]  probe parked — reading ONFI parameter page + READ-ID".to_string());

        // ---- probe mailbox: ID word + 64 bytes of the parameter page
        let mb = profile.sram_base + layout::MAILBOX;
        let mut bytes = Vec::new();
        for i in 0..20 {
            let w = ch
                .peek32(mb + i * 4)
                .map_err(|e| format!("PEEK failed: {e}"))?;
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let read_id_word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        geometry = NandGeometry::from_onfi_param_page(&bytes[4..68])
            .ok_or("ONFI parameter page invalid — refusing to assemble kernel")?;
        log.push(format!(
            "[PROBE]  READ-ID {:#010x} | ONFI: {}+{} B/page, {} ppb, {} blk/LUN, {} LUN → {} bytes",
            read_id_word,
            geometry.bytes_per_page,
            geometry.spare_bytes,
            geometry.pages_per_block,
            geometry.blocks_per_lun,
            geometry.luns,
            geometry.capacity()
        ));

        // ---- stage 2: assembled for the discovered silicon
        let verify = effective_verify(cfg, &geometry);
        let p2 = payload::assemble_kernel(&kernel_params(profile, geometry, verify, read_id_word));
        log.push(format!(
            "[ASM]   stage-2 erase kernel: {} B (self-assembled: {} verify, stride {}, {} dies)",
            p2.blob.len(),
            match verify {
                VerifyMode::Off => "no",
                VerifyMode::Sampled => "sampled",
                VerifyMode::Full => "full",
            },
            match verify {
                VerifyMode::Off => 0,
                VerifyMode::Sampled => (geometry.pages_per_block / 2).max(1),
                VerifyMode::Full => 1,
            },
            geometry.luns
        ));
        *last_kernel_sha_slot() = Some(p2.manifest.blob_sha256);
        *last_kernel_len_slot() = Some(p2.manifest.blob_len);
        *last_kernel_crc_slot() = Some(p2.manifest.blob_crc32);
        ch.download(&p2.blob, p2.manifest.load_base)
            .map_err(|e| format!("kernel download failed: {e}"))?;
        ch.jump(p2.manifest.entry)
            .map_err(|e| format!("kernel jump failed: {e}"))?;
        log.push("[EXEC]  kernel autonomous — operator may disconnect".to_string());
        wait_heartbeat(&mut ch, log, "kernel")?;

        // ---- mailbox readback: records are 5 words each, summary 6.
        let cap = geometry.total_blocks() as usize * 5 + 5 * geometry.luns as usize + 16;
        let mut words = Vec::with_capacity(cap);
        for i in 0..cap {
            let w = ch
                .peek32(mb + i as u32 * 4)
                .map_err(|e| format!("mailbox PEEK failed: {e}"))?;
            words.push(w);
            if w == MB_SUM_DONE {
                break;
            }
        }
        let mbx = parse_mailbox(&words);
        if let Some(s) = mbx.summary {
            if s[5] != MB_SUM_DONE {
                return Err("kernel summary incomplete (no DONE marker)".into());
            }
            log.push(format!(
                "[EXEC]  park: {} total | {} erased | {} skipped | {} failed",
                s[1], s[2], s[3], s[4]
            ));
        } else {
            return Err("no summary record in mailbox".into());
        }
        records = mbx.records;
    }
    log.push(format!(
        "[EXEC]  core executed {} instructions",
        link.target.core.executed
    ));
    Ok(RouteOut {
        link,
        records,
        geometry,
        bitbang: None,
    })
}

fn wait_heartbeat<U: UartLink>(
    ch: &mut BromChannel<'_, U>,
    log: &mut Vec<String>,
    what: &str,
) -> Result<(), String> {
    let mut quiet = 0u32;
    let mut seen = 0u32;
    loop {
        match ch
            .read_heartbeat(500)
            .map_err(|e| format!("heartbeat read failed: {e}"))?
        {
            Some(hb) => {
                quiet = 0;
                if hb.hb_type == HB_PROGRESS {
                    seen += 1;
                    if seen.is_multiple_of(256) {
                        log.push(format!("[EXEC]  {} — block #{}", what, hb.block));
                    }
                } else if hb.hb_type == HB_DONE {
                    log.push(format!(
                        "[EXEC]  {} heartbeat: DONE (data {:#x})",
                        what, hb.data
                    ));
                    return Ok(());
                }
            }
            None => {
                quiet += 1;
                if quiet > 2000 {
                    return Err(format!("{what} never signaled DONE ({quiet} silent polls)"));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Route 2: SWD / MEM-AP injection
// ---------------------------------------------------------------------------

fn run_via_swd(
    link: SimLink,
    profile: &ControllerProfile,
    cfg: &MissionConfig,
    log: &mut Vec<String>,
) -> Result<RouteOut, String> {
    let geometry;
    let records;
    let mut swd = SwdEngine::new(link);
    let dpidr = swd
        .connect()
        .map_err(|e| format!("SWD connect failed: {e}"))?;
    log.push(format!("[SWD]    connected, DPIDR {:#010x}", dpidr));
    let dbg = profile.dbg_mmio;
    {
        let mut ap = MemAp::new(&mut swd, 0);
        ap.power_up()
            .map_err(|e| format!("DP power-up failed: {e}"))?;
        let idr = ap.idr().map_err(|e| format!("AP IDR read failed: {e}"))?;
        log.push(format!(
            "[SWD]    MEM-AP IDR {:#010x} — system + debug power ACKed",
            idr
        ));
        ap.halt_core(dbg)
            .map_err(|e| format!("DBG_HALT failed: {e}"))?;
        log.push("[SWD]    core halted (was fault-looped) — taking SRAM".to_string());

        // ---- stage 1
        let p1 = payload::assemble_probe(&probe_params(profile));
        let words = blob_words(&p1.blob);
        ap.write_block32(p1.manifest.load_base, &words)
            .map_err(|e| format!("probe SRAM write failed: {e}"))?;
        ap.jump_core(dbg, p1.manifest.entry)
            .map_err(|e| format!("DBG_JUMP failed: {e}"))?;
        log.push(format!(
            "[INJECT] stage-1 probe: {} B into SRAM via MEM-AP, core released",
            p1.blob.len()
        ));
        wait_core_parked(&mut ap, dbg, log, "probe")?;

        // ---- probe mailbox
        let mb = profile.sram_base + layout::MAILBOX;
        let mut probe_words = vec![0u32; 20];
        ap.read_block32(mb, &mut probe_words)
            .map_err(|e| format!("mailbox read failed: {e}"))?;
        let mut bytes = Vec::new();
        for w in &probe_words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let read_id_word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        geometry = NandGeometry::from_onfi_param_page(&bytes[4..68])
            .ok_or("ONFI parameter page invalid")?;
        log.push(format!(
            "[PROBE]  READ-ID {:#010x} | ONFI: {} B/page, {} ppb, {} blk/LUN, {} LUN",
            read_id_word,
            geometry.bytes_per_page,
            geometry.pages_per_block,
            geometry.blocks_per_lun,
            geometry.luns
        ));

        // ---- stage 2
        let verify = effective_verify(cfg, &geometry);
        let p2 = payload::assemble_kernel(&kernel_params(profile, geometry, verify, read_id_word));
        *last_kernel_sha_slot() = Some(p2.manifest.blob_sha256);
        *last_kernel_len_slot() = Some(p2.manifest.blob_len);
        *last_kernel_crc_slot() = Some(p2.manifest.blob_crc32);
        ap.halt_core(dbg)
            .map_err(|e| format!("DBG_HALT failed: {e}"))?;
        let words = blob_words(&p2.blob);
        ap.write_block32(p2.manifest.load_base, &words)
            .map_err(|e| format!("kernel SRAM write failed: {e}"))?;
        ap.jump_core(dbg, p2.manifest.entry)
            .map_err(|e| format!("DBG_JUMP failed: {e}"))?;
        log.push(format!(
            "[INJECT] stage-2 kernel: {} B — autonomous erase begins",
            p2.blob.len()
        ));
        wait_core_parked(&mut ap, dbg, log, "kernel")?;

        // ---- mailbox readback (chunked; stop at the summary DONE marker)
        let cap = geometry.total_blocks() as usize * 5 + 5 * geometry.luns as usize + 16;
        let mut words = vec![0u32; cap];
        let mut done = false;
        {
            let mut got = 0usize;
            while got < cap && !done {
                let take = 64.min(cap - got);
                let mut chunk = vec![0u32; take];
                ap.read_block32(mb + (got as u32) * 4, &mut chunk)
                    .map_err(|e| format!("mailbox read failed: {e}"))?;
                if chunk.contains(&MB_SUM_DONE) {
                    done = true;
                }
                words[got..got + take].copy_from_slice(&chunk);
                got += take;
            }
        }
        let mbx = parse_mailbox(&words);
        if let Some(s) = mbx.summary {
            if s[5] != MB_SUM_DONE {
                return Err("kernel summary incomplete".into());
            }
            log.push(format!(
                "[EXEC]  park: {} total | {} erased | {} skipped | {} failed",
                s[1], s[2], s[3], s[4]
            ));
        } else {
            return Err("no summary record in mailbox".into());
        }
        records = mbx.records;
    }
    let link = swd.into_inner();
    log.push(format!(
        "[EXEC]  core executed {} instructions",
        link.target.core.executed
    ));
    Ok(RouteOut {
        link,
        records,
        geometry,
        bitbang: None,
    })
}

fn wait_core_parked<'a, P: crate::dp::DpPort>(
    ap: &mut MemAp<'a, P>,
    dbg: u32,
    log: &mut Vec<String>,
    what: &str,
) -> Result<(), String> {
    for _ in 0..4000 {
        let st = ap
            .core_status(dbg)
            .map_err(|e| format!("DBG_STATS read failed: {e}"))?;
        if st & 0x2 != 0 {
            log.push(format!("[EXEC]  {} parked (status {:#x})", what, st));
            return Ok(());
        }
        if st & 0x10 != 0 {
            return Err(format!("{what} core faulted after jump"));
        }
    }
    Err(format!("{what} never parked"))
}

fn blob_words(blob: &[u8]) -> Vec<u32> {
    let mut v = Vec::with_capacity(blob.len() / 4 + 1);
    let mut i = 0;
    while i < blob.len() {
        let b: [u8; 4] = [
            blob.get(i).copied().unwrap_or(0),
            blob.get(i + 1).copied().unwrap_or(0),
            blob.get(i + 2).copied().unwrap_or(0),
            blob.get(i + 3).copied().unwrap_or(0),
        ];
        v.push(u32::from_le_bytes(b));
        i += 4;
    }
    v
}

// ---------------------------------------------------------------------------
// Route 3: boundary-scan pin takeover
// ---------------------------------------------------------------------------

fn run_via_bitbang(
    link: SimLink,
    profile: &ControllerProfile,
    geometry: &NandGeometry,
    cfg: &MissionConfig,
    log: &mut Vec<String>,
) -> Result<RouteOut, String> {
    log.push("[BSR]    debug ports locked — taking the NAND bus through boundary scan".to_string());
    let verify = effective_verify(cfg, geometry);
    log.push(format!(
        "[BSR]    pin-level path: {} verify — every byte costs two BSR shifts",
        match verify {
            VerifyMode::Off => "no",
            VerifyMode::Sampled => "sampled",
            VerifyMode::Full => "full",
        }
    ));
    let records;
    let shifts;
    let mut link = link;
    {
        let mut jeng = JtagEngine::new(link);
        let taps = jeng.scan_chain(2048, 32);
        if taps.is_empty() {
            return Err("TAP disappeared — silicon fully dead".into());
        }
        let mut bb = BitBangNand::new(&mut jeng, profile.jtag_irlen, profile.bsr_len);
        let mut seen = 0u32;
        records = bb.run_erase(geometry, verify, profile.jtag_irlen, |_, _| {
            seen += 1;
        });
        shifts = bb.shifts;
        log.push(format!(
            "[BSR]    {} BSR shifts | {} bytes strobed in, {} bytes read out",
            bb.shifts, bb.bytes_written, bb.bytes_read
        ));
        link = jeng.into_inner();
    }
    let seconds = estimate_seconds(shifts, profile.bsr_len, 1_000_000);
    log.push(format!(
        "[BSR]    estimated pin-level duration @1 MHz TCK: {:.1} s — the in-silicon kernel runs hundreds of times faster",
        seconds
    ));
    // Pin-level path has no injected payload; the proof records this.
    *last_kernel_sha_slot() = None;
    *last_kernel_len_slot() = None;
    *last_kernel_crc_slot() = None;
    let n_erased = records.iter().filter(|r| r.status == ST_ERASED).count();
    log.push(format!(
        "[BSR]    pin-level pass complete: {} blocks erased",
        n_erased
    ));
    Ok(RouteOut {
        link,
        records,
        geometry: *geometry,
        bitbang: Some(BitBangStats {
            shifts,
            seconds_at_1mhz: seconds,
        }),
    })
}

// ---------------------------------------------------------------------------
// Route plumbing
// ---------------------------------------------------------------------------

/// What a resurrection route hands back to the pipeline.
struct RouteOut {
    link: SimLink,
    records: Vec<BlockRecord>,
    geometry: NandGeometry,
    bitbang: Option<BitBangStats>,
}

// Shared slots for the stage-2 manifest hashes (single-threaded CLI).
use std::sync::Mutex;

static LAST_SHA: Mutex<Option<[u8; 32]>> = Mutex::new(None);
static LAST_LEN: Mutex<Option<u32>> = Mutex::new(None);
static LAST_CRC: Mutex<Option<u32>> = Mutex::new(None);

fn last_kernel_sha() -> std::sync::MutexGuard<'static, Option<[u8; 32]>> {
    LAST_SHA.lock().unwrap()
}

fn last_kernel_len() -> std::sync::MutexGuard<'static, Option<u32>> {
    LAST_LEN.lock().unwrap()
}

fn last_kernel_crc() -> std::sync::MutexGuard<'static, Option<u32>> {
    LAST_CRC.lock().unwrap()
}

fn last_kernel_sha_slot() -> std::sync::MutexGuard<'static, Option<[u8; 32]>> {
    LAST_SHA.lock().unwrap()
}

fn last_kernel_len_slot() -> std::sync::MutexGuard<'static, Option<u32>> {
    LAST_LEN.lock().unwrap()
}

fn last_kernel_crc_slot() -> std::sync::MutexGuard<'static, Option<u32>> {
    LAST_CRC.lock().unwrap()
}
