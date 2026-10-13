//! dc-resurrect CLI — the bench rig console.

use std::path::PathBuf;
use std::process::ExitCode;

use dc_resurrect::attest::ErasureProof;
use dc_resurrect::nand::NandGeometry;
use dc_resurrect::payload::{self, VerifyMode};
use dc_resurrect::pipeline::{self, MissionConfig};
use dc_resurrect::sim::{ScenarioKind, demo_geometry};

fn usage() -> i32 {
    eprintln!(
        "dc-resurrect {} — dead-silicon sanitization rig (PR16, discCleaner)",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!();
    eprintln!("usage:");
    eprintln!(
        "  dc-resurrect demo     run a full resurrection mission on the simulated dead drive"
    );
    eprintln!("  dc-resurrect verify <proof.drz>   verify an erasure proof file");
    eprintln!("  dc-resurrect inspect-payload       assemble + disassemble the stage-2 nucleus");
    eprintln!("  dc-resurrect vendors               list built-in controller profiles");
    eprintln!();
    eprintln!("options for demo:");
    eprintln!(
        "  --scenario <firmware|hardfault|tvn|lockdown>   failure to simulate (default: firmware)"
    );
    eprintln!("  --vendor <name>                                force a controller profile");
    eprintln!(
        "  --verify <off|sampled|full>                   kernel verification depth (default: sampled)"
    );
    eprintln!("  --seed <hex>                                   reproducible scenario seed");
    eprintln!("  --stuck <die:block>                            inject a permanently stuck block");
    eprintln!("  --out <path>                                   proof file (default: proof.drz)");
    eprintln!(
        "  --compact                                      omit per-block records from the proof"
    );
    eprintln!("  --blocks <n> --ppb <n> --bytes <n> --luns <n>  override geometry");
    0
}

fn parse_seed(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hexs) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hexs, 16).ok()
    } else {
        s.parse().ok()
    }
}

struct CommonOpts {
    scenario: ScenarioKind,
    vendor: Option<String>,
    verify: VerifyMode,
    seed: u64,
    stuck: Option<(usize, u32)>,
    out: PathBuf,
    full_records: bool,
    geometry: Option<NandGeometry>,
}

fn parse_common(args: &[String]) -> Result<CommonOpts, String> {
    let mut o = CommonOpts {
        scenario: ScenarioKind::FirmwareCorrupt,
        vendor: None,
        verify: VerifyMode::Sampled,
        seed: 0x5EED_C0DE,
        stuck: None,
        out: PathBuf::from("proof.drz"),
        full_records: true,
        geometry: None,
    };
    let mut geo = demo_geometry();
    let mut geo_touched = false;
    let mut i = 0;
    let next = |i: &mut usize, what: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("missing value for {what}"))
    };
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--scenario" => {
                let v = next(&mut i, "--scenario")?;
                o.scenario = ScenarioKind::parse(&v).ok_or_else(|| {
                    format!("unknown scenario: {v} (firmware|hardfault|tvn|lockdown)")
                })?;
            }
            "--vendor" => {
                o.vendor = Some(next(&mut i, "--vendor")?);
            }
            "--verify" => {
                let v = next(&mut i, "--verify")?;
                o.verify = match v.as_str() {
                    "off" | "none" => VerifyMode::Off,
                    "sampled" => VerifyMode::Sampled,
                    "full" => VerifyMode::Full,
                    _ => return Err(format!("unknown verify mode: {v}")),
                };
            }
            "--seed" => {
                let v = next(&mut i, "--seed")?;
                o.seed = parse_seed(&v).ok_or_else(|| format!("bad seed: {v}"))?;
            }
            "--stuck" => {
                let v = next(&mut i, "--stuck")?;
                let mut it = v.split(':');
                let die: usize = it
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--stuck wants <die:block>")?;
                let block: u32 = it
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--stuck wants <die:block>")?;
                o.stuck = Some((die, block));
            }
            "--out" => {
                o.out = PathBuf::from(next(&mut i, "--out")?);
            }
            "--compact" => {
                o.full_records = false;
            }
            "--blocks" => {
                geo.blocks_per_lun = next(&mut i, "--blocks")?
                    .parse()
                    .map_err(|_| "bad --blocks")?;
                geo_touched = true;
            }
            "--ppb" => {
                geo.pages_per_block = next(&mut i, "--ppb")?.parse().map_err(|_| "bad --ppb")?;
                geo_touched = true;
            }
            "--bytes" => {
                geo.bytes_per_page = next(&mut i, "--bytes")?
                    .parse()
                    .map_err(|_| "bad --bytes")?;
                geo_touched = true;
            }
            "--luns" => {
                geo.luns = next(&mut i, "--luns")?.parse().map_err(|_| "bad --luns")?;
                geo_touched = true;
            }
            other => return Err(format!("unknown option: {other}")),
        }
        i += 1;
    }
    if geo_touched {
        o.geometry = Some(geo);
    }
    Ok(o)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return ExitCode::from(usage() as u8);
    }
    let cmd = args[0].as_str();
    let rest: Vec<String> = args[1..].to_vec();
    match cmd {
        "demo" | "resurrect" => {
            let opts = match parse_common(&rest) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let cfg = MissionConfig {
                scenario: opts.scenario,
                vendor: opts.vendor,
                verify: opts.verify,
                seed: opts.seed,
                geometry: opts.geometry,
                stuck: opts.stuck,
                proof_path: opts.out,
                full_records: opts.full_records,
            };
            let mut log = Vec::new();
            match pipeline::run(&cfg, &mut log) {
                Ok(report) => {
                    for line in &report.log {
                        println!("{line}");
                    }
                    println!();
                    println!(
                        "mission complete — class {} | {} | core instructions {} | proof: {}",
                        report.class.name(),
                        report.transport.name(),
                        report.core_instructions,
                        report.proof_path.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    for line in &log {
                        eprintln!("{line}");
                    }
                    eprintln!("mission failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "verify" => {
            if rest.is_empty() {
                eprintln!("usage: dc-resurrect verify <proof.drz>");
                return ExitCode::from(2);
            }
            match ErasureProof::verify_file(std::path::Path::new(&rest[0])) {
                Ok(rep) => {
                    println!("PROOF OK");
                    println!("  controller   : {}", rep.controller);
                    println!(
                        "  merkle root  : {}",
                        dc_resurrect::sha256::hex(&rep.merkle_root)
                    );
                    println!(
                        "  leaves       : {} rehashed, preimages verified",
                        rep.leaves_checked
                    );
                    println!("  inclusions   : {} verified", rep.inclusions_checked);
                    println!(
                        "  blocks       : {} total / {} erased / {} skipped / {} failed / {} die-fail",
                        rep.stats.total,
                        rep.stats.erased,
                        rep.stats.skipped_bad,
                        rep.stats.failed,
                        rep.stats.die_id_fail
                    );
                    println!(
                        "  payload sha  : {}",
                        dc_resurrect::sha256::hex(&rep.payload_sha256)
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("PROOF REJECTED: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "inspect-payload" => {
            let profile =
                dc_resurrect::vendors::ControllerProfile::builtin_by_name("marvell-88ss1077")
                    .unwrap();
            let geo = demo_geometry();
            let params = payload::PayloadParams {
                load_base: profile.sram_base,
                nand_mmio: profile.nand_mmio,
                dbg_mmio: profile.dbg_mmio,
                uart_mmio: Some(profile.uart_mmio),
                geometry: geo,
                verify: VerifyMode::Sampled,
                read_id_word: 0x3294_DE98,
            };
            let probe = payload::assemble_probe(&params);
            let kernel = payload::assemble_kernel(&params);
            println!(
                "stage-1 probe:  {} B  entry {:#010x}  crc32 {:08x}",
                probe.blob.len(),
                probe.manifest.entry,
                probe.manifest.blob_crc32
            );
            println!(
                "  sha256 {}",
                dc_resurrect::sha256::hex(&probe.manifest.blob_sha256)
            );
            println!(
                "stage-2 kernel: {} B  entry {:#010x}  crc32 {:08x}",
                kernel.blob.len(),
                kernel.manifest.entry,
                kernel.manifest.blob_crc32
            );
            println!(
                "  sha256 {}",
                dc_resurrect::sha256::hex(&kernel.manifest.blob_sha256)
            );
            println!("  relocs: {}", kernel.manifest.relocs.len());
            println!();
            println!("--- stage-2 disassembly (first 96 instructions) ---");
            for line in payload::asm::disasm(&kernel.blob, kernel.manifest.load_base)
                .into_iter()
                .take(96)
            {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        "vendors" => {
            println!(
                "{:<26} {:<14} {:<10} {:<10} {:<8}",
                "PROFILE", "FAMILY", "SRAM", "DPIDR", "AUTH"
            );
            for p in dc_resurrect::vendors::ControllerProfile::builtins() {
                println!(
                    "{:<26} {:<14} {:<10} {:<10} {:<8}",
                    p.name,
                    p.family,
                    format!("{:#x}", p.sram_base),
                    p.swd_dpidr
                        .map(|d| format!("{:#x}", d))
                        .unwrap_or_else(|| "-".into()),
                    if p.brom.auth_required { "yes" } else { "no" },
                );
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("unknown command: {cmd}");
            ExitCode::from(usage() as u8)
        }
    }
}
