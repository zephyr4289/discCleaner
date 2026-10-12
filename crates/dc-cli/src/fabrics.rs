//! `dc fabrics` — NVMe-oF session management (v0.8.0, Vector 4).
//!
//! `list`: show fabric controllers currently known to the kernel
//! (sysfs walk matching fabric transports).
//! `connect` / `disconnect`: drive the genl session lifecycle directly.
//! `discover`: connect to the discovery NQN and print the subsystems the
//! fabric advertises (discovery log page LID 0x70 via admin passthrough
//! on the connected controller char device).

use crate::{FabricsArgs, FabricsSubcommands};
use dc_core::DcError;
use dc_nvme::NvmeAdminTransport as _;
use dc_nvme::fabric_disconnect;
use dc_nvme::fabrics::{self, FabricTarget, FabricTimeouts};
use std::time::Instant;

pub fn cmd_fabrics(args: FabricsArgs) -> Result<(), DcError> {
    match &args.sub {
        FabricsSubcommands::List => cmd_list(),
        FabricsSubcommands::Connect {
            target,
            ack_ms,
            ctrl_appear_ms,
            disconnect,
        } => cmd_connect(&ConnectArgs {
            target: target.clone(),
            ack_ms: *ack_ms,
            ctrl_appear_ms: *ctrl_appear_ms,
            disconnect: *disconnect,
        }),
        FabricsSubcommands::Disconnect { target } => cmd_disconnect(&DisconnectArgs {
            target: target.clone(),
        }),
        FabricsSubcommands::Discover {
            target,
            ack_ms,
            ctrl_appear_ms,
        } => cmd_discover(&DiscoverArgs {
            target: target.clone(),
            ack_ms: *ack_ms,
            ctrl_appear_ms: *ctrl_appear_ms,
        }),
    }
}

fn parse_target(uri: &str) -> Result<FabricTarget, DcError> {
    FabricTarget::parse(uri).map_err(|e| DcError::Usage(format!("{e}")))
}

fn cmd_list() -> Result<(), DcError> {
    let entries = std::fs::read_dir("/sys/class/nvme")
        .map_err(|e| DcError::Internal(format!("/sys/class/nvme: {e}")))?;
    let mut found = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let address = read_trim(path.join("address"));
        let subsysnqn = read_trim(path.join("subsysnqn"));
        let transport = read_trim(path.join("transport"));
        let model = read_trim(path.join("model"));
        // Fabric controllers expose a non-empty transport attribute.
        if transport.is_empty() {
            continue;
        }
        found += 1;
        println!("{name:10} {transport:6} {address:40} {model:24} {subsysnqn}");
    }
    if found == 0 {
        println!("no fabric controllers connected");
    }
    Ok(())
}

fn read_trim(p: std::path::PathBuf) -> String {
    std::fs::read_to_string(p)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn cmd_connect(c: &ConnectArgs) -> Result<(), DcError> {
    let target = parse_target(&c.target)?;
    let timeouts = FabricTimeouts {
        ack_ms: c.ack_ms,
        ctrl_appear_ms: c.ctrl_appear_ms,
        poll_ms: 100,
    };
    let started = Instant::now();
    let session = fabrics::connect(&target, &timeouts).map_err(fabric_err)?;
    println!(
        "connected: {}://{} ctrl {} ({} ms) — sanitize via `dc purge --target {}`",
        target.transport,
        target.traddr,
        session.ctrl_name,
        started.elapsed().as_millis(),
        c.target
    );
    if c.disconnect {
        fabric_disconnect(&target, &timeouts).map_err(fabric_err)?;
        println!("disconnected (session closed cleanly)");
    }
    Ok(())
}

fn cmd_disconnect(d: &DisconnectArgs) -> Result<(), DcError> {
    let target = parse_target(&d.target)?;
    let timeouts = FabricTimeouts::default();
    fabric_disconnect(&target, &timeouts).map_err(fabric_err)?;
    println!(
        "disconnect issued for {}://{}",
        target.transport, target.traddr
    );
    Ok(())
}

fn cmd_discover(d: &DiscoverArgs) -> Result<(), DcError> {
    let mut target = parse_target(&d.target)?;
    if !target.discovery {
        // Force the well-known discovery NQN when the user passed a bare
        // address.
        target.nqn = "nqn.2014-08.org.nvmexpress.discovery".to_string();
        target.discovery = true;
    }
    let timeouts = FabricTimeouts {
        ack_ms: d.ack_ms,
        ctrl_appear_ms: d.ctrl_appear_ms,
        poll_ms: 100,
    };
    let session = fabrics::connect(&target, &timeouts).map_err(fabric_err)?;
    println!(
        "discovery controller {} online ({}); subsystems advertised:",
        session.ctrl_name,
        session.ctrl_char_dev.display()
    );
    // Read the discovery log page (LID 0x70) via admin passthrough.
    let entries = read_discovery_log(&session)?;
    if entries.is_empty() {
        println!("  (discovery log reported zero entries)");
    }
    for e in entries {
        println!(
            "  {:6} {:40} trtype={} adrfam={}",
            e.trsvcid, e.traddr, e.trtype, e.adrfam
        );
    }
    // Always close the discovery session.
    let disconnect_result = fabric_disconnect(&target, &FabricTimeouts::default());
    println!("discovery session closed");
    disconnect_result.map_err(fabric_err)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Discovery log page (LID 0x70) decoding
// ---------------------------------------------------------------------------

/// One discovery log entry, decoded defensively (see the layout note in
/// the module docs of dc-nvme::fabrics).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryEntry {
    pub trtype: u8,
    pub adrfam: u8,
    pub traddr: String,
    pub trsvcid: String,
    pub subnqn: String,
}

/// Field offsets inside the 1024-byte discovery log entry (NVMe 2.0
/// Discovery Log Page): trtype@256, adrfam@257, traddr@268 (256),
/// trsvcid@524 (32), subnqn@560 (256).
mod entry_layout {
    pub const TRTYPE: usize = 256;
    pub const ADRFAM: usize = 257;
    pub const TRADDR: usize = 268;
    pub const TRADDR_LEN: usize = 256;
    pub const TRSVCID: usize = 524;
    pub const TRSVCID_LEN: usize = 32;
    pub const SUBNQN: usize = 560;
    pub const SUBNQN_LEN: usize = 256;
    pub const ENTRY_LEN: usize = 1024;
}

/// Header (first 512 bytes of the log): genctr u64 @0, numrec u64 @8,
/// recfmt u16 @16.
fn read_discovery_log(
    session: &dc_nvme::fabrics::FabricSession,
) -> Result<Vec<DiscoveryEntry>, DcError> {
    let mut admin = dc_nvme::LinuxNvmeAdmin::open(&session.ctrl_char_dev).map_err(|e| {
        DcError::Internal(format!("open {}: {e:?}", session.ctrl_char_dev.display()))
    })?;
    // Get Log Page LID 0x70, 512-byte header read.
    let cmd = encode_discovery_log_cmd(512);
    let header = admin
        .admin_passthrough(&cmd)
        .map_err(|e| DcError::Internal(format!("discovery log read: {e:?}")))?;
    if header.len() < 512 {
        return Err(DcError::Internal("discovery log header truncated".into()));
    }
    let numrec = u64::from_le_bytes([
        header[8], header[9], header[10], header[11], header[12], header[13], header[14],
        header[15],
    ]);
    let mut out = Vec::new();
    for i in 0..numrec.min(1024) {
        // Read each 1024-byte entry.
        let offset = 512 + i as usize * entry_layout::ENTRY_LEN;
        let cmd = encode_discovery_log_cmd_offset(1024, offset as u32);
        let entry = admin
            .admin_passthrough(&cmd)
            .map_err(|e| DcError::Internal(format!("discovery entry {i}: {e:?}")))?;
        if entry.len() < entry_layout::ENTRY_LEN {
            return Err(DcError::Internal(format!("discovery entry {i} truncated")));
        }
        let trtype = entry[entry_layout::TRTYPE];
        let adrfam = entry[entry_layout::ADRFAM];
        let traddr = ascii_field(
            &entry[entry_layout::TRADDR..entry_layout::TRADDR + entry_layout::TRADDR_LEN],
        );
        let trsvcid = ascii_field(
            &entry[entry_layout::TRSVCID..entry_layout::TRSVCID + entry_layout::TRSVCID_LEN],
        );
        let subnqn = ascii_field(
            &entry[entry_layout::SUBNQN..entry_layout::SUBNQN + entry_layout::SUBNQN_LEN],
        );
        // Defensive validation: a real entry carries an ASCII trtype.
        if trtype > 254 {
            continue;
        }
        out.push(DiscoveryEntry {
            trtype,
            adrfam,
            traddr,
            trsvcid,
            subnqn,
        });
    }
    Ok(out)
}

fn ascii_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// Encode a Get Log Page command for LID 0x70 (discovery) with the given
/// data length, as a 64-byte wire-format command (dc-hw NvmeCodec style:
/// the same framing the admin transport expects).
fn encode_discovery_log_cmd(data_len: usize) -> [u8; 64] {
    encode_discovery_log_cmd_offset(data_len, 0)
}

fn encode_discovery_log_cmd_offset(data_len: usize, offset: u32) -> [u8; 64] {
    let mut cmd = [0u8; 64];
    cmd[0] = 0x02; // Get Log Page
    cmd[4..8].copy_from_slice(&0u32.to_le_bytes()); // nsid (unused)
    let numdl = (data_len / 4 - 1) as u32;
    let lid = 0x70u32;
    // CDW10: LID bits 7:0, LSP bits 12:8 ... flags bits, NUMDL bits 31:16.
    let cdw10 = lid | (numdl << 16);
    cmd[40..44].copy_from_slice(&cdw10.to_le_bytes());
    // CDW11: LSD (log sector descriptor / offset high) — offset lower
    // 32 bits in cdw12/13 per NVMe 1.4+ extended log reads.
    cmd[44..48].copy_from_slice(&0u32.to_le_bytes());
    cmd[48..52].copy_from_slice(&offset.to_le_bytes());
    cmd[52..56].copy_from_slice(&0u32.to_le_bytes());
    cmd
}

// ---------------------------------------------------------------------------
// CLI surface (constructed by clap in lib.rs)
// ---------------------------------------------------------------------------

pub struct ConnectArgs {
    pub target: String,
    pub ack_ms: u64,
    pub ctrl_appear_ms: u64,
    pub disconnect: bool,
}

pub struct DisconnectArgs {
    pub target: String,
}

pub struct DiscoverArgs {
    pub target: String,
    pub ack_ms: u64,
    pub ctrl_appear_ms: u64,
}

fn fabric_err(e: dc_nvme::fabrics::FabricError) -> DcError {
    DcError::Internal(format!("fabric session: {e}"))
}
