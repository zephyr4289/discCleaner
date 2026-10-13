//! Controller profile database.
//!
//! Four built-in families model the controllers that actually ship inside
//! dead SSDs in decommissioning bins, plus a generic fallback. Every value
//! is a *reference model*: IDCODEs/DPIDRs use the public ARM JTAG-DP/SW-DP
//! values those cores report; SRAM windows, NAND-controller MMIO blocks and
//! BROM grammars follow each vendor's documented development flow shape.
//! Field engineers override any entry with a TOML-lite profile from
//! `vendors/` (see `--vendors-dir`), which is how lab-verified constants
//! plug in without recompiling the rig.
//!
//! What the rig needs from each profile:
//!
//! * where SRAM is (payload load address + size),
//! * which debug transports exist (JTAG IDCODE, SWD DPIDR, BROM UART knobs),
//! * the MMIO map the nucleus drives (NAND controller, UART, debug block),
//! * the boundary-scan register length for the pin-takeover fallback.

use std::path::Path;

use crate::sha256::sha256;
use crate::tomlite::Doc;
use crate::uart_brom::BromParams;

/// One controller family profile.
#[derive(Clone, Debug)]
pub struct ControllerProfile {
    pub name: String,
    pub family: String,
    /// Descriptive core model (e.g. "Cortex-R4") — flavors triage reports.
    pub core: String,
    pub sram_base: u32,
    pub sram_size: u32,
    /// IEEE 1149.1 IDCODE expected on the TAP (None: no JTAG support).
    pub jtag_idcode: Option<u32>,
    /// JTAG IR length in bits.
    pub jtag_irlen: u32,
    /// SW-DP DPIDR expected (None: SWD not bonded out).
    pub swd_dpidr: Option<u32>,
    /// NAND controller register block (cmd 0x00, addr 0x04, data 0x08,
    /// status 0x0C, chip-enable 0x10).
    pub nand_mmio: u32,
    /// Debug block (DBG_HALT 0x00, DBG_JUMP 0x04, DBG_STATS 0x08).
    pub dbg_mmio: u32,
    /// Payload UART TX register (heartbeat telemetry).
    pub uart_mmio: u32,
    /// Boundary-scan register length (pin takeover fallback).
    pub bsr_len: u32,
    pub brom: BromParams,
    /// Sha256 of the profile's canonical text (for provenance in proofs).
    pub profile_sha256: String,
}

impl ControllerProfile {
    fn new(
        name: &str,
        family: &str,
        core: &str,
        sram_base: u32,
        sram_size: u32,
        jtag_idcode: Option<u32>,
        jtag_irlen: u32,
        swd_dpidr: Option<u32>,
        nand_mmio: u32,
        dbg_mmio: u32,
        uart_mmio: u32,
        bsr_len: u32,
        brom: BromParams,
    ) -> Self {
        let canon = format!(
            "{name}|{family}|{core}|{sram_base:08x}|{sram_size:08x}|{:08x}|{jtag_irlen}|{:08x}|{nand_mmio:08x}|{dbg_mmio:08x}|{uart_mmio:08x}|{bsr_len}|{}|{:02x}|{}",
            jtag_idcode.unwrap_or(0),
            swd_dpidr.unwrap_or(0),
            String::from_utf8_lossy(&brom.magic),
            brom.sync,
            brom.auth_required,
        );
        ControllerProfile {
            name: name.into(),
            family: family.into(),
            core: core.into(),
            sram_base,
            sram_size,
            jtag_idcode,
            jtag_irlen,
            swd_dpidr,
            nand_mmio,
            dbg_mmio,
            uart_mmio,
            bsr_len,
            brom,
            profile_sha256: crate::sha256::hex(&sha256(canon.as_bytes())),
        }
    }

    /// Match a scanned IDCODE against this profile.
    pub fn matches_idcode(&self, idcode: u32) -> bool {
        self.jtag_idcode == Some(idcode)
    }

    /// Match a DPIDR, ignoring the version nibble [31:28] which varies
    /// by silicon revision.
    pub fn matches_dpidr(&self, dpidr: u32) -> bool {
        match self.swd_dpidr {
            Some(want) => (want & 0x0FFF_FFFF) == (dpidr & 0x0FFF_FFFF),
            None => false,
        }
    }

    /// The four built-in reference profiles.
    pub fn builtins() -> Vec<ControllerProfile> {
        vec![
            // Marvell 88SS1077 — the controller class that sits on a sea of
            // dead SATA SSDs (Cortex-R4, JTAG-DP, generous BROM).
            ControllerProfile::new(
                "marvell-88ss1077",
                "marvell",
                "ARM Cortex-R4",
                0x1000_0000,
                0x0002_0000,
                Some(0x4BA0_0477), // ARM JTAG-DP (public reference value)
                4,
                None,
                0xD100_0000,
                0xE000_1000,
                0xD100_2000,
                24,
                BromParams {
                    baud: 115_200,
                    sync: 0x55,
                    ack: 0x5A,
                    magic: b"MRVL-BROM-88SS".to_vec(),
                    auth_required: false,
                    key: Vec::new(),
                    reply_ms: 300,
                },
            ),
            // Silicon Motion SM2262EN — the DRAM-less era workhorse; SWD
            // bonded out for factory bring-up.
            ControllerProfile::new(
                "siliconmotion-sm2262en",
                "siliconmotion",
                "ARM Cortex-R5 (dual)",
                0x1000_0000,
                0x0004_0000,
                Some(0x4BA0_0477),
                4,
                Some(0x2BA0_1477), // ARM SW-DP reference value
                0xD000_0000,
                0xE000_1000,
                0xD000_2000,
                24,
                BromParams {
                    baud: 115_200,
                    sync: 0x55,
                    ack: 0x5A,
                    magic: b"SM2262-BROM".to_vec(),
                    auth_required: false,
                    key: Vec::new(),
                    reply_ms: 300,
                },
            ),
            // Phison PS5012-E12 — BROM behind a challenge/response wall.
            ControllerProfile::new(
                "phison-ps5012",
                "phison",
                "ARM Cortex-R5",
                0x2000_0000,
                0x0000_8000,
                Some(0x4BA0_0477),
                4,
                Some(0x2BA0_1477),
                0x4000_0000,
                0xE000_1000,
                0x4000_2000,
                16,
                BromParams {
                    baud: 57_600,
                    sync: 0x55,
                    ack: 0x5A,
                    magic: b"PS5012-BROM".to_vec(),
                    auth_required: true,
                    key: b"PS-DEV-KEY-DEMO".to_vec(),
                    reply_ms: 300,
                },
            ),
            // Samsung Pascal (MUON lineage) — JTAG + BROM, no SWD.
            ControllerProfile::new(
                "samsung-pascal",
                "samsung",
                "ARM Cortex-R4 (tri-core)",
                0x0F00_0000,
                0x0001_8000,
                Some(0x4BA0_0477),
                5,
                None,
                0xB000_0000,
                0xE000_1000,
                0xB000_2000,
                24,
                BromParams {
                    baud: 115_200,
                    sync: 0x55,
                    ack: 0x5A,
                    magic: b"SAMSUNG-BROM".to_vec(),
                    auth_required: false,
                    key: Vec::new(),
                    reply_ms: 300,
                },
            ),
            // Generic 32-bit ARM debug target — the "unknown corpse" profile.
            ControllerProfile::new(
                "generic-arm",
                "generic",
                "ARM (unknown)",
                0x1000_0000,
                0x0002_0000,
                Some(0x4BA0_0477),
                4,
                Some(0x2BA0_1477),
                0xD000_0000,
                0xE000_1000,
                0xD000_2000,
                24,
                BromParams::default(),
            ),
        ]
    }

    pub fn builtin_by_name(name: &str) -> Option<ControllerProfile> {
        let n = name.to_ascii_lowercase();
        Self::builtins().into_iter().find(|p| p.name == n)
    }

    /// Load built-ins, then overlay/extend from a directory of TOML-lite
    /// profiles (files named `*.toml`).
    pub fn load_all(dir: Option<&Path>) -> Vec<ControllerProfile> {
        let mut all = Self::builtins();
        if let Some(dir) = dir
            && let Ok(rd) = std::fs::read_dir(dir)
        {
            let mut files: Vec<_> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|e| e == "toml").unwrap_or(false))
                .collect();
            files.sort();
            for path in files {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    match Self::from_toml(&text) {
                        Ok(p) => {
                            all.retain(|x| x.name != p.name);
                            all.push(p);
                        }
                        Err(e) => {
                            eprintln!("warning: skipping {}: {e}", path.display());
                        }
                    }
                }
            }
        }
        all
    }

    /// Parse one TOML-lite profile.
    pub fn from_toml(text: &str) -> Result<ControllerProfile, String> {
        let doc = Doc::parse(text).map_err(|e| e.to_string())?;
        let name = doc.get_str("name").ok_or("missing name")?.to_string();
        let family = doc.get_str("family").unwrap_or("custom").to_string();
        let core = doc.get_str("core").unwrap_or("ARM (custom)").to_string();
        let sram_base = doc.get_u32("sram_base").ok_or("missing sram_base")?;
        let sram_size = doc.get_u32("sram_size").ok_or("missing sram_size")?;
        let jtag_idcode = doc.get_u32("jtag_idcode");
        let jtag_irlen = doc.get_u32("jtag_irlen").unwrap_or(4);
        let swd_dpidr = doc.get_u32("swd_dpidr");
        let nand_mmio = doc.get_u32("nand_mmio").ok_or("missing nand_mmio")?;
        let dbg_mmio = doc.get_u32("dbg_mmio").unwrap_or(0xE000_1000);
        let uart_mmio = doc.get_u32("uart_mmio").unwrap_or(nand_mmio + 0x2000);
        let bsr_len = doc.get_u32("bsr_len").unwrap_or(24);
        let mut brom = BromParams {
            baud: doc.get_u32("brom.baud").unwrap_or(115_200),
            sync: doc.get_u32("brom.sync").unwrap_or(0x55) as u8,
            ack: doc.get_u32("brom.ack").unwrap_or(0x5A) as u8,
            ..Default::default()
        };
        if let Some(m) = doc.get_str("brom.magic") {
            brom.magic = m.as_bytes().to_vec();
        }
        if let Some(a) = doc.get_bool("brom.auth_required") {
            brom.auth_required = a;
        }
        if let Some(k) = doc.get_str("brom.key") {
            brom.key = k.as_bytes().to_vec();
        }
        Ok(ControllerProfile::new(
            &name,
            &family,
            &core,
            sram_base,
            sram_size,
            jtag_idcode,
            jtag_irlen,
            swd_dpidr,
            nand_mmio,
            dbg_mmio,
            uart_mmio,
            bsr_len,
            brom,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_sane() {
        let b = ControllerProfile::builtins();
        assert!(b.len() >= 5);
        assert!(ControllerProfile::builtin_by_name("marvell-88ss1077").is_some());
        // Every profile's SRAM window can hold the nucleus (code+vars+table+
        // mailbox for a 2-die x 2048-block part).
        for p in &b {
            assert!(p.sram_size >= 0x8000, "{} SRAM too small", p.name);
            assert!(p.bsr_len >= 16);
        }
    }

    #[test]
    fn dpidr_match_ignores_version() {
        let p = ControllerProfile::builtin_by_name("siliconmotion-sm2262en").unwrap();
        assert!(p.matches_dpidr(0x2BA0_1477));
        assert!(p.matches_dpidr(0x3BA0_1477)); // newer rev
        assert!(!p.matches_dpidr(0x2BA0_1476)); // different part, same version nibble
        let m = ControllerProfile::builtin_by_name("marvell-88ss1077").unwrap();
        assert!(!m.matches_dpidr(0x2BA0_1477)); // no SWD on this one
    }

    #[test]
    fn toml_round_trip() {
        let text = r#"
name = "lab-verified-corp"
family = "custom"
core = "Cortex-R4"
sram_base = 0x10000000
sram_size = 0x00020000
jtag_idcode = 0x4BA00477
swd_dpidr = 0x2BA01477
nand_mmio = 0xD1000000
bsr_len = 24

[brom]
baud = 921600
magic = "LAB-BROM-XYZ"
auth_required = true
key = "field-entitlement-key"
"#;
        let p = ControllerProfile::from_toml(text).unwrap();
        assert_eq!(p.name, "lab-verified-corp");
        assert_eq!(p.brom.baud, 921_600);
        assert!(p.brom.auth_required);
        assert_eq!(p.brom.key, b"field-entitlement-key");
        assert_eq!(p.sram_base, 0x1000_0000);
        assert!(!p.profile_sha256.is_empty());
    }
}
