//! The self-assembling RAM-resident nucleus.
//!
//! "Self-assembling" is literal: no static binary exists. Two stages:
//!
//! 1. **Stage-1 probe** — a tiny geometry-independent blob that talks to
//!    NAND die 0 over the controller's register block, pulls the READ-ID
//!    word and the first 64 bytes of the ONFI parameter page into the SRAM
//!    mailbox, and parks. The host reads the mailbox through the same debug
//!    link (BROM PEEK or SWD MEM-AP) and parses the real geometry.
//! 2. **Stage-2 kernel** — assembled *for that geometry*: page sizes, row
//!    shifts (log2 pages-per-block, log2 blocks-per-LUN), verify stride,
//!    register addresses and the linkage table (HLP_*) are baked in as
//!    instruction immediates and VARS words at injection time. It builds
//!    its own CRC-32 table in SRAM, then — fully autonomously, no host
//!    babysitting — erases every block of every die, retries marginal
//!    blocks, verifies pages read back 0xFF, streams a per-block CRC-32
//!    attestation into the mailbox, heartbeats progress over UART when
//!    one exists, and parks.
//!
//! SRAM image layout (offsets from the profile's load base):
//!
//! ```text
//! 0x0000  code (entry, helpers, dispatch, literal pools)
//! 0x1000  VARS  (32 words: geometry, limits, MMIO addresses, HLP table)
//! 0x1400  CRC-32 table (256 words, built by the kernel at boot)
//! 0x2000  MAILBOX (20-byte records + 24-byte summary)
//! ```

pub mod asm;
pub mod fragments;

use crate::nand::NandGeometry;
use crate::sha256::Sha256;

/// Image layout offsets from the load base.
pub mod layout {
    pub const CODE: u32 = 0x0000;
    pub const VARS: u32 = 0x1000;
    pub const VARS_LEN: u32 = 0x80; // 32 words
    pub const CRCTAB: u32 = 0x1400;
    pub const MAILBOX: u32 = 0x2000;
    /// One block record: magic, (die<<16|block), status, nonzero, crc32.
    pub const REC_LEN: u32 = 20;
}

/// VARS word indices (must fit imm5 = 32 words, so exactly 32 slots).
#[allow(dead_code)]
pub mod vars {
    pub const DIES: u8 = 0;
    pub const BLOCKS: u8 = 1;
    pub const PPB: u8 = 2;
    pub const PAGE_BYTES: u8 = 3;
    pub const SPARE_OFF: u8 = 4;
    pub const VERIFY_STRIDE: u8 = 5;
    pub const L2_PPB: u8 = 6;
    pub const L2_BPL: u8 = 7;
    pub const DIE: u8 = 8;
    pub const BLOCK: u8 = 9;
    pub const PAGE: u8 = 10;
    pub const BYTECNT: u8 = 11;
    pub const ERASED: u8 = 12;
    pub const SKIPPED: u8 = 13;
    pub const FAILED: u8 = 14;
    pub const EXPECT_ID: u8 = 15;
    pub const OFF_CMD: u8 = 16;
    pub const OFF_ADDR: u8 = 17;
    pub const OFF_DATA: u8 = 18;
    pub const OFF_STATUS: u8 = 19;
    pub const OFF_CE: u8 = 20;
    pub const OFF_UART: u8 = 21;
    pub const MB_MAGIC: u8 = 22;
    pub const HLP_CE: u8 = 23;
    pub const HLP_CMD: u8 = 24;
    pub const HLP_ADDR: u8 = 25;
    pub const HLP_READ: u8 = 26;
    pub const HLP_READY: u8 = 27;
    pub const CRCTAB: u8 = 28;
    pub const TOTAL: u8 = 29;
    pub const TMP0: u8 = 30;
    /// slot 31 free.
    pub const SPARE31: u8 = 31;
}

/// Mailbox record magic "RZAT".
pub const MB_REC_MAGIC: u32 = 0x525A_4154;
/// Summary magic "RZDN".
pub const MB_SUM_MAGIC: u32 = 0x525A_444E;
/// Summary end marker.
pub const MB_SUM_DONE: u32 = 0xA5A5_A5A5;

/// Verify stride policy for the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyMode {
    /// Erase + status check only (bad markers still re-read).
    Off,
    /// Pages {0, ppb/2} per block.
    Sampled,
    /// Every page.
    Full,
}

/// Everything the assembler needs about the target.
#[derive(Clone, Debug)]
pub struct PayloadParams {
    pub load_base: u32,
    pub nand_mmio: u32,
    pub dbg_mmio: u32,
    pub uart_mmio: Option<u32>,
    pub geometry: NandGeometry,
    pub verify: VerifyMode,
    /// Expected READ-ID word (first four bytes, little-endian).
    pub read_id_word: u32,
}

impl PayloadParams {
    pub fn verify_stride(&self) -> u32 {
        match self.verify {
            VerifyMode::Off => 0,
            VerifyMode::Sampled => (self.geometry.pages_per_block / 2).max(1),
            VerifyMode::Full => 1,
        }
    }
}

/// Which stage this image is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Probe,
    Kernel,
}

impl Stage {
    pub fn name(&self) -> &'static str {
        match self {
            Stage::Probe => "stage-1-probe",
            Stage::Kernel => "stage-2-kernel",
        }
    }
}

/// Chain-of-trust manifest: the proof anchors on the blob SHA-256.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub stage: Stage,
    pub load_base: u32,
    pub entry: u32,
    pub code_off: u32,
    pub code_len: u32,
    pub vars_off: u32,
    pub mailbox_off: u32,
    pub blob_len: u32,
    pub blob_crc32: u32,
    pub blob_sha256: [u8; 32],
    pub relocs: Vec<asm::Reloc>,
    pub params: PayloadParams,
}

pub struct PayloadImage {
    pub blob: Vec<u8>,
    pub manifest: Manifest,
}

impl PayloadImage {
    pub fn entry(&self) -> u32 {
        self.manifest.entry
    }
}

/// Verify stride 0 == off, pages-per-block/2 == sampled, 1 == full.
fn stride_for(mode: VerifyMode, geo: &NandGeometry) -> u32 {
    match mode {
        VerifyMode::Off => 0,
        VerifyMode::Sampled => (geo.pages_per_block / 2).max(1),
        VerifyMode::Full => 1,
    }
}

/// Build the VARS block (32 words) for the given stage.
fn build_vars(a: &asm::Asm, p: &PayloadParams) -> [u32; 32] {
    let g = &p.geometry;
    let hlp = |name: &str| -> u32 {
        a.label_addr(name)
            .unwrap_or_else(|| panic!("helper {name} not bound"))
            | 1 // Thumb
    };
    let mut v = [0u32; 32];
    v[vars::DIES as usize] = g.luns;
    v[vars::BLOCKS as usize] = g.blocks_per_lun;
    v[vars::PPB as usize] = g.pages_per_block;
    v[vars::PAGE_BYTES as usize] = g.bytes_per_page;
    v[vars::SPARE_OFF as usize] = g.bytes_per_page;
    v[vars::VERIFY_STRIDE as usize] = stride_for(p.verify, g);
    v[vars::L2_PPB as usize] = g.log2_pages_per_block();
    v[vars::L2_BPL as usize] = g.log2_blocks_per_lun();
    v[vars::EXPECT_ID as usize] = p.read_id_word;
    v[vars::OFF_CMD as usize] = p.nand_mmio;
    v[vars::OFF_ADDR as usize] = p.nand_mmio + 0x04;
    v[vars::OFF_DATA as usize] = p.nand_mmio + 0x08;
    v[vars::OFF_STATUS as usize] = p.nand_mmio + 0x0C;
    v[vars::OFF_CE as usize] = p.nand_mmio + 0x10;
    v[vars::OFF_UART as usize] = p.uart_mmio.unwrap_or(0);
    v[vars::MB_MAGIC as usize] = MB_REC_MAGIC;
    v[vars::HLP_CE as usize] = hlp("hlp_ce");
    v[vars::HLP_CMD as usize] = hlp("hlp_cmd");
    v[vars::HLP_ADDR as usize] = hlp("hlp_addr");
    v[vars::HLP_READ as usize] = hlp("hlp_read");
    v[vars::HLP_READY as usize] = hlp("hlp_ready");
    v[vars::CRCTAB as usize] = p.load_base + layout::CRCTAB;
    v[vars::TOTAL as usize] = g.total_blocks();
    v
}

/// Splice `bytes` into `blob` at `off`.
fn splice(blob: &mut Vec<u8>, off: u32, bytes: &[u8]) {
    let off = off as usize;
    if blob.len() < off + bytes.len() {
        blob.resize(off + bytes.len(), 0);
    }
    blob[off..off + bytes.len()].copy_from_slice(bytes);
}

fn finish(
    blob: Vec<u8>,
    code_len: u32,
    relocs: Vec<asm::Reloc>,
    stage: Stage,
    p: &PayloadParams,
) -> PayloadImage {
    // Thumb bit set: every injection path (BROM JUMP, DBG_JUMP) releases the
    // core into Thumb state.
    let entry = (p.load_base + layout::CODE) | 1;
    let mut h = Sha256::new();
    h.update(&blob);
    let manifest = Manifest {
        stage,
        load_base: p.load_base,
        entry,
        code_off: layout::CODE,
        code_len,
        vars_off: layout::VARS,
        mailbox_off: layout::MAILBOX,
        blob_len: blob.len() as u32,
        blob_crc32: crate::crc::crc32(&blob),
        blob_sha256: h.finalize(),
        relocs,
        params: p.clone(),
    };
    PayloadImage { blob, manifest }
}

/// Assemble the stage-1 ONFI probe nucleus.
pub fn assemble_probe(p: &PayloadParams) -> PayloadImage {
    let mut a = asm::Asm::new(p.load_base + layout::CODE);
    fragments::emit_probe(&mut a, p);
    let vars = build_vars(&a, p);
    let relocs = a.relocs().to_vec();
    let code = a.link().expect("probe link");
    let code_len = code.len() as u32;
    let mut blob = vec![0u8; layout::VARS as usize];
    splice(&mut blob, layout::CODE, &code);
    splice(&mut blob, layout::VARS, &vars.to_le_bytes_flattened());
    finish(blob, code_len, relocs, Stage::Probe, p)
}

/// Assemble the stage-2 autonomous erase kernel.
pub fn assemble_kernel(p: &PayloadParams) -> PayloadImage {
    let mut a = asm::Asm::new(p.load_base + layout::CODE);
    fragments::emit_kernel(&mut a, p);
    let vars = build_vars(&a, p);
    let relocs = a.relocs().to_vec();
    let code = a.link().expect("kernel link");
    let code_len = code.len() as u32;
    assert!(code_len <= layout::VARS, "code overruns VARS region");
    let mut blob = vec![0u8; layout::MAILBOX as usize];
    splice(&mut blob, layout::CODE, &code);
    splice(&mut blob, layout::VARS, &vars.to_le_bytes_flattened());
    finish(blob, code_len, relocs, Stage::Kernel, p)
}

trait LeFlatten {
    fn to_le_bytes_flattened(&self) -> Vec<u8>;
}

impl LeFlatten for [u32; 32] {
    fn to_le_bytes_flattened(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(128);
        for w in self.iter() {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nand::NandGeometry;

    fn params() -> PayloadParams {
        PayloadParams {
            load_base: 0x1000_0000,
            nand_mmio: 0xD100_0000,
            dbg_mmio: 0xE000_1000,
            uart_mmio: Some(0xD100_2000),
            geometry: NandGeometry::new(2048, 64, 64, 512, 2),
            verify: VerifyMode::Sampled,
            read_id_word: 0x3294_DE98,
        }
    }

    #[test]
    fn probe_assembles_small() {
        let img = assemble_probe(&params());
        assert_eq!(img.manifest.entry, 0x1000_0001); // Thumb bit set
        assert_eq!(img.blob.len(), (layout::VARS + layout::VARS_LEN) as usize);
        assert!(
            img.manifest.code_len < 0x200,
            "probe should be tiny, got {}",
            img.manifest.code_len
        );
        assert_eq!(img.manifest.blob_crc32, crate::crc::crc32(&img.blob));
    }

    #[test]
    fn kernel_assembles_and_fits() {
        let img = assemble_kernel(&params());
        // code region must not collide with VARS
        assert!(img.manifest.code_len < layout::VARS);
        // VARS present at the right offset
        let vars_off = layout::VARS as usize;
        let dies = u32::from_le_bytes([
            img.blob[vars_off + vars::DIES as usize * 4..][0],
            img.blob[vars_off + vars::DIES as usize * 4 + 1],
            img.blob[vars_off + vars::DIES as usize * 4 + 2],
            img.blob[vars_off + vars::DIES as usize * 4 + 3],
        ]);
        assert_eq!(dies, 2);
        // every HLP slot is a Thumb pointer into the code region
        for slot in [
            vars::HLP_CE,
            vars::HLP_CMD,
            vars::HLP_ADDR,
            vars::HLP_READ,
            vars::HLP_READY,
        ] {
            let w = u32::from_le_bytes(
                img.blob[vars_off + slot as usize * 4..vars_off + slot as usize * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            assert!(w & 1 == 1, "HLP slot {slot} missing thumb bit: {w:#x}");
            assert!(w >= img.manifest.load_base && w < img.manifest.load_base + layout::VARS);
        }
        assert_eq!(img.manifest.blob_sha256.len(), 32);
    }

    #[test]
    fn disasm_round_trips_known_instruction() {
        // One spot-check that the disassembler speaks the same dialect.
        let lines = asm::disasm(&[0x2A, 0x20, 0x70, 0x47], 0);
        assert!(lines[0].contains("movs r0, #42"), "{}", lines[0]);
        assert!(lines[1].contains("bx"), "{}", lines[1]);
    }
}
