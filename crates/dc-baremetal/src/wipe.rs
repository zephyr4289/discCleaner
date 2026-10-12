//! Ghost run orchestrator (v0.12.0, Miracle 3).
//!
//! Enumerates storage endpoints through the trait-driven drivers and
//! sanitizes them: for NVMe, Format NVM with cryptographic erase (the
//! controller-side purge) plus a ChaCha20(RDRAND) pattern pass; for
//! SATA, a full-band 48-bit WRITE DMA EXT pattern pass. Progress is
//! reported through a sink (framebuffer on hardware, asserts in CI).

use crate::ahci::AhciError;
use crate::chacha::ChaCha20;
use crate::hal::Mmio;
use crate::nvme::{Nvme, NvmeError, SES_CRYPTO_ERASE};

/// What happened to one device.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DeviceVerdict {
    Purged {
        pattern_pass: bool,
        crypto_erase: bool,
    },
    Failed(&'static str),
    Skipped(&'static str),
}

/// Progress sink (framebuffer console on hardware).
pub trait ProgressSink {
    fn line(&mut self, msg: &str);
    fn progress_permille(&mut self, permille: u32);
}

/// A null sink (headless runs / CI sections that don't care).
pub struct NullSink;
impl ProgressSink for NullSink {
    fn line(&mut self, _msg: &str) {}
    fn progress_permille(&mut self, _permille: u32) {}
}

/// Outcome of a full Ghost run.
pub struct GhostReport {
    pub devices_seen: usize,
    pub devices_purged: usize,
    pub failures: usize,
}

/// Sanitize one NVMe controller.
///
/// Strategy: (1) controller-side Format NVM with cryptographic erase
/// where the controller supports it; (2) a ChaCha20(RDRAND) logical
/// pattern pass over the namespace in 64-block I/O writes — so even
/// controllers with a no-op crypto erase leave physically overwritten
/// media. The pattern pass is also the read-back source for auditors
/// who later image the drive.
pub fn wipe_nvme<M: Mmio>(
    mut dev: Nvme<M>,
    seed: &[u8; 32],
    out: &mut impl ProgressSink,
    mut poll: impl FnMut(&mut M),
) -> Result<(DeviceVerdict, Nvme<M>), NvmeError> {
    out.line("nvme: format-nvm crypto erase…");
    let crypto_ok = dev.format_nvm(SES_CRYPTO_ERASE, |m| poll(m)).is_ok();

    out.line("nvme: chacha20(rdrand) pattern pass…");
    let nlb = 64u32; // 32 KiB per write
    let total = dev.lba_count;
    let mut lba: u64 = 0;
    while lba < total {
        let chunk = nlb.min((total - lba) as u32);
        // Per-chunk nonce: the pattern never repeats across the namespace.
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&lba.to_le_bytes());
        let mut keystream = ChaCha20::new(seed, &nonce, 0);
        // Fill the data page with pattern bytes.
        let page = unsafe {
            core::slice::from_raw_parts_mut(
                dev.mmio.dma_ptr().add(dev.data_off),
                (chunk as usize) * 512,
            )
        };
        page.fill(0);
        keystream.apply(page);
        dev.io_write(lba, chunk, |m| poll(m))?;
        lba += chunk as u64;
        out.progress_permille(((lba as u64 * 1000) / total.max(1)) as u32);
    }
    let verdict = DeviceVerdict::Purged {
        pattern_pass: true,
        crypto_erase: crypto_ok,
    };
    Ok((verdict, dev))
}

/// Sanitize one SATA port: single full-band ChaCha20 pattern pass
/// (WRITE DMA EXT 48-bit), 8 KiB per command. Takes the driver by
/// reference — multiple ports share one HBA.
pub fn wipe_sata<M: Mmio>(
    port: &mut crate::ahci::Ahci<M>,
    port_idx: usize,
    total_lbas: u64,
    seed: &[u8; 32],
    out: &mut impl ProgressSink,
    mut poll: impl FnMut(&mut M),
) -> Result<DeviceVerdict, AhciError> {
    out.line("sata: chacha20(rdrand) full-band pattern pass…");
    let secs_per_cmd = 16u16; // 8 KiB
    let mut lba: u64 = 0;
    while lba < total_lbas {
        let chunk = secs_per_cmd.min((total_lbas - lba) as u16);
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&lba.to_le_bytes());
        let mut keystream = ChaCha20::new(seed, &nonce, 0);
        let page = unsafe {
            core::slice::from_raw_parts_mut(port.mmio.dma_ptr().add(32768), (chunk as usize) * 512)
        };
        page.fill(0);
        keystream.apply(page);
        port.dma_io(port_idx, true, lba, chunk, 32768, |m| poll(m))?;
        lba += chunk as u64;
        out.progress_permille(((lba * 1000) / total_lbas.max(1)) as u32);
    }
    Ok(DeviceVerdict::Purged {
        pattern_pass: true,
        crypto_erase: false,
    })
}

/// Compose the run header for the framebuffer.
pub fn banner_lines() -> [&'static str; 3] {
    [
        crate::GHOST_NAME,
        concat!(
            "version ",
            env!("CARGO_PKG_VERSION"),
            " — no kernel, no drivers, no OS"
        ),
        "USB ghost wipe: media will be sanitized, then the machine powers off",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::sim::SimBus;
    use crate::nvme::CompletionEntry;

    fn seeded_nvme_bus(blocks: u64) -> SimBus {
        let mut bus = SimBus::new(256 * 1024);
        bus.mmio64.insert(crate::nvme::REG_CAP, 63);
        unsafe {
            let p = bus.dma.as_mut_ptr().add(16384);
            (p as *mut u32).write_volatile(blocks as u32);
            (p.add(4) as *mut u32).write_volatile(0);
            *p.add(4) = 0;
            *p.add(26) = 9;
        }
        bus
    }

    #[test]
    fn nvme_ghost_run_purges_and_overwrites() {
        let bus = seeded_nvme_bus(512); // 512 blocks → 8 chunk writes
        let dev = Nvme::init(bus, 256).expect("init");
        let seed = [0x42u8; 32];
        let mut sink = NullSink;
        let mut cmds = 0u32;
        let (verdict, _dev) = wipe_nvme(dev, &seed, &mut sink, |m| {
            // Complete both admin (format) and I/O writes.
            cmds += 1;
            let cqe =
                unsafe { (m.dma_ptr() as *mut CompletionEntry).add(cmds.max(1) as usize % 16) };
            unsafe {
                core::ptr::write_volatile(
                    cqe,
                    CompletionEntry {
                        cdw0: 0,
                        rsvd: 0,
                        sq_head: 1,
                        sq_id: if cmds == 1 { 0 } else { 1 },
                        cid: cmds as u16,
                        status_p: 1,
                    },
                );
            }
        })
        .expect("ghost run");
        assert!(matches!(
            verdict,
            DeviceVerdict::Purged {
                pattern_pass: true,
                ..
            }
        ));
        assert!(cmds >= 9, "format + 8 chunk writes, got {cmds}");
    }
}
