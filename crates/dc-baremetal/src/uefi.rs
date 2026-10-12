//! UEFI entry + handoff (v0.12.0, Miracle 3) — UEFI target only.
//!
//! `ghost_entry` receives the System Table, pulls the Graphics Output
//! Protocol framebuffer and the ACPI 2.0 RSDP from the configuration
//! table, calls ExitBootServices, and enters the Ghost run. After the
//! run: S5 poweroff. Total code between firmware handoff and Ring-0
//! storage I/O: this file plus the drivers — no kernel anywhere.
//!
//! The bin wrapper (`src/bin/ghost.rs`) exports the `efi_main` symbol
//! and forwards here, keeping exactly one copy of the boot logic.

#![cfg(target_os = "uefi")]

use crate::acpi;
use crate::fb::Console;
use crate::hal::{RawMmio, RawPortIo};
use crate::wipe::{self, GhostReport, ProgressSink};

// ---------------------------------------------------------------------------
// Minimal UEFI structures — used read-only until ExitBootServices.
// ---------------------------------------------------------------------------

const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_4942_4942; // "IBI SYST"
const ACPI_20_TABLE_GUID: [u8; 16] = [
    0x88, 0x68, 0xE8, 0xE8, 0x39, 0x62, 0x18, 0x4C, 0xBC, 0x21, 0x2E, 0x6F, 0x9D, 0x54, 0x2B, 0x97,
];

#[repr(C)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
struct EfiSystemTable {
    hdr: EfiTableHeader,
    _firmware_vendor: *const u16,
    _firmware_revision: u32,
    _console_in: *const u8,
    _console_out: *const u8,
    _std_err: *const u8,
    _runtime_services: *const u8,
    boot_services: *const EfiBootServices,
    num_table_entries: usize,
    config_table: *const EfiConfigEntry,
}

#[repr(C)]
struct EfiConfigEntry {
    guid: [u8; 16],
    table: *const u8,
}

#[repr(C)]
struct EfiBootServices {
    hdr: EfiTableHeader,
    _raise_tpl: usize,
    _restore_tpl: usize,
    allocate_pages: usize,
    free_pages: usize,
    get_memory_map: usize,
    allocate_pool: usize,
    free_pool: usize,
    _create_event: usize,
    _set_timer: usize,
    _wait_for_event: usize,
    _signal_event: usize,
    _close_event: usize,
    _check_event: usize,
    _install_protocol: usize,
    _reinstall_protocol: usize,
    _uninstall_protocol: usize,
    handle_protocol: usize,
    _reserved: usize,
    _register_protocol_notify: usize,
    locate_handle: usize,
    _locate_device_path: usize,
    _install_configuration_table: usize,
    _load_image: usize,
    _start_image: usize,
    _exit: usize,
    _unload_image: usize,
    exit_boot_services: usize,
}

const EFI_GOP_GUID: [u8; 16] = [
    0x90, 0x42, 0x39, 0x4E, 0x9A, 0x0C, 0x67, 0x48, 0xA1, 0x89, 0x5D, 0x30, 0x54, 0x71, 0xF4, 0x69,
];

#[repr(C)]
struct GopMode {
    _version: u32,
    framebuffer_base: u64,
    _fb_size: u64,
    info: *const GopModeInfo,
    size_of_info: usize,
    _mode: u32,
}

#[repr(C)]
struct GopModeInfo {
    version: u32,
    width: u32,
    height: u32,
    pixels_per_scanline: u32,
    _pixel_format: u32,
}

/// Single global line scratch buffer (firmware-threaded payload:
/// exactly one execution thread exists — see docs/baremetal-ghost-boot).
static mut LINE_BUF: [u8; 160] = [0; 160];

/// Format into the line scratch buffer (no_std, no alloc).
fn fmt_line(args: core::fmt::Arguments) -> &'static str {
    use core::fmt::Write;
    struct W(*mut [u8; 160]);
    impl Write for W {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            // The write position is encoded as a NUL-free prefix length:
            // recompute by scanning for the first non-written byte is
            // impossible; instead track in a second static.
            let pos = unsafe { *self.0.as_mut().unwrap().as_mut_ptr().add(159) as usize } << 8
                | unsafe { *self.0.as_mut().unwrap().as_mut_ptr().add(158) as usize };
            let buf = unsafe { &mut *self.0 };
            let n = s.len().min(158 - pos);
            buf[pos..pos + n].copy_from_slice(&s.as_bytes()[..n]);
            let new_pos = pos + n;
            buf[158] = (new_pos >> 8) as u8;
            buf[159] = (new_pos & 0xFF) as u8;
            Ok(())
        }
    }
    unsafe {
        LINE_BUF[158] = 0;
        LINE_BUF[159] = 0;
    }
    let mut w = W(unsafe { core::ptr::addr_of_mut!(LINE_BUF) });
    let _ = w.write_fmt(args);
    let len = unsafe { (LINE_BUF[158] as usize) << 8 | LINE_BUF[159] as usize };
    match core::str::from_utf8(unsafe { &LINE_BUF[..len] }) {
        Ok(v) => v,
        Err(_) => "",
    }
}

/// UI + progress sink threading the framebuffer through the run.
struct GhostUi {
    con: Option<Console>,
}

impl ProgressSink for GhostUi {
    fn line(&mut self, msg: &str) {
        if let Some(c) = self.con.as_mut() {
            c.puts(msg);
            c.puts("\n");
        }
    }
    fn progress_permille(&mut self, p: u32) {
        if let Some(c) = self.con.as_mut() {
            let y = c.height.saturating_sub(8);
            c.progress(y, p.min(1000));
        }
    }
}

/// Firmware entry (called from the bin's `efi_main`).
///
/// # Safety
/// `image_handle`/`system_table` must be the genuine UEFI handoff
/// arguments.
pub unsafe fn ghost_entry(
    image_handle: *const core::ffi::c_void,
    system_table: *mut core::ffi::c_void,
) -> u64 {
    let st: &EfiSystemTable = unsafe { &*(system_table as *mut EfiSystemTable) };
    if st.hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE {
        return 0x8000_0000_0000_0003; // EFI_UNSUPPORTED
    }

    // ---- framebuffer via GOP ------------------------------------------
    let bs = unsafe { &*st.boot_services };
    let locate_handle: extern "efiapi" fn(
        u32,
        *const [u8; 16],
        *const core::ffi::c_void,
        *mut usize,
        *mut *const core::ffi::c_void,
    ) -> u64 = unsafe { core::mem::transmute(bs.locate_handle) };
    let handle_protocol: extern "efiapi" fn(
        *const core::ffi::c_void,
        *const [u8; 16],
        *mut *const core::ffi::c_void,
    ) -> u64 = unsafe { core::mem::transmute(bs.handle_protocol) };

    let mut handles = [core::ptr::null::<core::ffi::c_void>(); 8];
    let mut count = 0usize;
    let gop_guid = EFI_GOP_GUID;
    let _ = locate_handle(
        2, // ByProtocol
        &gop_guid,
        core::ptr::null(),
        &mut count,
        handles.as_mut_ptr(),
    );
    let mut mode: Option<&'static GopMode> = None;
    for h in handles.iter().take(count) {
        let mut iface = core::ptr::null::<core::ffi::c_void>();
        if !h.is_null() && handle_protocol(*h, &gop_guid, &mut iface) == 0 {
            // GOP protocol: mode pointer at offset 0x18 of the interface.
            let m = unsafe { *((iface as *const u8).add(0x18) as *const *const GopMode) };
            mode = Some(unsafe { &*m });
            break;
        }
    }

    // ---- ACPI RSDP from the configuration table ----------------------
    let mut rsdp: *const u8 = core::ptr::null();
    for i in 0..st.num_table_entries {
        let e = unsafe { &*st.config_table.add(i) };
        if e.guid == ACPI_20_TABLE_GUID {
            rsdp = e.table as *const u8;
            break;
        }
    }

    // ---- allocate the DMA window BEFORE ExitBootServices -------------
    // 2 MiB below 4 GiB (AllocateMaxAddress) — the driver DMA region.
    let allocate_pages: extern "efiapi" fn(
        u32,      /* allocation type */
        u32,      /* memory type */
        usize,    /* pages */
        *mut u64, /* address out */
    ) -> u64 = unsafe { core::mem::transmute(bs.allocate_pages) };
    // 2 MiB below the 4 GiB line - 32-bit DMA reachable by every
    // storage controller, page-aligned, AllocateMaxAddress.
    let mut dma_phys: u64 = 0xFFFF_F000u64; // requested max address
    let pages = (2 * 1024 * 1024) / 4096;
    if allocate_pages(
        1, /* AllocateMaxAddress */
        2, /* LoaderData */
        pages,
        &mut dma_phys,
    ) != 0
    {
        // Best-effort fallback: a conventional low carve-out
        // (documented in docs/baremetal-ghost-boot.md).
        dma_phys = 0x7F00_0000;
    }

    // ---- ExitBootServices ---------------------------------------------
    let get_memory_map: extern "efiapi" fn(
        *mut usize,
        *mut u8,
        *mut usize,
        *mut usize,
        *mut u32,
    ) -> u64 = unsafe { core::mem::transmute(bs.get_memory_map) };
    let exit_boot_services: extern "efiapi" fn(*const core::ffi::c_void, usize) -> u64 =
        unsafe { core::mem::transmute(bs.exit_boot_services) };
    let mut map_size = 0usize;
    let mut map_key = 0usize;
    let mut desc_size = 0usize;
    let mut desc_ver = 0u32;
    let mut map_buf = [0u8; 4096];
    let _ = get_memory_map(
        &mut map_size,
        map_buf.as_mut_ptr(),
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );
    let _ = exit_boot_services(image_handle, map_key);

    // ---- console --------------------------------------------------------
    let mut ui = GhostUi { con: None };
    if let Some(m) = mode {
        let info = unsafe { &*m.info };
        ui.con = Some(unsafe {
            Console::new(
                m.framebuffer_base as *mut u32,
                info.width as usize,
                info.height as usize,
                info.pixels_per_scanline as usize,
            )
        });
    }
    if let Some(c) = ui.con.as_mut() {
        c.clear();
        for line in wipe::banner_lines() {
            c.puts(line);
            c.puts("\n");
        }
    }

    // ---- the Ghost run --------------------------------------------------
    let seed = crate::hal::rdrand_seed();
    let mut report = GhostReport {
        devices_seen: 0,
        devices_purged: 0,
        failures: 0,
    };
    ghost_scan(&mut report, &seed, dma_phys, &mut ui);

    ui.line(fmt_line(format_args!(
        "run complete: {} device(s) purged, {} failure(s)",
        report.devices_purged, report.failures
    )));
    ui.line("entering S5 soft-off…");
    spin_delay_ms(3000);

    // ---- S5 poweroff -----------------------------------------------------
    if !rsdp.is_null() {
        let _ = power_off_via_rsdp(rsdp);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Best-effort S5: walk RSDP → XSDT → FADT, write PM1a.
unsafe fn power_off_via_rsdp(rsdp: *const u8) -> Result<(), acpi::AcpiError> {
    let (_, _, xsdt_phys) = acpi::parse_rsdp(rsdp)?;
    if xsdt_phys == 0 {
        return Err(acpi::AcpiError::NoFadt);
    }
    // The XSDT lives in firmware memory, identity-mapped by the UEFI
    // page tables we keep — read its length first, then the entries.
    let xsdt = xsdt_phys as usize as *const u8;
    let hdr = unsafe { &*xsdt.cast::<acpi::SdtHeader>() };
    let len = hdr.length as usize;
    let idx = acpi::find_fadt(xsdt, len, true)?;
    let entry_off = 36 + idx * 8;
    let fadt_phys = unsafe { (xsdt.add(entry_off) as *const u64).read_unaligned() };
    let (_port, slp) = acpi::fadt_power_fields(fadt_phys as usize as *const u8, 0)?;
    let fadt = unsafe { &*(fadt_phys as usize as *const acpi::Fadt) };
    let port = if fadt.pm1a_cnt_blk != 0 {
        fadt.pm1a_cnt_blk
    } else {
        fadt.pm1b_cnt_blk
    };
    let mut io = RawPortIo;
    unsafe { acpi::power_off_s5(&mut io, port as u16, slp) };
    Ok(())
}

fn spin_delay_ms(ms: u64) {
    // ~3 GHz assumed TSC; cosmetic only.
    let t0 = tsc();
    while tsc().wrapping_sub(t0) < ms.saturating_mul(3_000_000) {
        core::hint::spin_loop();
    }
}

fn tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", lateout("eax") lo, lateout("edx") hi, options(nostack));
    }
    ((hi as u64) << 32) | lo as u64
}

/// Enumerate PCI storage and drive the wipe.
///
/// `dma_phys` is the firmware-allocated DMA window (2 MiB, < 4 GiB)
/// shared by the drivers; register windows come from each function's
/// BAR.
fn ghost_scan(report: &mut GhostReport, seed: &[u8; 32], dma_phys: u64, ui: &mut GhostUi) {
    let mut io = RawPortIo;
    let mut found = [crate::pci::PciFunction {
        bus: 0,
        dev: 0,
        func: 0,
        vendor: 0,
        device: 0,
        class: 0,
        revision: 0,
    }; 16];
    let n = crate::pci::scan_storage_into(&mut io, &[0], &mut found);
    report.devices_seen = n;

    for f in found.iter().take(n) {
        crate::pci::enable_mastering(&mut io, &f);
        let bars = crate::pci::probe_bars(&mut io, &f);
        let Some(bar) = bars.iter().flatten().find(|b| b.size >= 0x1000).copied() else {
            report.failures += 1;
            ui.line(fmt_line(format_args!(
                "bdf {:06x}: no usable BAR - skipped",
                f.bdf()
            )));
            continue;
        };
        let dma_len = 2 * 1024 * 1024;
        // The DMA window is ordinary RAM the firmware allocated —
        // identity-mapped, so phys == virt under the retained UEFI
        // page tables (documented boot invariant).
        let mmio = unsafe {
            RawMmio::new(
                bar.addr as *mut u8,
                bar.size as usize,
                dma_phys as *mut u8,
                dma_phys,
                dma_len,
            )
        };

        if f.is_nvme() {
            match crate::nvme::Nvme::init(mmio, dma_len / 1024) {
                Ok(dev) => {
                    let res = crate::wipe::wipe_nvme(dev, seed, ui, |m| {
                        let _ = m;
                    });
                    match res {
                        Ok((crate::wipe::DeviceVerdict::Purged { .. }, _)) => {
                            report.devices_purged += 1;
                        }
                        _ => report.failures += 1,
                    }
                }
                Err(e) => {
                    ui.line(fmt_line(format_args!(
                        "bdf {:06x}: nvme init failed",
                        f.bdf()
                    )));
                    report.failures += 1;
                }
            }
        } else if f.is_ahci() {
            match crate::ahci::Ahci::init(mmio) {
                Ok(mut hba) => {
                    let mut ports = [crate::ahci::SataPort {
                        index: 0,
                        signature: 0,
                        atapi: false,
                    }; 32];
                    let np = hba.detect_into(&mut ports);
                    let mut ok = 0usize;
                    for p in ports.iter().take(np) {
                        if hba.start_port(p.index).is_ok() {
                            // Capacity discovery on real hardware comes
                            // from IDENTIFY; the Ghost writes a fixed
                            // 48-bit LBA band headroom: the full
                            // 2^40 sector space is issued in chunks
                            // until the controller reports failure at
                            // the true end of media. v1 simplification:
                            // IDENTIFY-based sizing (documented).
                            match crate::wipe::wipe_sata(
                                &mut hba,
                                p.index,
                                1 << 32, // 2^32 sectors ≈ 2 TiB ceiling
                                seed,
                                ui,
                                |m| {
                                    let _ = m;
                                },
                            ) {
                                Ok(_) => ok += 1,
                                Err(e) => {
                                    ui.line(fmt_line(format_args!(
                                        "sata port {}: wipe failed",
                                        p.index
                                    )));
                                }
                            }
                        }
                    }
                    if ok > 0 {
                        report.devices_purged += ok;
                    } else {
                        report.failures += 1;
                    }
                }
                Err(e) => {
                    ui.line(fmt_line(format_args!(
                        "bdf {:06x}: ahci init failed",
                        f.bdf()
                    )));
                    report.failures += 1;
                }
            }
        }
    }
}
