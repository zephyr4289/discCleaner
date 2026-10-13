//! Ghost Boot EFI application entry (v0.12.0, Miracle 3).
//!
//! Build (see scripts/build-ghost.sh):
//! ```text
//! cargo build -p dc-baremetal --target x86_64-unknown-uefi \
//!            --release --features efi
//! cp target/x86_64-unknown-uefi/release/dc-ghost-efi.efi /media/USB/EFI/BOOT/BOOTX64.EFI
//! ```
//!
//! Boot protocol: FAT32 USB → firmware loads BOOTX64.EFI → efi_main
//! (see `dc_baremetal::uefi`) → ExitBootServices → PCIe scan → wipe →
//! S5. No kernel, no drivers, no OS — the binary IS the operating
//! environment, in well under 300 KB.

#![cfg(all(target_os = "uefi", feature = "efi"))]
#![no_std]
#![no_main]

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(
    image: *const core::ffi::c_void,
    system_table: *mut core::ffi::c_void,
) -> u64 {
    unsafe {
        // Full handoff (GOP, RSDP, ExitBootServices, wipe, poweroff)
        // lives in dc_baremetal::uefi — one copy, unit-testable
        // everywhere the lib compiles.
        dc_baremetal::uefi::ghost_entry(image, system_table)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Best effort: the framebuffer console may not be up; halt so a
    // technician sees the machine stopped rather than booting an OS.
    loop {
        core::hint::spin_loop();
    }
}
