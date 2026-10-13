//! Ghost Silicon — the RISC-V open-silicon payload entry
//! (v0.13.0, Frontier 3).
//!
//! Build (see the workspace `ghost` profile):
//! ```text
//! cargo build -p dc-fpga --target riscv32imc-unknown-none-elf \
//!            --profile ghost --features silicon
//! ```
//!
//! Boot protocol: FPGA configuration (bitstream = this payload +
//! the open softcore RTL) → softcore reset vector jumps here →
//! `_start` sets the stack, clears BSS, calls `rust_main` → the
//! interceptor state machine runs to HALT (eFuse burned, lanes
//! latched) → WFI forever. No host CPU, no host OS, no vendor
//! microcode anywhere in the chain.
//!
//! Board map (override with the constants below when porting to a
//! specific NEORV32/VexRiscv SoC):
//!
//! ```text
//!   0x8000_0000  instruction/data SRAM base (linker places us)
//!   0x4000_0000  interceptor core MMIO bank (see hal::regs)
//!   0x4001_0000  UART16550-compatible console (see hal::Console)
//!   0x4000_0004  CSR_CTRL — ARM register (button-latched magic)
//! ```

#![cfg(feature = "silicon")]
#![no_std]
#![no_main]

use dc_fpga::hal::{Console, RealMmio};
use dc_fpga::statemachine::{InterceptorMachine, RunConfig};

/// Interceptor core MMIO base.
const INTERCEPTOR_BASE: *mut u32 = 0x4000_0000 as *mut u32;
/// UART 16550-compatible base.
const UART_BASE: *mut u32 = 0x4001_0000 as *mut u32;

/// Stack for the pre-main execution environment (16 KiB).
#[unsafe(link_section = ".sbss")]
static mut BOOT_STACK: [u32; 4096] = [0; 4096];

/// RISC-V machine-mode entry: naked so the compiler emits no
/// prologue; we set SP before any Rust code may touch memory.
#[unsafe(no_mangle)]
#[unsafe(naked)]
unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        // SP = &BOOT_STACK[0] + 16 KiB (top of the boot stack)
        ".option push",
        ".option norelax",
        "la      sp, {stack}",
        ".option pop",
        "li      t0, {stack_size}",
        "add     sp, sp, t0",
        // Keep (hart id, dtb) in a0/a1 for future bring-up.
        "call    {main}",
        // rust_main never returns; trap if it somehow does.
        "csrrw   zero, mscratch, zero",
        "1: wfi",
        "j       1b",
        stack = sym BOOT_STACK,
        stack_size = const core::mem::size_of::<[u32; 4096]>(),
        main = sym rust_main,
    )
}

/// The 16550-compatible console: the only output the payload has.
struct Uart16550 {
    base: *mut u32,
}

impl Uart16550 {
    fn init(&mut self) {
        // Word-stride 16550: offset/4. Divisor for 115200 from a
        // 50 MHz clock: 50e6 / (16 * 115200) ≈ 27.
        // SAFETY: fixed-address device registers (board contract).
        unsafe {
            core::ptr::write_volatile(self.base.add(1), 0x00); // IER off
            core::ptr::write_volatile(self.base.add(3), 0x80); // DLAB on
            core::ptr::write_volatile(self.base.add(0), 27); // divisor lo
            core::ptr::write_volatile(self.base.add(1), 0); // divisor hi
            core::ptr::write_volatile(self.base.add(3), 0x03); // 8N1, DLAB off
            core::ptr::write_volatile(self.base.add(2), 0xC7); // FIFO on
        }
    }
}

impl Console for Uart16550 {
    fn put_byte(&mut self, b: u8) {
        // SAFETY: fixed-address device registers (board contract).
        unsafe {
            // Line status (offset 5) bit 5 = THR empty.
            while core::ptr::read_volatile(self.base.add(5)) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(self.base.add(0), b as u32);
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn rust_main() {
    let mut uart = Uart16550 { base: UART_BASE };
    uart.init();
    uart.put_str("\r\ndc ghost silicon ");
    uart.put_str(dc_fpga::PAYLOAD_VERSION);
    uart.put_str(" — root of destruction\r\n");

    // SAFETY: the interceptor bank is a fixed-address, live MMIO
    // region for the lifetime of the payload (board contract).
    let mut mmio = unsafe { RealMmio::new(INTERCEPTOR_BASE) };
    // The ARM register (offset 0x38 in the same bank) holds the
    // button-latched consent magic; the state machine waits for it.
    let mut machine = InterceptorMachine::new(&mut mmio, &mut uart, RunConfig::default());
    let state = machine.run(1_000_000);
    uart.put_str("[fpga] terminal state: ");
    uart.put_str(state.as_str());
    uart.put_str("\r\n");
    // The eFuse is burned (or faulted) and the gate is latched:
    // park the softcore. WFI keeps power draw at microamps and the
    // evidence at room temperature.
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No console guarantee here: spin forever so a technician sees
    // the board stopped rather than silently continuing.
    loop {
        core::hint::spin_loop();
    }
}
