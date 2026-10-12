//! cargo-fuzz target: PCIe config-space DVSEC parsing.
//!
//! The CXL discovery path parses raw PCI config space from sysfs. A
//! corrupted or hostile config (VM passthrough quirks, torn reads) must
//! never panic the extended-capability walker or the register block
//! locator — only clean parse errors.

#![no_main]

use dc_cxl::dvsec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // the parser requires >= 256 bytes to even start; pad deterministically
    if data.len() >= 256 {
        if let Ok(dvsecs) = dvsec::find_cxl_dvsecs(data) {
            for d in &dvsecs {
                let _ = dvsec::register_block_locator(d);
            }
        }
    } else {
        let mut padded = data.to_vec();
        padded.resize(256, 0);
        if let Ok(dvsecs) = dvsec::find_cxl_dvsecs(&padded) {
            for d in &dvsecs {
                let _ = dvsec::register_block_locator(d);
            }
        }
    }
});
