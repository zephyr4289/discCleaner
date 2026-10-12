//! cargo-fuzz target: ZK receipt deserialization + verification surface.
//!
//! Receipts travel between organizations (operator -> regulator); a
//! hostile or corrupted artifact must be rejected cleanly — never panic —
//! regardless of how the hex point encodings, statement fields or JSON
//! structure are mangled.

#![no_main]

use dc_zk::{VerifyingKey, ZkReceipt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. JSON structure itself
    if let Ok(receipt) = serde_json::from_slice::<ZkReceipt>(data) {
        // 2. hex point decoding inside the proof/statement
        //    (decompression validates subgroup membership lazily in
        //     verify — exercise the statement parser here)
        let _ = receipt.statement.to_statement();
        // 3. verifying key side: build a fixed-form key attempt from the
        //    same bytes (exercises the SerG1/SerG2 decompression paths
        //    including Fp/Fp2 square roots)
        if let Ok(vk) = serde_json::from_slice::<VerifyingKey>(data) {
            let _ = dc_zk::vk_fingerprint(&vk);
        }
    }
});
