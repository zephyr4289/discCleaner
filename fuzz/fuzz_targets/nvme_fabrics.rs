//! cargo-fuzz target: NVMe-oF fabrics URI + generic-netlink reply parsers.
//!
//! Remote fabrics targets are operator/network-supplied strings, and the
//! genl control replies come from an untrusted kernel-side discovery
//! path. Both parsers must reject malformed input cleanly.

#![no_main]

use dc_nvme::fabrics::{parse_family_id, FabricTarget};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // FabricTarget::parse consumes an NVMe-oF URI string
    // ("nvme+tcp://10.0.0.1:4420/nqn.2014-08.org...").
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(target) = FabricTarget::parse(s) {
            // connect_attrs() over a parsed target must be side-effect free.
            let _ = target.connect_attrs();
        }
    }
    // Raw generic-netlink CTRL reply bytes.
    let _ = parse_family_id(data);
});
