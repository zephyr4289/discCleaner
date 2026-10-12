//! cargo-fuzz target: the TPM 2.0 wire-protocol response parsers.
//!
//! `/dev/tpmrm0` hands back attacker-shaped bytes whenever the TPM (or a
//! wedged driver, or a malicious virtual TPM) misbehaves. Every parser in
//! `dc-tpm` must classify/reject arbitrary input WITHOUT panicking,
//! looping, or indexing out of bounds — memory safety here is the boundary
//! between "untrusted hardware" and "ring-0 compromise".

#![no_main]

use dc_tpm::device::classify_response;
use dc_tpm::structures::{
    parse_attestation, parse_create_primary, parse_create_sealed, parse_ecdsa_signature,
    parse_load, parse_pcr_read, parse_policy_digest, parse_response_header,
    parse_start_auth_session, parse_unseal,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Header classification is the gateway every response passes through.
    if let Ok(params) = classify_response(data) {
        // Each downstream parser consumes the parameter area independently;
        // arbitrary bytes must be classified or cleanly rejected.
        let _ = parse_attestation(params);
        let _ = parse_pcr_read(params);
        let _ = parse_ecdsa_signature(params);
        let _ = parse_create_primary(params);
        let _ = parse_create_sealed(params);
        let _ = parse_start_auth_session(params);
        let _ = parse_policy_digest(params);
        let _ = parse_load(params);
        let _ = parse_unseal(params);
    }
    // Direct header parse path (success OR numeric error code both valid).
    let _ = parse_response_header(data);
});
