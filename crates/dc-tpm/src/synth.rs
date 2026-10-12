//! Synthetic TPM 2.0 for test rigs (v0.8.0, Vector 1).
//!
//! A protocol-level emulator of the exact command subset the attestation
//! stack uses: Startup, PCR Read/Extend, ReadPublic, CreatePrimary,
//! EvictControl and Quote — including a REAL ECDSA P-256 signature computed
//! over the TPMS_ATTEST bytes. The regression matrices (t28) drive the
//! entire ladder (provision → measure → quote → verify → tamper) against
//! this transport, so every wire-format bug is caught in CI without TPM
//! hardware.
//!
//! SECURITY: never used by any release path; `dc` only talks to
//! `/dev/tpmrm0`. This module exists so the attestation ladder has a
//! deterministic, hardware-free oracle. The AIK is deterministically
//! derived from a fixed test seed — never a production key.

use crate::constants::*;
use crate::structures::PcrSelectionList;
use crate::wire::{Reader, Writer};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest as _, Sha256};

/// Deterministic test AIK seed (documented test material, never secret).
const SYNTH_AIK_SEED: [u8; 32] = [0x5A; 32];

pub struct SynthTpm {
    aik: SigningKey,
    /// SHA-256 PCR bank (24 PCRs is the spec-legal maximum we touch).
    pcrs: [[u8; 32]; 24],
    started: bool,
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    firmware_version: u64,
    /// Test hook: when set, quotes sign a DOCTORED attestation — the
    /// verification ladder must reject it.
    pub tamper_mode: bool,
}

impl Default for SynthTpm {
    fn default() -> Self {
        Self::new()
    }
}

impl SynthTpm {
    pub fn new() -> Self {
        Self {
            aik: SigningKey::from_bytes(&SYNTH_AIK_SEED.into()).expect("valid seed"),
            pcrs: [[0u8; 32]; 24],
            started: false,
            clock: 1000,
            reset_count: 3,
            restart_count: 1,
            firmware_version: 0x0001_0002_0003_0004,
            tamper_mode: false,
        }
    }

    /// Pre-measure a PCR value (as if platform firmware had run).
    pub fn preset_pcr(&mut self, pcr: usize, value: [u8; 32]) {
        self.pcrs[pcr.min(23)] = value;
    }

    fn selected_pcrs(&self, list: &PcrSelectionList) -> Vec<usize> {
        let mut selected = Vec::new();
        for sel in &list.selections {
            if sel.hash_alg != TPM_ALG_SHA256 {
                continue;
            }
            for pcr in 0..24usize {
                if sel.selects(pcr) {
                    selected.push(pcr);
                }
            }
        }
        selected
    }

    fn handle_command(&mut self, command: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(command);
        let tag = r.u16().unwrap_or(0);
        let _size = r.u32().unwrap_or(0);
        let code = r.u32().unwrap_or(TPM_ALG_ERROR as u32);
        match code {
            TPM_CC_STARTUP => {
                if self.started {
                    return error_response(TPM_RC_INITIALIZE);
                }
                self.started = true;
                ok_response(tag, &[])
            }
            TPM_CC_SHUTDOWN => ok_response(tag, &[]),
            TPM_CC_GET_RANDOM => {
                let bytes = r.u16().unwrap_or(32) as usize;
                let digest = Sha256::digest(self.clock.to_le_bytes());
                let mut payload = digest.to_vec();
                while payload.len() < bytes {
                    let more = Sha256::digest(&payload).to_vec();
                    payload.extend_from_slice(&more);
                }
                payload.truncate(bytes);
                let mut body = Writer::new();
                body.tpm2b(&payload);
                ok_response(tag, body.as_bytes())
            }
            TPM_CC_PCR_READ => {
                let list = PcrSelectionList::read(&mut r)
                    .unwrap_or_else(|_| PcrSelectionList::single_sha256([0, 0, 0, 0]));
                let selected = self.selected_pcrs(&list);
                let mut body = Writer::new();
                list.write(&mut body); // echo
                body.u32(selected.len() as u32);
                for pcr in selected {
                    body.tpm2b(&self.pcrs[pcr]);
                }
                ok_response(tag, body.as_bytes())
            }
            TPM_CC_PCR_EXTEND => {
                // handle, authSize, auth, TPML_DIGEST_VALUES
                let _pcr = r.u32().unwrap_or(0);
                let auth_size = r.u32().unwrap_or(0) as usize;
                if r.raw(auth_size).is_err() {
                    return error_response(0x0002); // RC is param-aware; any
                }
                let count = r.u32().unwrap_or(0) as usize;
                let mut new_val: Option<[u8; 32]> = None;
                for _ in 0..count {
                    let alg = r.u16().unwrap_or(TPM_ALG_SHA256);
                    // TPMT_HA.digest is a FIXED-size union sized by hashAlg
                    // (NO TPM2B length prefix on the wire).
                    let mut fixed = [0u8; 32];
                    if alg == TPM_ALG_SHA256 && r.raw(32).map(|s| fixed.copy_from_slice(s)).is_ok()
                    {
                        new_val = Some(fixed);
                    }
                }
                let _pcr_handle = _pcr;
                if let Some(v) = new_val {
                    let idx = (_pcr as usize).min(23);
                    // TPM extend law: PCR' = SHA256(PCR || value)
                    let mut h = Sha256::new();
                    h.update(self.pcrs[idx]);
                    h.update(v);
                    self.pcrs[idx] = h.finalize().into();
                }
                ok_response(tag, &[])
            }
            TPM_CC_READ_PUBLIC | TPM_CC_CREATE_PRIMARY => {
                let (x, y) = self.aik_public();
                let mut public = Writer::new();
                public.u16(TPM_ALG_ECC);
                public.u16(TPM_ALG_SHA256);
                public.u32(AIK_OBJECT_ATTRIBUTES);
                public.tpm2b(&[]);
                public.u16(TPM_ALG_NULL); // symmetric
                public.u16(TPM_ALG_ECDSA);
                public.u16(TPM_ALG_SHA256);
                public.u16(TPM_ECC_NIST_P256);
                public.u16(TPM_ALG_NULL); // kdf
                public.tpm2b(&x);
                public.tpm2b(&y);
                let mut body = Writer::new();
                if code == TPM_CC_CREATE_PRIMARY {
                    // CreatePrimary: handle + outPublic (+ creation data we
                    // do not model); primarys stay inside the TPM.
                    body.u32(0x8000_00FF); // transient handle
                }
                // ReadPublic: outPublic + names (names not modeled).
                body.tpm2b(public.as_bytes());
                ok_response(tag, body.as_bytes())
            }
            TPM_CC_EVICT_CONTROL => ok_response(tag, &[]),
            TPM_CC_QUOTE => {
                let handle = r.u32().unwrap_or(0);
                let _ = handle;
                let auth_size = r.u32().unwrap_or(0) as usize;
                let _ = r.raw(auth_size);
                // scheme
                let scheme = r.u16().unwrap_or(TPM_ALG_NULL);
                let hash_alg = r.u16().unwrap_or(TPM_ALG_SHA256);
                if scheme != TPM_ALG_ECDSA || hash_alg != TPM_ALG_SHA256 {
                    return error_response(0x0002);
                }
                let qualifying = r.tpm2b().unwrap_or_default();
                let list = PcrSelectionList::read(&mut r)
                    .unwrap_or_else(|_| PcrSelectionList::single_sha256([0, 0, 0, 0]));
                let selected = self.selected_pcrs(&list);
                let mut h = Sha256::new();
                for pcr in &selected {
                    h.update(self.pcrs[*pcr]);
                }
                let pcr_digest: Vec<u8> = h.finalize().to_vec();

                self.clock += 1;
                let mut attest = Writer::new();
                attest.u32(TPM_GENERATED);
                attest.u16(TPM_ST_ATTEST_QUOTE);
                // qualifiedSigner: nameAlg(SHA256 LE) || SHA256(pub)
                let (x, y) = self.aik_public();
                let mut name_material = Vec::with_capacity(64);
                name_material.extend_from_slice(&x);
                name_material.extend_from_slice(&y);
                let name_digest = Sha256::digest(&name_material);
                let mut name = vec![0x0B, 0x00]; // SHA-16 LE
                name.extend_from_slice(&name_digest);
                attest.tpm2b(&name);
                attest.tpm2b(&qualifying);
                attest.u64(self.clock);
                attest.u32(self.reset_count);
                attest.u32(self.restart_count);
                attest.u8(1); // clock safe
                attest.u64(self.firmware_version);
                list.write(&mut attest);
                let digest_bytes = if self.tamper_mode {
                    // Doctored digest: verification must fail on this.
                    let mut d = pcr_digest.clone();
                    d[0] ^= 0xFF;
                    d
                } else {
                    pcr_digest
                };
                attest.tpm2b(&digest_bytes);

                let signature: Signature = self.aik.sign(attest.as_bytes());
                let (r_int, s_int) = signature.split_bytes();
                let mut sig = Writer::new();
                sig.u16(TPM_ALG_ECDSA);
                sig.u16(TPM_ALG_SHA256);
                sig.tpm2b(r_int.as_slice());
                sig.tpm2b(s_int.as_slice());

                let mut params = attest.as_bytes().to_vec();
                params.extend_from_slice(sig.as_bytes());
                // Sessions-tagged response: parameterSize word first.
                let mut rsp = Writer::new();
                rsp.u32(params.len() as u32);
                rsp.bytes(&params);
                sessions_response(rsp.as_bytes())
            }
            _ => error_response(0x0000_0143), // TPM_RC_COMMAND_CODE
        }
    }

    fn aik_public(&self) -> (Vec<u8>, Vec<u8>) {
        let point = self.aik.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        let x = bytes[1..33].to_vec();
        let y = bytes[33..65].to_vec();
        (x, y)
    }
}

impl crate::device::TpmTransport for SynthTpm {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, crate::device::TpmError> {
        Ok(self.handle_command(command))
    }

    fn describe(&self) -> String {
        "synth-tpm (test rig; never a release path)".to_string()
    }
}

fn ok_response(cmd_tag: u16, params: &[u8]) -> Vec<u8> {
    // Responses to session-tagged commands must mirror the session tag and
    // carry the parameterSize word (TPM 2.0 Part 1 §17).
    if cmd_tag == TPM_ST_SESSIONS {
        let mut sized = Writer::new();
        sized.u32(params.len() as u32);
        sized.bytes(params);
        return sessions_response(sized.as_bytes());
    }
    let mut w = Writer::new();
    w.u16(TPM_ST_NO_SESSIONS);
    w.u32(10 + params.len() as u32);
    w.u32(TPM_RC_SUCCESS);
    w.bytes(params);
    w.into_bytes()
}

fn sessions_response(params_with_size: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(TPM_ST_SESSIONS_RSP);
    w.u32(10 + params_with_size.len() as u32);
    w.u32(TPM_RC_SUCCESS);
    w.bytes(params_with_size);
    w.into_bytes()
}

fn error_response(code: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(TPM_ST_NO_SESSIONS);
    w.u32(10);
    w.u32(code);
    w.into_bytes()
}

/// Self-test oracle: quote through the emulator then tamper each field —
/// the verification ladder must reject all of them.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{TpmAttestor, verify_bundle, verify_quote};
    use crate::device::TpmTransport;
    use crate::structures::{encode_quote, parse_response_header};
    use p256::ecdsa::signature::Verifier as _;

    fn full_bundle() -> (
        crate::attest::QuoteBundle,
        crate::structures::QuoteAttestation,
    ) {
        let mut tpm = SynthTpm::new();
        let mut attestor = TpmAttestor::new(&mut tpm, DC_AIK_PERSISTENT_HANDLE).unwrap();
        attestor.measure_into_pcr(8, b"kernel").unwrap();
        attestor.measure_into_pcr(9, b"initramfs").unwrap();
        attestor.measure_into_pcr(10, b"dc-binary").unwrap();
        attestor.measure_into_pcr(11, b"plan-hash").unwrap();
        let bundle = attestor
            .generate_quote(b"audit-nonce-0123456789ab")
            .unwrap();
        let response = hex::decode(&bundle.quote_response_hex).unwrap();
        let params = crate::device::classify_response(&response).unwrap();
        let attest = crate::structures::parse_attestation(params).unwrap();
        (bundle, attest)
    }

    #[test]
    fn synthetic_ladder_produces_a_locally_verified_quote() {
        let (bundle, attest) = full_bundle();
        assert!(verify_quote(&bundle, &attest).unwrap());
        assert!(bundle.locally_verified);
        assert!(verify_bundle(&bundle).unwrap());
    }

    #[test]
    fn tampered_nonce_is_rejected() {
        let (mut bundle, _a) = full_bundle();
        bundle.nonce_hex = hex::encode(b"different-nonce-material__");
        assert!(verify_bundle(&bundle).is_err());
    }

    #[test]
    fn tampered_pcr_value_is_rejected() {
        let (mut bundle, _a) = full_bundle();
        let mut first = hex::decode(&bundle.pcr_values_hex[0]).unwrap();
        first[0] ^= 0x01;
        bundle.pcr_values_hex[0] = hex::encode(&first);
        assert!(verify_bundle(&bundle).is_err());
    }

    #[test]
    fn swapped_aik_key_is_rejected() {
        let (mut bundle, _a) = full_bundle();
        // A different (valid) key: flip to the seed ^ 1 — build another
        // deterministic key.
        let mut seed = SYNTH_AIK_SEED;
        seed[0] ^= 0x01;
        let other = SigningKey::from_bytes(&seed.into()).unwrap();
        let point = other.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        bundle.aik_x_hex = hex::encode(&bytes[1..33]);
        bundle.aik_y_hex = hex::encode(&bytes[33..65]);
        assert!(verify_bundle(&bundle).is_err());
    }

    #[test]
    fn doctored_pcr_digest_inside_quote_is_rejected() {
        let mut tpm = SynthTpm::new();
        tpm.tamper_mode = true;
        let mut attestor = TpmAttestor::new(&mut tpm, DC_AIK_PERSISTENT_HANDLE).unwrap();
        attestor.measure_into_pcr(8, b"kernel").unwrap();
        // The quote generation itself must fail verification (fail-closed).
        let result = attestor.generate_quote(b"nonce-123");
        assert!(result.is_err());
    }

    #[test]
    fn signature_bytes_are_ecdsa_verifiable_against_aik_point() {
        let (bundle, attest) = full_bundle();
        use p256::ecdsa::{Signature, VerifyingKey};
        let mut sec1 = vec![0x04u8];
        sec1.extend_from_slice(&hex::decode(&bundle.aik_x_hex).unwrap());
        sec1.extend_from_slice(&hex::decode(&bundle.aik_y_hex).unwrap());
        let vk = VerifyingKey::from_encoded_point(&p256::EncodedPoint::from_bytes(&sec1).unwrap())
            .unwrap();
        let r = hex::decode(&bundle.signature_r_hex).unwrap();
        let s = hex::decode(&bundle.signature_s_hex).unwrap();
        let mut der = Vec::new();
        for part in [&r, &s] {
            let lead = usize::from(part.first().map(|b| b & 0x80 != 0).unwrap_or(false));
            der.push(0x02);
            der.push((part.len() + lead) as u8);
            if lead == 1 {
                der.push(0x00);
            }
            der.extend_from_slice(part);
        }
        let mut sig_der = vec![0x30, der.len() as u8];
        sig_der.append(&mut der);
        let sig = Signature::from_der(&sig_der).unwrap();
        assert!(vk.verify(&attest.raw, &sig).is_ok());
    }

    #[test]
    fn quote_command_golden_round_trip_through_emulator() {
        // The encoder and the emulator agree on the wire layout — the
        // emulator parses what the encoder built without any error.
        let cmd = encode_quote(
            DC_AIK_PERSISTENT_HANDLE,
            b"golden",
            &PcrSelectionList::single_sha256(DC_QUOTE_PCR_MASK),
        );
        let mut tpm = SynthTpm::new();
        let response = tpm.transact(&cmd).unwrap();
        let (hdr, params) = parse_response_header(&response).unwrap().unwrap();
        assert_eq!(hdr.response_code, TPM_RC_SUCCESS);
        assert_eq!(hdr.tag, TPM_ST_SESSIONS_RSP);
        let attest = crate::structures::parse_attestation(params).unwrap();
        assert_eq!(attest.extra_data, b"golden".to_vec());
    }
}
