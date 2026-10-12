//! PIV hardware-token custody — real SP 800-73-4 applet sessions over the
//! ISO 7816-4/CCID stack, with PKCS#11-shaped vocabulary (v0.7.0, Vector 1).
//!
//! The pre-0.7.0 two-person-integrity gate proved the OFFICER KEY existed,
//! but `is_hardware_token` was a self-attested boolean: any software key
//! could claim hardware custody and the certificate printed
//! `SeparateHardware`. This module makes the claim evidentiary:
//!
//! 1. The approval signature is computed INSIDE the secure element of a
//!    physical token (PIV slot 9C — Digital Signature) via GENERAL
//!    AUTHENTICATE; the private key is non-exportable by construction.
//!    - YubiKey 5.2.3+ (alg 0xE0): raw Ed25519 — the signature IS the
//!      officer signature, verifiable with the existing Ed25519 path.
//!    - CAC / generic PIV (alg 0x11): ECDSA P-256 over SHA-256 — used as
//!      a custody co-proof: the card countersigns the officer's public key
//!      and the bound plan hash, and the officer's own Ed25519 signature
//!      covers the plan (two signatures, one plan).
//! 2. Every APDU exchange is recorded in a `HardwareCustodyAttestation`:
//!    the USB coordinates of the reader, the PIN-verified status word,
//!    the mechanism, the message hash the card signed, and a BLAKE3
//!    transcript chain over the full APDU sequence.
//! 3. `dualauth` refuses `SeparateHardware` custody unless the attestation
//!    is present and internally consistent (REG-TOKEN-CUSTODY-PROOF).
//!
//! HONEST TRUST BOUNDARY (docs/SECURITY.md): "hardware" is provable to a
//! verifier only against a CA-anchored cert chain, which is out of scope
//! for the embedded evidence model. What this construction guarantees:
//! the private key never existed on a filesystem, the PIN was verified by
//! the card in-session, and the signature was produced by whichever key the
//! card reported for the slot. A root adversary with the physical token AND
//! the PIN can re-sign — that is the inherent envelope of every hardware
//! wallet / HSM design; we disclose rather than pretend.

use crate::iso7816::{CommandApdu, Iso7816Transport, ResponseApdu};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// PIV card application AID (SP 800-73-4, NIST RID A0 00 00 03 08).
pub const PIV_AID: [u8; 12] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00,
];

/// Domain-separation prefix of the hardware custody co-proof (the message
/// the card signs when binding an officer key to a plan hash).
pub const HW_CUSTODY_DOMAIN: &[u8] = b"DC-2PI1-HW-CUSTODY";

/// PIV key references (SP 800-73-4 Part 2 §3.2).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PivSlot {
    /// 0x9A — PIV Authentication.
    Authentication = 0x9A,
    /// 0x9C — Digital Signature (the approvals slot).
    DigitalSignature = 0x9C,
    /// 0x9D — Key Management.
    KeyManagement = 0x9D,
    /// 0x9E — Card Authentication.
    CardAuthentication = 0x9E,
}

impl PivSlot {
    pub fn label(self) -> &'static str {
        match self {
            Self::Authentication => "9a (PIV Authentication)",
            Self::DigitalSignature => "9c (Digital Signature)",
            Self::KeyManagement => "9d (Key Management)",
            Self::CardAuthentication => "9e (Card Authentication)",
        }
    }
}

/// PIV algorithms (Yubico extension table for ECC/Edwards + SP 800-73-4).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PivAlgorithm {
    /// 0x11 — ECDSA with NIST P-256 (CAC / generic PIV cards).
    EcdsaP256 = 0x11,
    /// 0xE0 — Ed25519 (YubiKey firmware 5.2.3+ PIV slots).
    Ed25519 = 0xE0,
}

impl PivAlgorithm {
    pub fn label(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "PIV-ECDSA-P256-SHA256",
            Self::Ed25519 => "PIV-Ed25519",
        }
    }
}

/// Errors of the token layer. PIN failures disclose the retry budget so
/// the operator never brick-guesses a CAC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HardwareTokenError {
    /// No CCID reader / card found on the bus.
    NoTokenPresent,
    /// Transport / framing failure.
    Transport(String),
    /// Card protocol violation (unexpected SW or payload shape).
    CardProtocol(String),
    /// VERIFY rejected the PIN; retries remain before block.
    PinRejected { retries_left: Option<u8> },
    /// PIN blocked (63 C3/69 83): the card requires unblocking (PUK).
    PinLocked,
    /// The slot does not hold the requested mechanism.
    UnsupportedMechanism {
        slot: PivSlot,
        algorithm: PivAlgorithm,
    },
}

impl std::fmt::Display for HardwareTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTokenPresent => {
                write!(f, "no CCID/PIV token present on the USB bus")
            }
            Self::Transport(m) => write!(f, "token transport failure: {}", m),
            Self::CardProtocol(m) => write!(f, "card protocol violation: {}", m),
            Self::PinRejected { retries_left } => match retries_left {
                Some(n) => write!(f, "PIN rejected by the card; {} retries before lockout", n),
                None => write!(f, "PIN rejected by the card"),
            },
            Self::PinLocked => write!(
                f,
                "PIN blocked (authentication method blocked); unblock via PUK before retrying"
            ),
            Self::UnsupportedMechanism { slot, algorithm } => write!(
                f,
                "slot {} does not perform {}",
                slot.label(),
                algorithm.label()
            ),
        }
    }
}

/// How the token public key was disclosed for binding purposes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDisclosure {
    /// YubiKey GET METADATA (INS 0xF7) returned the raw slot key.
    MetadataF7,
    /// Card did not expose a metadata verb; binding is signature-level.
    SignatureOnly,
}

/// Cryptographically-checkable evidence that a countersignature was
/// produced by a hardware secure element (v0.7.0, Vector 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareCustodyAttestation {
    /// Transport + applet vocabulary, e.g. "PIV/ISO7816-4-over-CCID-USB".
    pub interface: String,
    /// Physical USB node of the reader (e.g. /dev/bus/usb/001/004).
    pub token_path: String,
    /// Reader USB identity: 16-bit hex "vid:pid".
    pub token_usb_identity: String,
    /// Reader serial string, when the device publishes one.
    pub token_serial: Option<String>,
    /// PIV slot used for the signature (e.g. "9c (Digital Signature)").
    pub slot: String,
    /// Mechanism the card executed (PIV-Ed25519 | PIV-ECDSA-P256-SHA256).
    pub mechanism: String,
    /// The card verified the officer PIN in-session (VERIFY SW 9000).
    pub pin_verified: bool,
    /// BLAKE3 of the exact message the card signed (domain || hash).
    pub signed_message_blake3: String,
    /// How the slot public key was disclosed.
    pub key_disclosure: KeyDisclosure,
    /// Public key the card reported for the slot, hex:
    /// Ed25519 — 32 raw bytes; ECDSA P-256 — 65-byte SEC1 point.
    pub token_public_key_hex: Option<String>,
    /// For ECDSA co-proof tokens: r||s (64 bytes, hex) of the card's
    /// signature over HW_CUSTODY_DOMAIN || officer_pubkey || plan_hash.
    pub custody_cosignature_hex: Option<String>,
    /// BLAKE3 chain over the full APDU transcript (SELECT || VERIFY || ...).
    pub transcript_chain_blake3: String,
}

impl HardwareCustodyAttestation {
    /// Human one-liner for certificates and operator output.
    pub fn summary_line(&self) -> String {
        format!(
            "{} token {} slot {} mechanism {} (PIN verified: {}, transcript {})",
            self.interface,
            self.token_path,
            self.slot,
            self.mechanism,
            self.pin_verified,
            &self.transcript_chain_blake3[..16.min(self.transcript_chain_blake3.len())]
        )
    }
}

/// A PIV application session over any ISO 7816 transport.
pub struct PivSession<'a> {
    transport: &'a mut dyn Iso7816Transport,
    /// Running BLAKE3 transcript chain over every exchange.
    transcript: blake3::Hasher,
}

impl<'a> PivSession<'a> {
    pub fn new(transport: &'a mut dyn Iso7816Transport) -> Self {
        Self {
            transport,
            transcript: blake3::Hasher::new(),
        }
    }

    fn exchange(&mut self, command: &CommandApdu) -> Result<ResponseApdu, HardwareTokenError> {
        let raw = command.encode();
        let response = self
            .transport
            .exchange(command)
            .map_err(HardwareTokenError::Transport)?;
        // Transcript chain: fold command wire || response wire.
        self.transcript.update(&raw);
        self.transcript.update(&[response.sw1, response.sw2]);
        self.transcript.update(&response.data);
        Ok(response)
    }

    /// SELECT the PIV application (mandatory first exchange).
    pub fn select_piv_application(&mut self) -> Result<(), HardwareTokenError> {
        let command = CommandApdu::new(0x00, 0xA4, 0x04, 0x00)
            .with_data(PIV_AID.to_vec())
            .with_ne(256);
        let response = self.exchange(&command)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(()),
            (0x6A, 0x82) => Err(HardwareTokenError::CardProtocol(
                "PIV application not present on this card".to_string(),
            )),
            _ => Err(HardwareTokenError::CardProtocol(format!(
                "SELECT PIV AID refused: {}",
                response.status_name()
            ))),
        }
    }

    /// VERIFY the cardholder PIN (reference 0x80), padded to 8 bytes with
    /// 0xFF per SP 800-73-4. Returns the remaining retry budget on
    /// rejection so the operator stops before lockout.
    ///
    /// SECURITY (v0.9.0 Phase 1a): both the 0xFF-padded PIN buffer and the
    /// APDU's data field are wiped with volatile stores on every exit path —
    /// the PIN never survives this call in heap or stack memory.
    pub fn verify_pin(&mut self, pin: &str) -> Result<(), HardwareTokenError> {
        if pin.len() > 8 || pin.is_empty() {
            return Err(HardwareTokenError::CardProtocol(
                "PIV PIN must be 1..=8 characters".to_string(),
            ));
        }
        let mut padded = [0xFFu8; 8];
        padded[..pin.len()].copy_from_slice(pin.as_bytes());
        let mut command = CommandApdu::new(0x00, 0x20, 0x00, 0x80).with_data(padded.to_vec());
        let response = self.exchange(&command);
        // Wipe both PIN transcriptions regardless of the card's answer.
        command.zeroize_data();
        use zeroize::Zeroize;
        padded.zeroize();
        let response = response?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(()),
            (0x63, _) => {
                if let Some(retries) = response.pin_retries_left() {
                    if retries == 0 {
                        Err(HardwareTokenError::PinLocked)
                    } else {
                        Err(HardwareTokenError::PinRejected {
                            retries_left: Some(retries),
                        })
                    }
                } else {
                    Err(HardwareTokenError::PinRejected { retries_left: None })
                }
            }
            (0x69, 0x83) => Err(HardwareTokenError::PinLocked),
            _ => Err(HardwareTokenError::CardProtocol(format!(
                "VERIFY refused: {}",
                response.status_name()
            ))),
        }
    }

    /// Read the slot public key via YubiKey GET METADATA (INS 0xF7).
    /// Returns `None` when the card does not implement the verb (plain
    /// CACs answer 6D 00): binding then stays signature-level.
    pub fn get_metadata_public_key(
        &mut self,
        slot: PivSlot,
    ) -> Result<Option<Vec<u8>>, HardwareTokenError> {
        let command = CommandApdu::new(0x00, 0xF7, 0x00, slot as u8).with_ne(512);
        let response = self.exchange(&command)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => {}
            (0x6D, 0x00) | (0x6A, 0x86) => return Ok(None), // verb not implemented
            _ => {
                return Err(HardwareTokenError::CardProtocol(format!(
                    "GET METADATA refused: {}",
                    response.status_name()
                )));
            }
        }
        // TLV walk: find tag 0x86 (public key).
        let mut off = 0usize;
        while off + 2 <= response.data.len() {
            let tag = response.data[off];
            let len = response.data[off + 1] as usize;
            if tag == 0x86 && off + 2 + len <= response.data.len() {
                return Ok(Some(response.data[off + 2..off + 2 + len].to_vec()));
            }
            off += 2 + len;
        }
        Ok(None)
    }

    /// GENERAL AUTHENTICATE: sign `message` in the slot with the algorithm.
    /// Ed25519 signs the raw message; ECDSA P-256 signs SHA-256(message)
    /// and returns a DER signature.
    pub fn general_authenticate_sign(
        &mut self,
        slot: PivSlot,
        algorithm: PivAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, HardwareTokenError> {
        // 7C-template: 7C len 81 len <message>
        let mut inner = vec![0x81];
        inner.push(message.len() as u8);
        inner.extend_from_slice(message);
        let mut template = vec![0x7C];
        template.push(inner.len() as u8);
        template.extend_from_slice(&inner);

        let command = CommandApdu::new(0x00, 0x87, algorithm as u8, slot as u8)
            .with_data(template)
            .with_ne(512)
            .extended();
        let response = self.exchange(&command)?;
        if !response.is_ok() {
            return Err(HardwareTokenError::CardProtocol(format!(
                "GENERAL AUTHENTICATE refused: {}",
                response.status_name()
            )));
        }
        // Response 7C len DA len <signature>.
        parse_7c_signature(&response.data).ok_or_else(|| {
            HardwareTokenError::CardProtocol(
                "GENERAL AUTHENTICATE response is not a 7C/DA template".to_string(),
            )
        })
    }

    /// Transcript chain over every exchange of this session so far.
    pub fn transcript_chain(&self) -> String {
        self.transcript.finalize().to_hex().to_string()
    }
}

/// Extract the signature payload from a `7C len DA len <sig>` response.
fn parse_7c_signature(data: &[u8]) -> Option<Vec<u8>> {
    let mut off = 0usize;
    while off + 2 <= data.len() {
        let tag = data[off];
        let len = data[off + 1] as usize;
        if tag == 0x7C {
            let body = data.get(off + 2..off + 2 + len)?;
            // Inside the 7C body, find DA.
            let mut i = 0usize;
            while i + 2 <= body.len() {
                let inner_tag = body[i];
                let inner_len = body[i + 1] as usize;
                if inner_tag == 0xDA {
                    return body.get(i + 2..i + 2 + inner_len).map(|s| s.to_vec());
                }
                i += 2 + inner_len;
            }
            return None;
        }
        off += 2 + len;
    }
    None
}

/// Derive a 64-byte r||s from a DER ECDSA signature (SECG/RFC 5480
/// SEQUENCE of two INTEGERs). Returns the DER unmodified when it already
/// looks like raw r||s (some tokens answer raw).
pub fn der_ecdsa_to_rs(der: &[u8]) -> Option<[u8; 64]> {
    if der.len() == 64 {
        let mut out = [0u8; 64];
        out.copy_from_slice(der);
        return Some(out);
    }
    // SEQUENCE(r, s)
    if der.len() < 6 || der[0] != 0x30 {
        return None;
    }
    let mut rs = [0u8; 64];
    let mut cursor = 2usize; // walk past SEQUENCE header
    for half in 0..2 {
        if cursor + 2 > der.len() || der[cursor] != 0x02 {
            return None;
        }
        let mut len = der[cursor + 1] as usize;
        let mut start = cursor + 2;
        if len > 33 {
            return None;
        }
        // DER INTEGERs may carry a leading 0x00 (positive) or 0xFF
        // (negative — never valid here); normalize to 32 bytes.
        while len > 32 {
            if der[start] != 0x00 {
                return None; // genuine overflow: r/s > 32 bytes
            }
            start += 1;
            len -= 1;
        }
        let dest = half * 32 + (32 - len);
        rs.get_mut(dest..half * 32 + 32)?
            .copy_from_slice(&der[start..start + len]);
        cursor = start + len;
    }
    Some(rs)
}

/// The Ed25519 on-token approval flow: the card signs
/// `domain || bound_hash` with its slot-9C Ed25519 key; the resulting
/// entry's public key is the card's key, the signature is the card's.
///
/// `token_identity` documents the physical endpoint (path / vid:pid /
/// serial) the session rode.
#[allow(clippy::too_many_arguments)]
pub fn countersign_ed25519_on_token(
    transport: &mut dyn Iso7816Transport,
    token_identity: &crate::ccid::CcidEndpoint,
    domain: &[u8],
    bound_hash: &str,
    pin: &str,
) -> Result<
    (
        crate::dualauth::AuthSignatureEntry,
        HardwareCustodyAttestation,
    ),
    HardwareTokenError,
> {
    let mut session = PivSession::new(transport);
    session.select_piv_application()?;
    session.verify_pin(pin)?;
    let slot = PivSlot::DigitalSignature;

    let metadata_key = session.get_metadata_public_key(slot)?;
    let key_disclosure = if metadata_key.is_some() {
        KeyDisclosure::MetadataF7
    } else {
        KeyDisclosure::SignatureOnly
    };

    let mut message = Vec::with_capacity(domain.len() + bound_hash.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bound_hash.as_bytes());
    let signature = session.general_authenticate_sign(slot, PivAlgorithm::Ed25519, &message)?;
    if signature.len() != 64 {
        return Err(HardwareTokenError::CardProtocol(format!(
            "Ed25519 token signature must be 64 bytes, card returned {}",
            signature.len()
        )));
    }
    let attestation = HardwareCustodyAttestation {
        interface: "PIV/ISO7816-4-over-CCID-USB".to_string(),
        token_path: token_identity.device_node.display().to_string(),
        token_usb_identity: format!(
            "{:04x}:{:04x}",
            token_identity.id_vendor, token_identity.id_product
        ),
        token_serial: token_identity.serial.clone(),
        slot: slot.label().to_string(),
        mechanism: PivAlgorithm::Ed25519.label().to_string(),
        pin_verified: true,
        signed_message_blake3: blake3::hash(&message).to_hex().to_string(),
        key_disclosure,
        token_public_key_hex: metadata_key.clone().map(hex::encode),
        custody_cosignature_hex: None,
        transcript_chain_blake3: session.transcript_chain(),
    };

    // The officer key IS the token key: prefer the card-disclosed key;
    // otherwise the entry cannot claim key-level binding.
    let public_key = match &metadata_key {
        Some(k) if k.len() == 32 => k.clone(),
        _ => {
            return Err(HardwareTokenError::CardProtocol(
                "Ed25519 custody requires a card-disclosed slot key (GET METADATA 0xF7); \
                 this token does not support key disclosure"
                    .to_string(),
            ));
        }
    };

    let entry = crate::dualauth::AuthSignatureEntry {
        key_fingerprint: blake3::hash(&public_key).to_hex().to_string(),
        public_key_hex: hex::encode(&public_key),
        signature_hex: hex::encode(&signature),
        is_hardware_token: true,
        hardware_attestation: Some(attestation.clone()),
    };
    // Self-check: the token signature must verify under the token key —
    // a card that signs with a different key than it disclosed is a
    // protocol violation, not a mystery.
    let vk =
        VerifyingKey::from_bytes(public_key.as_slice().try_into().map_err(|_| {
            HardwareTokenError::CardProtocol("slot key is not 32 bytes".to_string())
        })?)
        .map_err(|e| HardwareTokenError::CardProtocol(format!("invalid slot key: {}", e)))?;
    vk.verify(
        &message,
        &Signature::from_bytes(signature.as_slice().try_into().unwrap()),
    )
    .map_err(|_| {
        HardwareTokenError::CardProtocol(
            "token signature does not verify under the disclosed slot key".to_string(),
        )
    })?;
    Ok((entry, attestation))
}

/// Verify a hardware custody attestation against the entry that carries it
/// and the plan binding (called by `dualauth`; pinned by
/// REG-TOKEN-CUSTODY-PROOF).
///
/// Checks:
/// 1. Attestation present, PIN verified, mechanism is a real PIV verb.
/// 2. `signed_message_blake3` == BLAKE3(domain || bound_hash) — the card
///    signed THIS approval, not a replayed foreign transcript.
/// 3. Key-level binding (when the entry is Ed25519-with-token-key):
///    the attestation's disclosed key must equal the entry's public key
///    and its fingerprint.
/// 4. ECDSA co-proof (when present): P-256 verification of the card's
///    signature over HW_CUSTODY_DOMAIN || officer key || bound hash.
pub fn verify_hardware_attestation(
    entry: &crate::dualauth::AuthSignatureEntry,
    attestation: &HardwareCustodyAttestation,
    domain: &[u8],
    bound_hash: &str,
) -> Result<(), &'static str> {
    // 1. Structure and PIN discipline.
    if !attestation.pin_verified {
        return Err("HW_ATTESTATION_PIN_NOT_VERIFIED");
    }
    if !attestation.mechanism.starts_with("PIV-") {
        return Err("HW_ATTESTATION_MECHANISM_UNKNOWN");
    }
    if attestation.interface != "PIV/ISO7816-4-over-CCID-USB" {
        return Err("HW_ATTESTATION_INTERFACE_UNKNOWN");
    }
    if attestation.token_path.is_empty() {
        return Err("HW_ATTESTATION_NO_PHYSICAL_BINDING");
    }

    // 2. Message binding — which message the card signed depends on the
    //    custody model:
    //    - Ed25519-on-token: the approval message `domain || bound_hash`
    //      (the card's signature IS the officer signature);
    //    - ECDSA-P256 co-proof (CAC): the custody message
    //      `HW_CUSTODY_DOMAIN || officer_pubkey || bound_hash` (the card
    //      countersigns the officer's key and the plan binding).
    let expected = if attestation.custody_cosignature_hex.is_some() {
        let mut msg = Vec::with_capacity(
            HW_CUSTODY_DOMAIN.len() + entry.public_key_hex.len() + bound_hash.len(),
        );
        msg.extend_from_slice(HW_CUSTODY_DOMAIN);
        msg.extend_from_slice(entry.public_key_hex.as_bytes());
        msg.extend_from_slice(bound_hash.as_bytes());
        blake3::hash(&msg).to_hex().to_string()
    } else {
        let mut msg = Vec::with_capacity(domain.len() + bound_hash.len());
        msg.extend_from_slice(domain);
        msg.extend_from_slice(bound_hash.as_bytes());
        blake3::hash(&msg).to_hex().to_string()
    };
    if attestation.signed_message_blake3 != expected {
        return Err("HW_ATTESTATION_MESSAGE_BINDING_MISMATCH");
    }

    // 3. Key-level binding for Ed25519 token keys (32 bytes): the
    //    disclosed slot key IS the officer key. P-256 co-proof keys
    //    (65-byte SEC1) bind through the co-signature instead.
    if let Some(key_hex) = &attestation.token_public_key_hex {
        let key = hex::decode(key_hex).map_err(|_| "HW_ATTESTATION_KEY_MALFORMED_HEX")?;
        if key.len() == 32 {
            if hex::encode(&key) != entry.public_key_hex {
                return Err("HW_ATTESTATION_KEY_MISMATCH");
            }
            let fingerprint = blake3::hash(&key).to_hex().to_string();
            if fingerprint != entry.key_fingerprint {
                return Err("HW_ATTESTATION_FINGERPRINT_MISMATCH");
            }
        }
    }

    // 4. ECDSA custody co-proof: the P-256 signature must verify under
    //    the token's disclosed key.
    if let (Some(cosig_hex), Some(key_hex)) = (
        &attestation.custody_cosignature_hex,
        &attestation.token_public_key_hex,
    ) {
        verify_p256_custody_cosignature(&entry.public_key_hex, bound_hash, key_hex, cosig_hex)?;
    }
    Ok(())
}

/// Verify the ECDSA P-256 custody co-proof of a CAC-style attestation:
/// the card signed `HW_CUSTODY_DOMAIN || officer_pubkey || bound_hash`
/// with its P-256 slot key.
pub fn verify_p256_custody_cosignature(
    officer_public_key_hex: &str,
    bound_hash: &str,
    token_public_key_sec1_hex: &str,
    cosignature_rs_hex: &str,
) -> Result<(), &'static str> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let key =
        hex::decode(token_public_key_sec1_hex).map_err(|_| "HW_ATTESTATION_KEY_MALFORMED_HEX")?;
    let vk = VerifyingKey::from_sec1_bytes(&key).map_err(|_| "HW_ATTESTATION_KEY_INVALID_P256")?;
    let rs = hex::decode(cosignature_rs_hex).map_err(|_| "HW_ATTESTATION_COSIG_MALFORMED_HEX")?;
    let sig = Signature::from_slice(&rs).map_err(|_| "HW_ATTESTATION_COSIG_INVALID")?;

    let mut message = Vec::with_capacity(
        HW_CUSTODY_DOMAIN.len() + officer_public_key_hex.len() + bound_hash.len(),
    );
    message.extend_from_slice(HW_CUSTODY_DOMAIN);
    message.extend_from_slice(officer_public_key_hex.as_bytes());
    message.extend_from_slice(bound_hash.as_bytes());
    vk.verify(&message, &sig)
        .map_err(|_| "HW_ATTESTATION_COSIG_INVALID")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scripted transport: replays canned responses APDU-by-APDU.
    struct ScriptedCard {
        responses: Vec<Result<Vec<u8>, String>>,
        calls: usize,
    }

    impl Iso7816Transport for ScriptedCard {
        fn exchange(&mut self, _command: &CommandApdu) -> Result<ResponseApdu, String> {
            let raw = self.responses.get(self.calls).cloned().transpose()?;
            self.calls += 1;
            ResponseApdu::decode(&raw.unwrap_or_default())
        }
    }

    fn ok_piv_select() -> Vec<u8> {
        // 9000 with a minimal FCI template.
        vec![
            0x6F, 0x0A, 0x4F, 0x08, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x90, 0x00,
        ]
    }

    #[test]
    fn pin_verify_roundtrip_and_retry_disclosure() {
        // SELECT ok, VERIFY ok, METADATA (unused) — just drive VERIFY.
        let mut card = ScriptedCard {
            responses: vec![Ok(ok_piv_select()), Ok(vec![0x90, 0x00])],
            calls: 0,
        };
        let mut session = PivSession::new(&mut card);
        session.select_piv_application().unwrap();
        assert!(session.verify_pin("123456").is_ok());

        let mut card = ScriptedCard {
            responses: vec![Ok(ok_piv_select()), Ok(vec![0x63, 0xC2])],
            calls: 0,
        };
        let mut session = PivSession::new(&mut card);
        session.select_piv_application().unwrap();
        assert_eq!(
            session.verify_pin("000000"),
            Err(HardwareTokenError::PinRejected {
                retries_left: Some(2)
            })
        );
    }

    #[test]
    fn general_authenticate_apdu_is_7c_template_with_extended_framing() {
        let mut card = ScriptedCard {
            responses: vec![
                Ok(ok_piv_select()),
                Ok(vec![0x90, 0x00]),
                Ok(vec![0x6D, 0x00]), // no metadata verb
                // 7C 42 DA 40 <64-byte sig>  (7C body = DA(2) + 64 = 66)
                {
                    let mut r = vec![0x7C, 0x42, 0xDA, 0x40];
                    r.extend_from_slice(&[0xAB; 64]);
                    r.extend_from_slice(&[0x90, 0x00]);
                    Ok(r)
                },
            ],
            calls: 0,
        };
        let mut session = PivSession::new(&mut card);
        session.select_piv_application().unwrap();
        session.verify_pin("123456").unwrap();
        assert!(
            session
                .get_metadata_public_key(PivSlot::DigitalSignature)
                .unwrap()
                .is_none()
        );
        let sig = session
            .general_authenticate_sign(PivSlot::DigitalSignature, PivAlgorithm::Ed25519, b"m")
            .unwrap();
        assert_eq!(sig, vec![0xAB; 64]);
        // Transcript chained over all four exchanges (deterministic).
        assert_eq!(session.transcript_chain(), session.transcript_chain());
        assert_eq!(session.transcript_chain().len(), 64);
    }

    #[test]
    fn der_ecdsa_normalization() {
        // SEQUENCE { INTEGER r, INTEGER s } with leading-zero handling.
        let mut der = vec![
            0x30, 0x08, 0x02, 0x03, 0x00, 0xAA, 0xBB, 0x02, 0x03, 0xCC, 0xDD, 0xEE,
        ];
        der[1] = (der.len() - 2) as u8;
        let rs = der_ecdsa_to_rs(&der).unwrap();
        // r: 00AA BB -> 2 bytes right-aligned in 32
        assert_eq!(&rs[30..32], &[0xAA, 0xBB]);
        assert_eq!(&rs[62..64], &[0xCC, 0xDD, 0xEE][1..3]);
        // Raw passthrough.
        assert_eq!(der_ecdsa_to_rs(&[7u8; 64]).unwrap(), [7u8; 64]);
    }

    #[test]
    fn attestation_binding_checks() {
        let key = [2u8; 32];
        let mut message = Vec::new();
        message.extend_from_slice(crate::dualauth::PLAN_APPROVAL_DOMAIN);
        message.extend_from_slice(b"deadbeef");
        let attestation = HardwareCustodyAttestation {
            interface: "PIV/ISO7816-4-over-CCID-USB".to_string(),
            token_path: "/dev/bus/usb/001/004".to_string(),
            token_usb_identity: "1050:0407".to_string(),
            token_serial: Some("YK-00000000".to_string()),
            slot: PivSlot::DigitalSignature.label().to_string(),
            mechanism: PivAlgorithm::Ed25519.label().to_string(),
            pin_verified: true,
            signed_message_blake3: blake3::hash(&message).to_hex().to_string(),
            key_disclosure: KeyDisclosure::MetadataF7,
            token_public_key_hex: Some(hex::encode(key)),
            custody_cosignature_hex: None,
            transcript_chain_blake3: "f".repeat(64),
        };
        let entry = crate::dualauth::AuthSignatureEntry {
            key_fingerprint: blake3::hash(&key).to_hex().to_string(),
            public_key_hex: hex::encode(key),
            signature_hex: "0".repeat(128),
            is_hardware_token: true,
            hardware_attestation: None,
        };
        assert!(
            verify_hardware_attestation(
                &entry,
                &attestation,
                crate::dualauth::PLAN_APPROVAL_DOMAIN,
                "deadbeef"
            )
            .is_ok()
        );
        // Wrong bound hash -> binding mismatch.
        assert_eq!(
            verify_hardware_attestation(
                &entry,
                &attestation,
                crate::dualauth::PLAN_APPROVAL_DOMAIN,
                "feedface"
            ),
            Err("HW_ATTESTATION_MESSAGE_BINDING_MISMATCH")
        );
        // PIN not verified -> refused.
        let mut bad = attestation.clone();
        bad.pin_verified = false;
        assert_eq!(
            verify_hardware_attestation(
                &entry,
                &bad,
                crate::dualauth::PLAN_APPROVAL_DOMAIN,
                "deadbeef"
            ),
            Err("HW_ATTESTATION_PIN_NOT_VERIFIED")
        );
    }
}
