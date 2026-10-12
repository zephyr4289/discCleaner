//! TPM 2.0 structure serialization (Part 2) and the command set discCleaner
//! needs for remote attestation (Part 3): startup hygiene, PCR read/extend,
//! AIK provisioning (`CreatePrimary` restricted signing key + `EvictControl`
//! persistence), `ReadPublic` for AIK discovery, `GetRandom` for vault
//! entropy, and `TPM2_Quote`.
//!
//! Command marshaling is byte-exact and covered by golden-vector tests
//! below; response parsers are defensive (`Reader` is bounds-checked).

use crate::constants::*;
use crate::wire::{Reader, WireError, WireResult, Writer};

/// One `TPMS_PCR_SELECTION`: hash algorithm + bitmap of selected PCRs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrSelection {
    pub hash_alg: u16,
    /// PCR bitmap, `pcr_select[i]` bit j selects PCR `8*i + j`.
    pub pcr_select: [u8; 4],
}

impl PcrSelection {
    pub fn sha256(mask: [u8; 4]) -> Self {
        Self {
            hash_alg: TPM_ALG_SHA256,
            pcr_select: mask,
        }
    }

    pub fn selects(&self, pcr: usize) -> bool {
        pcr < 32 && (self.pcr_select[pcr / 8] >> (pcr % 8)) & 1 == 1
    }

    pub fn write(&self, w: &mut Writer) {
        w.u16(self.hash_alg);
        w.u8(self.pcr_select.len() as u8); // sizeofSelect
        w.bytes(&self.pcr_select);
    }

    pub fn read(r: &mut Reader<'_>) -> WireResult<Self> {
        let hash_alg = r.u16()?;
        let size = r.u8()? as usize;
        if size > 4 {
            return Err(WireError::Oversized { len: size, cap: 4 });
        }
        let mut pcr_select = [0u8; 4];
        pcr_select[..size].copy_from_slice(r.raw(size)?);
        Ok(Self {
            hash_alg,
            pcr_select,
        })
    }
}

/// `TPML_PCR_SELECTION` — count + selections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrSelectionList {
    pub selections: Vec<PcrSelection>,
}

impl PcrSelectionList {
    pub fn single_sha256(mask: [u8; 4]) -> Self {
        Self {
            selections: vec![PcrSelection::sha256(mask)],
        }
    }

    pub fn write(&self, w: &mut Writer) {
        w.u32(self.selections.len() as u32);
        for s in &self.selections {
            s.write(w);
        }
    }

    pub fn read(r: &mut Reader<'_>) -> WireResult<Self> {
        let count = r.u32()? as usize;
        if count > 4 {
            return Err(WireError::Oversized { len: count, cap: 4 });
        }
        let mut selections = Vec::with_capacity(count);
        for _ in 0..count {
            selections.push(PcrSelection::read(r)?);
        }
        Ok(Self { selections })
    }
}

/// The empty password authorization session (`TPMS_AUTH_COMMAND` with
/// `TPM_RS_PW`, empty nonce, empty HMAC). Under the kernel resource
/// manager (`/dev/tpmrm0`) sessions are managed by the RM; the empty
/// password session is the only authorization form this stack uses —
/// owner-auth-less TPMs (the firmware default) work unmodified.
fn empty_pw_session(w: &mut Writer) {
    w.u32(TPM_RS_PW); // sessionHandle
    w.tpm2b(&[]); // nonce
    w.u8(0); // sessionAttributes: continue
    w.tpm2b(&[]); // hmac
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// `TPM2_Startup(TPM_SU_CLEAR)`.
pub fn encode_startup(clear: bool) -> Vec<u8> {
    Writer::new()
        .u16(if clear { 0x0000 } else { 0x0001 })
        .into_command(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP)
}

/// `TPM2_Shutdown(TPM_SU_CLEAR)`.
pub fn encode_shutdown(clear: bool) -> Vec<u8> {
    Writer::new()
        .u16(if clear { 0x0000 } else { 0x0001 })
        .into_command(TPM_ST_NO_SESSIONS, TPM_CC_SHUTDOWN)
}

/// `TPM2_GetRandom(bytes)`.
pub fn encode_get_random(bytes: u16) -> Vec<u8> {
    Writer::new()
        .u16(bytes)
        .into_command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM)
}

/// `TPM2_PCR_Read`.
pub fn encode_pcr_read(list: &PcrSelectionList) -> Vec<u8> {
    let mut body = Writer::new();
    list.write(&mut body);
    body.into_command(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ)
}

/// `TPM2_PCR_Extend(pcr, sha256(digest))`.
pub fn encode_pcr_extend(pcr: u32, digest32: &[u8; 32]) -> Vec<u8> {
    let mut auth = Writer::new();
    empty_pw_session(&mut auth);
    let mut cmd = Writer::new();
    cmd.u32(pcr); // pcrHandle
    cmd.u32(auth.len() as u32); // authSize (u32 length of the auth area)
    cmd.bytes(auth.as_bytes());
    // TPML_DIGEST_VALUES: count=1, SHA-256 value
    cmd.u32(1);
    cmd.u16(TPM_ALG_SHA256);
    cmd.bytes(digest32);
    cmd.into_command(TPM_ST_SESSIONS, TPM_CC_PCR_EXTEND)
}

/// `TPM2_Quote(signHandle, scheme=ECDSA-SHA256, qualifyingData, selection)`.
/// `qualifying_data` is the freshness nonce echoed back as `extraData`.
pub fn encode_quote(sign_handle: u32, qualifying_data: &[u8], list: &PcrSelectionList) -> Vec<u8> {
    let mut auth = Writer::new();
    empty_pw_session(&mut auth);

    let mut cmd = Writer::new();
    cmd.u32(sign_handle); // signHandle
    cmd.u32(auth.len() as u32); // authSize
    cmd.bytes(auth.as_bytes());
    // TPMT_SIG_SCHEME: ECDSA with SHA-256 (0x0018, 0x000B)
    cmd.u16(TPM_ALG_ECDSA);
    cmd.u16(TPM_ALG_SHA256);
    // TPM2B_DATA qualifyingData — the freshness nonce (max 32 bytes here).
    cmd.tpm2b(qualifying_data);
    list.write(&mut cmd);
    cmd.into_command(TPM_ST_SESSIONS, TPM_CC_QUOTE)
}

/// `TPM2_CreatePrimary` of a restricted ECC signing key (the AIK template).
///
/// The template is exactly the TCG "attestation key" profile: NIST P-256,
/// nameAlg SHA-256, restricted sign, FIXED_TPM|FIXED_PARENT, empty auth.
/// A key created from this template can never leave the TPM — the
/// non-exportability the hardware-attestation guarantee rests on.
pub fn encode_create_primary_aik(parent: u32) -> Vec<u8> {
    let mut auth = Writer::new();
    empty_pw_session(&mut auth);

    // TPMS_SENSITIVE_CREATE (as TPMS_SENSITIVE_CREATE_DATA is marshaled):
    // userAuth TPM2B + data TPM2B — both empty (SENSITIVE_DATA_ORIGIN set).
    let mut sensitive = Writer::new();
    sensitive.tpm2b(&[]); // userAuth
    sensitive.tpm2b(&[]); // data

    // TPMT_PUBLIC for the AIK (see function docs).
    let mut public = Writer::new();
    public.u16(TPM_ALG_ECC); // type
    public.u16(TPM_ALG_SHA256); // nameAlg
    public.u32(AIK_OBJECT_ATTRIBUTES);
    public.tpm2b(&[]); // authPolicy
    // TPMS_ECC_PARMS
    public.u16(TPM_ALG_NULL); // symmetric.algorithm
    // (TPMU_SYM_KEY_BITS for NULL marshals to nothing)
    public.u16(TPM_ALG_ECDSA); // scheme.scheme
    public.u16(TPM_ALG_SHA256); // scheme hashAlg
    public.u16(TPM_ECC_NIST_P256); // curveID
    public.u16(TPM_ALG_NULL); // kdf.kdf (→ no KDF details)
    public.tpm2b(&[]); // unique.x
    public.tpm2b(&[]); // unique.y
    let pub_bytes = public.as_bytes().to_vec();

    let mut cmd = Writer::new();
    cmd.u32(parent);
    cmd.u32(auth.len() as u32); // authSize
    cmd.bytes(auth.as_bytes());
    cmd.tpm2b(sensitive.as_bytes()); // inSensitive (TPM2B_SENSITIVE_CREATE)
    // inPublic is a TPM2B_TEMPLATE: u16 length + the TPMT_PUBLIC bytes.
    cmd.tpm2b(&pub_bytes);
    cmd.tpm2b(&[]); // outsideInfo
    cmd.u32(0); // creationPCR count = 0
    cmd.into_command(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY)
}

/// `TPM2_ReadPublic(objectHandle)`.
pub fn encode_read_public(handle: u32) -> Vec<u8> {
    Writer::new()
        .u32(handle)
        .into_command(TPM_ST_NO_SESSIONS, TPM_CC_READ_PUBLIC)
}

/// `TPM2_EvictControl(ownerAuth, objectHandle, persistentHandle)`.
pub fn encode_evict_control(object_handle: u32, persistent_handle: u32) -> Vec<u8> {
    let mut auth = Writer::new();
    empty_pw_session(&mut auth);
    let mut cmd = Writer::new();
    cmd.u32(TPM_RH_OWNER); // authHandle
    cmd.u32(object_handle); // objectHandle
    cmd.u32(auth.len() as u32); // authSize
    cmd.bytes(auth.as_bytes());
    cmd.u32(persistent_handle); // newPersistentHandle
    cmd.into_command(TPM_ST_SESSIONS, TPM_CC_EVICT_CONTROL)
}

// ---------------------------------------------------------------------------
// v0.9.0 Phase 1b — PCR-policy sealed key storage
// ---------------------------------------------------------------------------

/// Authorization area naming an EXISTING session (policy or trial): the
/// session handle with empty nonce/hmac. The session is the proof.
fn session_auth(w: &mut Writer, session_handle: u32) {
    w.u32(session_handle);
    w.tpm2b(&[]); // nonce
    w.u8(0); // sessionAttributes: continue
    w.tpm2b(&[]); // hmac
}

/// `TPM2_StartAuthSession(NULL bind, trial-or-policy, SHA-256)`.
///
/// The session is unbound and unsalted (tpmKey/bind = NULL, empty salt) —
/// exactly the shape tss libraries use for PCR policy sessions on the RM
/// (the kernel resource manager is the confidentiality boundary between
/// concurrent userspace callers).
pub fn encode_start_auth_session(session_type: u16, nonce_caller: &[u8]) -> Vec<u8> {
    let mut cmd = Writer::new();
    cmd.u32(TPM_RH_NULL); // tpmKey
    cmd.u32(TPM_RH_NULL); // bind
    cmd.tpm2b(nonce_caller); // nonceCaller (freshness)
    cmd.tpm2b(&[]); // encryptedSalt (unsalted)
    cmd.u16(session_type); // sessionType: TRIAL or POLICY
    cmd.u16(TPM_ALG_NULL); // symmetric.algorithm (no session encryption)
    cmd.u16(TPM_ALG_SHA256); // authHash
    cmd.into_command(TPM_ST_NO_SESSIONS, TPM_CC_START_AUTH_SESSION)
}

/// `TPM2_PolicyPCR(policySession, pcrs, pcrDigest)`.
///
/// `pcr_digest` is SHA-256 over the concatenation of the selected PCR
/// values — the *expected* platform state. On a real TPM the command
/// fails with `TPM_RC_POLICY_FAIL` when the live registers differ.
pub fn encode_policy_pcr(session_handle: u32, list: &PcrSelectionList, pcr_digest: &[u8]) -> Vec<u8> {
    let mut auth = Writer::new();
    session_auth(&mut auth, session_handle);
    let mut cmd = Writer::new();
    cmd.u32(session_handle); // policySession
    cmd.u32(auth.len() as u32);
    cmd.bytes(auth.as_bytes());
    list.write(&mut cmd);
    cmd.tpm2b(pcr_digest);
    cmd.into_command(TPM_ST_SESSIONS, TPM_CC_POLICY_PCR)
}

/// `TPM2_PolicyGetDigest(policySession)` — trial sessions use this to
/// harvest the authPolicy digest for `TPM2_Create`.
pub fn encode_policy_get_digest(session_handle: u32) -> Vec<u8> {
    let mut auth = Writer::new();
    session_auth(&mut auth, session_handle);
    let mut cmd = Writer::new();
    cmd.u32(session_handle);
    cmd.u32(auth.len() as u32);
    cmd.bytes(auth.as_bytes());
    cmd.into_command(TPM_ST_SESSIONS, TPM_CC_POLICY_GET_DIGEST)
}

/// `TPM2_Create(parent, inSensitive{data=secret}, inPublic{KEYEDHASH,
/// authPolicy=policy, FIXED_TPM|FIXED_PARENT})`.
///
/// The sealed object carries NO user auth: unsealing is possible only by
/// replaying the PCR policy the caller bound at seal time.
pub fn encode_create_sealed(parent: u32, policy_digest: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut auth = Writer::new();
    empty_pw_session(&mut auth);

    // TPMS_SENSITIVE_CREATE: empty userAuth, data = the secret plaintext.
    let mut sensitive = Writer::new();
    sensitive.tpm2b(&[]);
    sensitive.tpm2b(secret);

    // TPMT_PUBLIC for a sealed data object (TPMS_KEYEDHASH_PARMS).
    let mut public = Writer::new();
    public.u16(TPM_ALG_KEYEDHASH); // type
    public.u16(TPM_ALG_SHA256); // nameAlg
    public.u32(SEALED_OBJECT_ATTRIBUTES);
    public.tpm2b(policy_digest); // authPolicy — the PCR binding
    public.u16(TPM_ALG_NULL); // parameters.scheme (plain data, no HMAC)
    public.tpm2b(&[]); // unique (TPM2B_DIGEST, empty at creation)
    let pub_bytes = public.as_bytes().to_vec();

    let mut cmd = Writer::new();
    cmd.u32(parent);
    cmd.u32(auth.len() as u32);
    cmd.bytes(auth.as_bytes());
    cmd.tpm2b(sensitive.as_bytes()); // inSensitive (TPM2B_SENSITIVE_CREATE)
    cmd.tpm2b(&pub_bytes); // inPublic (TPM2B_TEMPLATE)
    cmd.tpm2b(&[]); // outsideInfo
    cmd.u32(0); // creationPCR count
    cmd.into_command(TPM_ST_SESSIONS, TPM_CC_CREATE)
}

/// `TPM2_Load(parent, inPrivate, inPublic)`.
pub fn encode_load(parent: u32, private: &[u8], public: &[u8]) -> Vec<u8> {
    let mut auth = Writer::new();
    empty_pw_session(&mut auth);
    let mut cmd = Writer::new();
    cmd.u32(parent);
    cmd.u32(auth.len() as u32);
    cmd.bytes(auth.as_bytes());
    cmd.tpm2b(private); // inPrivate (TPM2B_PRIVATE)
    cmd.tpm2b(public); // inPublic (TPM2B_PUBLIC)
    cmd.into_command(TPM_ST_SESSIONS, TPM_CC_LOAD)
}

/// `TPM2_Unseal(objectHandle)` authorized BY THE POLICY SESSION — the
/// session handle rides in the auth area; the TPM accepts only if the
/// session satisfied the object's authPolicy (live PCR state).
pub fn encode_unseal(session_handle: u32, object_handle: u32) -> Vec<u8> {
    let mut auth = Writer::new();
    session_auth(&mut auth, session_handle);
    let mut cmd = Writer::new();
    cmd.u32(object_handle); // objectHandle
    cmd.u32(auth.len() as u32);
    cmd.bytes(auth.as_bytes());
    cmd.into_command(TPM_ST_SESSIONS, TPM_CC_UNSEAL)
}

/// `TPM2_FlushContext(flushHandle)` — transient objects and sessions
/// never outlive the operation that created them.
pub fn encode_flush_context(handle: u32) -> Vec<u8> {
    Writer::new()
        .u32(handle)
        .into_command(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT)
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// Parsed response header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHeader {
    pub tag: u16,
    pub response_code: u32,
    /// Byte offset at which parameters start (after the parameterSize word
    /// for session-tagged responses).
    pub params_offset: usize,
}

/// Parse and classify a TPM response: success → header + parameter slice;
/// failure → the numeric response code (callers map it to diagnostics).
pub fn parse_response_header(buf: &[u8]) -> WireResult<Result<(ResponseHeader, &[u8]), u32>> {
    let mut r = Reader::new(buf);
    let tag = r.u16()?;
    let _size = r.u32()?;
    let code = r.u32()?;
    if code != TPM_RC_SUCCESS {
        return Ok(Err(code));
    }
    let mut params_offset = r.offset();
    if tag == TPM_ST_SESSIONS_RSP {
        // parameterSize (u32) separates parameters from trailing sessions.
        let _parameter_size = r.u32()?;
        params_offset = r.offset();
    }
    let params = &buf[params_offset.min(buf.len())..];
    Ok(Ok((
        ResponseHeader {
            tag,
            response_code: code,
            params_offset,
        },
        params,
    )))
}

/// `TPM2_PCR_Read` response: echoed selection + digest list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrReadResponse {
    pub selection: PcrSelectionList,
    /// Digests in selection order (bitmap ascending).
    pub digests: Vec<[u8; 32]>,
}

pub fn parse_pcr_read(params: &[u8]) -> WireResult<PcrReadResponse> {
    let mut r = Reader::new(params);
    let selection = PcrSelectionList::read(&mut r)?;
    let count = r.u32()? as usize;
    if count > 24 {
        return Err(WireError::Oversized {
            len: count,
            cap: 24,
        });
    }
    let mut digests = Vec::with_capacity(count);
    for _ in 0..count {
        let d = r.tpm2b()?;
        let mut fixed = [0u8; 32];
        if d.len() == 32 {
            fixed.copy_from_slice(&d);
        } else {
            return Err(WireError::Truncated {
                offset: r.offset(),
                need: 32,
                have: d.len(),
            });
        }
        digests.push(fixed);
    }
    Ok(PcrReadResponse { selection, digests })
}

/// `TPM2_Quote`/`TPM2_CreatePrimary`-style ECDSA public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EccPublicKey {
    pub curve_id: u16,
    /// Uncompressed coordinates, exactly 32 bytes each for P-256.
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

/// `TPM2_CreatePrimary` response (AIK provisioning path).
#[derive(Clone, Debug)]
pub struct CreatePrimaryResponse {
    pub handle: u32,
    pub public: EccPublicKey,
    /// Raw TPMT_PUBLIC bytes (archived into the evidence package so the AIK
    /// can be re-verified offline without the TPM).
    pub public_raw: Vec<u8>,
}

pub fn parse_create_primary(params: &[u8]) -> WireResult<CreatePrimaryResponse> {
    let mut r = Reader::new(params);
    let handle = r.u32()?;
    // NOTE: CreatePrimary responses carry no private blob — primary keys
    // never leave the TPM (that is the non-exportability guarantee).
    let public_raw = r.tpm2b()?;
    let mut pr = Reader::new(&public_raw);
    let key_type = pr.u16()?;
    if key_type != TPM_ALG_ECC {
        return Err(WireError::Unexpected {
            what: "public key type, expected ECC",
            value: key_type,
        });
    }
    let _name_alg = pr.u16()?;
    let _attrs = pr.u32()?;
    let _policy = pr.tpm2b()?;
    // TPMS_ECC_PARMS: symmetric (TPMT_SYM_DEF_OBJECT: algorithm only for
    // NULL), scheme (TPMT_ECC_SCHEME: scheme + hashAlg), curveID, kdf.
    let _sym = pr.u16()?;
    let _scheme_alg = pr.u16()?;
    let _scheme_hash = pr.u16()?;
    let curve_id = pr.u16()?;
    let _kdf = pr.u16()?;
    let x = pr.tpm2b()?;
    let y = pr.tpm2b()?;
    Ok(CreatePrimaryResponse {
        handle,
        public: EccPublicKey { curve_id, x, y },
        public_raw,
    })
}

/// `TPM2_ReadPublic` response → ECDSA key + raw template.
/// Layout: `TPM2B_PUBLIC outPublic, TPM2B_NAME name, TPM2B_NAME qualifiedName`
/// (only the public blob is consumed).
pub fn parse_read_public(params: &[u8]) -> WireResult<(EccPublicKey, Vec<u8>)> {
    let mut r = Reader::new(params);
    let public_raw = r.tpm2b()?;
    let mut pr = Reader::new(&public_raw);
    let key_type = pr.u16()?;
    if key_type != TPM_ALG_ECC {
        return Err(WireError::Unexpected {
            what: "public key type, expected ECC",
            value: key_type,
        });
    }
    let _name_alg = pr.u16()?;
    let _attrs = pr.u32()?;
    let _policy = pr.tpm2b()?;
    let _sym = pr.u16()?;
    let _scheme_alg = pr.u16()?;
    let _scheme_hash = pr.u16()?;
    let curve_id = pr.u16()?;
    let _kdf = pr.u16()?;
    let x = pr.tpm2b()?;
    let y = pr.tpm2b()?;
    Ok((EccPublicKey { curve_id, x, y }, public_raw))
}

/// Decoded `TPMS_ATTEST` (quote variant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteAttestation {
    pub magic: u32,
    pub attest_type: u16,
    /// TPM2B_NAME of the signing key (nameAlg || name digest).
    pub qualified_signer: Vec<u8>,
    /// Our nonce (TPM2B_DATA / extraData).
    pub extra_data: Vec<u8>,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub clock_safe: bool,
    pub firmware_version: u64,
    pub pcr_selection: PcrSelectionList,
    pub pcr_digest: Vec<u8>,
    /// The exact serialized TPMS_ATTEST bytes (signature input).
    pub raw: Vec<u8>,
}

pub fn parse_attestation(params: &[u8]) -> WireResult<QuoteAttestation> {
    let mut r = Reader::new(params);
    let start = r.offset();
    let magic = r.u32()?;
    let attest_type = r.u16()?;
    let qualified_signer = r.tpm2b()?;
    let extra_data = r.tpm2b()?;
    // TPMS_CLOCK_INFO
    let clock = r.u64()?;
    let reset_count = r.u32()?;
    let restart_count = r.u32()?;
    let clock_safe = r.u8()? != 0;
    let firmware_version = r.u64()?;
    // TPMS_QUOTE_INFO
    let pcr_selection = PcrSelectionList::read(&mut r)?;
    let pcr_digest = r.tpm2b()?;
    let raw = params[start..r.offset()].to_vec();
    Ok(QuoteAttestation {
        magic,
        attest_type,
        qualified_signer,
        extra_data,
        clock,
        reset_count,
        restart_count,
        clock_safe,
        firmware_version,
        pcr_selection,
        pcr_digest,
        raw,
    })
}

/// `TPMT_SIGNATURE` (ECDSA flavor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdsaSignature {
    /// Signature algorithm (must be `TPM_ALG_ECDSA` — verified by the
    /// replay ladder; a doctored scheme word is a doctored quote).
    pub alg: u16,
    pub hash_alg: u16,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

pub fn parse_ecdsa_signature(params: &[u8]) -> WireResult<EcdsaSignature> {
    let mut r = Reader::new(params);
    let alg = r.u16()?;
    let hash_alg = r.u16()?;
    let r_bytes = r.tpm2b()?;
    let s_bytes = r.tpm2b()?;
    Ok(EcdsaSignature {
        alg,
        hash_alg,
        r: r_bytes,
        s: s_bytes,
    })
}

// ---------------------------------------------------------------------------
// v0.9.0 Phase 1b — seal-path response parsers
// ---------------------------------------------------------------------------

/// `TPM2_StartAuthSession` response: the session handle (+ TPM nonce).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartAuthSessionResponse {
    pub session_handle: u32,
    pub nonce_tpm: Vec<u8>,
}

pub fn parse_start_auth_session(params: &[u8]) -> WireResult<StartAuthSessionResponse> {
    let mut r = Reader::new(params);
    let session_handle = r.u32()?;
    // Session handles belong to the 0x03 (HMAC/policy) or 0x04 (policy)
    // class per the handle-type table; anything else is a broken transport.
    let class = (session_handle >> 24) as u16;
    if class != 0x03 {
        return Err(WireError::Unexpected {
            what: "session handle class, expected 0x03",
            value: class,
        });
    }
    let nonce_tpm = r.tpm2b()?;
    Ok(StartAuthSessionResponse {
        session_handle,
        nonce_tpm,
    })
}

/// `TPM2_PolicyGetDigest` response: the running policy digest.
pub fn parse_policy_digest(params: &[u8]) -> WireResult<Vec<u8>> {
    let mut r = Reader::new(params);
    r.tpm2b()
}

/// `TPM2_Create` response: the sealed private blob + public template.
/// (creationData/creationHash/creationTicket are present but not consumed.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSealedResponse {
    /// TPM2B_PRIVATE — parent-wrapped ciphertext of the secret.
    pub private: Vec<u8>,
    /// TPM2B_PUBLIC — the sealed object's public area (carries authPolicy).
    pub public: Vec<u8>,
}

pub fn parse_create_sealed(params: &[u8]) -> WireResult<CreateSealedResponse> {
    let mut r = Reader::new(params);
    let private = r.tpm2b()?;
    let public = r.tpm2b()?;
    if private.is_empty() || public.is_empty() {
        return Err(WireError::Truncated {
            offset: r.offset(),
            need: 1,
            have: 0,
        });
    }
    Ok(CreateSealedResponse { private, public })
}

/// `TPM2_Load` response: the loaded transient object handle (+ name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadResponse {
    pub handle: u32,
    pub name: Vec<u8>,
}

pub fn parse_load(params: &[u8]) -> WireResult<LoadResponse> {
    let mut r = Reader::new(params);
    let handle = r.u32()?;
    let name = r.tpm2b()?;
    // Transient objects live in the 0x80 class.
    let class = (handle >> 24) as u16;
    if class != 0x80 {
        return Err(WireError::Unexpected {
            what: "transient object handle class, expected 0x80",
            value: class,
        });
    }
    Ok(LoadResponse { handle, name })
}

/// `TPM2_Unseal` response: the recovered plaintext (TPM2B_SENSITIVE_DATA).
pub fn parse_unseal(params: &[u8]) -> WireResult<Vec<u8>> {
    let mut r = Reader::new(params);
    r.tpm2b()
}

// ---------------------------------------------------------------------------
// Golden-vector tests: byte-exact command marshaling
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn quote_command_bytes_are_pinned() {
        let nonce = b"freshness-nonce-material__";
        let cmd = encode_quote(
            0x8180_0001,
            nonce,
            &PcrSelectionList::single_sha256(DC_QUOTE_PCR_MASK),
        );
        // tag / size / code
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(
            u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]),
            cmd.len() as u32
        );
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x58]);
        // handle
        assert_eq!(&cmd[10..14], &0x8180_0001u32.to_be_bytes());
        // authSize
        let auth_size = u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]);
        // auth block: sessionHandle(4) + nonce TPM2B(2) + attrs(1) + hmac TPM2B(2) = 9
        assert_eq!(auth_size, 9);
        // first auth word: TPM_RS_PW
        assert_eq!(&cmd[18..22], &TPM_RS_PW.to_be_bytes());
        let scheme_off = 18 + auth_size as usize;
        // scheme: ECDSA / SHA-256
        assert_eq!(&cmd[scheme_off..scheme_off + 4], &[0x00, 0x18, 0x00, 0x0B]);
        // qualifyingData TPM2B
        let qd_len = u16::from_be_bytes([cmd[scheme_off + 4], cmd[scheme_off + 5]]) as usize;
        assert_eq!(qd_len, nonce.len());
        assert_eq!(&cmd[scheme_off + 6..scheme_off + 6 + qd_len], nonce);
        // TPML_PCR_SELECTION: count 1, hash 0x000B, sizeofSelect 4, mask
        let sel_off = scheme_off + 6 + qd_len;
        assert_eq!(
            &cmd[sel_off..sel_off + 8],
            &[0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x04, 0xFF]
        );
        // mask = [0xFF, 0x0F, 0x00, 0x00] — PCRs 0-11
        assert_eq!(&cmd[cmd.len() - 4..], &[0xFF, 0x0F, 0x00, 0x00]);
    }

    #[test]
    fn pcr_extend_command_bytes_are_pinned() {
        let digest = Sha256::digest(b"disc");
        let mut fixed = [0u8; 32];
        fixed.copy_from_slice(&digest);
        let cmd = encode_pcr_extend(9, &fixed);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x82]);
        assert_eq!(&cmd[10..14], &9u32.to_be_bytes()); // pcrHandle
        let auth_size = u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]);
        assert_eq!(auth_size, 9);
        // TPML_DIGEST_VALUES: count 1, alg SHA-256, 32-byte digest
        let body = 18 + auth_size as usize;
        assert_eq!(&cmd[body..body + 6], &[0, 0, 0, 1, 0x00, 0x0B]);
        assert_eq!(&cmd[body + 6..body + 38], &fixed);
    }

    #[test]
    fn pcr_read_command_bytes_are_pinned() {
        let cmd = encode_pcr_read(&PcrSelectionList::single_sha256([0xFF, 0, 0, 0]));
        assert_eq!(cmd.len(), 21); // 10 header + 11 selection
        assert_eq!(&cmd[0..2], &[0x80, 0x01]);
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x7E]);
        assert_eq!(
            &cmd[10..],
            &[0, 0, 0, 1, 0x00, 0x0B, 0x04, 0xFF, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn attestation_round_trip_preserves_raw_and_fields() {
        let mut w = Writer::new();
        w.u32(TPM_GENERATED);
        w.u16(TPM_ST_ATTEST_QUOTE);
        let signer: Vec<u8> = [0x0Bu8].iter().copied().chain([0xAAu8; 33]).collect();
        w.tpm2b(&signer); // qualifiedSigner: nameAlg + SHA-256
        w.tpm2b(b"nonce-32-bytes________________!");
        w.u64(1234); // clock
        w.u32(7); // resetCount
        w.u32(2); // restartCount
        w.u8(1); // safe
        w.u64(0x0102_0304_0506_0708); // firmwareVersion
        // selection
        w.u32(1);
        w.u16(TPM_ALG_SHA256);
        w.u8(4);
        w.bytes(&DC_QUOTE_PCR_MASK);
        w.tpm2b(&[0xAB; 32]);
        let a = parse_attestation(w.as_bytes()).unwrap();
        assert_eq!(a.magic, TPM_GENERATED);
        assert_eq!(a.attest_type, TPM_ST_ATTEST_QUOTE);
        assert_eq!(a.extra_data, b"nonce-32-bytes________________!");
        assert_eq!(a.clock, 1234);
        assert!(a.clock_safe);
        assert_eq!(a.raw.len(), w.as_bytes().len());
        assert_eq!(a.raw, w.as_bytes());
    }

    #[test]
    fn truncated_attestation_is_clean_error() {
        let mut w = Writer::new();
        w.u32(TPM_GENERATED);
        w.u16(TPM_ST_ATTEST_QUOTE);
        let signer: Vec<u8> = [0x0Bu8].iter().copied().chain([0xAAu8; 33]).collect();
        w.tpm2b(&signer);
        w.tpm2b(b"short-nonce");
        w.u64(1);
        // ... missing the rest
        assert!(parse_attestation(w.as_bytes()).is_err());
    }

    #[test]
    fn create_primary_aik_template_is_restricted_sign() {
        let cmd = encode_create_primary_aik(TPM_RH_OWNER);
        assert_eq!(&cmd[6..10], &TPM_CC_CREATE_PRIMARY.to_be_bytes());
        // locate the TPMT_PUBLIC bytes: handle(4) + authSize(4) + auth(13)
        // + inSensitive TPM2B(u16 len + 4) ...
        let mut off = 10 + 4 + 4 + 13;
        let sens_len = u16::from_be_bytes([cmd[off], cmd[off + 1]]) as usize;
        off += 2 + sens_len;
        let pub_len = u16::from_be_bytes([cmd[off], cmd[off + 1]]) as usize;
        let pub_bytes = &cmd[off + 2..off + 2 + pub_len];
        let mut pr = Reader::new(pub_bytes);
        assert_eq!(pr.u16().unwrap(), TPM_ALG_ECC);
        assert_eq!(pr.u16().unwrap(), TPM_ALG_SHA256);
        assert_eq!(pr.u32().unwrap(), AIK_OBJECT_ATTRIBUTES);
        // Attribute laws as compile-time constants.
        const _: () = assert!(AIK_OBJECT_ATTRIBUTES & 0x0001_0000 != 0); // RESTRICTED
        const _: () = assert!(AIK_OBJECT_ATTRIBUTES & 0x0004_0000 != 0); // SIGN
        const _: () = assert!(AIK_OBJECT_ATTRIBUTES & 0x0000_0002 != 0); // FIXED_TPM
        const _: () = assert!(AIK_OBJECT_ATTRIBUTES & 0x0000_0010 != 0); // FIXED_PARENT
    }
}
