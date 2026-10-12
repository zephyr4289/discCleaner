//! TPM 2.0 wire constants (TPM 2.0 Part 2, Tables 17/28/69 and the command
//! index from Part 3). Values are pinned literals — the TPM wire protocol is
//! frozen by TCG specification, not by any per-kernel header, so these are
//! stable across kernel versions (guarded by the golden-vector tests in
//! `commands.rs`).

#![allow(dead_code)] // full constant surface kept for evidence replay tooling

// --- Structure tags ---------------------------------------------------------
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
/// Response tag mirroring `TPM_ST_SESSIONS` (command carried authorization).
pub const TPM_ST_SESSIONS_RSP: u16 = 0x8002;
/// Attestation-structure magic ("TCG" generation marker).
pub const TPM_GENERATED: u32 = 0xFF54_4347;
/// `TPM_ST_ATTEST_QUOTE`.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

// --- Algorithm IDs ----------------------------------------------------------
pub const TPM_ALG_ERROR: u16 = 0x0000;
pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_SHA384: u16 = 0x000C;
pub const TPM_ALG_SHA512: u16 = 0x000D;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_ECDAA: u16 = 0x0019;
pub const TPM_ALG_RSASSA: u16 = 0x0014;
pub const TPM_ALG_RSA: u16 = 0x0001;

// --- Handle classes ---------------------------------------------------------
pub const TPM_RH_OWNER: u32 = 0x4000_0001;
pub const TPM_RH_ENDORSEMENT: u32 = 0x4000_0003;
pub const TPM_RH_NULL: u32 = 0x4000_0007;
/// Password authorization session handle (empty HMAC session).
pub const TPM_RS_PW: u32 = 0x4000_0009;
/// First legal persistent-object handle (TPM 2.0 Part 2 Table 28:
/// the `0x81` handle class covers persistent objects).
pub const TPM_HR_PERSISTENT: u32 = 0x8100_0000;
/// Last legal persistent-object handle.
pub const TPM_HR_PERSISTENT_LAST: u32 = 0x81FF_FFFF;

// --- Command codes (TPM 2.0 Part 3 command index) --------------------------
pub const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
pub const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub const TPM_CC_READ_PUBLIC: u32 = 0x0000_0173;
pub const TPM_CC_EVICT_CONTROL: u32 = 0x0000_0120;
pub const TPM_CC_QUOTE: u32 = 0x0000_0158;
// v0.9.0 Phase 1b: PCR-policy sealed key storage (TPM2_Create / TPM2_Unseal).
pub const TPM_CC_CREATE: u32 = 0x0000_015A;
pub const TPM_CC_LOAD: u32 = 0x0000_0157;
pub const TPM_CC_UNSEAL: u32 = 0x0000_015E;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
pub const TPM_CC_POLICY_PCR: u32 = 0x0000_017F;
pub const TPM_CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;

// --- Response codes ---------------------------------------------------------
pub const TPM_RC_SUCCESS: u32 = 0x0000_0000;
/// `TPM_RC_INITIALIZE` — startup already performed (treated as benign for
/// `TPM2_Startup`: the device is in the state we wanted anyway).
pub const TPM_RC_INITIALIZE: u32 = 0x0000_0100;
/// `TPM_RC_POLICY_FAIL` — the authorization policy (PCR binding) did not
/// match; the sealed key stays sealed.
pub const TPM_RC_POLICY_FAIL: u32 = 0x0000_0099;
/// `TPM_RC_SIZE` — command/response size violation (oversized secret).
pub const TPM_RC_SIZE: u32 = 0x0000_01D5;

// --- NIST P-256 curve id (TPM_ECC_NIST_P256) --------------------------------
pub const TPM_ECC_NIST_P256: u16 = 0x0003;

// --- AIK policy -------------------------------------------------------------
/// Conventional persistent handle for the discCleaner attestation key.
/// 0x81800001 sits inside the persistent range but outside the slots
/// commonly burned in by OS provisioning (SRK at 0x81000001 etc.), so `dc`
/// never collides with an existing key hierarchy.
pub const DC_AIK_PERSISTENT_HANDLE: u32 = 0x8180_0001;

/// Object attributes for a restricted signing key (an attestation identity
/// key): FIXED_TTPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH
/// | RESTRICTED | SIGN. A key with these attributes can sign quotes but can
/// never be exported from the TPM — the mathematical basis of the
/// hardware-attestation guarantee.
pub const AIK_OBJECT_ATTRIBUTES: u32 = 0x0005_0072;

/// PCR banks this stack quotes: SHA-256, PCRs 0-11.
/// PCR 0-7 measure platform firmware (SRTM: BIOS/UEFI); the dc appliance
/// extends its own measurements into PCR 8 (kernel), 9 (initramfs),
/// 10 (dc binary) and 11 (plan evidence) before quoting.
pub const DC_QUOTE_PCR_MASK: [u8; 4] = [0xFF, 0x0F, 0x00, 0x00];

// --- v0.9.0 Phase 1b: sealed-key storage constants ---------------------------
/// `TPM_ALG_KEYEDHASH` — the object type of a sealed data blob.
pub const TPM_ALG_KEYEDHASH: u16 = 0x0008;
/// `TPM_ALG_CFB` — the only session-symmetric mode this stack offers.
pub const TPM_ALG_CFB: u16 = 0x0043;

/// `TPM_SE_HMAC` — HMAC authorization session.
pub const TPM_SE_HMAC: u16 = 0x0000;
/// `TPM_SE_POLICY` — policy authorization session (enforced at Unseal).
pub const TPM_SE_POLICY: u16 = 0x0001;
/// `TPM_SE_TRIAL` — trial policy session (computes the authPolicy digest
/// for `TPM2_Create` without enforcing anything).
pub const TPM_SE_TRIAL: u16 = 0x0003;

/// First transient-session handle class (0x0000_0003 range is reserved
/// for loaded sessions by the handle-type table; we only sanity-check the
/// high nibble in the parser).
pub const TPM_HR_HMAC_SESSION: u32 = 0x0300_0000;

/// Object attributes for a sealed data object: FIXED_TPM | FIXED_PARENT —
/// no USER_WITH_AUTH and no ADMIN_WITH_AUTH. A key sealed with these bits
/// can ONLY be unsealed by satisfying its authPolicy (the PCR policy):
/// no owner password, no empty-password escape hatch, ever.
pub const SEALED_OBJECT_ATTRIBUTES: u32 = 0x0000_0012;

/// Hard cap on sealed payload size. Real TPMs marshal `TPM2_Create`
/// sensitive data through the parent's symmetric encryption, which caps
/// plaintext at 128 bytes for the ubiquitous AES-128 primaries — the
/// operator Ed25519 seed (32 bytes) fits with 4x headroom.
pub const DC_SEALED_SECRET_MAX: usize = 128;
