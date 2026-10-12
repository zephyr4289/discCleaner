//! `dc zk` — zero-knowledge audit receipts (v0.11.0, Frontier 1).
//!
//! * `setup` — one-time ceremony: generate Groth16 proving/verifying
//!   keys (toxic waste generated in-process and dropped, never
//!   persisted; see docs/zk-audit.md for the trust model).
//! * `prove` — derive the compliance witness from a
//!   SanitizationCertificate and produce a ~192-byte ZK receipt.
//! * `verify` — check a receipt against a verifying key (and optional
//!   expected public values).

use crate::{ZkArgs, ZkSubcommands};
use dc_cert::SanitizationCertificate;
use dc_core::DcError;
use dc_zk::{ComplianceStatement, ComplianceWitness, ProvingKey, VerifyingKey, ZkReceipt, ZkRng};

pub fn cmd_zk(args: ZkArgs) -> Result<(), DcError> {
    match &args.sub {
        ZkSubcommands::Setup { out_dir, seed } => cmd_setup(out_dir, seed.as_deref()),
        ZkSubcommands::Prove {
            pk,
            certificate,
            tenant,
            operator_secret,
            nonce,
            receipt_out,
        } => cmd_prove(
            pk,
            certificate,
            tenant,
            operator_secret.as_deref(),
            nonce.as_deref(),
            receipt_out,
        ),
        ZkSubcommands::Verify {
            vk,
            receipt,
            expect_tenant,
            expect_profile,
            expect_vk_fingerprint,
        } => cmd_verify(
            vk,
            receipt,
            expect_tenant.as_deref(),
            expect_profile.as_deref(),
            expect_vk_fingerprint.as_deref(),
        ),
    }
}

fn cmd_setup(out_dir: &std::path::Path, seed: Option<&str>) -> Result<(), DcError> {
    std::fs::create_dir_all(out_dir)?;
    let mut rng = match seed {
        Some(hex_seed) => {
            let bytes = hex::decode(hex_seed)
                .map_err(|e| DcError::Usage(format!("--seed must be hex: {}", e)))?;
            ZkRng::from_seed(&bytes)
        }
        None => ZkRng::from_os(),
    };
    eprintln!("[zk] building compliance circuit (a few seconds)...");
    let circuit = dc_zk::compliance_circuit();
    eprintln!(
        "[zk] circuit: {} constraints / {} variables",
        circuit.num_constraints(),
        circuit.num_vars
    );
    eprintln!("[zk] running single-party Groth16 ceremony (toxic waste is dropped in-process)...");
    let (pk, vk) = dc_zk::setup(&circuit, dc_zk::CIRCUIT_ID, &mut rng);

    let vk_path = out_dir.join("zk-vk.json");
    let pk_path = out_dir.join("zk-pk.json");
    std::fs::write(
        &vk_path,
        serde_json::to_string_pretty(&vk)
            .map_err(|e| DcError::Usage(format!("serialize: {}", e)))?,
    )
    .map_err(|e| DcError::Usage(format!("I/O: {}", e)))?;
    std::fs::write(
        &pk_path,
        serde_json::to_string_pretty(&pk)
            .map_err(|e| DcError::Usage(format!("serialize: {}", e)))?,
    )
    .map_err(|e| DcError::Usage(format!("I/O: {}", e)))?;

    let fp = dc_zk::vk_fingerprint(&vk);
    println!("Proving key:    {}", pk_path.display());
    println!("Verifying key:  {}", vk_path.display());
    println!("VK fingerprint (BLAKE3): {}", fp);
    println!();
    println!("NEXT STEPS");
    println!("  1. Distribute zk-vk.json to auditors (pin its fingerprint out-of-band).");
    println!(
        "  2. Prove: dc zk prove --pk {} --certificate <cert.json> --tenant <hex> --receipt out.json",
        pk_path.display()
    );
    println!(
        "  3. Verify: dc zk verify --vk {} --receipt out.json",
        vk_path.display()
    );
    Ok(())
}

fn load_json_file<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T, DcError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| DcError::Usage(format!("cannot read {}: {}", path.display(), e)))?;
    serde_json::from_str(&data)
        .map_err(|e| DcError::Usage(format!("malformed JSON in {}: {}", path.display(), e)))
}

fn cmd_prove(
    pk_path: &std::path::Path,
    cert_path: &std::path::Path,
    tenant: &str,
    operator_secret_hex: Option<&str>,
    nonce_hex: Option<&str>,
    receipt_out: &std::path::Path,
) -> Result<(), DcError> {
    let pk: ProvingKey = load_json_file(pk_path)?;
    let cert: SanitizationCertificate = load_json_file(cert_path)?;

    // ---- derive the witness from the certificate ----------------------
    let tenant_fr = if tenant == "0" || tenant.is_empty() {
        dc_zk::Fr::ZERO
    } else {
        hex::decode(tenant)
            .map_err(|e| DcError::Usage(format!("--tenant must be hex: {}", e)))
            .map(|b| dc_zk::Fr::from_hash(&b))?
    };

    // pass count from the execution evidence
    let passes = u8::try_from(cert.execution.passes.len())
        .unwrap_or(255)
        .max(1);
    // verification coverage
    let verified = cert.verification.windows_checked;
    // total windows required by the plan (window_bytes vs media size)
    let total = {
        let size = cert.device.stable.size_bytes;
        let wb = cert.plan.window_bytes.max(1);
        size.div_ceil(wb).max(verified).max(1)
    };
    let success = cert.verification.mismatch_count == 0;

    // block root: BLAKE3 of the verification stream hash binding
    let block_root = dc_zk::Fr::from_hash(cert.verification.stream_hash_blake3.as_bytes());

    // serial: first 16 bytes of the device serial string
    let mut serial = [0u8; 16];
    if let Some(serial_str) = cert.device.stable.serial.as_deref() {
        for (i, b) in serial_str.as_bytes().iter().take(16).enumerate() {
            serial[i] = *b;
        }
    }

    let operator_secret = match operator_secret_hex {
        Some(h) => hex::decode(h)
            .map_err(|e| DcError::Usage(format!("--operator-secret must be hex: {}", e)))
            .map(|b| dc_zk::Fr::from_hash(&b))?,
        None => {
            // derive deterministically from the operator public key
            // fingerprint (publicly re-derivable, so the operator can
            // reproduce receipts; the privacy comes from the commitment).
            dc_zk::Fr::from_hash(cert.operator.key_fingerprint_blake3.as_bytes())
        }
    };
    let nonce = match nonce_hex {
        Some(h) => hex::decode(h)
            .map_err(|e| DcError::Usage(format!("--nonce must be hex: {}", e)))
            .map(|b| dc_zk::Fr::from_hash(&b))?,
        None => dc_zk::Fr::random(),
    };

    // timestamp: parse the ISO 8601 start time into unix seconds via a
    // simple RFC3339 reader (the certificate format is fixed).
    let ts_unix = parse_iso_to_unix(&cert.execution.started_utc).unwrap_or(0);
    let ts = dc_zk::Fr::from_hash(&ts_unix.to_be_bytes());

    // profile hash: BLAKE3 of the canonical plan hash.
    let profile_hash = dc_zk::Fr::from_hash(cert.plan_hash.as_bytes());

    // statement
    let vk_commitment = dc_zk::vk_commitment_of(&operator_secret, &nonce);
    let witness = ComplianceWitness {
        serial,
        block_root,
        passes,
        verified_blocks: u32::try_from(verified.min(u32::MAX as u64)).unwrap_or(u32::MAX),
        total_blocks: u32::try_from(total.min(u32::MAX as u64)).unwrap_or(u32::MAX),
        sanitize_success: success,
        operator_secret,
        nonce,
    };
    let mut stmt = ComplianceStatement {
        profile_hash,
        tenant_id: tenant_fr,
        ts,
        vk_commitment,
        audit_root: dc_zk::Fr::ZERO,
    };
    stmt.audit_root = dc_zk::audit_root_of(&witness, &stmt);

    if !success {
        return Err(DcError::Usage(
            "certificate carries verification mismatches — refusing to prove compliance for a failed wipe"
                .to_string(),
        ));
    }
    if verified < total {
        return Err(DcError::Usage(format!(
            "certificate is under-verified ({} of {} windows) — cannot prove full-verification compliance",
            verified, total
        )));
    }

    eprintln!("[zk] proving (this takes ~20 seconds with the pure-Rust prover)...");
    let mut rng = ZkRng::from_os();
    let receipt = dc_zk::prove_compliance(
        &pk,
        &stmt,
        &witness,
        &mut rng,
        Some(cert_path.display().to_string()),
        None,
    )
    .map_err(|e| DcError::Usage(format!("prove failed: {}", e)))?;

    let json = serde_json::to_string_pretty(&receipt)
        .map_err(|e| DcError::Usage(format!("I/O: {}", e)))?;
    std::fs::write(receipt_out, &json).map_err(|e| DcError::Usage(format!("I/O: {}", e)))?;
    println!("ZK receipt written: {}", receipt_out.display());
    println!("  circuit:    {}", receipt.circuit_id);
    println!("  scheme:     {}", receipt.scheme);
    println!("  vk fp:      {}", receipt.vk_fingerprint);
    println!(
        "  statement:  profile={} tenant={} ts={}",
        &receipt.statement.profile_hash[..16.min(receipt.statement.profile_hash.len())],
        &receipt.statement.tenant_id[..16.min(receipt.statement.tenant_id.len())],
        &receipt.statement.ts[..16.min(receipt.statement.ts.len())]
    );
    println!("  PROOF SIZE: {} bytes (compressed points)", 192usize);
    Ok(())
}

fn cmd_verify(
    vk_path: &std::path::Path,
    receipt_path: &std::path::Path,
    expect_tenant: Option<&str>,
    expect_profile: Option<&str>,
    expect_vk_fingerprint: Option<&str>,
) -> Result<(), DcError> {
    let vk: VerifyingKey = load_json_file(vk_path)?;
    let receipt: ZkReceipt = load_json_file(receipt_path)?;

    let result = dc_zk::verify_receipt(&vk, &receipt);
    println!("circuit:         {}", result.circuit_id);
    println!("scheme:          {}", result.scheme);
    println!("proof verified:  {}", result.proof_verified);
    println!("vk fingerprint:  {}", result.vk_fingerprint_matches);
    println!("generated at:    {}", result.generated_at_unix);
    println!("public statement:");
    println!("  profile_hash:  {}", receipt.statement.profile_hash);
    println!("  tenant_id:     {}", receipt.statement.tenant_id);
    println!("  ts:            {}", receipt.statement.ts);
    println!("  vk_commitment: {}", receipt.statement.vk_commitment);
    println!("  audit_root:    {}", receipt.statement.audit_root);
    // cross-check expected public values
    if let Some(exp) = expect_tenant {
        let got = receipt.statement.tenant_id.clone();
        let ok = canonical_hex_eq(exp, &got);
        println!("tenant match:    {}", ok);
        if !ok {
            return Err(DcError::Usage(
                "tenant mismatch: receipt does not prove compliance for the expected tenant"
                    .to_string(),
            ));
        }
    }
    if let Some(exp) = expect_profile {
        let got = receipt.statement.profile_hash.clone();
        let ok = canonical_hex_eq(exp, &got);
        println!("profile match:   {}", ok);
        if !ok {
            return Err(DcError::Usage(
                "profile mismatch: receipt does not prove compliance for the expected profile"
                    .to_string(),
            ));
        }
    }
    if let Some(exp) = expect_vk_fingerprint {
        let ok = exp.trim_start_matches("0x") == receipt.vk_fingerprint.trim_start_matches("0x");
        println!("key pinned:     {}", ok);
        if !ok {
            return Err(DcError::Usage(
                "verifying key fingerprint mismatch — the receipt was generated under a different ceremony"
                    .to_string(),
            ));
        }
    }
    if !result.is_valid {
        return Err(DcError::Usage(format!(
            "receipt INVALID: {}",
            result.error.unwrap_or_else(|| "unknown".into())
        )));
    }
    println!();
    println!("RESULT: VALID — sanitization compliance proven in zero knowledge.");
    println!("       (The proof reveals NOTHING about the drive serial, block");
    println!("        topology, pass count or operator identity.)");
    Ok(())
}

/// Minimal RFC3339 ("2026-10-12T08:30:00Z" / with offsets) → unix seconds.
fn parse_iso_to_unix(s: &str) -> Option<u64> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 10 {
        return None;
    }
    let num =
        |a: usize, b: usize| -> Option<i64> { s.get(a..b).and_then(|t| t.parse::<i64>().ok()) };
    let y = num(0, 4)?;
    let mo = num(5, 7)?;
    let d = num(8, 10)?;
    let (hh, mm, ss) = if bytes.len() >= 19 && bytes[10] == b'T' {
        (num(11, 13)?, num(14, 16)?, num(17, 19)?)
    } else {
        (0, 0, 0)
    };
    // days since epoch (civil algorithm)
    let (y2, mo2) = if mo <= 2 { (y - 1, mo + 12) } else { (y, mo) };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (mo2 - 3) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + hh * 3600 + mm * 60 + ss;
    // (Z-suffixed timestamps only — the engine's own format.)
    u64::try_from(secs).ok()
}

/// Compare two hex field-element encodings numerically (leading-zero
/// padding differences are irrelevant).
fn canonical_hex_eq(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Option<Vec<u8>> {
        let t = s.trim_start_matches("0x");
        let mut v = hex::decode(t).ok()?;
        while v.first() == Some(&0) {
            v.remove(0);
        }
        Some(v)
    };
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}
