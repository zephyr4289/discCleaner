//! `dc fhe` — Homomorphic Verifiable Computation over Encrypted
//! Drives (v0.14.0, Breakthrough 2).
//!
//! * `simulate` — run the full customer ↔ provider protocol on a
//!   deterministic demo volume: encrypt, blind-zeroize without the
//!   key, prove, batch-verify in milliseconds, spot-decrypt with
//!   the customer's key; assemble the FHE Erasure Certificate.
//! * `verify` — offline verification (digest binding, eval-key
//!   recomputation, Merkle root recomputation, ZK replay).
//! * `explain` — the custody paradox, the algebra, and the threat
//!   model in operator terms.

use crate::{FheArgs, FheSubcommands};
use dc_core::DcError;

pub fn cmd_fhe(args: FheArgs) -> Result<(), DcError> {
    match &args.sub {
        FheSubcommands::Simulate {
            volume_id,
            sectors,
            seed,
            out,
        } => cmd_simulate(volume_id, *sectors, *seed, out.as_deref()),
        FheSubcommands::Verify { cert } => cmd_verify(cert),
        FheSubcommands::Explain => cmd_explain(),
    }
}

fn cmd_simulate(
    volume_id: &str,
    sectors: u32,
    seed: u64,
    out: Option<&str>,
) -> Result<(), DcError> {
    if sectors == 0 {
        return Err(DcError::Usage("an empty volume has nothing to wipe".into()));
    }
    println!("[FHE] homomorphic erasure protocol: volume {volume_id}");
    println!("[FHE] {sectors} sector ciphertexts, Ring-LWE N=1024 q=65537 CBD-3 (demo-grade)");
    let cert =
        dc_fhe::certificate::FheErasureCertificate::assemble(volume_id, sectors as usize, seed)
            .map_err(|e| DcError::Internal(format!("protocol run: {e}")))?;

    println!();
    println!("[FHE] customer : keygen, encrypted {sectors} sectors, published commitment root");
    println!(
        "[FHE] provider : blind-zeroized every sector WITHOUT the key ({} ms), proved ({} ms)",
        cert.eval_ms, cert.prove_ms
    );
    println!(
        "[FHE] customer : batched ZK verification {} ms ({} sectors, constant-time), spot-decrypted sector {} → {}",
        cert.batched_verify_ms,
        sectors,
        cert.spot_sector,
        if cert.spot_is_zero { "0^N" } else { "NONZERO" }
    );
    println!(
        "[FHE] roots    : original {}… → final {}…",
        &cert.original_root[..12.min(cert.original_root.len())],
        &cert.final_root[..12.min(cert.final_root.len())]
    );
    println!(
        "[FHE] noise    : worst margin {:.1}x below the decryptability ceiling",
        cert.worst_noise_margin
    );
    for note in &cert.notes {
        println!("[FHE] NOTE: {note}");
    }
    if cert.verified {
        println!("[FHE] FHE ERASURE CERTIFICATE: VERIFIED");
        println!("       Dec_sk(C') = 0^N holds by the circuit algebra — the provider never");
        println!("       decrypted, and the customer never showed the key");
    } else {
        println!("[FHE] FHE ERASURE CERTIFICATE: REFUSED");
        println!("       the provider failed to prove the wipe");
    }

    if let Some(path) = out {
        let json = serde_json::to_string_pretty(&cert)
            .map_err(|e| DcError::Internal(format!("serialize certificate: {e}")))?;
        std::fs::write(path, json).map_err(|e| DcError::Internal(format!("write {path}: {e}")))?;
        println!(
            "[FHE] certificate written to {path} (digest {})",
            &cert.digest[..16.min(cert.digest.len())]
        );
    }
    Ok(())
}

fn cmd_verify(cert_path: &str) -> Result<(), DcError> {
    let raw = std::fs::read_to_string(cert_path)
        .map_err(|e| DcError::Usage(format!("read {cert_path}: {e}")))?;
    let cert: dc_fhe::certificate::FheErasureCertificate = serde_json::from_str(&raw)
        .map_err(|e| DcError::Usage(format!("parse fhe certificate: {e}")))?;
    println!("[FHE] FHE erasure certificate verification");
    println!("       volume       : {}", cert.volume_id);
    println!(
        "       digest       : {}",
        &cert.digest[..16.min(cert.digest.len())]
    );
    println!("       sectors      : {}", cert.sector_count);
    println!(
        "       eval key     : {}…",
        &cert.eval_key_digest[..16.min(cert.eval_key_digest.len())]
    );
    cert.verify()
        .map_err(|e| DcError::Internal(format!("certificate verification: {e}")))?;
    if cert.verified {
        println!("[FHE] VERIFIED — digest covers the body, roots recompute, ZK replay holds");
    } else {
        println!("[FHE] VERIFIED AS A DOCUMENT — but the run itself REFUSED (see notes)");
        for note in &cert.notes {
            println!("       NOTE: {note}");
        }
    }
    Ok(())
}

fn cmd_explain() -> Result<(), DcError> {
    println!("dc-fhe — Homomorphic Verifiable Computation over Encrypted Drives");
    println!();
    println!("THE CUSTODY PARADOX: Customer A wants the cloud provider to wipe their encrypted");
    println!("volume. A refuses to hand over the key; the provider refuses to run A's code on");
    println!("the host. Software-visible wipes are unverifiable in BOTH directions.");
    println!();
    println!("dc-fhe closes it with homomorphic cryptography:");
    println!("  * Ring-LWE encryption (rlwe.rs): pk = (a, b = a*s + e); sectors encrypt as");
    println!("    (u, v) pairs under the customer's public key.");
    println!("  * Blind zeroize (fhe.rs): the provider transforms every stored ciphertext");
    println!("    in place:  C' = (C - C) + Enc_pk(0; r').  Dec_sk(C') = m - m + 0 = 0^N");
    println!("    by the circuit algebra — no key, no decryption, and the output is a fresh");
    println!("    encryption of zero: the provider learns nothing, not even whether data");
    println!("    was present.");
    println!("  * Zero-knowledge proof (zkp.rs): a Lyubashevsky-style Fiat-Shamir argument");
    println!("    that every stored ciphertext admits a short encryption-of-zero witness.");
    println!("    An encrypted data ciphertext has no such witness — a lazy provider cannot");
    println!("    prove.");
    println!("  * Batched verification: all sector equations collapse into TWO polynomial");
    println!("    products — milliseconds, independent of the sector count. Plus the spot");
    println!("    challenge: the customer decrypts one Fiat-Shamir-chosen sector with");
    println!("    their own key and must see 0^N.");
    println!();
    println!("THE CERTIFICATE binds the volume identity, the evaluation key, both commitment");
    println!("roots, the proof, the noise margins and the measured verification time under a");
    println!("BLAKE3 digest — replayable offline without any secrets.");
    println!();
    println!("OPERATION:");
    println!("  dc fhe simulate --volume-id vol-uuid --sectors 8 --out fhe-cert.json");
    println!("  dc fhe verify --cert fhe-cert.json");
    println!();
    println!("PARAMETER HONESTY: N=1024, q=65537, CBD-3 are demo-grade so the whole pipeline");
    println!("runs in milliseconds with schoolbook arithmetic. Production swaps in the");
    println!("current RLWE literature parameters via the Params struct — the protocol logic");
    println!("is parameter-independent.");
    Ok(())
}
