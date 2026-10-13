//! `dc mesh` — Autonomous Multi-Node Consensus & Byzantine
//! Sanitization Swarm (v0.13.0, Frontier 1).
//!
//! * `simulate` — deterministic whole-swarm drill on the virtual
//!   LAN: N nodes, scripted Byzantine actors, a full consensus run
//!   and the threshold co-signed Swarm Certificate of
//!   Decommission, byte-replayable from the seed.
//! * `verify` — offline verification of a swarm certificate: roots,
//!   quorums, rogue evidence, FROST2 aggregate and the ML-DSA-44
//!   t-of-n seal, against optional anchors (group key /
//!   membership hash / per-node PQ keys).

use crate::{MeshArgs, MeshSubcommands};
use dc_core::DcError;
use std::collections::HashMap;

pub fn cmd_mesh(args: MeshArgs) -> Result<(), DcError> {
    match &args.sub {
        MeshSubcommands::Simulate {
            nodes,
            byzantine,
            drives,
            windows,
            seed,
            out,
        } => cmd_simulate(*nodes, byzantine, *drives, *windows, *seed, out.as_deref()),
        MeshSubcommands::Verify {
            cert,
            group_pub,
            membership_hash,
        } => cmd_verify(cert, group_pub.as_deref(), membership_hash.as_deref()),
        MeshSubcommands::Explain => cmd_explain(),
    }
}

/// Parse "3=liar,5=equivocator,1=silent" into sim byzantine actors.
fn parse_byzantine(spec: &str) -> Result<Vec<(usize, dc_mesh::mesh::NodeBehavior)>, DcError> {
    let mut out = Vec::new();
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(out);
    }
    for part in spec.split(',') {
        let part = part.trim();
        let (idx, behavior) = part.split_once('=').ok_or_else(|| {
            DcError::Usage(format!(
                "bad byzantine actor '{part}' (want 'index=behavior')"
            ))
        })?;
        let idx: usize = idx
            .trim()
            .parse()
            .map_err(|e| DcError::Usage(format!("bad node index in '{part}': {e}")))?;
        let behavior = match behavior.trim().to_ascii_lowercase().as_str() {
            "liar" => dc_mesh::mesh::NodeBehavior::Liar,
            "silent" => dc_mesh::mesh::NodeBehavior::Silent,
            "equivocator" => dc_mesh::mesh::NodeBehavior::Equivocator,
            "honest" => dc_mesh::mesh::NodeBehavior::Honest,
            other => {
                return Err(DcError::Usage(format!(
                    "unknown behavior '{other}' (liar | silent | equivocator | honest)"
                )));
            }
        };
        out.push((idx, behavior));
    }
    Ok(out)
}

fn cmd_simulate(
    nodes: usize,
    byzantine: &str,
    drives: u32,
    windows: u64,
    seed: u64,
    out: Option<&str>,
) -> Result<(), DcError> {
    let byz = parse_byzantine(byzantine)?;
    let n_min = dc_mesh::MIN_BYZ_CLUSTER;
    if nodes < n_min {
        return Err(DcError::Usage(format!(
            "a Byzantine-tolerant swarm needs n >= {n_min} (n = 3f+1); got {nodes}"
        )));
    }
    for (idx, _) in &byz {
        if *idx >= nodes {
            return Err(DcError::Usage(format!(
                "byzantine actor index {idx} outside the {nodes}-node membership"
            )));
        }
    }
    println!(
        "[MESH] swarm drill: {nodes} nodes, {} drives/node, {windows} windows/drive",
        drives
    );
    if byz.is_empty() {
        println!("[MESH] byzantine actors: none (happy path)");
    } else {
        for (idx, behavior) in &byz {
            let name = match behavior {
                dc_mesh::mesh::NodeBehavior::Liar => "LIAR (forges reports)",
                dc_mesh::mesh::NodeBehavior::Silent => "SILENT (goes dark)",
                dc_mesh::mesh::NodeBehavior::Equivocator => "EQUIVOCATOR (divergent proposals)",
                dc_mesh::mesh::NodeBehavior::Honest => "honest",
            };
            println!("[MESH] byzantine actor: node #{idx} — {name}");
        }
    }
    let f = dc_mesh::byzantine_tolerance(nodes);
    println!(
        "[MESH] tolerance f = {f}, decision quorum 2f+1 = {} of {nodes}",
        dc_mesh::decision_quorum(nodes)
    );

    let config = dc_mesh::mesh::SwarmSimConfig {
        nodes,
        byzantine: byz,
        drives_per_node: drives,
        windows_per_drive: windows,
        pattern: dc_core::Pattern::Zero,
        threshold: None,
        seed,
    };
    let mut sim = dc_mesh::mesh::SwarmSim::new(&config)
        .map_err(|e| DcError::Internal(format!("swarm construction: {e}")))?;
    sim.run()
        .map_err(|e| DcError::Internal(format!("swarm drill failed: {e}")))?;

    println!(
        "[MESH] converged in {} ticks (deterministic from seed {seed})",
        sim.ticks_run
    );
    let certs = sim.certificates();
    if certs.is_empty() {
        return Err(DcError::Internal(
            "no node certified — the swarm refused to vouch".into(),
        ));
    }
    let c = certs[0];
    println!(
        "[MESH] Swarm Certificate of Decommission ({} assemblers)",
        certs.len()
    );
    println!(
        "       membership hash : {}",
        &c.membership_hash[..16.min(c.membership_hash.len())]
    );
    println!(
        "       block hash      : {}",
        &c.block_hash[..16.min(c.block_hash.len())]
    );
    println!("       certified drives: {}", c.certified_drives());
    println!(
        "       uncertified      : {} (rogue-owned, explicitly refused)",
        c.uncertified.len()
    );
    println!(
        "       rogue ledger     : {} entr{}",
        c.rogue_ledger.len(),
        if c.rogue_ledger.len() == 1 {
            "y"
        } else {
            "ies"
        }
    );
    for e in &c.rogue_ledger {
        println!(
            "         - node {}..{}: {} ({} accusers, evidence {}..{})",
            &e.node[..6.min(e.node.len())],
            &e.node[e.node.len().saturating_sub(4)..],
            e.kind.as_str(),
            e.accusers.len(),
            &e.evidence_digest[..8.min(e.evidence_digest.len())],
            &e.evidence_digest[e.evidence_digest.len().saturating_sub(4)..]
        );
    }
    println!(
        "       FROST2 seal     : t = {} of {} (aggregate Ed25519)",
        c.frost_threshold,
        c.membership.len()
    );
    println!(
        "       ML-DSA-44 seal  : {} of {} partial signatures (post-quantum)",
        c.ml_dsa.entries.len(),
        c.membership.len()
    );

    // Full offline verification with self-anchors.
    let anchor = dc_mesh::cert::SwarmAnchor {
        group_pub: Some(c.frost_group_pub.clone()),
        membership_hash: Some(c.membership_hash.clone()),
        ml_dsa_pks: HashMap::new(),
    };
    let report = dc_mesh::cert::verify_swarm_certificate(c, &anchor);
    if !report.verified {
        return Err(DcError::Internal(format!(
            "certificate failed verification: {:?}",
            report.notes
        )));
    }
    println!("[MESH] certificate verifies offline (roots, quorums, FROST2, ML-DSA seals)");

    if let Some(path) = out {
        let json = serde_json::to_string_pretty(c)
            .map_err(|e| DcError::Internal(format!("serialize certificate: {e}")))?;
        std::fs::write(path, json).map_err(|e| DcError::Internal(format!("write {path}: {e}")))?;
        println!("[MESH] certificate written to {path}");
    }
    Ok(())
}

fn cmd_verify(
    cert_path: &str,
    group_pub: Option<&str>,
    membership_hash: Option<&str>,
) -> Result<(), DcError> {
    let raw = std::fs::read_to_string(cert_path)
        .map_err(|e| DcError::Usage(format!("read {cert_path}: {e}")))?;
    let cert: dc_mesh::cert::SwarmCertificate = serde_json::from_str(&raw)
        .map_err(|e| DcError::Usage(format!("parse swarm certificate: {e}")))?;
    let anchor = dc_mesh::cert::SwarmAnchor {
        group_pub: group_pub.map(str::to_string),
        membership_hash: membership_hash.map(str::to_string),
        ml_dsa_pks: HashMap::new(),
    };
    let report = dc_mesh::cert::verify_swarm_certificate(&cert, &anchor);
    println!("[MESH] swarm certificate verification");
    println!("       schema             : {}", cert.schema);
    println!(
        "       membership          : {} nodes, hash {}...",
        cert.membership.len(),
        &cert.membership_hash[..12.min(cert.membership_hash.len())]
    );
    println!(
        "       drive reports       : {} (root {}...)",
        cert.report_count,
        &cert.report_root[..12.min(cert.report_root.len())]
    );
    println!(
        "       spot transcripts    : {} (root {}...)",
        cert.spot_count,
        &cert.spot_root[..12.min(cert.spot_root.len())]
    );
    println!("       quorum reached      : {}", report.quorum_reached);
    println!(
        "       rogue quorums valid : {}",
        report.rogue_quorums_valid
    );
    println!("       FROST2 aggregate    : {}", report.frost_ok);
    println!("       ML-DSA-44 seal      : {}", report.ml_dsa_ok);
    println!("       drives accounted    : {}", report.drives_accounted);
    if !report.verified {
        for note in &report.notes {
            eprintln!("       NOTE: {note}");
        }
        return Err(DcError::Internal(
            "swarm certificate failed verification".into(),
        ));
    }
    println!("[MESH] VERIFIED — the cluster's collective signature holds");
    Ok(())
}

fn cmd_explain() -> Result<(), DcError> {
    println!("dc-mesh — Autonomous Multi-Node Consensus & Byzantine Sanitization Swarm");
    println!();
    println!("THE PARADIGM: wipe a 500-node cluster with no central orchestrator.");
    println!("If the Ansible/PXE/jump-box is compromised, rogue nodes can skip drives");
    println!("and report false success. dc-mesh removes the single point of trust:");
    println!("the swarm itself is the orchestrator.");
    println!();
    println!("PROTOCOL:");
    println!("  * L2 Ethernet, EtherType 0x88B5, raw AF_PACKET — no IP, no ARP, no ports.");
    println!("  * Broadcast HELLO/HELLO_ACK discovery freezes an epoch membership at 2f+1.");
    println!("  * Epidemic gossip of per-drive zero-entropy attestations (BLAKE3 roots).");
    println!("  * Witness spot-proofs: fresh nonce, fresh LBA window, bytes must recompute.");
    println!("  * PBFT-family rotating-speaker consensus (PRE-PREPARE/PREPARE/COMMIT).");
    println!("  * Byzantine rogue detection: equivocation, duplicate serials, failed");
    println!("    spot-proofs, timeouts — 2f+1 signed accusations isolate a node.");
    println!("  * Threshold co-signing: FROST2 Ed25519 (t-of-n aggregate, the group key");
    println!("    never exists anywhere after the ceremony) + ML-DSA-44 post-quantum set.");
    println!();
    println!("OPERATION:");
    println!("  dc mesh simulate --nodes 7 --byzantine 3=liar --out swarm-cert.json");
    println!("  dc mesh verify swarm-cert.json");
    println!();
    println!("SECURITY: see docs/MESH.md and docs/SECURITY.md (CAP_NET_RAW policy).");
    Ok(())
}
