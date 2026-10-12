// quick prove/verify latency probe (kept in scripts/, not shipped)
use dc_zk::circuit::*;
use dc_zk::field::Fr;
use dc_zk::groth16;
use dc_zk::receipt::*;
use dc_zk::rng::ZkRng;
use std::time::Instant;

fn main() {
    let w = ComplianceWitness {
        serial: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        block_root: Fr::from_be_bytes_reduced(&[0xab; 31]),
        passes: 1,
        verified_blocks: 65536,
        total_blocks: 65536,
        sanitize_success: true,
        operator_secret: Fr::from_be_bytes_reduced(&[0x42; 31]),
        nonce: Fr::from_be_bytes_reduced(&[0x24; 31]),
    };
    let stmt = ComplianceStatement {
        profile_hash: Fr::from_be_bytes_reduced(&[0xcd; 31]),
        tenant_id: Fr::from_be_bytes_reduced(&[0xef; 31]),
        ts: Fr::from_be_bytes_reduced(&1_770_000_000u64.to_be_bytes()),
        vk_commitment: vk_commitment_of(&w.operator_secret, &w.nonce),
        audit_root: Fr::ZERO,
    };
    let stmt = ComplianceStatement {
        audit_root: audit_root_of(&w, &stmt),
        ..stmt
    };

    let t0 = Instant::now();
    let cs = compliance_circuit();
    println!(
        "circuit build: {:?} ({} constraints, {} vars)",
        t0.elapsed(),
        cs.num_constraints(),
        cs.num_vars
    );

    let t1 = Instant::now();
    let mut rng = ZkRng::from_seed(b"bench");
    let (pk, vk) = groth16::setup(&cs, CIRCUIT_ID, &mut rng);
    println!("setup: {:?}", t1.elapsed());

    let t2 = Instant::now();
    let receipt = prove_compliance(&pk, &stmt, &w, &mut rng, None, None).unwrap();
    println!("prove: {:?}", t2.elapsed());

    let t3 = Instant::now();
    let res = verify_receipt(&vk, &receipt);
    println!("verify: {:?} (valid: {})", t3.elapsed(), res.is_valid);
    assert!(res.is_valid);
}
