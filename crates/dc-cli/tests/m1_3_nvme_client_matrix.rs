use dc_nvme::{
    ErrnoClassifier, IoctlTaxonomy, NvmeAdminTransport, NvmePurgeClient, PurgeMechanism,
    PurgePermit,
};
use dc_testkit::RigLedger;

struct MockFaultyTransport {
    fail_crypto_erase: bool,
}

impl NvmeAdminTransport for MockFaultyTransport {
    fn admin_passthrough(&mut self, cmd: &[u8; 64]) -> Result<Vec<u8>, IoctlTaxonomy> {
        let opcode = cmd[0];

        if opcode == 0x84 {
            // Sanitize Command
            let cdw10 = u32::from_le_bytes([cmd[40], cmd[41], cmd[42], cmd[43]]);
            let action = cdw10 & 0x07;

            if action == 4 && self.fail_crypto_erase {
                // Reject Crypto Erase to trigger ladder fallback
                return Err(IoctlTaxonomy::ControllerRejected {
                    errno: libc::EIO,
                    description: "Sanitize Crypto Erase unsupported by controller".to_string(),
                });
            }

            // Return success for Block Erase
            return Ok(vec![]);
        }

        if opcode == 0x02 {
            // Get Log Page 0x81 (Sanitize Status)
            let mut log = vec![0u8; 512];
            log[0..2].copy_from_slice(&65535u16.to_le_bytes()); // SPROG = 100%
            log[2..4].copy_from_slice(&1u16.to_le_bytes());     // SSTAT = Completed
            return Ok(log);
        }

        Ok(vec![])
    }
}

#[test]
fn test_m1_3_nvme_client_matrix() {
    let ledger = RigLedger::new();

    // 1. TCONF-ERRNO-TAXONOMY: Linux Errno to Client Taxonomy Mapping (Δ268)
    run_errno_taxonomy_tests(&ledger);

    // 2. PURGE-PERMIT-TYPESTATE: Permit Minting & Target Binding (Δ272, INV11)
    run_permit_typestate_tests(&ledger);

    // 3. PURGE-FALLBACK-LADDER: Planned Mechanism Fallback Ladder (Δ269, Δ270)
    run_fallback_ladder_tests(&ledger);

    assert!(ledger.is_all_green(), "[M1.3-FAIL] NVMe Client matrix contains failing assertions!");
    println!("\n[=== MILESTONE M1.3 NVME PURGE CLIENT MATRIX PASSED ALL CELLS ===]\n");
}

fn run_errno_taxonomy_tests(ledger: &RigLedger) {
    println!("\n[>>> TCONF-ERRNO-TAXONOMY: Testing Errno Classification (Δ268) <<<]");

    assert_eq!(ErrnoClassifier::classify(0), IoctlTaxonomy::Success);

    let eio = ErrnoClassifier::classify(libc::EIO);
    assert!(matches!(eio, IoctlTaxonomy::ControllerRejected { .. }));

    let efault = ErrnoClassifier::classify(libc::EFAULT);
    assert!(matches!(efault, IoctlTaxonomy::OurBug { .. }));

    let etimedout = ErrnoClassifier::classify(libc::ETIMEDOUT);
    assert!(matches!(etimedout, IoctlTaxonomy::TimeoutAmbiguous { .. }));

    ledger.assert("M1.3-ERRNO", "TCONF-ERRNO-TAXONOMY", "true", "true", None);
}

fn run_permit_typestate_tests(ledger: &RigLedger) {
    println!("\n[>>> PURGE-PERMIT-TYPESTATE: Testing PurgePermit Binding (Δ272, INV11) <<<]");

    let permit = PurgePermit::mint("/dev/nvme0n1", "S6B0NJ0W123456X", 1724890000);
    assert_eq!(permit.target_device, "/dev/nvme0n1");
    assert_eq!(permit.target_serial, "S6B0NJ0W123456X");

    ledger.assert("M1.3-PERMIT", "PURGE-PERMIT-TYPESTATE", "/dev/nvme0n1", permit.target_device, None);
}

fn run_fallback_ladder_tests(ledger: &RigLedger) {
    println!("\n[>>> PURGE-FALLBACK-LADDER: Testing Planned Mechanism Fallback (Δ269, Δ270) <<<]");

    let mut transport = MockFaultyTransport {
        fail_crypto_erase: true,
    };
    let permit = PurgePermit::mint("/dev/nvme0", "S6B0NJ0W123456X", 1724890000);

    let mut client = NvmePurgeClient::new(&mut transport);
    let summary = client
        .execute_purge_ladder(&permit, PurgeMechanism::SanitizeCryptoErase)
        .unwrap();

    // Must have fallen back to Block Erase and completed successfully!
    assert_eq!(summary.executed_mechanism, PurgeMechanism::SanitizeBlockErase);
    assert_eq!(summary.fallbacks.len(), 1);
    assert_eq!(summary.fallbacks[0].from, PurgeMechanism::SanitizeCryptoErase);
    assert_eq!(summary.fallbacks[0].to, PurgeMechanism::SanitizeBlockErase);
    assert!(summary.status.is_completed);

    ledger.assert(
        "M1.3-LADDER",
        "PURGE-FALLBACK-LADDER",
        "SanitizeBlockErase",
        format!("{:?}", summary.executed_mechanism),
        None,
    );
}
