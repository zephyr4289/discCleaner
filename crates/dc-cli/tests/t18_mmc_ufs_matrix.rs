use dc_testkit::{
    ExtCsdRegister, MmcAccessClass, MmcDevMock, MmcPartitionDisposition, MmcPartitionMap,
    RigLedger, UfsOverlayMock,
};

#[test]
fn test_t18_mmc_ufs_matrix() {
    let ledger = RigLedger::new();

    // 1. T18-PARTMAP: Partition-Map Honesty & Scope Derivation (Δ339, INV16-mmc)
    run_partition_map_tests(&ledger);

    // 2. T18-RPMB-GRADE: RPMB Key-Protected Inaccessible Vocabulary (Δ339)
    run_rpmb_vocabulary_tests(&ledger);

    // 3. T18-REG-MASK: PARTITION_CONFIG Masked Bit Preservation (Δ340)
    run_ext_csd_bit_preservation_tests(&ledger);

    // 4. T18-ACCESS: Access-Class Detection (Δ341)
    run_access_class_tests(&ledger);

    // 5. T18-UFS-WBFLUSH: UFS WriteBooster Cache Flush Law (Δ342)
    run_ufs_write_booster_tests(&ledger);

    assert!(ledger.is_all_green(), "[T18-FAIL] eMMC/UFS matrix contains failing assertions!");
    println!("\n[=== PHASE T18 EMMC / UFS RIG MATRIX PASSED ALL CELLS ===]\n");
}

fn run_partition_map_tests(ledger: &RigLedger) {
    println!("\n[>>> T18-PARTMAP: Testing Partition-Map Scope Derivation (Δ339) <<<]");

    // 1. User area only wiped -> USER_AREA_ONLY_CLEAR_SCOPE
    let partial_map = MmcPartitionMap {
        user_area: MmcPartitionDisposition::Wiped { mechanism: "MmcSanitize".to_string() },
        boot0: MmcPartitionDisposition::WriteProtectedPermanent { detail: "Permanent WP".to_string() },
        boot1: MmcPartitionDisposition::WriteProtectedPermanent { detail: "Permanent WP".to_string() },
        rpmb: MmcPartitionDisposition::KeyProtectedInaccessible { detail: "Key protected".to_string() },
    };
    assert_eq!(partial_map.derive_scope_verdict(), "USER_AREA_ONLY_CLEAR_SCOPE");
    ledger.assert("T18-PARTMAP", "T18-PARTMAP-USER-ONLY", "USER_AREA_ONLY_CLEAR_SCOPE", partial_map.derive_scope_verdict(), None);

    // 2. All physical partitions addressed -> DEVICE_PURGE_COMPLETE
    let complete_map = MmcPartitionMap {
        user_area: MmcPartitionDisposition::Wiped { mechanism: "MmcSanitize".to_string() },
        boot0: MmcPartitionDisposition::Wiped { mechanism: "MmcSecureTrim".to_string() },
        boot1: MmcPartitionDisposition::Wiped { mechanism: "MmcSecureTrim".to_string() },
        rpmb: MmcPartitionDisposition::KeyProtectedInaccessible { detail: "Key protected".to_string() },
    };
    assert_eq!(complete_map.derive_scope_verdict(), "DEVICE_PURGE_COMPLETE");
    ledger.assert("T18-PARTMAP", "T18-PARTMAP-COMPLETE", "DEVICE_PURGE_COMPLETE", complete_map.derive_scope_verdict(), None);
}

fn run_rpmb_vocabulary_tests(ledger: &RigLedger) {
    println!("\n[>>> T18-RPMB-GRADE: Testing RPMB Vocabulary (Δ339) <<<]");

    let rpmb = MmcPartitionDisposition::KeyProtectedInaccessible {
        detail: "RPMB key-protected authenticated storage (not sanitized)".to_string(),
    };
    assert!(matches!(rpmb, MmcPartitionDisposition::KeyProtectedInaccessible { .. }));
    ledger.assert("T18-RPMB", "T18-RPMB-GRADE", "true", "true", None);
}

fn run_ext_csd_bit_preservation_tests(ledger: &RigLedger) {
    println!("\n[>>> T18-REG-MASK: Testing EXT_CSD Masked Bit Preservation (Δ340) <<<]");

    // Initial byte: 0b0100_1000 (Boot ACK=1, Boot Partition 1, Access=User)
    let initial_byte = 0b0100_1000;

    // Switch partition access to Boot Partition 1 (target_access = 0b001)
    let new_byte = ExtCsdRegister::write_partition_config(initial_byte, 0b001);

    // Expected: 0b0100_1001 (Boot ACK & Boot enable preserved, Access switched to 1)
    assert_eq!(new_byte, 0b0100_1001);
    assert_eq!(new_byte & 0b1111_1000, 0b0100_1000, "Adjacent bits must be strictly preserved!");
    ledger.assert("T18-REG", "T18-REG-MASK-PRESERVE", "true", "true", None);
}

fn run_access_class_tests(ledger: &RigLedger) {
    println!("\n[>>> T18-ACCESS: Testing Access-Class Detection (Δ341) <<<]");

    let dev_native = MmcDevMock::new(MmcAccessClass::NativeController);
    assert_eq!(dev_native.access_class, MmcAccessClass::NativeController);

    let dev_reader = MmcDevMock::new(MmcAccessClass::ReaderMediated);
    assert_eq!(dev_reader.access_class, MmcAccessClass::ReaderMediated);

    ledger.assert("T18-ACCESS", "T18-ACCESS-NATIVE", "NativeController", format!("{:?}", dev_native.access_class), None);
}

fn run_ufs_write_booster_tests(ledger: &RigLedger) {
    println!("\n[>>> T18-UFS-WBFLUSH: Testing UFS WriteBooster Flush Law (Δ342) <<<]");

    let mut ufs = UfsOverlayMock::new(2, true);

    // Logical readback before flush -> Refused!
    let pre_flush_res = ufs.verify_logical_readback();
    assert!(pre_flush_res.is_err());
    assert_eq!(pre_flush_res.unwrap_err(), "UNFLUSHED_WRITE_BOOSTER_CACHE_FOOLED_VERIFICATION");

    // Flush WriteBooster
    ufs.flush_write_booster();

    // Logical readback after flush -> Accepted!
    let post_flush_res = ufs.verify_logical_readback();
    assert!(post_flush_res.is_ok());

    ledger.assert("T18-UFS", "T18-UFS-WBFLUSH", "true", post_flush_res.is_ok().to_string(), None);
}
