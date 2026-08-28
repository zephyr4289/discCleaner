use dc_hw::NvmeCodec;
use dc_probe::IdentityComparator;
use dc_testkit::RigLedger;

#[test]
fn test_m1_2_identity_matrix() {
    let ledger = RigLedger::new();

    // 1. NVME-ID-CTRL & NVME-ID-NS: Controller & Namespace Decoders (Δ249)
    run_identify_decoders_tests(&ledger);

    // 2. NVME-ID-TOKEN-NS: Namespace-Qualified Token Precedence (Δ250)
    run_token_precedence_tests(&ledger);

    // 3. NVME-HEALTH-UNITS: SMART / Health Log Unit Decodes (Δ252)
    run_health_units_tests(&ledger);

    assert!(ledger.is_all_green(), "[M1.2-FAIL] Identity & Health matrix contains failing assertions!");
    println!("\n[=== MILESTONE M1.2 IDENTITY & HEALTH MATRIX PASSED ALL CELLS ===]\n");
}

fn run_identify_decoders_tests(ledger: &RigLedger) {
    println!("\n[>>> NVME-ID-CTRL & NVME-ID-NS: Testing Identify Decoders (Δ249) <<<]");

    // 1. 4 KiB Identify Controller Payload
    let mut raw_ctrl = vec![0u8; 4096];
    raw_ctrl[0..2].copy_from_slice(&0x144Du16.to_le_bytes()); // VID (Samsung)
    raw_ctrl[4..24].copy_from_slice(b"S6B0NJ0W123456X     "); // Serial
    raw_ctrl[24..64].copy_from_slice(b"Samsung SSD 990 PRO 2TB                 "); // Model
    raw_ctrl[64..72].copy_from_slice(b"3B2QGXA7"); // FW
    raw_ctrl[516..520].copy_from_slice(&1u32.to_le_bytes()); // NN = 1

    let ctrl = NvmeCodec::decode_identify_controller(&raw_ctrl).unwrap();
    assert_eq!(ctrl.vid, 0x144D);
    assert_eq!(ctrl.sn, "S6B0NJ0W123456X");
    assert_eq!(ctrl.mn, "Samsung SSD 990 PRO 2TB");
    assert_eq!(ctrl.fr, "3B2QGXA7");
    assert_eq!(ctrl.nn, 1);
    ledger.assert("M1.2-ID", "NVME-ID-CTRL", "S6B0NJ0W123456X", ctrl.sn, None);

    // 2. 4 KiB Identify Namespace Payload
    let mut raw_ns = vec![0u8; 4096];
    let nsze: u64 = 3_907_029_168; // 2 TB in 512B sectors
    raw_ns[0..8].copy_from_slice(&nsze.to_le_bytes());
    raw_ns[8..16].copy_from_slice(&nsze.to_le_bytes());
    raw_ns[26] = 0; // FLBAS = 0 (512B)

    let nguid_bytes = hex::decode("002538b5915049380000000000000001").unwrap();
    raw_ns[104..120].copy_from_slice(&nguid_bytes);

    let ns = NvmeCodec::decode_identify_namespace(&raw_ns).unwrap();
    assert_eq!(ns.nsze, nsze);
    assert_eq!(ns.nguid, Some("002538b5915049380000000000000001".to_string()));
    ledger.assert("M1.2-ID", "NVME-ID-NS", "002538b5915049380000000000000001", ns.nguid.unwrap(), None);
}

fn run_token_precedence_tests(ledger: &RigLedger) {
    println!("\n[>>> NVME-ID-TOKEN-NS: Testing Token Precedence (Δ250) <<<]");

    // Precedence: NGUID > EUI64 > serial+nsid > kernel_name
    let tok_nguid = IdentityComparator::derive_confirmation_token(
        Some("002538b591504938"),
        Some("0025385915049380"),
        Some("S6B0NJ0W"),
        Some(1),
        "nvme0n1",
    );
    assert_eq!(tok_nguid, "nguid:002538b591504938");

    let tok_eui64 = IdentityComparator::derive_confirmation_token(
        None,
        Some("0025385915049380"),
        Some("S6B0NJ0W"),
        Some(1),
        "nvme0n1",
    );
    assert_eq!(tok_eui64, "eui64:0025385915049380");

    let tok_sn_ns = IdentityComparator::derive_confirmation_token(
        None,
        None,
        Some("S6B0NJ0W"),
        Some(2),
        "nvme0n2",
    );
    assert_eq!(tok_sn_ns, "S6B0NJ0W:n2");

    let tok_dev = IdentityComparator::derive_confirmation_token(
        None,
        None,
        None,
        None,
        "nvme0n1",
    );
    assert_eq!(tok_dev, "nvme0n1");

    ledger.assert("M1.2-TOKEN", "NVME-ID-TOKEN-NS", "S6B0NJ0W:n2", tok_sn_ns, None);
}

fn run_health_units_tests(ledger: &RigLedger) {
    println!("\n[>>> NVME-HEALTH-UNITS: Testing SMART / Health Units (Δ252) <<<]");

    let mut raw_health = vec![0u8; 512];
    raw_health[0] = 0x00; // Critical warning = 0 (healthy)
    raw_health[1..3].copy_from_slice(&312u16.to_le_bytes()); // 312 Kelvin = 39 °C
    raw_health[3] = 100; // 100% available spare
    raw_health[5] = 10;  // 10% percentage used

    let data_units_written: u128 = 4_000_000; // 4 million × 1,000 × 512B = ~2 TB
    raw_health[48..64].copy_from_slice(&data_units_written.to_le_bytes());

    let health = NvmeCodec::decode_health_log(&raw_health).unwrap();
    assert_eq!(health.temperature_kelvin, 312);
    assert_eq!(health.data_units_written, 4_000_000);
    assert_eq!(health.percentage_used, 10);

    ledger.assert("M1.2-HEALTH", "NVME-HEALTH-UNITS", "312", health.temperature_kelvin.to_string(), None);
}
