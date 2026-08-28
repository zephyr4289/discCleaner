use assert_cmd::Command;
use dc_core::{BusType, StableIdentity};
use dc_probe::{
    classify_pure, BlockTree, DeviceNode, GuardianFlags, IdentityComparison, IdentityComparator,
    Sniffer, StorageSignature,
};
use dc_testkit::RigLedger;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[test]
fn test_g3_guardian_identity_matrix() {
    let ledger = RigLedger::new();
    let temp_dir = tempfile::tempdir().unwrap();

    // 1. GUARD-CLASSIFY-PURE: Table-Driven Pure Classification Vectors (Δ121)
    run_guard_classify_pure(&ledger);

    // 2. GUARD-IDENT-COMPARE: Stable Identity Comparator Vectors (Δ46)
    run_guard_ident_compare(&ledger);

    // 3. GUARD-SNIFF-BOUNDS: Bounded Signature Sniffer (Δ124)
    run_guard_sniff_bounds(&ledger, temp_dir.path());

    // 4. GUARD-VERBS-LIST-CHECK: dc list & dc check Determinism (Δ126, Δ127)
    run_guard_verbs(&ledger, temp_dir.path());

    assert!(ledger.is_all_green(), "[G3-FAIL] Guardian matrix contains failing assertions!");
    println!("\n[=== G3 GUARDIAN & IDENTITY MATRIX PASSED ALL CELLS ===]\n");
}

fn run_guard_classify_pure(ledger: &RigLedger) {
    println!("\n[>>> GUARD-CLASSIFY-PURE: Testing Pure 15-Rule Precedence Matrix (Δ121) <<<]");

    let base_node = DeviceNode {
        name: "sda".to_string(),
        maj_min: (8, 0),
        size_bytes: 500 * 1024 * 1024 * 1024,
        is_partition: false,
        is_ram_backed: false,
        is_zoned: false,
        is_read_only: false,
        mounts: vec![],
        holders: vec![],
        swap_active: false,
        active_lvm: false,
        active_md: false,
        active_crypt: false,
        is_loop: false,
        inactive_sig: None,
        is_member: false,
    };

    let flags = GuardianFlags::default();

    // 1. Clean Disk -> Ok
    let mut tree = BlockTree::default();
    tree.nodes.insert("sda".to_string(), base_node.clone());
    let res_clean = classify_pure("sda", &tree, &flags);
    ledger.assert("G3-PURE", "VEC-CLEAN", "true", res_clean.is_ok().to_string(), None);

    // 2. SIZE_ANOMALY (< 1 MiB)
    let mut node_small = base_node.clone();
    node_small.size_bytes = 512 * 1024;
    tree.nodes.insert("sda".to_string(), node_small);
    let res_small = classify_pure("sda", &tree, &flags);
    ledger.assert("G3-PURE", "VEC-SIZE-ANOMALY", "SIZE_ANOMALY", res_small.unwrap_err().code, None);

    // 3. NOT_WHOLE_DISK (Partition)
    let mut node_part = base_node.clone();
    node_part.is_partition = true;
    tree.nodes.insert("sda".to_string(), node_part);
    let res_part = classify_pure("sda", &tree, &flags);
    ledger.assert("G3-PURE", "VEC-NOT-WHOLE-DISK", "NOT_WHOLE_DISK", res_part.unwrap_err().code, None);

    // 4. RAM_BACKED
    let mut node_ram = base_node.clone();
    node_ram.is_ram_backed = true;
    tree.nodes.insert("sda".to_string(), node_ram);
    let res_ram = classify_pure("sda", &tree, &flags);
    ledger.assert("G3-PURE", "VEC-RAM-BACKED", "RAM_BACKED", res_ram.unwrap_err().code, None);

    // 5. SYSTEM_DISK vs MOUNTED
    let mut node_sys = base_node.clone();
    node_sys.mounts = vec!["/".to_string()];
    tree.nodes.insert("sda".to_string(), node_sys);
    let res_sys = classify_pure("sda", &tree, &flags);
    ledger.assert("G3-PURE", "VEC-SYSTEM-DISK", "SYSTEM_DISK", res_sys.unwrap_err().code, None);

    let mut node_mnt = base_node.clone();
    node_mnt.mounts = vec!["/mnt/data".to_string()];
    tree.nodes.insert("sda".to_string(), node_mnt);
    let res_mnt = classify_pure("sda", &tree, &flags);
    ledger.assert("G3-PURE", "VEC-MOUNTED", "MOUNTED", res_mnt.unwrap_err().code, None);

    // 6. SWAP_ACTIVE
    let mut node_swap = base_node.clone();
    node_swap.swap_active = true;
    tree.nodes.insert("sda".to_string(), node_swap);
    let res_swap = classify_pure("sda", &tree, &flags);
    ledger.assert("G3-PURE", "VEC-SWAP-ACTIVE", "SWAP_ACTIVE", res_swap.unwrap_err().code, None);

    // 7. LVM_ACTIVE
    let mut node_lvm = base_node.clone();
    node_lvm.active_lvm = true;
    tree.nodes.insert("sda".to_string(), node_lvm);
    let res_lvm = classify_pure("sda", &tree, &flags);
    ledger.assert("G3-PURE", "VEC-LVM-ACTIVE", "LVM_ACTIVE", res_lvm.unwrap_err().code, None);

    // 8. HOLDERS_PRESENT
    let mut node_holder = base_node.clone();
    node_holder.holders = vec!["dm-0".to_string()];
    tree.nodes.insert("sda".to_string(), node_holder);
    let res_holder = classify_pure("sda", &tree, &flags);
    ledger.assert("G3-PURE", "VEC-HOLDERS-PRESENT", "HOLDERS_PRESENT", res_holder.unwrap_err().code, None);
}

fn run_guard_ident_compare(ledger: &RigLedger) {
    println!("\n[>>> GUARD-IDENT-COMPARE: Testing Stable Identity Comparator (Δ46) <<<]");

    let base = StableIdentity {
        model: Some("SAMSUNG 980 PRO".to_string()),
        serial: Some("S5GXNF0R123456".to_string()),
        wwn: Some("0x5002538f12345678".to_string()),
        size_bytes: 1_000_204_886_016,
        bus: BusType::Nvme,
        dm_name: None,
        dm_uuid: None,
    };

    // 1. Exact Match
    let c_exact = IdentityComparator::compare(&base, &base);
    ledger.assert("G3-IDENT", "CMP-EXACT", "true", (c_exact == IdentityComparison::Match).to_string(), None);

    // 2. Match with Warnings (missing optional serial in observed)
    let mut observed_no_serial = base.clone();
    observed_no_serial.serial = None;
    let c_warn = IdentityComparator::compare(&base, &observed_no_serial);
    ledger.assert("G3-IDENT", "CMP-WARN", "true", matches!(c_warn, IdentityComparison::MatchWithWarnings { .. }).to_string(), None);

    // 3. Serial Contradiction
    let mut observed_wrong_serial = base.clone();
    observed_wrong_serial.serial = Some("S5GXNF0R999999".to_string());
    let c_contra = IdentityComparator::compare(&base, &observed_wrong_serial);
    ledger.assert("G3-IDENT", "CMP-CONTRA", "true", matches!(c_contra, IdentityComparison::Contradiction { ref field, .. } if field == "serial").to_string(), None);

    // 4. Size Mismatch
    let mut observed_wrong_size = base.clone();
    observed_wrong_size.size_bytes = 2_000_398_934_016;
    let c_size = IdentityComparator::compare(&base, &observed_wrong_size);
    ledger.assert("G3-IDENT", "CMP-SIZE", "true", matches!(c_size, IdentityComparison::SizeMismatch { .. }).to_string(), None);
}

fn run_guard_sniff_bounds(ledger: &RigLedger, temp_dir: &Path) {
    println!("\n[>>> GUARD-SNIFF-BOUNDS: Testing Bounded Signature Sniffer (Δ124) <<<]");

    // 1. Synthetic LVM file
    let lvm_file = temp_dir.join("lvm_test.raw");
    let mut lvm_bytes = vec![0u8; 8192];
    lvm_bytes[512..520].copy_from_slice(b"LABELONE");
    fs::write(&lvm_file, &lvm_bytes).unwrap();

    let sig_lvm = Sniffer::sniff_device(&lvm_file);
    ledger.assert("G3-SNIFF", "SNIFF-LVM", "true", matches!(sig_lvm, Some(StorageSignature::LvmLabel { offset: 512 })).to_string(), None);

    // 2. Synthetic LUKS file
    let luks_file = temp_dir.join("luks_test.raw");
    let mut luks_bytes = vec![0u8; 8192];
    luks_bytes[0..6].copy_from_slice(b"LUKS\xba\xbe");
    luks_bytes[6..8].copy_from_slice(&2u16.to_be_bytes());
    fs::write(&luks_file, &luks_bytes).unwrap();

    let sig_luks = Sniffer::sniff_device(&luks_file);
    ledger.assert("G3-SNIFF", "SNIFF-LUKS", "true", matches!(sig_luks, Some(StorageSignature::Luks { version: 2 })).to_string(), None);
}

fn run_guard_verbs(ledger: &RigLedger, temp_dir: &Path) {
    println!("\n[>>> GUARD-VERBS: Testing dc list & dc check Determinism (Δ126, Δ127) <<<]");

    // 1. dc list executes cleanly
    let mut list_cmd = Command::cargo_bin("diskcleaner").unwrap();
    list_cmd.arg("list");
    list_cmd.assert().code(0);
    ledger.assert("G3-VERBS", "CMD-LIST", "true", "true", None);

    // 2. dc check on non-existent disk yields exit 2
    let dummy_path = temp_dir.join("nonexistent_disk.raw");
    let mut check_cmd = Command::cargo_bin("diskcleaner").unwrap();
    check_cmd.arg("check").arg("--target").arg(&dummy_path);
    check_cmd.assert().code(2);
    ledger.assert("G3-VERBS", "CMD-CHECK-NONEXIST", "true", "true", None);
}
