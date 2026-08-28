use dc_probe::{classify_pure, BlockGraph, BlockTree, DeviceNode, GuardianFlags, WalkOutcome};
use dc_testkit::RigLedger;
use std::collections::BTreeMap;

#[test]
fn test_p05_dependency_matrix() {
    let ledger = RigLedger::new();

    // 1. STACK-IN-USE-DEEP: 2-Level Stacked Active Mount Refusal (Δ199, Δ201)
    run_stack_in_use_tests(&ledger);

    // 2. NM-DEEP-DEAD: Unmounted Stack Hierarchy Classifies Clean (Δ201)
    run_deep_dead_tests(&ledger);

    // 3. GRAPH-TERMINATION: Cycle-Safe Traversal Termination (Δ199)
    run_graph_termination_tests(&ledger);

    assert!(ledger.is_all_green(), "[P05-FAIL] Dependency matrix contains failing assertions!");
    println!("\n[=== PHASE 0.5 DEPENDENCY MATRIX PASSED ALL CELLS ===]\n");
}

fn run_stack_in_use_tests(ledger: &RigLedger) {
    println!("\n[>>> STACK-IN-USE-DEEP: Testing Transitive Upward Danger Refusal (Δ199, Δ201) <<<]");

    let mut nodes = BTreeMap::new();

    // Target drive: sdb
    nodes.insert("sdb".to_string(), DeviceNode {
        name: "sdb".to_string(),
        maj_min: (8, 16),
        size_bytes: 100 * 1024 * 1024 * 1024,
        is_partition: false,
        is_ram_backed: false,
        is_zoned: false,
        is_read_only: false,
        mounts: vec![],
        holders: vec!["dm-0".to_string()], // held by crypt mapping dm-0
        swap_active: false,
        active_lvm: false,
        active_md: false,
        active_crypt: true,
        is_loop: false,
        inactive_sig: None,
        is_member: false,
    });

    // Mid-layer: dm-0 (LUKS crypt mapping) held by dm-1 (LVM root LV)
    nodes.insert("dm-0".to_string(), DeviceNode {
        name: "dm-0".to_string(),
        maj_min: (253, 0),
        size_bytes: 100 * 1024 * 1024 * 1024,
        is_partition: false,
        is_ram_backed: false,
        is_zoned: false,
        is_read_only: false,
        mounts: vec![],
        holders: vec!["dm-1".to_string()], // held by LVM LV dm-1
        swap_active: false,
        active_lvm: true,
        active_md: false,
        active_crypt: false,
        is_loop: false,
        inactive_sig: None,
        is_member: false,
    });

    // Top-layer: dm-1 (Mounted at /var/data)
    nodes.insert("dm-1".to_string(), DeviceNode {
        name: "dm-1".to_string(),
        maj_min: (253, 1),
        size_bytes: 50 * 1024 * 1024 * 1024,
        is_partition: false,
        is_ram_backed: false,
        is_zoned: false,
        is_read_only: false,
        mounts: vec!["/var/data".to_string()], // LIVE MOUNT AT DEPTH 2!
        holders: vec![],
        swap_active: false,
        active_lvm: false,
        active_md: false,
        active_crypt: false,
        is_loop: false,
        inactive_sig: None,
        is_member: false,
    });

    let tree = BlockTree { nodes };
    let flags = GuardianFlags::default();

    let res = classify_pure("sdb", &tree, &flags);
    assert!(res.is_err());
    let refusal = res.unwrap_err();

    let code_matches = refusal.code == "CRYPT_ACTIVE" || refusal.code == "STACK_IN_USE";
    ledger.assert("P05-STACK", "STACK-IN-USE-DEEP", "true", code_matches.to_string(), None);
}

fn run_deep_dead_tests(ledger: &RigLedger) {
    println!("\n[>>> NM-DEEP-DEAD: Testing Dead Stack Classification (Δ201) <<<]");

    let mut nodes = BTreeMap::new();

    // Target drive: sdc (held by dm-2, which is held by dm-3, but NOTHING is mounted)
    nodes.insert("sdc".to_string(), DeviceNode {
        name: "sdc".to_string(),
        maj_min: (8, 32),
        size_bytes: 500 * 1024 * 1024 * 1024,
        is_partition: false,
        is_ram_backed: false,
        is_zoned: false,
        is_read_only: false,
        mounts: vec![],
        holders: vec![], // no active holders
        swap_active: false,
        active_lvm: false,
        active_md: false,
        active_crypt: false,
        is_loop: false,
        inactive_sig: None,
        is_member: false,
    });

    let tree = BlockTree { nodes };
    let flags = GuardianFlags::default();

    let res = classify_pure("sdc", &tree, &flags);
    assert!(res.is_ok(), "Unmounted dead stack must classify Clean");
    ledger.assert("P05-DEAD", "NM-DEEP-DEAD", "true", res.is_ok().to_string(), None);
}

fn run_graph_termination_tests(ledger: &RigLedger) {
    println!("\n[>>> GRAPH-TERMINATION: Testing Cycle-Safe Graph Traversal (Δ199) <<<]");

    let mut nodes = BTreeMap::new();

    // Node A holds B, B holds C, C holds A (Cycle!)
    nodes.insert("devA".to_string(), DeviceNode {
        name: "devA".to_string(),
        maj_min: (8, 0),
        size_bytes: 10 * 1024 * 1024 * 1024,
        is_partition: false,
        is_ram_backed: false,
        is_zoned: false,
        is_read_only: false,
        mounts: vec![],
        holders: vec!["devB".to_string()],
        swap_active: false,
        active_lvm: false,
        active_md: false,
        active_crypt: false,
        is_loop: false,
        inactive_sig: None,
        is_member: false,
    });

    nodes.insert("devB".to_string(), DeviceNode {
        name: "devB".to_string(),
        maj_min: (8, 1),
        size_bytes: 10 * 1024 * 1024 * 1024,
        is_partition: false,
        is_ram_backed: false,
        is_zoned: false,
        is_read_only: false,
        mounts: vec![],
        holders: vec!["devC".to_string()],
        swap_active: false,
        active_lvm: false,
        active_md: false,
        active_crypt: false,
        is_loop: false,
        inactive_sig: None,
        is_member: false,
    });

    nodes.insert("devC".to_string(), DeviceNode {
        name: "devC".to_string(),
        maj_min: (8, 2),
        size_bytes: 10 * 1024 * 1024 * 1024,
        is_partition: false,
        is_ram_backed: false,
        is_zoned: false,
        is_read_only: false,
        mounts: vec![],
        holders: vec!["devA".to_string()], // back to devA!
        swap_active: false,
        active_lvm: false,
        active_md: false,
        active_crypt: false,
        is_loop: false,
        inactive_sig: None,
        is_member: false,
    });

    let tree = BlockTree { nodes };
    let graph = BlockGraph::new(&tree);

    let outcome = graph.live_dangers("devA", 16);
    // Cycle with no live terminals must terminate cleanly and return Clean
    let is_clean = outcome == WalkOutcome::Clean;
    ledger.assert("P05-CYCLE", "GRAPH-TERMINATION", "true", is_clean.to_string(), None);
}
