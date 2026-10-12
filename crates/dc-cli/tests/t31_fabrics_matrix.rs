//! t31 — NVMe-oF fabric session matrix (v0.8.0, Vector 4).
//!
//! The netlink wire format is pinned byte-exactly; URI parsing covers
//! the transport matrix; the CLI refuses unreachable fabrics within its
//! timeout budget; FC topology mapping is validated against sysfs
//! fixtures.

use dc_nvme::fabrics::{
    Attr, FabricTarget, FabricTransport, NVME_CMD_CONNECT, NVME_CMD_DISCONNECT, NVMF_ATTR_KATO,
    NVMF_ATTR_NQN, NVMF_ATTR_TRADDR, NVMF_ATTR_TRANSPORT, NVMF_ATTR_TRSVCID, build_genl_message,
};

#[test]
fn t31_a1_genl_connect_message_is_byte_pinned() {
    let attrs = [
        (NVMF_ATTR_TRANSPORT, Attr::Str("tcp".into())),
        (NVMF_ATTR_TRADDR, Attr::Str("10.0.0.5".into())),
        (NVMF_ATTR_TRSVCID, Attr::Str("4420".into())),
        (
            NVMF_ATTR_NQN,
            Attr::Str("nqn.2014-08.org.example:sub1".into()),
        ),
        (NVMF_ATTR_KATO, Attr::U32(30)),
    ];
    let msg = build_genl_message(0x0023, NVME_CMD_CONNECT, 1, &attrs);
    // nlmsghdr: len = total (u32 LE), type = family, flags 0.
    assert_eq!(&msg[0..4], &(msg.len() as u32).to_le_bytes());
    assert_eq!(&msg[4..6], &0x0023u16.to_le_bytes());
    assert_eq!(&msg[6..8], &0u16.to_le_bytes());
    // genlmsghdr: cmd CONNECT, version 1.
    assert_eq!(msg[16], NVME_CMD_CONNECT);
    assert_eq!(msg[17], 1);
    // First attribute at 20: len 8, type TRANSPORT, payload "tcp\0".
    assert_eq!(&msg[20..22], &8u16.to_le_bytes());
    assert_eq!(&msg[22..24], &NVMF_ATTR_TRANSPORT.to_le_bytes());
    assert_eq!(&msg[24..28], b"tcp\0");
    // Attribute walk finds the KATO u32 payload intact.
    let mut off = 20usize;
    let mut found_kato = None;
    while off + 4 <= msg.len() {
        let len = u16::from_le_bytes([msg[off], msg[off + 1]]) as usize;
        let ty = u16::from_le_bytes([msg[off + 2], msg[off + 3]]);
        if ty == NVMF_ATTR_KATO {
            found_kato = Some(u32::from_le_bytes([
                msg[off + 4],
                msg[off + 5],
                msg[off + 6],
                msg[off + 7],
            ]));
        }
        off += (len + 3) & !3;
    }
    assert_eq!(found_kato, Some(30));
}

#[test]
fn t31_a2_disconnect_message_shape() {
    let target = FabricTarget::parse("nvme+loop:///nqn.2014-08.org.example:l").unwrap();
    let msg = build_genl_message(0x0023, NVME_CMD_DISCONNECT, 1, &target.connect_attrs());
    assert_eq!(msg[16], NVME_CMD_DISCONNECT);
}

#[test]
fn t31_a3_uri_matrix() {
    let t = FabricTarget::parse("nvme+rdma://192.168.100.7:4420/nqn.2014-08.org.x:y").unwrap();
    assert_eq!(t.transport, FabricTransport::Rdma);
    assert_eq!(t.trsvcid, "4420");
    let t = FabricTarget::parse("nvme+tcp://fabric.example.com/nqn.2014-08.org.x:y").unwrap();
    assert_eq!(t.trsvcid, "4420", "default port");
    let t = FabricTarget::parse(
        "nvme+fc://nn-0x200000109b57b1f9:pn-0x100000109b57b1f9/nqn.2014-08.org.x:y",
    )
    .unwrap();
    assert_eq!(t.transport, FabricTransport::Fc);
    assert!(t.traddr.contains("nn-0x"));
    // rejections
    assert!(FabricTarget::parse("nvme+iscsi://h/nqn.x").is_err());
    assert!(FabricTarget::parse("nvme+tcp://h:4420x/nqn.x").is_err());
    assert!(FabricTarget::parse("nvme+tcp://h:4420/not-an-nqn").is_err());
}

#[test]
fn t31_a4_cli_fabrics_list_survives_sandboxes() {
    // `dc fabrics list` reads sysfs; in containers without nvme it prints
    // "no fabric controllers connected" and exits 0 — never a panic.
    let out = assert_cmd::Command::cargo_bin("dc")
        .unwrap()
        .arg("fabrics")
        .arg("list")
        .output()
        .expect("run");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("fabric controller") || text.trim().is_empty() || text.contains("nvme"));
}

#[test]
fn t31_a5_cli_connect_to_unreachable_fabric_fails_within_budget() {
    // 10.255.255.1 with a tight ACK budget: refused quickly, typed error.
    let started = std::time::Instant::now();
    let out = assert_cmd::Command::cargo_bin("dc")
        .unwrap()
        .arg("fabrics")
        .arg("connect")
        .arg("nvme+tcp://10.255.255.1:4420/nqn.2014-08.org.example:nothing")
        .arg("--ack-ms")
        .arg("1500")
        .arg("--ctrl-appear-ms")
        .arg("2000")
        .output()
        .expect("run");
    let elapsed = started.elapsed();
    assert!(!out.status.success(), "unreachable fabric must not succeed");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("fabric") || err.contains("netlink") || err.contains("refus"),
        "typed fabric refusal expected, got: {err}"
    );
    // The fail-safe must be substantially faster than an OS-level TCP
    // timeout (~2 min): our budget governs.
    assert!(
        elapsed < std::time::Duration::from_secs(25),
        "took {elapsed:?}"
    );
}

#[test]
fn t31_a6_fc_topology_mapping() {
    use dc_scsi::fc::{self, FcSysfs};
    struct Fixture;
    impl FcSysfs for Fixture {
        fn read_to_string(&self, path: &str) -> Option<String> {
            match path {
                "/sys/class/fc_host/host3/port_name" => Some("0x100000109b57b1f9".into()),
                "/sys/class/fc_host/host3/node_name" => Some("0x200000109b57b1f9".into()),
                "/sys/class/fc_host/host3/port_state" => Some("Online".into()),
                "/sys/class/fc_host/host3/speed" => Some("16 Gbit".into()),
                _ => None,
            }
        }
        fn read_dir_names(&self, path: &str) -> Vec<String> {
            match path {
                "/sys/class/fc_host" => vec!["host3".into()],
                _ => Vec::new(),
            }
        }
    }
    let inv = fc::scan(&Fixture);
    assert_eq!(inv.hosts.len(), 1);
    assert_eq!(inv.online_hosts().len(), 1);
    assert!(inv.host_by_port_name("pn-0x100000109b57b1f9").is_some());
    assert!(inv.field_lines().iter().any(|(k, _)| k.contains("host3")));
}

#[test]
fn t31_a7_purge_fabric_target_refused_cleanly_when_unreachable() {
    // `dc purge --target nvme+tcp://unreachable/nqn…` must fail with the
    // FABRIC_CONNECT_REFUSED guardian path, not attempt a local device
    // probe of a nonexistent path.
    let out = assert_cmd::Command::cargo_bin("dc")
        .unwrap()
        .arg("purge")
        .arg("--target")
        .arg("nvme+tcp://10.255.255.1:4420/nqn.2014-08.org.example:nothing")
        .arg("--dry-run")
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("fabric") || err.contains("FABRIC"),
        "fabric refusal expected, got: {err}"
    );
}
