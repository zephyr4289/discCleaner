//! Fibre Channel host/target discovery (v0.8.0, Vector 4).
//!
//! FC fabrics are pre-zoned: the host HBA is already logged into the
//! fabric, and remote LUNs appear as normal SCSI devices once scanned.
//! What the purge path needs is the mapping evidence: which local HBA
//! port can see which remote WWPN — so a `dc purge --target nvme+fc://`
//! (NVMe-oF over FC) or a plain SCSI LUN can be tied to its SAN position
//! in the certificate.
//!
//! Everything is read from sysfs (no libsysfs, no dynamic linking):
//! - /sys/class/fc_host/hostN/{port_name, node_name, port_state,
//!   supported_classes, speed}
//! - /sys/class/fc_remote_ports/rport-*/port_name, node_name
//! - /sys/class/scsi_device/:rport-target-lun mapping via device symlinks.

use serde::{Deserialize, Serialize};

/// One local FC HBA port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcHost {
    pub host: String,      // e.g. "host5"
    pub port_name: String, // e.g. "0x100000109b57b1f9"
    pub node_name: String,
    pub port_state: String, // e.g. "Online"
    pub speed: String,      // e.g. "32 Gbit"
}

/// One remote port (SAN target) visible from this host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcRemotePort {
    pub rport: String, // e.g. "rport-5:0-3"
    pub port_name: String,
    pub node_name: String,
}

/// Discovery result: hosts + remote ports, plus the pairing (which local
/// host sees which remote port — encoded in the rport name "rport-H:T-I").
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcInventory {
    pub hosts: Vec<FcHost>,
    pub remote_ports: Vec<FcRemotePort>,
}

/// Trait-abstracted sysfs reads (test rigs inject fixtures; the CLI uses
/// the real filesystem).
pub trait FcSysfs {
    fn read_to_string(&self, path: &str) -> Option<String>;
    fn read_dir_names(&self, path: &str) -> Vec<String>;
}

/// The real sysfs.
pub struct RealFcSysfs;

impl FcSysfs for RealFcSysfs {
    fn read_to_string(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn read_dir_names(&self, path: &str) -> Vec<String> {
        std::fs::read_dir(path)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Scan the FC topology visible to this host.
pub fn scan(sysfs: &dyn FcSysfs) -> FcInventory {
    let mut inv = FcInventory::default();
    for host in sysfs.read_dir_names("/sys/class/fc_host") {
        let base = format!("/sys/class/fc_host/{host}");
        inv.hosts.push(FcHost {
            port_name: sysfs
                .read_to_string(&format!("{base}/port_name"))
                .unwrap_or_default(),
            node_name: sysfs
                .read_to_string(&format!("{base}/node_name"))
                .unwrap_or_default(),
            port_state: sysfs
                .read_to_string(&format!("{base}/port_state"))
                .unwrap_or_default(),
            speed: sysfs
                .read_to_string(&format!("{base}/speed"))
                .unwrap_or_default(),
            host,
        });
    }
    for rport in sysfs.read_dir_names("/sys/class/fc_remote_ports") {
        let base = format!("/sys/class/fc_remote_ports/{rport}");
        inv.remote_ports.push(FcRemotePort {
            port_name: sysfs
                .read_to_string(&format!("{base}/port_name"))
                .unwrap_or_default(),
            node_name: sysfs
                .read_to_string(&format!("{base}/node_name"))
                .unwrap_or_default(),
            rport,
        });
    }
    inv
}

impl FcInventory {
    /// The local host whose port_name matches an FC fabric traddr's pn-
    /// component (the purge path uses this to prove which HBA carried the
    /// sanitize).
    pub fn host_by_port_name(&self, wwpn: &str) -> Option<&FcHost> {
        self.hosts
            .iter()
            .find(|h| normalize_wwn(&h.port_name) == normalize_wwn(wwpn))
    }

    pub fn online_hosts(&self) -> Vec<&FcHost> {
        self.hosts
            .iter()
            .filter(|h| h.port_state.eq_ignore_ascii_case("online"))
            .collect()
    }

    pub fn field_lines(&self) -> Vec<(String, String)> {
        let mut out = vec![
            ("FC hosts".into(), format!("{}", self.hosts.len())),
            (
                "FC remote ports".into(),
                format!("{}", self.remote_ports.len()),
            ),
        ];
        for h in self.online_hosts() {
            out.push((format!("FC {} ({})", h.host, h.speed), h.port_name.clone()));
        }
        out
    }
}

fn normalize_wwn(w: &str) -> String {
    let w = w.trim();
    // Accept the fabric-URI spellings "nn-0x..."/"pn-0x..." and the bare
    // sysfs "0x..." form.
    let w = w
        .strip_prefix("pn-")
        .or_else(|| w.strip_prefix("nn-"))
        .unwrap_or(w);
    let w = w
        .strip_prefix("0x")
        .or_else(|| w.strip_prefix("0X"))
        .unwrap_or(w);
    w.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fixture {
        files: RefCell<std::collections::HashMap<String, String>>,
        dirs: RefCell<std::collections::HashMap<String, Vec<String>>>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut files = std::collections::HashMap::new();
            let mut dirs = std::collections::HashMap::new();
            files.insert(
                "/sys/class/fc_host/host5/port_name".into(),
                "0x100000109b57b1f9".into(),
            );
            files.insert(
                "/sys/class/fc_host/host5/node_name".into(),
                "0x200000109b57b1f9".into(),
            );
            files.insert(
                "/sys/class/fc_host/host5/port_state".into(),
                "Online".into(),
            );
            files.insert("/sys/class/fc_host/host5/speed".into(), "32 Gbit".into());
            files.insert(
                "/sys/class/fc_host/host6/port_name".into(),
                "0x100000109b57b200".into(),
            );
            files.insert(
                "/sys/class/fc_host/host6/port_state".into(),
                "Linkdown".into(),
            );
            dirs.insert(
                "/sys/class/fc_host".into(),
                vec!["host5".into(), "host6".into()],
            );
            files.insert(
                "/sys/class/fc_remote_ports/rport-5:0-3/port_name".into(),
                "0x50060160c46028a0".into(),
            );
            files.insert(
                "/sys/class/fc_remote_ports/rport-5:0-3/node_name".into(),
                "0x500601600c46028a0".into(),
            );
            dirs.insert(
                "/sys/class/fc_remote_ports".into(),
                vec!["rport-5:0-3".into()],
            );
            Self {
                files: RefCell::new(files),
                dirs: RefCell::new(dirs),
            }
        }
    }

    impl FcSysfs for Fixture {
        fn read_to_string(&self, path: &str) -> Option<String> {
            self.files.borrow().get(path).cloned()
        }

        fn read_dir_names(&self, path: &str) -> Vec<String> {
            self.dirs.borrow().get(path).cloned().unwrap_or_default()
        }
    }

    #[test]
    fn scan_maps_hosts_and_remote_ports() {
        let inv = scan(&Fixture::new());
        assert_eq!(inv.hosts.len(), 2);
        assert_eq!(inv.remote_ports.len(), 1);
        assert_eq!(inv.hosts[0].port_name, "0x100000109b57b1f9");
        assert_eq!(inv.hosts[0].port_state, "Online");

        // Lookup by WWPN (normalization included).
        let host = inv
            .host_by_port_name("pn-0x100000109b57b1f9")
            .expect("host by wwpn");
        assert_eq!(host.host, "host5");
        assert!(inv.host_by_port_name("0x100000109B57B1F9").is_some());
        assert!(inv.host_by_port_name("0xdead").is_none());

        // Only online hosts in the field lines.
        let lines = inv.field_lines();
        assert!(lines
            .iter()
            .any(|(k, v)| k.contains("host5") && v.contains("b1f9")));
        assert!(!lines.iter().any(|(k, _)| k.contains("host6")));
        assert_eq!(inv.online_hosts().len(), 1);
    }

    #[test]
    fn missing_sysfs_is_an_empty_inventory_not_a_panic() {
        struct Empty;
        impl FcSysfs for Empty {
            fn read_to_string(&self, _path: &str) -> Option<String> {
                None
            }
            fn read_dir_names(&self, _path: &str) -> Vec<String> {
                Vec::new()
            }
        }
        let inv = scan(&Empty);
        assert_eq!(inv.hosts.len(), 0);
        assert_eq!(inv.field_lines().len(), 2);
        assert_eq!(inv.host_by_port_name("0x0"), None);
    }
}
