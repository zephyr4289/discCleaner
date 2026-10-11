pub mod client;
pub mod discovery;
pub mod psid;

pub use client::{OpalPurgeClient, OpalRescueSummary};
pub use discovery::{DiscoveryTree, OpalSscType};
pub use psid::PsidSecret;

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn psid_hash_is_stable_and_debug_never_leaks_secret() {
        let psid = PsidSecret::load_from_slice(b"0123456789ABCDEF");
        assert_eq!(
            psid.compute_hash(),
            blake3::hash(b"0123456789ABCDEF").to_hex().to_string()
        );
        let dbg = format!("{:?}", psid);
        assert!(dbg.contains("PsidSecret(hash="));
        assert!(
            !dbg.contains("0123456789ABCDEF"),
            "Debug must never leak the secret"
        );
    }

    #[test]
    fn psid_revert_is_state_gated() {
        // Δ368: PSID revert is a rescue path for LOCKED SEDs only.
        let permit = dc_nvme::PurgePermit::mint("/dev/nvme0n1", "SN-SED", 1724890000);
        let psid = PsidSecret::load_from_slice(b"0123456789ABCDEF");

        // Unlocked drive: refused.
        let refused = OpalPurgeClient::execute_psid_revert(&permit, &psid, false);
        assert_eq!(refused, Err("REVERT_REFUSED_DRIVE_NOT_LOCKED_AT_INTAKE"));

        // Locked drive: rescue proceeds and records only the PSID hash.
        let ok = OpalPurgeClient::execute_psid_revert(&permit, &psid, true).unwrap();
        assert_eq!(ok.target_device, "/dev/nvme0n1");
        assert_eq!(ok.psid_hash, psid.compute_hash());
    }
}
