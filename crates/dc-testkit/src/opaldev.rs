use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpalLifecycle {
    Manufactured,
    Owned,
    Locked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PsidAuthResult {
    Success,
    WrongDevice { expected: String, actual: String },
    PsidRejected,
}

pub struct OpalFrameParser;

impl OpalFrameParser {
    /// Strict nested bounds validation across ComPacket, Packet, and SubPacket (Δ361).
    pub fn validate_frame_bounds(
        com_packet_len: usize,
        packet_len: usize,
        subpacket_len: usize,
    ) -> Result<(), &'static str> {
        if packet_len > com_packet_len {
            return Err("PACKET_LENGTH_EXCEEDS_COMPACKET");
        }
        if subpacket_len > packet_len {
            return Err("SUBPACKET_LENGTH_EXCEEDS_PACKET");
        }
        Ok(())
    }
}

pub struct OpalDevMock {
    pub serial: String,
    pub psid_secret: String,
    pub lifecycle: OpalLifecycle,
    pub shadow_mbr_enabled: bool,
    pub locking_ranges_configured: bool,
}

impl OpalDevMock {
    pub fn new(serial: &str, psid: &str) -> Self {
        Self {
            serial: serial.to_string(),
            psid_secret: psid.to_string(),
            lifecycle: OpalLifecycle::Manufactured,
            shadow_mbr_enabled: false,
            locking_ranges_configured: false,
        }
    }

    /// Stage the hostage scenario: take ownership, configure locking, and lock the drive (Δ357).
    pub fn stage_hostage(&mut self) {
        self.lifecycle = OpalLifecycle::Owned;
        self.locking_ranges_configured = true;
        self.shadow_mbr_enabled = true;
        self.lifecycle = OpalLifecycle::Locked;
    }

    /// Execute zero-repair PSID revert with identity-check-first disambiguation (Δ358).
    pub fn revert_with_psid(
        &mut self,
        target_serial: &str,
        candidate_psid: &str,
    ) -> PsidAuthResult {
        // Step 1: Disambiguation - Check device identity FIRST
        if target_serial != self.serial {
            return PsidAuthResult::WrongDevice {
                expected: target_serial.to_string(),
                actual: self.serial.clone(),
            };
        }

        // Step 2: Authenticate PSID
        if candidate_psid != self.psid_secret {
            return PsidAuthResult::PsidRejected;
        }

        // Step 3: RevertSP - Reset to manufactured state, regenerate MEK
        self.lifecycle = OpalLifecycle::Manufactured;
        self.locking_ranges_configured = false;
        self.shadow_mbr_enabled = false;

        PsidAuthResult::Success
    }

    /// Obtain post-revert state attestation with spec-inferred MEK vocabulary (Δ360).
    pub fn get_post_revert_attestation(&self) -> Result<&'static str, &'static str> {
        if self.lifecycle == OpalLifecycle::Manufactured && !self.locking_ranges_configured {
            Ok("SPEC_INFERRED_STATE_ATTESTED_MEK_REGENERATED")
        } else {
            Err("DRIVE_NOT_IN_MANUFACTURED_STATE")
        }
    }
}
