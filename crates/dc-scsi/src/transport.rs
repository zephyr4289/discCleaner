use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolRoute {
    NativeScsi,
    SatAta,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScsiSession {
    pub dev_path: String,
    pub protocol_route: ProtocolRoute,
    pub uas_negotiated: bool,
}

impl ScsiSession {
    /// Open block node with runtime verification (strictly refusing sg/bsg character nodes per Δ330).
    pub fn open_block_node(
        path: &str,
        vpd_page_89_present: bool,
        uas_negotiated: bool,
    ) -> Result<Self, &'static str> {
        if path.starts_with("/dev/sg") || path.contains("bsg") {
            return Err("UNCOVERED_DOOR_CHARACTER_NODE_REFUSED");
        }

        let protocol_route = if vpd_page_89_present {
            ProtocolRoute::SatAta // ATA Information VPD page indicates SAT translation
        } else {
            ProtocolRoute::NativeScsi
        };

        Ok(Self {
            dev_path: path.to_string(),
            protocol_route,
            uas_negotiated,
        })
    }

    /// Enforce resid discipline on data-in transfers (Δ331).
    pub fn check_resid(resid_bytes: usize) -> Result<(), &'static str> {
        if resid_bytes > 0 {
            Err("RESID_SHORT_TRANSFER_ERROR")
        } else {
            Ok(())
        }
    }
}
