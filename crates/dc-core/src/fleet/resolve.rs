use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvisoryResolution {
    Unique { path: String, serial: String },
    Absent,
    Ambiguous(Vec<String>),
}

pub struct IdentityResolver;

impl IdentityResolver {
    /// Pure advisory identity-to-path resolution (Δ390, Δ392).
    /// `live_devices` is a slice of `(device_path, device_serial)`.
    pub fn resolve_identity(
        expected_serial: &str,
        live_devices: &[(String, String)],
    ) -> AdvisoryResolution {
        let matching: Vec<_> = live_devices
            .iter()
            .filter(|(_, s)| s == expected_serial)
            .collect();

        match matching.len() {
            0 => AdvisoryResolution::Absent,
            1 => AdvisoryResolution::Unique {
                path: matching[0].0.clone(),
                serial: matching[0].1.clone(),
            },
            _ => AdvisoryResolution::Ambiguous(
                matching.into_iter().map(|(p, _)| p.clone()).collect(),
            ),
        }
    }
}
