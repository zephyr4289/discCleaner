use dc_core::fleet::{
    AdvisoryResolution, ArgvConstructor, BatchManifest, BatchReconstructor, ChildJournalState,
    FleetJobOutcome, FleetJobRecord, FleetReport, IdentityResolver, SpawnContext,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildSpawnSeam {
    pub slot_id: usize,
    pub serial: String,
    pub constructed_argv: Vec<String>,
    pub constructed_argv_hash: String,
}

pub struct FleetSupervisor {
    pub manifest: BatchManifest,
    pub spawn_ctx: SpawnContext,
    pub is_estate_managed: bool,
}

impl FleetSupervisor {
    pub fn new(manifest: BatchManifest, spawn_ctx: SpawnContext, is_estate_managed: bool) -> Self {
        Self {
            manifest,
            spawn_ctx,
            is_estate_managed,
        }
    }

    /// Prepare child spawn parameters and compute deterministic argv hashes (Δ393).
    pub fn prepare_spawns(
        &self,
        live_devices: &[(String, String)],
    ) -> Result<Vec<ChildSpawnSeam>, String> {
        self.manifest.validate().map_err(|e| e.to_string())?;

        let mut spawns = Vec::new();

        for row in &self.manifest.rows {
            let res = IdentityResolver::resolve_identity(&row.expected_serial, live_devices);
            match res {
                AdvisoryResolution::Unique { path, serial } => {
                    let argv = ArgvConstructor::construct_child_argv(
                        &serial,
                        &path,
                        &self.spawn_ctx,
                    );
                    let hash = ArgvConstructor::compute_argv_hash(&argv);
                    spawns.push(ChildSpawnSeam {
                        slot_id: row.slot_id,
                        serial,
                        constructed_argv: argv,
                        constructed_argv_hash: hash,
                    });
                }
                AdvisoryResolution::Absent => {
                    return Err(format!(
                        "RESOLUTION_FAILURE_ABSENT_DEVICE: Expected serial '{}' not found!",
                        row.expected_serial
                    ));
                }
                AdvisoryResolution::Ambiguous(candidates) => {
                    return Err(format!(
                        "RESOLUTION_FAILURE_AMBIGUOUS: Expected serial '{}' matched multiple paths: {:?}",
                        row.expected_serial, candidates
                    ));
                }
            }
        }

        Ok(spawns)
    }

    /// Verify argv seam: constructed hash must exactly match what child recorded in journal (Δ393).
    pub fn verify_argv_seam(
        constructed_hash: &str,
        child_journal_header_argv_hash: &str,
    ) -> Result<(), &'static str> {
        if constructed_hash == child_journal_header_argv_hash {
            Ok(())
        } else {
            Err("ARGV_SEAM_MISMATCH_INTENT_DIVERGED_FROM_PERCEPTION")
        }
    }
}
