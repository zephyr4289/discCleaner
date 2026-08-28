use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildProvenance {
    pub builder_host: String,
    pub target_triple: String,
    pub artifact_hash: String,
}

pub struct ReproducibilityTriangle;

impl ReproducibilityTriangle {
    /// Verify reproducibility triangle: x86 native, x86 cross, and ARM native builds (Δ487).
    pub fn verify_triangle(
        build_x86_cross_1: &BuildProvenance,
        build_x86_cross_2: &BuildProvenance,
        build_arm_native: &BuildProvenance,
    ) -> Result<&'static str, &'static str> {
        if build_x86_cross_1.artifact_hash != build_x86_cross_2.artifact_hash {
            return Err("REPRODUCIBILITY_FAILURE_CROSS_ENVS_DIVERGED");
        }

        if build_x86_cross_1.artifact_hash != build_arm_native.artifact_hash {
            return Err("REPRODUCIBILITY_FAILURE_CROSS_VS_NATIVE_DIVERGED");
        }

        Ok("REPRODUCIBILITY_TRIANGLE_VERIFIED_BYTE_IDENTICAL")
    }
}
