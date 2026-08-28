use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnContext {
    pub plan_path: String,
    pub key_path: Option<String>,
    pub out_dir: String,
}

pub struct ArgvConstructor;

impl ArgvConstructor {
    /// Pure, deterministic child argument vector construction (Δ393).
    pub fn construct_child_argv(
        serial: &str,
        target_path: &str,
        ctx: &SpawnContext,
    ) -> Vec<String> {
        let mut argv = vec![
            "dc".to_string(),
            "execute".to_string(),
            "--target".to_string(),
            target_path.to_string(),
            "--serial-confirm".to_string(),
            serial.to_string(),
            "--plan".to_string(),
            ctx.plan_path.clone(),
            "--out-dir".to_string(),
            ctx.out_dir.clone(),
        ];

        if let Some(ref key) = ctx.key_path {
            argv.push("--operator-key".to_string());
            argv.push(key.clone());
        }

        argv
    }

    /// Compute cryptographic BLAKE3 hash of child argument vector (Δ393).
    pub fn compute_argv_hash(argv: &[String]) -> String {
        let mut hasher = blake3::Hasher::new();
        for arg in argv {
            hasher.update(arg.as_bytes());
            hasher.update(b"\0"); // Delimiter
        }
        hasher.finalize().to_hex().to_string()
    }
}
