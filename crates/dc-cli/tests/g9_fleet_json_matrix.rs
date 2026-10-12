//! Fleet JSON envelope integration matrix (v0.9.0, Phase 3).
//!
//! `--json` is the automation contract for Ansible / SaltStack / k8s
//! DaemonSet agents: stdout carries EXACTLY ONE machine-parsable
//! envelope, the exit code preserves the documented bucket map, and the
//! human-readable output never contaminates the harvest channel.

use assert_cmd::Command;
use serde_json::Value;

fn dc() -> Command {
    Command::cargo_bin("dc").unwrap()
}

#[test]
fn json_list_emits_exactly_one_parseable_envelope() {
    let out = dc().arg("--json").arg("list").output().unwrap();
    assert!(out.status.success(), "list must succeed: {}", out.status);

    // THE contract: stdout is a single JSON document — no interleaved
    // human text, no progress bars, no partial lines.
    let stdout = String::from_utf8(out.stdout).expect("envelope must be UTF-8");
    let envelope: Value =
        serde_json::from_str(&stdout).expect("stdout must be exactly one JSON document");
    assert_eq!(envelope["schema"], "dc.fleet/v1");
    assert_eq!(envelope["tool"], "diskcleaner");
    assert_eq!(envelope["command"], "list");
    assert_eq!(envelope["status"], "ok");
    assert_eq!(envelope["exit_code"], 0);
    assert!(envelope["duration_ms"].is_u64());
    // `list` attaches the structured inventory.
    let data = &envelope["data"];
    assert!(data.is_object(), "list must carry a data payload");
    assert!(data["device_count"].is_u64());
    assert!(data["devices"].is_array());
    // Every device entry is fully-populated machine-readable identity.
    for dev in data["devices"].as_array().unwrap() {
        assert!(dev["dev_path"].is_string());
        assert!(dev["bus"].is_string());
        assert!(dev["size_bytes"].is_u64());
    }
}

#[test]
fn json_human_output_is_relocated_to_stderr() {
    let out = dc().arg("--json").arg("profiles").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let envelope: Value = serde_json::from_str(&stdout).expect("one JSON doc on stdout");
    assert_eq!(envelope["status"], "ok");
    // The human catalog is NOT on stdout...
    assert!(!stdout.contains("NIST"));
    // ...but an operator still sees it on stderr.
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("NIST") || stderr.contains("profile"),
        "human-readable catalog must remain visible on stderr"
    );
}

#[test]
fn json_error_envelope_keeps_machine_code_and_exit_bucket() {
    // A nonexistent plan file: USAGE bucket (8), machine-code USAGE.
    let out = dc()
        .arg("--json")
        .arg("plan")
        .arg("--target")
        .arg("/dev/null")
        .arg("--profile")
        .arg("nonexistent-profile-name")
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let envelope: Value = serde_json::from_str(&stdout)
        .expect("error paths must still emit exactly one JSON document");
    assert_eq!(envelope["status"], "error");
    assert_eq!(envelope["exit_code"], code);
    assert!(code != 0, "a failure must keep a nonzero exit code");
    assert!(
        envelope["error"]["code"].is_string(),
        "error.code must be a machine-readable class"
    );
    assert!(envelope["error"]["message"].is_string());
    assert_eq!(envelope["data"], Value::Null);
}

#[test]
fn json_flag_is_available_on_every_subcommand() {
    // Spot-check that the global flag parses alongside deep subcommands.
    let out = dc()
        .arg("--json")
        .arg("key")
        .arg("inspect")
        .arg("/nonexistent/blob.json")
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let envelope: Value =
        serde_json::from_str(&stdout).expect("single envelope even for nested subcommands");
    assert_eq!(envelope["command"], "key");
    assert_eq!(envelope["status"], "error");
    // USAGE bucket for a missing file (StdIo) — machine class present.
    assert!(envelope["error"]["code"].is_string());
}
