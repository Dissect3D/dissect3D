#![cfg(windows)]

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const CLI: &str = env!("CARGO_BIN_EXE_dissect3d");

#[test]
fn isolated_windows_engine_start_reuse_status_and_stop() {
    let engine = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE");
    assert!(engine.is_absolute() && engine.is_file());
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root = isolated.path().join("engine");
    let profile = isolated.path().join("profile.json");
    set_config(
        &profile,
        "connection.data_root",
        data_root.to_str().expect("UTF-8 test path"),
    );
    set_config(
        &profile,
        "connection.engine_binary",
        engine.to_str().expect("UTF-8 binary path"),
    );
    let _guard = EngineGuard(profile.clone());

    let start = run(&profile, &["engine", "start"]);
    assert_success(&start);
    let start: Value = serde_json::from_slice(&start.stdout).expect("start response");
    let instance = start["data"]["instance_id"].as_str().expect("instance id");

    let reuse = run(&profile, &["engine", "start"]);
    assert_success(&reuse);
    let reuse: Value = serde_json::from_slice(&reuse.stdout).expect("reuse response");
    assert_eq!(reuse["data"]["already_running"], true);
    assert_eq!(reuse["data"]["instance_id"], instance);
    assert_success(&run(&profile, &["auth", "setup"]));
    assert_success(&run(&profile, &["engine", "status"]));
    assert_success(&run(&profile, &["engine", "stop"]));
}

struct EngineGuard(std::path::PathBuf);

impl Drop for EngineGuard {
    fn drop(&mut self) {
        let _ = run(&self.0, &["engine", "stop"]);
    }
}

fn set_config(profile: &Path, key: &str, value: &str) {
    assert_success(&run(profile, &["config", "set", key, value]));
}

fn run(profile: &Path, args: &[&str]) -> Output {
    Command::new(CLI)
        .args(args)
        .arg("--json")
        .env("DISSECT3D_CONFIG_FILE", profile)
        .env_remove("DISSECT3D_OUTPUT")
        .output()
        .expect("CLI subprocess")
}

fn assert_success(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("one JSON response");
    assert_eq!(response["ok"], true);
}
