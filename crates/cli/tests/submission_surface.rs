#![expect(
    clippy::expect_used,
    reason = "integration test harness; engineering.md Rule 9 allows expect in test setup"
)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const CLI: &str = env!("CARGO_BIN_EXE_dissect3d");

struct EngineStopGuard {
    profile: PathBuf,
}

impl Drop for EngineStopGuard {
    fn drop(&mut self) {
        let _ = Command::new(CLI)
            .args(["--json", "engine", "stop"])
            .env("DISSECT3D_CONFIG_FILE", &self.profile)
            .output();
    }
}

fn run_cli(profile: &Path, args: &[&str]) -> std::process::Output {
    Command::new(CLI)
        .args(args)
        .env("DISSECT3D_CONFIG_FILE", profile)
        .output()
        .expect("launch CLI")
}

#[test]
fn foreground_run_against_normal_engine_exits_5_without_opening_inputs_or_creating_submission_records()
 {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE to its absolute path");
    assert!(engine_path.is_absolute() && engine_path.is_file());

    let temporary = TempDir::new().expect("temporary profile root");
    let data_root = temporary.path().join("engine");
    let profile = temporary.path().join("profile.json");

    let set_root = run_cli(
        &profile,
        &[
            "--json",
            "config",
            "set",
            "connection.data_root",
            data_root.to_str().expect("utf8 data_root"),
        ],
    );
    assert_eq!(set_root.status.code(), Some(0));
    let set_bin = run_cli(
        &profile,
        &[
            "--json",
            "config",
            "set",
            "connection.engine_binary",
            engine_path.to_str().expect("utf8 engine_binary"),
        ],
    );
    assert_eq!(set_bin.status.code(), Some(0));

    let started = run_cli(&profile, &["--json", "engine", "start"]);
    assert_eq!(
        started.status.code(),
        Some(0),
        "engine start failed: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let _stop_guard = EngineStopGuard {
        profile: profile.clone(),
    };

    let enrolled = run_cli(&profile, &["--json", "auth", "setup"]);
    assert_eq!(
        enrolled.status.code(),
        Some(0),
        "auth setup failed: {}",
        String::from_utf8_lossy(&enrolled.stderr)
    );

    let nonexistent_input = temporary.path().join("must-not-be-opened.obj");
    let output = run_cli(
        &profile,
        &[
            "--json",
            "run",
            "--model",
            "test.mesh-copy@fixture-r2",
            "--input",
            &format!("mesh={}", nonexistent_input.display()),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(5),
        "expected exit 5 against normal engine; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("one JSON envelope");
    assert_eq!(envelope["command"], "run");
    assert_eq!(envelope["accepted"], false);
    assert_eq!(envelope["error"]["category"], "operation_unavailable");
    let submissions_dir = PathBuf::from(format!("{}.state", profile.display())).join("submissions");
    assert!(
        !submissions_dir.exists(),
        "refused foreground run must not create submissions/ records"
    );
}
