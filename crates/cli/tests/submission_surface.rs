use serde_json::Value;
use std::process::Command;

#[test]
fn ordinary_run_rejects_before_opening_inputs_or_creating_profile_state() {
    let temporary = tempfile::tempdir().expect("temporary profile root");
    let profile = temporary.path().join("profile.json");
    let nonexistent_input = temporary.path().join("must-not-be-opened.obj");
    let output = Command::new(env!("CARGO_BIN_EXE_dissect3d"))
        .args([
            "run",
            "--model",
            "test.mesh-copy@fixture-r1",
            "--input",
            &format!("mesh={}", nonexistent_input.display()),
            "--json",
        ])
        .env("DISSECT3D_CONFIG_FILE", &profile)
        .output()
        .expect("launch CLI");

    assert_eq!(output.status.code(), Some(5));
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("one JSON envelope");
    assert_eq!(envelope["command"], "run");
    assert_eq!(envelope["accepted"], false);
    assert_eq!(envelope["error"]["category"], "operation_unavailable");
    assert!(!profile.exists());
    assert!(!std::path::PathBuf::from(format!("{}.state", profile.display())).exists());
}
