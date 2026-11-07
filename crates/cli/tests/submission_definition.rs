use serde_json::Value;
use std::process::Command;

#[test]
fn local_submission_errors_precede_engine_work_and_create_no_state() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("profile.json");
    std::fs::write(&config, b"{}").unwrap();
    let request = temp.path().join("invalid.json");
    std::fs::write(
        &request,
        br#"{"cli_request_version":"1.0","model":"x","model":"y"}"#,
    )
    .unwrap();
    for args in [
        vec!["jobs", "submit", "--request", request.to_str().unwrap()],
        vec![
            "jobs",
            "submit",
            "--model",
            "x",
            "--input",
            "mesh=absent.obj",
            "--parameters-json",
            r#"{"x":1,"x":2}"#,
        ],
        vec![
            "run",
            "--detach",
            "--model",
            "x",
            "--input",
            "mesh=absent.obj",
            "--idempotency-key",
            "invalid/key",
        ],
        vec![
            "jobs",
            "submit",
            "--request",
            request.to_str().unwrap(),
            "--model",
            "x",
            "--input",
            "mesh=absent.obj",
        ],
        vec!["jobs", "submit", "--prepare"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dissect3d"))
            .args(&args)
            .arg("--json")
            .env("DISSECT3D_CONFIG_FILE", &config)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["error"]["category"], "usage_error");
        assert!(!temp.path().join("profile.json.state").exists());
    }
}

#[test]
fn request_and_detached_arguments_share_the_offline_validation_path() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("profile.json");
    std::fs::write(&config, b"{}").unwrap();
    for args in [
        vec![
            "jobs",
            "submit",
            "--model",
            "x",
            "--input",
            "mesh=absent.obj",
        ],
        vec![
            "run",
            "--detach",
            "--model",
            "x",
            "--input",
            "mesh=absent.obj",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dissect3d"))
            .args(&args)
            .arg("--json")
            .env("DISSECT3D_CONFIG_FILE", &config)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["accepted"], false);
        assert_eq!(envelope["error"]["category"], "engine_unavailable");
        assert!(!temp.path().join("profile.json.state").exists());
    }
}
