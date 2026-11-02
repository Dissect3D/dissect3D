use std::fs;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

fn run(root: &TempDir, args: &[&str], output: Option<&str>) -> Output {
    let config = root.path().join("client.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dissect3d"));
    command
        .env_clear()
        .args(args)
        .env("DISSECT3D_CONFIG_FILE", &config)
        .env("HOME", root.path());
    if let Some(value) = output {
        command.env("DISSECT3D_OUTPUT", value);
    } else {
        command.env_remove("DISSECT3D_OUTPUT");
    }
    command.output().expect("launch CLI test binary")
}

fn json(stdout: &[u8]) -> Value {
    serde_json::from_slice(stdout).expect("one JSON response on stdout")
}

#[test]
fn help_and_version_work_without_config_or_engine() {
    let root = TempDir::new().expect("temporary profile");
    let help = run(&root, &["--help"], None);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));
    let version = run(&root, &["--json", "--version"], None);
    assert!(version.status.success());
    assert_eq!(json(&version.stdout)["data"]["cli_output_version"], "1.0");
    assert!(!root.path().join("client.json").exists());
}

#[test]
fn unconfigured_read_commands_report_unverified_connection_state() {
    let root = TempDir::new().expect("isolated alternate profile");
    fs::write(root.path().join("client.json"), "{}").expect("available empty config");
    for (args, status) in [
        (&["--json", "engine", "status"][..], "unavailable"),
        (&["--json", "engine", "info"][..], "unavailable"),
        (&["--json", "auth", "status"][..], "unverified"),
    ] {
        let output = run(&root, args, None);
        assert_eq!(
            output.status.code(),
            Some(3),
            "args={args:?} stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let response = json(&output.stdout);
        assert_eq!(response["error"]["category"], "engine_unavailable");
        assert_eq!(response["data"]["status"], status);
        assert_eq!(response["data"]["detail"], "missing_connection");
    }
    assert!(!root.path().join("client.json.state").exists());
}

#[test]
fn offline_config_does_not_connect_to_an_ambient_engine_url() {
    use std::net::TcpListener;

    let root = TempDir::new().expect("temporary profile");
    let listener = TcpListener::bind("127.0.0.1:0").expect("local connection sentinel");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let endpoint = format!("http://{}", listener.local_addr().expect("bound address"));
    let config = root.path().join("client.json");
    fs::write(&config, "{}").expect("write isolated config");
    #[cfg(unix)]
    let launch_marker = {
        use std::os::unix::fs::PermissionsExt;

        let script = root.path().join("engine-canary");
        let marker = root.path().join("engine-was-launched");
        fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .expect("write engine canary");
        let mut permissions = fs::metadata(&script)
            .expect("engine canary metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&script, permissions).expect("make canary executable");
        assert!(
            Command::new(&script)
                .status()
                .expect("check canary")
                .success()
        );
        fs::remove_file(&marker).expect("reset canary marker");
        (script, marker)
    };
    #[cfg(unix)]
    let engine_binary = launch_marker.0.clone();
    #[cfg(not(unix))]
    let engine_binary = root.path().join("missing-engine");
    let result = Command::new(env!("CARGO_BIN_EXE_dissect3d"))
        .env_clear()
        .args(["--json", "config", "show"])
        .env("DISSECT3D_CONFIG_FILE", config)
        .env("DISSECT3D_ENGINE_URL", endpoint)
        .env("DISSECT3D_ENGINE_BINARY", engine_binary)
        .output()
        .expect("launch CLI test binary");
    assert!(result.status.success());
    assert!(matches!(
        listener.accept().map(|_| ()),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    #[cfg(unix)]
    assert!(!launch_marker.1.exists());
}

#[test]
fn config_crud_and_precedence_preserve_sources() {
    let root = TempDir::new().expect("temporary profile");
    let set = run(&root, &["--json", "config", "set", "output", "json"], None);
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );
    let stored: Value = serde_json::from_slice(
        &fs::read(root.path().join("client.json")).expect("written preferences"),
    )
    .expect("valid config JSON");
    assert_eq!(stored["preferences"]["output"], "json");

    let show = run(&root, &["config", "show"], Some("human"));
    assert!(show.status.success());
    let output = String::from_utf8_lossy(&show.stdout);
    assert!(output.contains("output=human"));
    assert!(output.contains("source=environment"));

    let stored_show = run(&root, &["config", "show"], None);
    assert!(stored_show.status.success());
    let response = json(&stored_show.stdout);
    assert_eq!(response["data"]["effective"]["output"]["value"], "json");
    assert_eq!(
        response["data"]["effective"]["output"]["source"],
        "configuration"
    );

    let get = run(&root, &["config", "get", "output"], None);
    assert_eq!(json(&get.stdout)["data"]["value"], "json");
    assert_eq!(json(&get.stdout)["data"]["source"], "configuration");

    let unset = run(&root, &["--json", "config", "unset", "output"], None);
    assert!(unset.status.success());
    let stored: Value = serde_json::from_slice(
        &fs::read(root.path().join("client.json")).expect("updated preferences"),
    )
    .expect("valid config JSON");
    assert!(stored["preferences"].get("output").is_none());
    let defaults = run(&root, &["config", "show"], None);
    assert!(defaults.status.success());
    assert!(String::from_utf8_lossy(&defaults.stdout).contains("output=human source=default"));
}

#[test]
fn config_set_enforces_numeric_bounds_and_allows_staged_credential_references() {
    let root = TempDir::new().expect("temporary profile");
    let invalid = run(
        &root,
        &["--json", "config", "set", "read_attempts", "4"],
        None,
    );
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!root.path().join("client.json").exists());

    let credential = root.path().join("client.token");
    let set_credential = run(
        &root,
        &[
            "--json",
            "config",
            "set",
            "connection.credential_file",
            credential.to_str().expect("test path is UTF-8"),
        ],
        None,
    );
    assert!(set_credential.status.success());
    let installation = run(
        &root,
        &[
            "--json",
            "config",
            "set",
            "connection.installation_id",
            "ins_0123456789abcdef0123456789abcdef",
        ],
        None,
    );
    assert!(installation.status.success());
    let config: Value = serde_json::from_slice(
        &fs::read(root.path().join("client.json")).expect("written connection references"),
    )
    .expect("valid config JSON");
    assert_eq!(
        config["connection"]["credential_file"],
        credential.to_string_lossy().as_ref()
    );
    assert_eq!(
        config["connection"]["installation_id"],
        "ins_0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn arguments_override_environment_and_configuration() {
    let root = TempDir::new().expect("temporary profile");
    fs::write(
        root.path().join("client.json"),
        r#"{"preferences":{"output":"human","connect_timeout_ms":250}}"#,
    )
    .expect("write config");
    let result = run(
        &root,
        &["config", "show", "--json", "--connect-timeout-ms", "500"],
        Some("human"),
    );
    assert!(result.status.success());
    let response = json(&result.stdout);
    assert_eq!(response["data"]["effective"]["output"]["value"], "json");
    assert_eq!(
        response["data"]["effective"]["output"]["source"],
        "arguments"
    );
    assert_eq!(
        response["data"]["effective"]["connect_timeout_ms"]["value"],
        500
    );
    assert_eq!(
        response["data"]["effective"]["connect_timeout_ms"]["source"],
        "arguments"
    );
}

#[test]
fn start_timeout_precedence_reports_default_file_environment_and_argument_sources() {
    let root = TempDir::new().expect("temporary profile");
    fs::write(
        root.path().join("client.json"),
        r#"{"preferences":{"start_timeout_ms":3000}}"#,
    )
    .expect("write config");
    let config = root.path().join("client.json");
    let run = |env_value: Option<&str>, args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dissect3d"));
        command
            .env_clear()
            .args(args)
            .env("DISSECT3D_CONFIG_FILE", &config)
            .env("HOME", root.path())
            .env("DISSECT3D_OUTPUT", "json");
        if let Some(value) = env_value {
            command.env("DISSECT3D_START_TIMEOUT_MS", value);
        }
        command.output().expect("launch CLI config query")
    };

    let file = run(None, &["config", "show"]);
    let file: Value = serde_json::from_slice(&file.stdout).expect("file preferences");
    assert_eq!(file["data"]["effective"]["start_timeout_ms"]["value"], 3000);
    assert_eq!(
        file["data"]["effective"]["start_timeout_ms"]["source"],
        "configuration"
    );

    let environment = run(Some("2000"), &["config", "show"]);
    let environment: Value =
        serde_json::from_slice(&environment.stdout).expect("environment preferences");
    assert_eq!(
        environment["data"]["effective"]["start_timeout_ms"]["value"],
        2000
    );
    assert_eq!(
        environment["data"]["effective"]["start_timeout_ms"]["source"],
        "environment"
    );

    let argument = run(
        Some("2000"),
        &["--start-timeout-ms", "1000", "config", "show"],
    );
    let argument: Value = serde_json::from_slice(&argument.stdout).expect("argument preferences");
    assert_eq!(
        argument["data"]["effective"]["start_timeout_ms"]["value"],
        1000
    );
    assert_eq!(
        argument["data"]["effective"]["start_timeout_ms"]["source"],
        "arguments"
    );

    let default_root = TempDir::new().expect("default profile");
    let default_config = default_root.path().join("client.json");
    fs::write(&default_config, "{}").expect("write default-value profile");
    let mut default = Command::new(env!("CARGO_BIN_EXE_dissect3d"));
    let default = default
        .env_clear()
        .args(["--json", "config", "show"])
        .env("DISSECT3D_CONFIG_FILE", default_config)
        .env("HOME", default_root.path())
        .env("DISSECT3D_OUTPUT", "json")
        .output()
        .expect("launch default config query");
    let default: Value = serde_json::from_slice(&default.stdout).expect("default preferences");
    assert_eq!(
        default["data"]["effective"]["start_timeout_ms"]["value"],
        15000
    );
    assert_eq!(
        default["data"]["effective"]["start_timeout_ms"]["source"],
        "default"
    );
}

#[test]
fn malformed_and_unknown_config_are_usage_errors() {
    let root = TempDir::new().expect("temporary profile");
    fs::write(root.path().join("client.json"), "{\"unexpected\":1}").expect("write invalid config");
    let result = run(&root, &["--json", "config", "show"], None);
    assert_eq!(result.status.code(), Some(2));
    let response = json(&result.stdout);
    assert_eq!(response["ok"], false);
    assert_eq!(response["accepted"], Value::Null);
    assert!(!String::from_utf8_lossy(&result.stderr).contains("unexpected"));
}

#[test]
fn unknown_nested_preferences_and_missing_explicit_config_are_usage_errors() {
    let root = TempDir::new().expect("temporary profile");
    fs::write(
        root.path().join("client.json"),
        r#"{"preferences":{"unrecognized":true}}"#,
    )
    .expect("write config with unknown preference");
    let unknown = run(&root, &["--json", "config", "show"], None);
    assert_eq!(unknown.status.code(), Some(2));
    assert_eq!(json(&unknown.stdout)["ok"], false);

    let missing = TempDir::new().expect("second profile");
    let missing_config = missing.path().join("missing.json");
    let result = Command::new(env!("CARGO_BIN_EXE_dissect3d"))
        .env_clear()
        .args(["--json", "config", "show"])
        .env("DISSECT3D_CONFIG_FILE", &missing_config)
        .output()
        .expect("launch CLI test binary");
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(json(&result.stdout)["ok"], false);
}

#[test]
fn json_usage_errors_emit_one_response_and_keep_diagnostics_on_stderr() {
    let root = TempDir::new().expect("temporary profile");
    let result = run(&root, &["--json", "not-a-command"], None);
    assert_eq!(result.status.code(), Some(2));
    let response = json(&result.stdout);
    assert_eq!(response["ok"], false);
    assert_eq!(response["accepted"], Value::Null);
    assert!(response.get("job_id").is_none());
    assert!(!String::from_utf8_lossy(&result.stderr).is_empty());
}
