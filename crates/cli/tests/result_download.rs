//! CLI surface, argument validation, offline error handling, and exit-code
//! contract tests for `results` and `storage` commands (`RP-P05`, `CT-CLI-SURFACE`).

use serde_json::Value;
use std::fs;
use std::process::{Command, Output};
use tempfile::TempDir;

const CLI: &str = env!("CARGO_BIN_EXE_dissect3d");

fn run_cli(root: &TempDir, args: &[&str]) -> Output {
    let config = root.path().join("client.json");
    Command::new(CLI)
        .env_clear()
        .args(args)
        .env("DISSECT3D_CONFIG_FILE", &config)
        .env("HOME", root.path())
        .output()
        .expect("launch dissect3d CLI binary")
}

fn json_envelope(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "expected single JSON envelope on stdout: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn results_and_storage_help_work_offline_without_creating_profile_state() {
    let root = TempDir::new().unwrap();
    for args in [
        &["results", "--help"][..],
        &["results", "list", "--help"][..],
        &["results", "show", "--help"][..],
        &["results", "download", "--help"][..],
        &["storage", "--help"][..],
        &["storage", "show", "--help"][..],
    ] {
        let output = run_cli(&root, args);
        assert!(
            output.status.success(),
            "args={args:?} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!root.path().join("client.json").exists());
    assert!(!root.path().join("client.json.state").exists());
}

#[test]
fn results_download_requires_explicit_output_and_rejects_malformed_ids_before_connecting() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("client.json"), "{}").unwrap();
    let dest = root.path().join("out");

    // Missing --output flag is a CLI usage error (exit 2).
    let missing_output = run_cli(
        &root,
        &[
            "--json",
            "results",
            "download",
            "res_11111111111111111111111111111111",
        ],
    );
    assert_eq!(missing_output.status.code(), Some(2));
    let envelope = json_envelope(&missing_output);
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"]["category"], "usage_error");

    // Malformed result IDs fail before touching the destination or engine.
    for args in [
        vec!["--json", "results", "show", "not-a-result-id"],
        vec![
            "--json",
            "results",
            "download",
            "art_11111111111111111111111111111111",
            "--output",
            dest.to_str().unwrap(),
        ],
        vec!["--json", "results", "list", "--limit", "0"],
        vec!["--json", "results", "list", "--limit", "101"],
    ] {
        let output = run_cli(&root, &args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "args={args:?} stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
        let envelope = json_envelope(&output);
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"]["category"], "usage_error");
    }
    assert!(
        !dest.exists(),
        "invalid ID must not create output directory"
    );
}

#[test]
fn run_rejects_combining_detach_with_output() {
    let root = TempDir::new().unwrap();
    let dest = root.path().join("out");
    let output = run_cli(
        &root,
        &[
            "--json",
            "run",
            "--detach",
            "--output",
            dest.to_str().unwrap(),
            "--model",
            "test.mesh-copy@fixture-r2",
            "--input",
            "mesh=input.obj",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    let envelope = json_envelope(&output);
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"]["category"], "usage_error");
}

#[test]
fn unconfigured_results_and_storage_commands_fail_honestly_with_exit_3() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("client.json"), "{}").unwrap();
    let dest = root.path().join("out");

    for (args, expected_cmd) in [
        (vec!["--json", "results", "list"], "results list"),
        (
            vec![
                "--json",
                "results",
                "show",
                "res_11111111111111111111111111111111",
            ],
            "results show",
        ),
        (
            vec![
                "--json",
                "results",
                "download",
                "res_11111111111111111111111111111111",
                "--output",
                dest.to_str().unwrap(),
            ],
            "results download",
        ),
        (vec!["--json", "storage", "show"], "storage show"),
    ] {
        let output = run_cli(&root, &args);
        assert_eq!(
            output.status.code(),
            Some(3),
            "args={args:?} stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
        let envelope = json_envelope(&output);
        assert_eq!(envelope["cli_output_version"], "1.0");
        assert_eq!(envelope["command"], expected_cmd);
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"]["category"], "engine_unavailable");
    }
    assert!(!dest.exists());
}
