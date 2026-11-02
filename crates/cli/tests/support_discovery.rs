use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const CLI: &str = env!("CARGO_BIN_EXE_dissect3d");

#[test]
fn connected_cli_inspects_aliases_selections_runtimes_and_task_bindings() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_DISCOVERY_ENGINE")
        .map(PathBuf::from)
        .expect("build discovery_test_host and set DISSECT3D_TEST_DISCOVERY_ENGINE");
    assert!(engine_path.is_absolute() && engine_path.is_file());

    let isolated = TempDir::new().expect("isolated discovery CLI root");
    let data_root = isolated.path().join("engine");
    let profile = isolated.path().join("profile.json");
    configure(&profile, &data_root, &engine_path);
    let _engine = TestEngineGuard(profile.clone());
    assert_success(&run(&profile, &["engine", "start"]));
    assert_success(&run(&profile, &["auth", "setup"]));

    let selected = run(
        &profile,
        &[
            "models",
            "show",
            "test-current",
            "--task",
            "dissect3d.test.mesh-copy",
            "--task-version",
            "1.0",
            "--runtime",
            "test-cpu",
            "--variant",
            "fixture",
        ],
    );
    let selected = successful_data(&selected);
    assert_eq!(selected["item"]["support_ref"], "test.mesh-copy@fixture-r1");
    assert_eq!(selected["item"]["observations"][0]["scope"], "selection");
    assert_eq!(
        selected["item"]["observations"][0]["selection"]["runtime_ref"],
        "test.cpu@fixture-r1"
    );
    assert_eq!(
        selected["item"]["observations"][0]["selection"]["variant"],
        "fixture"
    );

    let runtime_list = successful_data(&run(&profile, &["runtimes", "list", "--limit", "1"]));
    assert_eq!(runtime_list["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        successful_data(&run(&profile, &["runtimes", "show", "test-cpu"]))["item"]["runtime_ref"],
        "test.cpu@fixture-r1"
    );

    let task_list = successful_data(&run(
        &profile,
        &[
            "tasks",
            "list",
            "--support",
            "test.mask@fixture-r1",
            "--limit",
            "1",
        ],
    ));
    let task_items = task_list["items"].as_array().unwrap();
    assert_eq!(task_items.len(), 1);
    assert_eq!(task_items[0]["support_ref"], "test.mask@fixture-r1");

    let task = successful_data(&run(
        &profile,
        &[
            "tasks",
            "show",
            "dissect3d.test.shared",
            "--task-version",
            "1.0",
            "--support",
            "test.mask@fixture-r1",
        ],
    ));
    assert_eq!(task["item"]["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(
        task["item"]["bindings"][0]["support_ref"],
        "test.mask@fixture-r1"
    );
    assert_eq!(
        task["item"]["bindings"][0]["binding"]["input_schema"]["id"],
        "test.mask"
    );

    let loaded = successful_data(&run(&profile, &["models", "loaded"]));
    assert_eq!(loaded["items"], serde_json::json!([]));
}

fn configure(profile: &Path, data_root: &Path, engine: &Path) {
    assert_success(&run(
        profile,
        &["config", "set", "connection.data_root", path_arg(data_root)],
    ));
    assert_success(&run(
        profile,
        &[
            "config",
            "set",
            "connection.engine_binary",
            path_arg(engine),
        ],
    ));
}

struct TestEngineGuard(PathBuf);

impl Drop for TestEngineGuard {
    fn drop(&mut self) {
        let _ = run(&self.0, &["engine", "stop"]);
    }
}

fn path_arg(path: &Path) -> &str {
    path.to_str().expect("test-owned path is UTF-8")
}

fn run(profile: &Path, args: &[&str]) -> Output {
    let output = Command::new(CLI)
        .args(args)
        .arg("--json")
        .env("DISSECT3D_CONFIG_FILE", profile)
        .env_remove("DISSECT3D_OUTPUT")
        .output()
        .expect("CLI process");
    if output.status.code() == Some(101) {
        let detail = String::from_utf8_lossy(&output.stderr);
        panic!(
            "CLI subprocess panicked during {:?}: {}",
            args,
            detail
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("no panic diagnostic")
        );
    }
    output
}

fn assert_success(output: &Output) {
    let response = successful_data(output);
    assert!(response.is_object());
}

fn successful_data(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(0),
        "CLI command failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("single JSON envelope");
    assert_eq!(envelope["cli_output_version"], "1.0");
    assert_eq!(envelope["ok"], true);
    assert!(envelope["accepted"].is_null());
    envelope["data"].clone()
}
