#![cfg(unix)]

use dissect3d_platform::{OwnedRoot, RelativePath, RootPurpose};
use serde_json::Value;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Engine(Child);
impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli(profile: &Path, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_dissect3d"))
        .args(args)
        .arg("--json")
        .arg("--non-interactive")
        .env("DISSECT3D_CONFIG_FILE", profile)
        .env_remove("DISSECT3D_OUTPUT")
        .output()
        .unwrap();
    assert!(output.status.success(), "test CLI operation failed");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn lost_opt_in_receipt_replays_the_original_identity_through_native_enrollment() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("engine");
    let profile = temp.path().join("client.json");
    let binary = std::env::var_os("DISSECT3D_TEST_ENGINE").expect("fresh engine binary required");
    let mut engine = Engine(
        Command::new(binary)
            .arg("--data-root")
            .arg(&data)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(root) = OwnedRoot::open(&data, RootPurpose::EngineData)
            && dissect3d_connection::verify_engine(&root, Duration::from_millis(250)).is_ok()
        {
            break;
        }
        assert!(
            engine.0.try_wait().unwrap().is_none(),
            "test engine exited before readiness"
        );
        assert!(Instant::now() < deadline, "test engine readiness deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    cli(
        &profile,
        &[
            "config",
            "set",
            "connection.data_root",
            data.to_str().unwrap(),
        ],
    );
    let first = cli(&profile, &["auth", "setup", "--submission-access"]);
    assert_eq!(first["data"]["replayed"], false);
    let mut state_path = profile.as_os_str().to_os_string();
    state_path.push(".state");
    let state = OwnedRoot::open(Path::new(&state_path), RootPurpose::ClientConfig).unwrap();
    let path = RelativePath::parse("credential.json").unwrap();
    let original = state.read_file(&path, 16_384).unwrap();
    let mut pending: Value = serde_json::from_slice(&original).unwrap();
    // Recreate the exact client-side state left when a committed enrollment's
    // receipt is lost. Engine records and the original secret stay unchanged.
    pending["state"] = Value::String("pending".to_owned());
    state
        .write_atomic(&path, &serde_json::to_vec(&pending).unwrap())
        .unwrap();
    let replay = cli(&profile, &["auth", "setup", "--submission-access"]);
    assert_eq!(replay["data"]["replayed"], true);
    assert_eq!(replay["data"]["client_id"], first["data"]["client_id"]);
    let recovered: Value =
        serde_json::from_slice(&state.read_file(&path, 16_384).unwrap()).unwrap();
    assert_eq!(recovered["state"], "active");
    assert_eq!(recovered["enrollment_id"], pending["enrollment_id"]);
    assert!(recovered["secret_hex"] == pending["secret_hex"]);
    assert_eq!(recovered["submission_access"], true);
}
