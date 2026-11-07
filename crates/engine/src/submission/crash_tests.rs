//! Controlled engine-process death on either side of the SQLite commit.
//! Child mode exists only in this Rust test executable, never a product host.

use super::test_support::{Hooks, register};
use dissect3d_platform::{AuthorityLease, OwnedRoot, RelativePath, RootPurpose};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, Command};

const MARKER: &str = "run/private-commit-boundary";

#[test]
fn crash_host_helper() {
    let Some(path) = std::env::var_os("D3_CRASH_TEST_ROOT") else {
        return;
    };
    let path = PathBuf::from(path);
    let tool = PathBuf::from(std::env::var_os("D3_CRASH_TEST_TOOL").unwrap());
    let after = std::env::var("D3_CRASH_TEST_PHASE").unwrap() == "after";
    let root = OwnedRoot::open(&path, RootPurpose::EngineData).unwrap();
    let material = crate::submission_fixture::load_prepared_fixture(&root, &tool).unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    let marker_root = OwnedRoot::open(&path, RootPurpose::EngineData).unwrap();
    let hooks = Arc::new(Hooks::default());
    register(root.path(), &hooks);
    let (entered, release) = hooks.pause_transaction(after);
    let _boundary_thread = std::thread::spawn(move || {
        entered.recv_timeout(Duration::from_secs(30)).unwrap();
        marker_root
            .write_atomic(&RelativePath::parse(MARKER).unwrap(), b"boundary\n")
            .unwrap();
        std::thread::sleep(Duration::from_secs(45));
        let _ = release.send(());
    });
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime
        .block_on(crate::startup::run_engine_with_lease(
            &path,
            root,
            lease,
            Arc::new(material.catalog),
            Some(material.readiness),
        ))
        .unwrap();
}

fn binary(variable: &str, fallback: &str) -> PathBuf {
    let debug = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let path = std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| debug.join(fallback));
    assert!(
        path.is_absolute() && path.is_file(),
        "BLOCKED: build {variable}"
    );
    path
}

fn command(cli: &Path, config: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(cli);
    command.args(args).args(["--json", "--non-interactive"]);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("DISSECT3D_") {
            command.env_remove(key);
        }
    }
    command.env("DISSECT3D_CONFIG_FILE", config);
    command
}

async fn invoke(cli: &Path, config: &Path, args: &[&str], expected: i32) -> Value {
    let output = tokio::time::timeout(Duration::from_secs(20), command(cli, config, args).output())
        .await
        .unwrap()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{:?}",
        value["error"]["category"]
    );
    value
}

async fn ready(root: &Path, child: &mut Child) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "controlled host exited before readiness"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "controlled host readiness deadline"
        );
        let path = root.to_owned();
        let verified = tokio::task::spawn_blocking(move || {
            let owned = OwnedRoot::open(&path, RootPurpose::EngineData).ok()?;
            dissect3d_connection::verify_engine(&owned, Duration::from_secs(1)).ok()
        })
        .await
        .unwrap();
        if verified.is_some_and(|engine| Some(engine.discovery.process.pid) == child.id()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_death_before_and_after_commit_recovers_one_exact_job() {
    let cli = binary("DISSECT3D_TEST_CLI", "dissect3d");
    let tool = binary(
        "DISSECT3D_TEST_SUBMISSION_TOOL",
        "examples/submission_fixture_tool",
    );
    let host = binary(
        "DISSECT3D_TEST_SUBMISSION_ENGINE",
        "examples/submission_test_host",
    );
    for after in [false, true] {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("engine");
        let prepared = Command::new(&tool)
            .args(["prepare", "--data-root"])
            .arg(&root)
            .output()
            .await
            .unwrap();
        assert!(prepared.status.success());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "submission::crash_tests::crash_host_helper",
                "--nocapture",
            ])
            .env("D3_CRASH_TEST_ROOT", &root)
            .env("D3_CRASH_TEST_TOOL", &tool)
            .env(
                "D3_CRASH_TEST_PHASE",
                if after { "after" } else { "before" },
            )
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        ready(&root, &mut child).await;
        let config = root.join("client.json");
        invoke(
            &cli,
            &config,
            &[
                "config",
                "set",
                "connection.data_root",
                root.to_str().unwrap(),
            ],
            0,
        )
        .await;
        invoke(
            &cli,
            &config,
            &[
                "config",
                "set",
                "connection.engine_binary",
                std::env::current_exe().unwrap().to_str().unwrap(),
            ],
            0,
        )
        .await;
        invoke(&cli, &config, &["auth", "setup", "--submission-access"], 0).await;
        let mesh = root.join("source.obj");
        std::fs::write(
            &mesh,
            include_bytes!("../../tests/fixtures/submission/tetrahedron.obj"),
        )
        .unwrap();
        let submission = command(
            &cli,
            &config,
            &[
                "jobs",
                "submit",
                "--model",
                "test.mesh-copy@fixture-r1",
                "--input",
                &format!("mesh={}", mesh.display()),
                "--idempotency-key",
                "crash-key",
            ],
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !root.join(MARKER).is_file() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "commit boundary not reached"
            );
            assert!(child.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Read-only internal persistence inspection, never database edits or a
        // client/worker access path. WAL readers see only committed authority.
        let db = rusqlite::Connection::open_with_flags(
            root.join("metadata.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        for table in [
            "jobs",
            "job_inputs",
            "job_acceptance_events",
            "submission_bindings",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                i64::from(after)
            );
        }
        let committed_resolution: Option<String> = if after {
            Some(
                db.query_row("SELECT resolved_json FROM jobs", [], |row| row.get(0))
                    .unwrap(),
            )
        } else {
            None
        };
        drop(db);
        child.kill().await.unwrap();
        let output = tokio::time::timeout(Duration::from_secs(10), submission.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(output.status.code(), Some(15));
        let uncertain: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(uncertain["accepted"].is_null());
        std::fs::remove_file(mesh).unwrap();
        invoke(
            &cli,
            &config,
            &[
                "config",
                "set",
                "connection.engine_binary",
                host.to_str().unwrap(),
            ],
            0,
        )
        .await;
        let mut restarted = Command::new(&host)
            .arg("--data-root")
            .arg(&root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        ready(&root, &mut restarted).await;
        let before = invoke(&cli, &config, &["jobs", "list"], 0).await;
        assert_eq!(
            before["data"]["items"].as_array().unwrap().len(),
            usize::from(after)
        );
        let recovered = invoke(
            &cli,
            &config,
            &[
                "jobs",
                "recover",
                uncertain["data"]["sub_id"].as_str().unwrap(),
            ],
            0,
        )
        .await;
        assert_eq!(recovered["accepted"], true);
        assert_eq!(recovered["data"]["replayed"], after);
        if after {
            assert_eq!(
                recovered["data"]["job_id"],
                before["data"]["items"][0]["job_id"]
            );
        }
        let replay = invoke(
            &cli,
            &config,
            &[
                "jobs",
                "recover",
                uncertain["data"]["sub_id"].as_str().unwrap(),
            ],
            0,
        )
        .await;
        assert_eq!(replay["data"]["job_id"], recovered["data"]["job_id"]);
        let listed = invoke(&cli, &config, &["jobs", "list"], 0).await;
        assert_eq!(listed["data"]["items"].as_array().unwrap().len(), 1);
        assert_eq!(listed["data"]["items"][0]["acceptance_sequence"], 1);
        let db = rusqlite::Connection::open_with_flags(
            root.join("metadata.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        for table in [
            "jobs",
            "job_inputs",
            "job_acceptance_events",
            "submission_bindings",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        assert_eq!(
            db.query_row("SELECT value FROM job_sequence", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        if let Some(expected) = committed_resolution {
            assert_eq!(
                db.query_row("SELECT resolved_json FROM jobs", [], |row| row
                    .get::<_, String>(0))
                    .unwrap(),
                expected
            );
        }
        drop(db);

        invoke(&cli, &config, &["engine", "stop"], 0).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(10), restarted.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
}
