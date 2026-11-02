#![cfg(unix)]

use dissect3d_api::OperationId;
use rusqlite::Connection;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn native_interrupt_commits_and_completes_internal_shutdown_operation() {
    let directory = TempDir::new().expect("isolated data root");
    let root = directory.path().join("engine");
    let mut engine = Command::new(env!("CARGO_BIN_EXE_dissect3d-engine"))
        .arg("--data-root")
        .arg(&root)
        .spawn()
        .expect("start test engine");
    wait_for_discovery(&root, &mut engine);

    let interrupted = Command::new("kill")
        .arg("-INT")
        .arg(engine.id().to_string())
        .status()
        .expect("send native interrupt");
    assert!(interrupted.success(), "interrupt delivery failed");
    wait_for_exit(&mut engine);

    let database = Connection::open(root.join("metadata.sqlite3")).expect("metadata database");
    let (operation, state, phase): (String, String, String) = database
        .query_row(
            "SELECT operation_id,state,phase FROM internal_shutdowns",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("durable signal operation");
    OperationId::parse(operation).expect("internal operation identity");
    assert_eq!(
        (state.as_str(), phase.as_str()),
        ("succeeded", "shutdown_committed")
    );
}

fn wait_for_discovery(root: &std::path::Path, engine: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let descriptor = root.join("run").join("endpoint.json");
    loop {
        if descriptor.is_file() {
            return;
        }
        if let Some(status) = engine.try_wait().expect("observe engine startup") {
            panic!("engine exited before readiness: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "engine did not publish readiness"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_exit(engine: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if engine
            .try_wait()
            .expect("observe signal shutdown")
            .is_some()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "signal shutdown did not complete"
        );
        thread::sleep(Duration::from_millis(20));
    }
}
