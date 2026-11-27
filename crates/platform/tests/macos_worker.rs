//! Native-only macOS candidate checks. Cross-checking does not execute these.
#![cfg_attr(
    target_os = "macos",
    expect(
        clippy::unwrap_used,
        reason = "integration test helpers; engineering.md Rule 6 permits unwrap in test setup"
    )
)]
#![cfg(target_os = "macos")]
use dissect3d_platform::{CleanupFault, WorkerCommand, WorkerProcess};
use std::time::{Duration, Instant};

#[test]
fn mac_worker_helper() {
    let Some(entry) = std::env::var_os("D3D_MAC_ENTRY") else {
        return;
    };
    if std::env::var_os("D3D_MAC_FORK").is_some() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "mac_leaf_helper", "--nocapture"])
            .spawn()
            .unwrap();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    std::fs::write(entry, b"entered").unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn mac_leaf_helper() {
    if std::env::var_os("D3D_MAC_ENTRY").is_some() {
        loop {
            std::thread::park();
        }
    }
}

fn launch(entry: &std::path::Path, fork: bool) -> WorkerProcess {
    let mut command = WorkerCommand::new(std::env::current_exe().unwrap());
    command.args = vec![
        "--exact".into(),
        "mac_worker_helper".into(),
        "--nocapture".into(),
    ];
    command.guardian = Some(env!("CARGO_BIN_EXE_dissect3d-worker-guardian").into());
    command.environment = vec![("D3D_MAC_ENTRY".into(), entry.as_os_str().into())];
    if fork {
        command
            .environment
            .push(("D3D_MAC_FORK".into(), "1".into()));
    }
    WorkerProcess::launch(command, [41; 16]).unwrap()
}

fn entered(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn observed_no_fork_leader_can_produce_cleanup_confirmation() {
    let temp = tempfile::tempdir().unwrap();
    let entry = temp.path().join("entry");
    let mut worker = launch(&entry, false);
    entered(&entry);
    assert!(
        worker
            .terminate_tree(Instant::now() + Duration::from_secs(5))
            .is_ok()
    );
}

#[test]
fn forked_descendants_cannot_produce_unproven_cleanup_confirmation() {
    let temp = tempfile::tempdir().unwrap();
    let entry = temp.path().join("entry");
    let mut worker = launch(&entry, true);
    entered(&entry);
    assert!(matches!(
        worker.terminate_tree(Instant::now() + Duration::from_secs(5)),
        Err(CleanupFault::OwnershipLost)
    ));
}
