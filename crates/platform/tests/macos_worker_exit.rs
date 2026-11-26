//! 2026-11-26 regression (Stage B F2): a worker that exits on its own before
//! the lifeline closes is an unreaped zombie leader when the Darwin guardian
//! signals its group. Darwin reports EPERM, not ESRCH, for a zombie-only group,
//! and the guardian reported FAULT even though nothing forked. These cases end
//! with the worker already exited; a fork still forbids a closure witness.
//! Native-only: cross-checking compiles this target empty.
#![cfg(target_os = "macos")]
use dissect3d_platform::{CleanupFault, WorkerCommand, WorkerProcess, wait_for_process_exit};
use std::time::{Duration, Instant};

const ENTRY_ENV: &str = "D3D_EXIT_ENTRY";
const FORK_ENV: &str = "D3D_EXIT_FORK";

/// Worker entry: optionally forks and reaps a short-lived child, records that
/// it ran, then exits voluntarily. A no-op in a normal test run.
#[test]
fn voluntary_exit_worker_helper() {
    let Some(entry) = std::env::var_os(ENTRY_ENV) else {
        return;
    };
    if std::env::var_os(FORK_ENV).is_some() {
        let status = std::process::Command::new("/usr/bin/true")
            .status()
            .unwrap();
        assert!(status.success());
    }
    std::fs::write(entry, b"entered").unwrap();
    std::process::exit(0);
}

fn launch(entry: &std::path::Path, fork: bool) -> WorkerProcess {
    let mut command = WorkerCommand::new(std::env::current_exe().unwrap());
    command.args = vec![
        "--exact".into(),
        "voluntary_exit_worker_helper".into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
    ];
    command.guardian = Some(env!("CARGO_BIN_EXE_dissect3d-worker-guardian").into());
    command.environment = vec![(ENTRY_ENV.into(), entry.as_os_str().into())];
    if fork {
        command.environment.push((FORK_ENV.into(), "1".into()));
    }
    WorkerProcess::launch(command, [43; 16]).unwrap()
}

/// Launch, then wait until the worker has recorded entry and its exit is
/// observed, so the guardian's group signal meets a zombie-only group.
fn exited_worker(fork: bool) -> (tempfile::TempDir, WorkerProcess) {
    let temp = tempfile::tempdir().unwrap();
    let entry = temp.path().join("entry");
    let worker = launch(&entry, fork);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !entry.exists() {
        assert!(Instant::now() < deadline, "worker never entered");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        wait_for_process_exit(&worker.identity().process, Duration::from_secs(10)).unwrap(),
        "worker did not exit voluntarily"
    );
    (temp, worker)
}

#[test]
fn a_voluntarily_exited_leader_that_never_forked_is_confirmed_clean() {
    let (_temp, mut worker) = exited_worker(false);
    let outcome = worker.terminate_tree(Instant::now() + Duration::from_secs(5));
    assert!(outcome.is_ok(), "{:?}", outcome.err());
}

#[test]
fn a_voluntarily_exited_leader_that_forked_stays_unconfirmed() {
    let (_temp, mut worker) = exited_worker(true);
    assert!(matches!(
        worker.terminate_tree(Instant::now() + Duration::from_secs(5)),
        Err(CleanupFault::OwnershipLost)
    ));
}
