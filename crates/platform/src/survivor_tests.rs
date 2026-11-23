//! WE-P07/4 restart reconciliation of a previous engine's worker identity
//! against real processes: a matching survivor is ended through a verified
//! handle, a reused PID (different start marker) is never signaled, and an
//! exited worker is simply absent.
use crate::process::process_start_marker;
use crate::{ProcessIdentity, WorkerIdentity, process_matches, reconcile_survivors};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const HELPER: &str = "survivor_tests::survivor_child_helper";
const HELPER_ENV: &str = "DISSECT3D_SURVIVOR_CHILD";

/// Re-executed as a long-lived stand-in survivor.
#[test]
fn survivor_child_helper() {
    if std::env::var_os(HELPER_ENV).is_some() {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn spawn() -> (Child, ProcessIdentity) {
    let child = Command::new(std::env::current_exe().unwrap())
        .args([HELPER, "--exact", "--test-threads=1", "--nocapture"])
        .env(HELPER_ENV, "1")
        .spawn()
        .unwrap();
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(10);
    let start_marker = loop {
        if let Ok(marker) = process_start_marker(pid) {
            break marker;
        }
        assert!(Instant::now() < deadline, "no start marker");
        std::thread::sleep(Duration::from_millis(10));
    };
    (child, ProcessIdentity { pid, start_marker })
}

fn identity(process: ProcessIdentity) -> WorkerIdentity {
    WorkerIdentity {
        process,
        guardian: None,
        session_nonce: [7; 16],
    }
}

#[test]
fn a_matching_survivor_is_ended_and_reported_terminated() {
    let (mut child, process) = spawn();
    let absent = reconcile_survivors(&identity(process.clone()), Duration::from_secs(10)).unwrap();
    assert!(absent.terminated());
    assert_eq!(absent.identity().process, process);
    let _ = child.wait();
    // Windows keeps an exited process object while any handle is open.
    drop(child);
    assert!(!process_matches(&process).unwrap());
}

#[test]
fn a_reused_pid_is_never_signaled() {
    let (mut child, process) = spawn();
    let stale = ProcessIdentity {
        pid: process.pid,
        start_marker: format!("{}-earlier", process.start_marker),
    };
    let absent = reconcile_survivors(&identity(stale), Duration::from_secs(5)).unwrap();
    assert!(!absent.terminated());
    assert!(
        process_matches(&process).unwrap(),
        "the live process is untouched"
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn an_exited_worker_is_absent() {
    let (mut child, process) = spawn();
    child.kill().unwrap();
    child.wait().unwrap();
    let absent = reconcile_survivors(&identity(process), Duration::from_secs(5)).unwrap();
    assert!(!absent.terminated());
}
