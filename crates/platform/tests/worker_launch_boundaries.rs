//! Deterministic native handoffs; developer feature is absent from normal builds.
#![cfg_attr(
    all(feature = "native-test-hooks", any(windows, target_os = "linux")),
    expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "integration test helpers; engineering.md Rule 6 permits unwrap in test setup"
    )
)]
#![cfg(all(feature = "native-test-hooks", any(windows, target_os = "linux")))]
use dissect3d_platform::native_test_hooks::{Action, Event, Stage, with_hook};
use dissect3d_platform::{
    ProcessIdentity, ProcessWatcher, WorkerCommand, WorkerProcess, current_process_identity,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn hook(event: Event) -> Action {
    if let Some(error) = event.native_error {
        let _ = writeln!(std::io::stdout(), "FAILURE {:?} {error}", event.stage);
        let _ = std::io::stdout().flush();
        return Action::Continue;
    }
    if std::env::var("D3D_BOUNDARY_STAGE").unwrap() != format!("{:?}", event.stage) {
        return Action::Continue;
    }
    let identity = |value: Option<ProcessIdentity>| {
        value.map_or_else(
            || "0 -".into(),
            |id| format!("{} {}", id.pid, id.start_marker),
        )
    };
    let line = format!(
        "BOUNDARY {} {}\n",
        identity(event.process),
        identity(event.guardian)
    );
    if std::io::stdout()
        .write_all(line.as_bytes())
        .and_then(|_| std::io::stdout().flush())
        .is_err()
    {
        return Action::Abort;
    }
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut byte = [0];
        let _ = send.send(std::io::stdin().read_exact(&mut byte).is_ok());
    });
    if receive.recv_timeout(Duration::from_secs(10)) != Ok(true) {
        return Action::Abort;
    }
    match std::env::var("D3D_BOUNDARY_ACTION").unwrap().as_str() {
        "attribute" => Action::FailAttribute,
        "assignment" => Action::FailAssignment,
        "resume" => Action::FailResume,
        "guardian" => Action::KillGuardian,
        "abort" | "sigchld" => Action::Abort,
        _ => Action::Continue,
    }
}

#[test]
fn native_owner_helper() {
    if std::env::var_os("D3D_BOUNDARY_STAGE").is_none() {
        return;
    }
    #[cfg(target_os = "linux")]
    if std::env::var("D3D_BOUNDARY_ACTION").as_deref() == Ok("sigchld") {
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
        }
    }
    let mut command = WorkerCommand::new(std::env::current_exe().unwrap());
    command.args = vec![
        "--exact".into(),
        "native_worker_helper".into(),
        "--nocapture".into(),
    ];
    command.environment = vec![(
        "D3D_BOUNDARY_ENTRY".into(),
        std::env::var_os("D3D_BOUNDARY_ENTRY").unwrap(),
    )];
    #[cfg(target_os = "linux")]
    {
        command.guardian = Some(env!("CARGO_BIN_EXE_dissect3d-worker-guardian").into());
    }
    let result = with_hook(hook, || WorkerProcess::launch(command, [31; 16]));
    assert!(
        result.is_err(),
        "injected native failure must not return a live worker"
    );
}

#[test]
fn native_worker_helper() {
    let Some(entry) = std::env::var_os("D3D_BOUNDARY_ENTRY") else {
        return;
    };
    std::fs::write(entry, current_process_identity().unwrap().pid.to_string()).unwrap();
    loop {
        std::thread::park();
    }
}

struct Owner(Child);
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn scenario(stage: Stage, action: &str, death: bool, worker_must_not_execute: bool) {
    let temp = tempfile::tempdir().unwrap();
    let entry = temp.path().join("entered");
    let mut owner = Owner(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_owner_helper", "--nocapture"])
            .env("D3D_BOUNDARY_STAGE", format!("{stage:?}"))
            .env("D3D_BOUNDARY_ACTION", action)
            .env("D3D_BOUNDARY_ENTRY", &entry)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let output = owner.0.stdout.take().unwrap();
    let (send, receive) = mpsc::sync_channel(1);
    let (drained_send, drained_receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut failures = Vec::new();
        for line in BufReader::new(output).lines().take(32) {
            let Ok(line) = line else {
                break;
            };
            if let Some(record) = line.strip_prefix("BOUNDARY ") {
                let _ = send.send(record.to_owned());
                // Drain until EOF: closing this read end would manufacture a
                // broken stdout in the owner helper after a successful test.
            }
            if let Some(failure) = line.strip_prefix("FAILURE ") {
                failures.push(failure.to_owned());
            }
        }
        let _ = drained_send.send(failures);
    });
    let record = receive
        .recv_timeout(Duration::from_secs(12))
        .expect("native seam must report before release");
    let fields: Vec<_> = record.split_whitespace().collect();
    assert_eq!(fields.len(), 4);
    let identities: Vec<_> = fields
        .as_chunks::<2>()
        .0
        .iter()
        .filter_map(|pair| {
            let pid: u32 = pair[0].parse().unwrap();
            (pid != 0).then(|| ProcessIdentity {
                pid,
                start_marker: pair[1].into(),
            })
        })
        .collect();
    let watchers: Vec<_> = identities
        .iter()
        .map(|id| ProcessWatcher::new(id).unwrap())
        .collect();
    #[cfg(target_os = "linux")]
    let handles: Vec<_> = identities
        .iter()
        .map(|id| {
            use rustix::process::{Pid, PidfdFlags, pidfd_open};
            pidfd_open(Pid::from_raw(id.pid as i32).unwrap(), PidfdFlags::empty()).unwrap()
        })
        .collect();
    #[cfg(target_os = "linux")]
    let pinned = if action == "sigchld" {
        rustix::process::pidfd_send_signal(&handles[0], rustix::process::Signal::KILL).unwrap();
        assert!(watchers[0].wait(Duration::from_secs(3)).unwrap());
        dissect3d_platform::process_matches(&identities[0]).unwrap()
    } else {
        true
    };
    if death {
        owner.0.kill().unwrap();
    } else {
        owner.0.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    let status = loop {
        if let Some(status) = owner.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "owner failed bounded exit");
        std::thread::sleep(Duration::from_millis(5));
    };
    let terminated = watchers
        .iter()
        .all(|watcher| watcher.wait(Duration::from_secs(3)).unwrap());
    let failures = drained_receive
        .recv_timeout(Duration::from_secs(3))
        .expect("owner output must close without inherited writer leaks");
    #[cfg(windows)]
    if let Some(expected) = match action {
        "attribute" => Some("WindowsAttributeRejected"),
        "assignment" => Some("WindowsCreateRejected"),
        "resume" => Some("WindowsResumeRejected"),
        _ => None,
    } {
        assert!(
            failures.iter().any(|failure| failure.starts_with(expected)
                && failure
                    .split_whitespace()
                    .last()
                    .unwrap()
                    .parse::<u32>()
                    .unwrap()
                    != 0),
            "missing native API failure: {failures:?}"
        );
    }
    for failure in failures {
        println!("observed native failure: {failure}");
    }
    #[cfg(target_os = "linux")]
    for handle in handles {
        let _ = rustix::process::pidfd_send_signal(&handle, rustix::process::Signal::KILL);
    }
    assert!(terminated, "native ownership handoff left a live process");
    #[cfg(target_os = "linux")]
    assert!(
        pinned,
        "ignored SIGCHLD auto-reaped the owned group leader before cleanup"
    );
    assert!(
        death || status.success(),
        "owner helper must observe a truthful launch rejection"
    );
    if worker_must_not_execute {
        assert!(
            !entry.exists(),
            "suspended/uncreated worker executed user code"
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_native_attribute_failure_is_fail_closed() {
    scenario(Stage::WindowsAttributes, "attribute", false, true);
}
#[cfg(windows)]
#[test]
fn windows_native_assignment_failure_is_fail_closed() {
    scenario(Stage::WindowsJobList, "assignment", false, true);
}
#[cfg(windows)]
#[test]
fn windows_owner_death_before_creation_cannot_launch() {
    scenario(Stage::WindowsCreate, "continue", true, true);
}
#[cfg(windows)]
#[test]
fn windows_owner_death_after_creation_kills_suspended_worker() {
    scenario(Stage::WindowsCreated, "continue", true, true);
}
#[cfg(windows)]
#[test]
fn windows_resume_failure_kills_created_worker() {
    scenario(Stage::WindowsResume, "resume", false, true);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_owner_death_before_guardian_creation_cannot_launch() {
    scenario(Stage::GuardianSpawn, "continue", true, true);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_owner_death_after_guardian_creation_prevents_worker_handoff() {
    scenario(Stage::GuardianSpawned, "continue", true, true);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_owner_death_after_fork_before_exec_cannot_execute_worker() {
    scenario(Stage::GuardianBeforeExec, "continue", true, true);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_guardian_failure_after_fork_before_exec_stops_suspended_handoff() {
    scenario(Stage::GuardianBeforeExec, "guardian", false, true);
}
#[cfg(target_os = "linux")]
#[test]
fn linux_owner_death_before_worker_creation_closes_lifeline() {
    scenario(Stage::GuardianBeforeWorker, "continue", true, true);
}
#[cfg(target_os = "linux")]
#[test]
fn linux_owner_death_after_worker_creation_cleans_group() {
    scenario(Stage::GuardianWorkerCreated, "continue", true, false);
}
#[cfg(target_os = "linux")]
#[test]
fn linux_guardian_failure_before_worker_creation_is_rejected() {
    scenario(Stage::GuardianBeforeWorker, "guardian", false, true);
}
#[cfg(target_os = "linux")]
#[test]
fn linux_guardian_failure_after_worker_creation_is_rejected_and_stops_leader() {
    scenario(Stage::GuardianWorkerCreated, "guardian", false, false);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_ignored_sigchld_cannot_remove_the_group_identity_pin() {
    scenario(Stage::GuardianWorkerCreated, "sigchld", false, false);
}
