//! Supplementary WE-P02 regressions; these do not activate engine dispatch.
#![cfg(any(windows, target_os = "linux"))]

use dissect3d_platform::{
    ProcessIdentity, ProcessWatcher, WorkerCommand, WorkerProcess, current_process_identity,
};
use std::time::{Duration, Instant};

fn command() -> WorkerCommand {
    let mut command = WorkerCommand::new(std::env::current_exe().unwrap());
    command.args = vec![
        "--exact".into(),
        "worker_child".into(),
        "--nocapture".into(),
    ];
    command.environment = vec![("D3D_WORKER_CHILD".into(), "1".into())];
    #[cfg(target_os = "linux")]
    {
        command.guardian = Some(env!("CARGO_BIN_EXE_dissect3d-worker-guardian").into());
    }
    command
}

#[test]
fn worker_child() {
    if std::env::var_os("D3D_WORKER_CHILD").is_none() {
        return;
    }
    if std::env::var_os("D3D_WORKER_EARLY_EXIT").is_some() {
        std::process::exit(0);
    }
    #[cfg(windows)]
    if let Ok(handle) = std::env::var("D3D_FORBIDDEN_HANDLE") {
        let handle = handle.parse::<usize>().unwrap() as *mut std::ffi::c_void;
        let leaked = windows_file_identity(handle) == std::env::var("D3D_FORBIDDEN_FILE_ID").ok();
        let root = std::env::var_os("D3D_HANDLE_CHECK_ROOT").unwrap();
        std::fs::write(
            std::path::Path::new(&root).join("handle-check"),
            if leaked { b"leaked" } else { b"sealed" },
        )
        .unwrap();
    }
    if let Some(root) = std::env::var_os("D3D_WORKER_TREE") {
        let root = std::path::PathBuf::from(root);
        let depth: u32 = std::env::var("D3D_WORKER_DEPTH")
            .unwrap_or_else(|_| "0".into())
            .parse()
            .unwrap();
        #[cfg(target_os = "linux")]
        if depth == 2 && std::env::var_os("D3D_WORKER_ESCAPE").is_some() {
            assert!(unsafe { libc::setsid() } > 0);
        }
        let id = current_process_identity().unwrap();
        std::fs::write(
            root.join(format!("{depth}.id")),
            format!("{} {}", id.pid, id.start_marker),
        )
        .unwrap();
        if depth < 2 {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "worker_child", "--nocapture"])
                .env("D3D_WORKER_DEPTH", (depth + 1).to_string())
                .spawn()
                .unwrap();
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
    loop {
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn tree_ready(root: &std::path::Path) -> Vec<ProcessIdentity> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let values: Vec<_> = (0..3)
            .filter_map(|depth| {
                let text = std::fs::read_to_string(root.join(format!("{depth}.id"))).ok()?;
                let (pid, marker) = text.split_once(' ')?;
                Some(ProcessIdentity {
                    pid: pid.parse().ok()?,
                    start_marker: marker.into(),
                })
            })
            .collect();
        if values.len() == 3 {
            return values;
        }
        assert!(
            Instant::now() < deadline,
            "real child/grandchild did not start"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn tree_command(root: &std::path::Path) -> WorkerCommand {
    let mut command = command();
    command
        .environment
        .push(("D3D_WORKER_TREE".into(), root.as_os_str().into()));
    command
}

#[test]
fn cleanup_covers_real_child_and_grandchild_with_blocked_worker() {
    let temp = tempfile::tempdir().unwrap();
    let mut worker = WorkerProcess::launch(tree_command(temp.path()), [3; 16]).unwrap();
    let identities = tree_ready(temp.path());
    let watchers: Vec<_> = identities
        .iter()
        .map(|id| ProcessWatcher::new(id).unwrap())
        .collect();
    worker
        .terminate_tree(Instant::now() + Duration::from_secs(5))
        .unwrap();
    for watcher in watchers {
        assert!(watcher.wait(Duration::from_secs(2)).unwrap());
    }
}

#[test]
fn owner_process_exit_helper() {
    let Some(root) = std::env::var_os("D3D_ENGINE_DEATH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let _worker = WorkerProcess::launch(tree_command(&root), [4; 16]).unwrap();
    tree_ready(&root);
    std::fs::write(root.join("owner-ready"), b"ready").unwrap();
    // No Rust Drop: native ownership must survive engine process death.
    std::process::exit(0);
}

#[test]
fn owner_death_cleans_subtree_without_worker_cooperation() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "owner_process_exit_helper", "--nocapture"])
        .env("D3D_ENGINE_DEATH_ROOT", temp.path())
        .spawn()
        .unwrap();
    let identities = tree_ready(temp.path());
    let watchers: Vec<_> = identities
        .iter()
        .filter_map(|id| match ProcessWatcher::new(id) {
            Ok(watcher) => Some(watcher),
            Err(dissect3d_platform::PlatformError::NotFound) => None,
            Err(error) => panic!("watcher failed: {error:?}"),
        })
        .collect();
    assert!(owner.wait().unwrap().success());
    assert!(temp.path().join("owner-ready").exists());
    for watcher in watchers {
        assert!(watcher.wait(Duration::from_secs(5)).unwrap());
    }
}

#[test]
fn contained_worker_is_terminated_and_confirmation_is_session_bound() {
    let mut worker = WorkerProcess::launch(command(), [7; 16]).unwrap();
    let identity = worker.identity();
    assert_eq!(identity.session_nonce, [7; 16]);
    assert!(identity.process.pid > 0);
    let confirmation = worker
        .terminate_tree(Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert_eq!(confirmation.identity(), &identity);
    assert!(
        worker
            .terminate_tree(Instant::now() + Duration::from_secs(1))
            .is_ok()
    );
}

#[test]
fn launch_failure_cannot_execute_a_worker() {
    let mut command = command();
    command.executable = std::env::current_exe()
        .unwrap()
        .with_file_name("absent-worker.exe");
    assert!(WorkerProcess::launch(command, [8; 16]).is_err());
}

#[test]
fn native_loader_failure_never_returns_a_live_worker() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("invalid-worker.exe");
    std::fs::write(&binary, b"not an executable image").unwrap();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut command = command();
    command.executable = binary;
    assert!(WorkerProcess::launch(command, [13; 16]).is_err());
}

#[test]
fn drop_is_a_subtree_cleanup_fallback_without_a_confirmation_witness() {
    let temp = tempfile::tempdir().unwrap();
    let worker = WorkerProcess::launch(tree_command(temp.path()), [14; 16]).unwrap();
    let identities = tree_ready(temp.path());
    let watchers: Vec<_> = identities
        .iter()
        .map(|id| ProcessWatcher::new(id).unwrap())
        .collect();
    drop(worker);
    for watcher in watchers {
        assert!(watcher.wait(Duration::from_secs(5)).unwrap());
    }
}

#[test]
fn command_rejects_ambiguous_environment_and_unbounded_arguments() {
    let mut command = command();
    command
        .environment
        .push(("INVALID=NAME".into(), "value".into()));
    assert!(WorkerProcess::launch(command, [9; 16]).is_err());
    let mut command = self::command();
    command.args.push("x".repeat(65_537).into());
    assert!(WorkerProcess::launch(command, [9; 16]).is_err());
}

#[test]
fn early_worker_exit_and_mutated_pid_copy_cannot_redirect_cleanup() {
    let mut command = command();
    command
        .environment
        .push(("D3D_WORKER_EARLY_EXIT".into(), "1".into()));
    let mut worker = WorkerProcess::launch(command, [6; 16]).unwrap();
    let original = worker.identity();
    let mut stale = worker.identity();
    stale.process.pid = std::process::id();
    stale.process.start_marker = "stale".into();
    std::thread::sleep(Duration::from_millis(30));
    let confirmation = worker
        .terminate_tree(Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert_eq!(confirmation.identity(), &original);
    assert_ne!(confirmation.identity(), &stale);
}

#[cfg(target_os = "linux")]
#[test]
fn guardian_death_is_an_ownership_fault_never_cleanup_confirmation() {
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
    let mut worker = WorkerProcess::launch(command(), [5; 16]).unwrap();
    let identity = worker.identity();
    let leader = pidfd_open(
        Pid::from_raw(identity.process.pid as i32).unwrap(),
        PidfdFlags::empty(),
    )
    .unwrap();
    let guardian = identity.guardian.unwrap();
    let guardian_handle = pidfd_open(
        Pid::from_raw(guardian.pid as i32).unwrap(),
        PidfdFlags::empty(),
    )
    .unwrap();
    assert!(dissect3d_platform::process_matches(&guardian).unwrap());
    pidfd_send_signal(&guardian_handle, Signal::KILL).unwrap();
    let result = worker.terminate_tree(Instant::now() + Duration::from_secs(2));
    // Clean up the exact live test process through its retained pidfd, even if
    // the following assertion fails. No signal uses an unverified/reused PID.
    let _ = pidfd_send_signal(&leader, Signal::KILL);
    assert!(result.is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn inheritable_engine_descriptor_is_absent_in_guardian_and_worker() {
    use std::os::fd::AsRawFd;
    let temp = tempfile::tempdir().unwrap();
    let sentinel = temp.path().join("private-engine-only");
    let file = std::fs::File::create(&sentinel).unwrap();
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let mut worker = WorkerProcess::launch(command(), [10; 16]).unwrap();
    let identity = worker.identity();
    let leaked = [identity.process.pid, identity.guardian.unwrap().pid]
        .into_iter()
        .any(|pid| {
            std::fs::read_dir(format!("/proc/{pid}/fd"))
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                .any(|path| path == sentinel)
        });
    worker
        .terminate_tree(Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert!(
        !leaked,
        "engine-only descriptor leaked across private launch boundary"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn escaped_descendant_and_deadline_never_release_a_cleanup_witness() {
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
    let temp = tempfile::tempdir().unwrap();
    let mut command = tree_command(temp.path());
    command
        .environment
        .push(("D3D_WORKER_ESCAPE".into(), "1".into()));
    let mut worker = WorkerProcess::launch(command, [11; 16]).unwrap();
    let identities = tree_ready(temp.path());
    let escaped = &identities[2];
    let handle = pidfd_open(
        Pid::from_raw(escaped.pid as i32).unwrap(),
        PidfdFlags::empty(),
    )
    .unwrap();
    assert!(dissect3d_platform::process_matches(escaped).unwrap());
    assert!(
        worker
            .terminate_tree(Instant::now() + Duration::from_millis(5))
            .is_err()
    );
    let result = worker.terminate_tree(Instant::now() + Duration::from_secs(6));
    let _ = pidfd_send_signal(&handle, Signal::KILL);
    assert!(
        result.is_err(),
        "a group escape must retain the resource reservation"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn guardian_report_failure_cleans_worker_instead_of_panicking() {
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let output = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let mut guardian = Command::new(env!("CARGO_BIN_EXE_dissect3d-worker-guardian"))
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "worker_child", "--nocapture"])
        .env("D3D_WORKER_CHILD", "1")
        .env("D3D_WORKER_TREE", temp.path())
        .env("D3D_WORKER_DEPTH", "2")
        .stdin(Stdio::piped())
        .stdout(output)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = guardian.wait().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let mut exited = true;
    if let Ok(text) = std::fs::read_to_string(temp.path().join("2.id")) {
        let (pid, marker) = text.split_once(' ').unwrap();
        let id = ProcessIdentity {
            pid: pid.parse().unwrap(),
            start_marker: marker.into(),
        };
        match ProcessWatcher::new(&id) {
            Ok(watcher) => {
                exited = watcher.wait(Duration::from_secs(1)).unwrap();
                if !exited {
                    let handle =
                        pidfd_open(Pid::from_raw(id.pid as i32).unwrap(), PidfdFlags::empty())
                            .unwrap();
                    assert!(dissect3d_platform::process_matches(&id).unwrap());
                    let _ = pidfd_send_signal(&handle, Signal::KILL);
                }
            }
            Err(dissect3d_platform::PlatformError::NotFound) => {}
            Err(error) => panic!("watcher failed: {error:?}"),
        }
    }
    assert!(exited, "broken report channel orphaned the real worker");
    assert!(
        status.success(),
        "failed READY delivery must enter cleanup without panic"
    );
}

#[cfg(windows)]
fn windows_file_identity(handle: *mut std::ffi::c_void) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // Querying a possibly absent handle cannot open or grant file authority.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return None;
    }
    Some(format!(
        "{}:{}:{}",
        info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
    ))
}

#[cfg(windows)]
#[test]
fn inheritable_windows_engine_handle_is_not_in_the_worker_handle_set() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    let temp = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(temp.path().join("engine-only")).unwrap();
    let handle = file.as_raw_handle();
    assert_ne!(
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
        0
    );
    let expected = windows_file_identity(handle).unwrap();
    let mut command = command();
    command.environment.extend([
        (
            "D3D_FORBIDDEN_HANDLE".into(),
            (handle as usize).to_string().into(),
        ),
        ("D3D_FORBIDDEN_FILE_ID".into(), expected.into()),
        (
            "D3D_HANDLE_CHECK_ROOT".into(),
            temp.path().as_os_str().into(),
        ),
    ]);
    let mut worker = WorkerProcess::launch(command, [12; 16]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        if let Ok(bytes) = std::fs::read(temp.path().join("handle-check")) {
            break Some(bytes);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    worker
        .terminate_tree(Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert_eq!(result.as_deref(), Some(b"sealed".as_slice()));
}
