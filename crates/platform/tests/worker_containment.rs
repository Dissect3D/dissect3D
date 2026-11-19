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
    if std::env::var_os("D3D_WORKER_ECHO").is_some() {
        echo_worker();
    }
    if let Some(root) = std::env::var_os("D3D_WORKER_INPUT_ROOT") {
        input_worker(std::path::PathBuf::from(root));
    }
    if let Some(root) = std::env::var_os("D3D_WORKER_STORM") {
        let root = std::path::PathBuf::from(root);
        if std::env::var_os("D3D_STORM_CHILD").is_some() {
            let id = current_process_identity().unwrap();
            let name = format!("{}-{}", id.pid, id.start_marker);
            let _ = std::fs::write(root.join(format!("{name}.tmp")), &name);
            let _ = std::fs::rename(
                root.join(format!("{name}.tmp")),
                root.join(format!("{name}.id")),
            );
            loop {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        // Keep creating members, before and during termination.
        loop {
            if let Ok(mut child) = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "worker_child", "--nocapture"])
                .env("D3D_STORM_CHILD", "1")
                .spawn()
            {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            let _ = std::fs::write(root.join("storming"), b"1");
        }
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

/// Worker side of the private channel checks: upstream-style noise goes to
/// stdout/stderr, one command is echoed on the report pipe.
fn echo_worker() -> ! {
    use std::io::{BufRead, Write};
    let (commands, mut reports) = dissect3d_platform::worker_control_channels().unwrap();
    // A second take in one process is refused (no double ownership).
    assert!(dissect3d_platform::worker_control_channels().is_err());
    println!("noise-out");
    eprintln!("noise-err");
    let mut line = String::new();
    std::io::BufReader::new(commands)
        .read_line(&mut line)
        .unwrap();
    reports
        .write_all(format!("echo {line}").as_bytes())
        .unwrap();
    if let Some(root) = std::env::var_os("D3D_ECHO_DESCENDANT") {
        // A live descendant must not hold the control channel open.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "worker_child", "--nocapture"])
            .env_remove("D3D_WORKER_ECHO")
            .env("D3D_WORKER_TREE", root)
            .env("D3D_WORKER_DEPTH", "2")
            .spawn()
            .unwrap();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !std::path::Path::new(&std::env::var_os("D3D_ECHO_DESCENDANT").unwrap())
            .join("2.id")
            .exists()
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        std::process::exit(0);
    }
    loop {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Worker side of the inherited-input checks: adopt each listed input, read
/// it from offset 0, try to write through it, then report.
fn input_worker(root: std::path::PathBuf) -> ! {
    use std::io::{Read, Seek, Write};
    let listed = std::env::var(dissect3d_platform::WORKER_INPUTS_ENV).unwrap_or_default();
    let mut report = vec![format!("listed={listed}")];
    for value in listed.split(',').filter(|v| !v.is_empty()) {
        let value: u64 = value.parse().unwrap();
        match dissect3d_platform::worker_inherited_input(value) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                file.seek(std::io::SeekFrom::Start(0)).unwrap();
                file.read_to_end(&mut bytes).unwrap();
                let wrote = file
                    .write_all(b"tamper")
                    .and_then(|()| file.flush())
                    .is_ok();
                report.push(format!(
                    "{value}:{}:{}",
                    String::from_utf8_lossy(&bytes),
                    if wrote { "written" } else { "denied" }
                ));
                let again = dissect3d_platform::worker_inherited_input(value).err();
                report.push(format!("again:{again:?}"));
            }
            Err(error) => report.push(format!("{value}:error:{error:?}")),
        }
    }
    let unlisted = dissect3d_platform::worker_inherited_input(999_999).err();
    report.push(format!("unlisted:{unlisted:?}"));
    std::fs::write(
        root.join("report.tmp"),
        report.join(
            "
",
        ),
    )
    .unwrap();
    std::fs::rename(root.join("report.tmp"), root.join("report")).unwrap();
    loop {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Read until end of file on a helper thread, bounded by `timeout`.
fn read_to_end_within(mut file: std::fs::File, timeout: Duration) -> Option<Vec<u8>> {
    use std::io::Read;
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = file.read_to_end(&mut bytes);
        let _ = send.send(bytes);
    });
    receive.recv_timeout(timeout).ok()
}

fn echo_command() -> WorkerCommand {
    let mut command = command();
    command
        .environment
        .push(("D3D_WORKER_ECHO".into(), "1".into()));
    command
}

#[test]
fn private_control_channel_is_separate_from_diagnostics() {
    use std::io::{BufRead, Write};
    let mut worker = WorkerProcess::launch(echo_command(), [14; 16]).unwrap();
    let channels = worker.take_channels().unwrap();
    assert!(worker.take_channels().is_none());
    let mut to_worker = channels.to_worker;
    to_worker
        .write_all(
            b"hello
",
        )
        .unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let from_worker = channels.from_worker;
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::BufReader::new(from_worker).read_line(&mut line);
        let _ = send.send(line);
    });
    let echoed = receive.recv_timeout(Duration::from_secs(10)).unwrap();
    worker
        .terminate_tree(Instant::now() + Duration::from_secs(5))
        .unwrap();
    // Only the protocol line crosses the control pipe; harness and upstream
    // output reach diagnostics only.
    assert_eq!(
        echoed,
        "echo hello
"
    );
    let diagnostics = String::from_utf8(
        read_to_end_within(channels.diagnostics, Duration::from_secs(5)).unwrap(),
    )
    .unwrap();
    assert!(diagnostics.contains("noise-out"), "{diagnostics}");
    assert!(diagnostics.contains("noise-err"), "{diagnostics}");
    assert!(!diagnostics.contains("echo hello"));
}

#[test]
fn worker_descendant_never_holds_the_control_channel() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let mut command = echo_command();
    command
        .environment
        .push(("D3D_ECHO_DESCENDANT".into(), temp.path().as_os_str().into()));
    let mut worker = WorkerProcess::launch(command, [15; 16]).unwrap();
    let channels = worker.take_channels().unwrap();
    let mut to_worker = channels.to_worker;
    to_worker
        .write_all(
            b"go
",
        )
        .unwrap();
    // The worker exits while its descendant lives: reports reach end of file.
    let reports = read_to_end_within(channels.from_worker, Duration::from_secs(10));
    let descendant = std::fs::read_to_string(temp.path().join("2.id")).unwrap();
    let (pid, marker) = descendant.split_once(' ').unwrap();
    let descendant = ProcessIdentity {
        pid: pid.parse().unwrap(),
        start_marker: marker.into(),
    };
    let alive = dissect3d_platform::process_matches(&descendant).unwrap();
    let watcher = ProcessWatcher::new(&descendant).ok();
    let cleanup = worker.terminate_tree(Instant::now() + Duration::from_secs(5));
    assert_eq!(
        reports.as_deref(),
        Some(
            &b"echo go
"[..]
        )
    );
    assert!(
        alive,
        "descendant must still be running when EOF is observed"
    );
    assert!(cleanup.is_ok());
    if let Some(watcher) = watcher {
        assert!(watcher.wait(Duration::from_secs(2)).unwrap());
    }
}

#[test]
fn caller_cannot_supply_the_reserved_control_variable() {
    for key in ["DISSECT3D_WORKER_CONTROL", "dissect3d_worker_control"] {
        let mut command = command();
        command.environment.push((key.into(), "3:4".into()));
        assert!(WorkerProcess::launch(command, [16; 16]).is_err());
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
fn confirmation_means_every_tree_member_has_already_exited() {
    // Regression (2026-11-19): Windows confirmed on a zero active-process
    // count while a member's process object was still exiting.
    for nonce in 30..35u8 {
        let temp = tempfile::tempdir().unwrap();
        let mut worker = WorkerProcess::launch(tree_command(temp.path()), [nonce; 16]).unwrap();
        let watchers: Vec<_> = tree_ready(temp.path())
            .iter()
            .map(|id| ProcessWatcher::new(id).unwrap())
            .collect();
        worker
            .terminate_tree(Instant::now() + Duration::from_secs(5))
            .unwrap();
        for watcher in watchers {
            assert!(
                watcher.wait(Duration::ZERO).unwrap(),
                "member still running"
            );
        }
    }
}

#[test]
fn members_created_during_termination_are_covered_by_confirmation() {
    // Regression (2026-11-19 QA): a member created after the membership
    // snapshot could be missed. Every recorded member must already be gone.
    for nonce in 40..43u8 {
        let temp = tempfile::tempdir().unwrap();
        let mut command = command();
        command
            .environment
            .push(("D3D_WORKER_STORM".into(), temp.path().as_os_str().into()));
        let mut worker = WorkerProcess::launch(command, [nonce; 16]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_dir(temp.path()).unwrap().count() < 4 {
            assert!(Instant::now() < deadline, "storm did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        worker
            .terminate_tree(Instant::now() + Duration::from_secs(5))
            .unwrap();
        for entry in std::fs::read_dir(temp.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("id") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let (pid, marker) = text.split_once('-').unwrap();
            let id = ProcessIdentity {
                pid: pid.parse().unwrap(),
                start_marker: marker.into(),
            };
            match ProcessWatcher::new(&id) {
                Ok(watcher) => assert!(watcher.wait(Duration::ZERO).unwrap(), "member running"),
                Err(dissect3d_platform::PlatformError::NotFound) => {}
                Err(error) => panic!("watcher failed: {error:?}"),
            }
        }
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
    // The guardian's launch contract: the worker's pipe ends at 3, 4 and 5.
    let channels = std::fs::File::open("/dev/null").unwrap();
    let mut launch = Command::new(env!("CARGO_BIN_EXE_dissect3d-worker-guardian"));
    launch
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "worker_child", "--nocapture"])
        .env("D3D_WORKER_CHILD", "1")
        .env("D3D_WORKER_TREE", temp.path())
        .env("D3D_WORKER_DEPTH", "2")
        .stdin(Stdio::piped())
        .stdout(output)
        .stderr(Stdio::null());
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let source = channels.as_raw_fd();
        // SAFETY: only fcntl/dup2 run in the forked child.
        unsafe {
            launch.pre_exec(move || {
                let copy = libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 10);
                if copy < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for target in 3..6 {
                    if libc::dup2(copy, target) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    let mut guardian = launch.spawn().unwrap();
    drop(channels);
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

#[test]
fn inherited_inputs_are_read_only_exactly_listed_and_adopted_once() {
    let temp = tempfile::tempdir().unwrap();
    let alpha = temp.path().join("alpha.bin");
    let beta = temp.path().join("beta.bin");
    std::fs::write(&alpha, b"alpha").unwrap();
    std::fs::write(&beta, b"beta").unwrap();
    let mut command = command();
    command.environment.push((
        "D3D_WORKER_INPUT_ROOT".into(),
        temp.path().as_os_str().into(),
    ));
    let a = command
        .inherit_read_only(&std::fs::File::open(&alpha).unwrap())
        .unwrap();
    let b = command
        .inherit_read_only(&std::fs::File::open(&beta).unwrap())
        .unwrap();
    assert_ne!(a, b);
    let mut worker = WorkerProcess::launch(command, [21; 16]).unwrap();
    let report = temp.path().join("report");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !report.exists() {
        assert!(
            Instant::now() < deadline,
            "worker reported within the bound"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    worker
        .terminate_tree(Instant::now() + Duration::from_secs(5))
        .unwrap();
    let report = std::fs::read_to_string(report).unwrap();
    assert_eq!(
        report.lines().collect::<Vec<_>>(),
        [
            format!("listed={a},{b}"),
            format!("{a}:alpha:denied"),
            "again:Some(Busy)".to_owned(),
            format!("{b}:beta:denied"),
            "again:Some(Busy)".to_owned(),
            "unlisted:Some(NotFound)".to_owned(),
        ]
    );
    // The snapshots are unchanged.
    assert_eq!(std::fs::read(&alpha).unwrap(), b"alpha");
    assert_eq!(std::fs::read(&beta).unwrap(), b"beta");
}

#[test]
fn a_worker_without_inputs_can_adopt_none() {
    let temp = tempfile::tempdir().unwrap();
    let mut command = command();
    command.environment.push((
        "D3D_WORKER_INPUT_ROOT".into(),
        temp.path().as_os_str().into(),
    ));
    let mut worker = WorkerProcess::launch(command, [22; 16]).unwrap();
    let report = temp.path().join("report");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !report.exists() {
        assert!(
            Instant::now() < deadline,
            "worker reported within the bound"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    worker
        .terminate_tree(Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "listed=
unlisted:Some(NotFound)"
    );
}

#[test]
fn writable_or_excess_inputs_and_the_reserved_variable_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.bin");
    std::fs::write(&path, b"input").unwrap();
    // A file still open for writing never becomes a worker input.
    let writable = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(command().inherit_read_only(&writable).is_err());
    drop(writable);
    // Only regular files (a directory opens read-only on Unix).
    #[cfg(unix)]
    assert!(
        command()
            .inherit_read_only(&std::fs::File::open(temp.path()).unwrap())
            .is_err()
    );
    let reader = std::fs::File::open(&path).unwrap();
    let mut full = command();
    for _ in 0..dissect3d_platform::MAX_WORKER_INPUTS {
        full.inherit_read_only(&reader).unwrap();
    }
    assert!(full.inherit_read_only(&reader).is_err());
    for key in ["DISSECT3D_WORKER_INPUTS", "dissect3d_worker_inputs"] {
        let mut command = command();
        command.environment.push((key.into(), "5".into()));
        assert!(WorkerProcess::launch(command, [23; 16]).is_err());
    }
}

/// With inputs present the worker's descriptors are exactly stdio, the two
/// control ends and the listed inputs; an inheritable engine descriptor
/// reaches neither the guardian nor the worker.
#[cfg(target_os = "linux")]
#[test]
fn worker_descriptor_set_with_inputs_is_exactly_stdio_control_and_inputs() {
    use std::os::fd::AsRawFd;
    let temp = tempfile::tempdir().unwrap();
    let sentinel = temp.path().join("private-engine-only");
    let file = std::fs::File::create(&sentinel).unwrap();
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let inputs = ["first.bin", "second.bin"].map(|name| {
        let path = temp.path().join(name);
        std::fs::write(&path, name).unwrap();
        path
    });
    let mut command = command();
    for path in &inputs {
        command
            .inherit_read_only(&std::fs::File::open(path).unwrap())
            .unwrap();
    }
    let mut worker = WorkerProcess::launch(command, [24; 16]).unwrap();
    let identity = worker.identity();
    let table = |pid: u32| -> Vec<(i32, std::path::PathBuf)> {
        let mut entries: Vec<_> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let fd = entry.file_name().to_str()?.parse().ok()?;
                Some((fd, std::fs::read_link(entry.path()).ok()?))
            })
            .collect();
        entries.sort();
        entries
    };
    let worker_table = table(identity.process.pid);
    let guardian_table = table(identity.guardian.unwrap().pid);
    worker
        .terminate_tree(Instant::now() + Duration::from_secs(5))
        .unwrap();
    let numbers: Vec<i32> = worker_table.iter().map(|(fd, _)| *fd).collect();
    assert_eq!(numbers, [0, 1, 2, 3, 4, 5, 6], "{worker_table:?}");
    assert_eq!(worker_table[5].1, inputs[0]);
    assert_eq!(worker_table[6].1, inputs[1]);
    for (fd, path) in worker_table.iter().chain(&guardian_table) {
        assert_ne!(path, &sentinel, "engine-only descriptor leaked at {fd}");
    }
}

/// With inputs present an inheritable engine handle still never reaches the
/// worker: the explicit handle list stays exact.
#[cfg(windows)]
#[test]
fn inheritable_windows_engine_handle_is_absent_with_inputs_present() {
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
    let input = temp.path().join("input.bin");
    std::fs::write(&input, b"input").unwrap();
    let mut command = command();
    command
        .inherit_read_only(&std::fs::File::open(&input).unwrap())
        .unwrap();
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
    let mut worker = WorkerProcess::launch(command, [25; 16]).unwrap();
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

/// A directory handle is never a worker input on Windows either.
#[cfg(windows)]
#[test]
fn a_windows_directory_handle_is_not_an_input() {
    use std::os::windows::fs::OpenOptionsExt;
    let temp = tempfile::tempdir().unwrap();
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
        .open(temp.path())
        .unwrap();
    assert!(command().inherit_read_only(&directory).is_err());
}
