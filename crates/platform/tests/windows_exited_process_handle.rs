//! Windows keeps an exited process object alive while any handle to it remains
//! open (for example, an antivirus scanner or indexer holding a query handle).
//! `process_matches` must report such an exited process as absent, never live.
#![cfg_attr(
    windows,
    expect(
        clippy::unwrap_used,
        reason = "integration test helpers; engineering.md Rule 6 permits unwrap in test setup"
    )
)]
#![cfg(windows)]

use dissect3d_platform::{
    PlatformError, ProcessIdentity, ProcessWatcher, current_process_identity, process_matches,
    wait_for_process_exit,
};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

const HELPER: &str = "exited_process_child_helper";
const HELPER_ENV: &str = "DISSECT3D_EXITED_PROCESS_HELPER";
const EXIT_CODE_ENV: &str = "DISSECT3D_EXITED_PROCESS_CODE";

const MARKER_PREFIX: &str = "DISSECT3D_MARKER:";

#[test]
fn exited_process_child_helper() {
    if std::env::var_os(HELPER_ENV).is_none() {
        return;
    }
    let identity = current_process_identity().expect("child process identity");
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\n{MARKER_PREFIX}{}", identity.start_marker).unwrap();
    stdout.flush().unwrap();
    if let Ok(code) = std::env::var(EXIT_CODE_ENV) {
        let code: i32 = code.parse().unwrap();
        std::process::exit(code);
    }
    std::thread::sleep(Duration::from_secs(60));
}

fn spawn_helper(exit_code: Option<i32>) -> (Child, ProcessIdentity) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([HELPER, "--exact", "--test-threads=1", "--nocapture"])
        .env(HELPER_ENV, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(code) = exit_code {
        command.env(EXIT_CODE_ENV, code.to_string());
    }
    let mut child = command.spawn().unwrap();
    let pid = child.id();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let start_marker = loop {
        line.clear();
        let read = reader.read_line(&mut line).unwrap();
        assert!(read > 0, "helper did not report its start marker");
        if let Some(marker) = line.trim().strip_prefix(MARKER_PREFIX) {
            break marker.to_owned();
        }
    };
    let identity = ProcessIdentity { pid, start_marker };
    (child, identity)
}

fn open_external_query_handle(pid: u32) -> OwnedHandle {
    // SAFETY: OpenProcess returns a unique owned handle or null.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    assert!(
        !raw.is_null(),
        "failed to open extra handle to child pid {pid}: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: raw is a non-null handle owned by this call.
    unsafe { OwnedHandle::from_raw_handle(raw.cast()) }
}

#[test]
fn exited_process_with_retained_handle_does_not_match() {
    let (mut child, identity) = spawn_helper(None);
    assert!(
        process_matches(&identity).unwrap(),
        "live child must match its recorded identity"
    );

    // Simulate another program (e.g. Defender or an indexer) holding a handle
    // to the process object after our child handle closes.
    let _external_handle = open_external_query_handle(identity.pid);

    child.kill().unwrap();
    child.wait().unwrap();
    drop(child);

    assert!(
        !process_matches(&identity).unwrap(),
        "exited process pinned by an external handle must be reported absent"
    );
    assert!(matches!(
        ProcessWatcher::new(&identity),
        Err(PlatformError::NotFound)
    ));
    assert!(
        wait_for_process_exit(&identity, Duration::from_secs(1)).unwrap(),
        "wait_for_process_exit must treat an exited pinned process as exited"
    );
}

#[test]
fn exited_process_with_still_active_code_and_retained_handle_does_not_match() {
    // Exit code 259 equals STILL_ACTIVE; exit detection must not rely on
    // GetExitCodeProcess != STILL_ACTIVE.
    let (mut child, identity) = spawn_helper(Some(259));
    let _external_handle = open_external_query_handle(identity.pid);

    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(259));
    drop(child);

    assert!(
        !process_matches(&identity).unwrap(),
        "exited process with exit code 259 pinned by a handle must be reported absent"
    );
}
