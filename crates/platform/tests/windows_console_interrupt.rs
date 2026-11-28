#![cfg(windows)]
#![cfg_attr(
    windows,
    expect(
        clippy::expect_used,
        reason = "Windows console interrupt integration test setup"
    )
)]

use std::io::{BufRead, BufReader};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Console::{CTRL_C_EVENT, GenerateConsoleCtrlEvent};
use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;

fn probe_binary() -> PathBuf {
    let current = std::env::current_exe().expect("current test exe");
    let debug_dir = current
        .parent()
        .and_then(|p| p.parent())
        .expect("target debug dir");
    let probe = debug_dir
        .join("examples")
        .join("console_interrupt_probe.exe");
    assert!(
        probe.is_file(),
        "build console_interrupt_probe example first (`cargo build -p dissect3d-platform --examples`): missing {}",
        probe.display()
    );
    probe
}

#[test]
fn create_new_process_group_child_receives_ctrl_c_after_enable_console_ctrl_c() {
    let mut child = Command::new(probe_binary())
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn console_interrupt_probe");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let read_bytes = reader.read_line(&mut line).expect("read ready line");
    assert!(
        read_bytes > 0 && line.trim() == "ready",
        "unexpected probe output: {line:?}"
    );

    // SAFETY: `child.id()` is a live child process group created with
    // `CREATE_NEW_PROCESS_GROUP` sharing this console.
    let sent = unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, child.id()) };
    if sent == 0 {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "GenerateConsoleCtrlEvent(CTRL_C_EVENT, {}) failed: {:?}",
            child.id(),
            std::io::Error::last_os_error()
        );
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("console_interrupt_probe did not exit on CTRL_C_EVENT within 5s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        !status.success(),
        "expected non-zero Ctrl+C termination status, got {status:?}"
    );
}
