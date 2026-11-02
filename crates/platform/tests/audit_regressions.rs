#![cfg(unix)]

use dissect3d_platform::{OwnedRoot, RelativePath, RootPurpose};
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn fifo_probe_child() {
    let Some(path) = std::env::var_os("DISSECT3D_FIFO_PROBE") else {
        return;
    };
    let root = OwnedRoot::open(path.as_ref(), RootPurpose::EngineData).unwrap();
    let name = RelativePath::parse("credential.json").unwrap();
    assert!(root.read_file(&name, 256).is_err());
    assert!(root.file_metadata(&name).is_err());
}

#[test]
fn protected_fifo_is_rejected_without_waiting_for_a_writer() {
    let temp = tempfile::tempdir().unwrap();
    let root_path = temp.path().join("root");
    let _root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData).unwrap();
    let fifo = root_path.join("credential.json");
    assert!(
        Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "fifo_probe_child"])
        .env("DISSECT3D_FIFO_PROBE", &root_path)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("protected FIFO read blocked before checking file type");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
