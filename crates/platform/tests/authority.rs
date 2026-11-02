use std::fs;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use dissect3d_platform::{AuthorityLease, OwnedRoot, PlatformError, RootPurpose};
use tempfile::TempDir;

const CHILD_ROOT: &str = "DISSECT3D_AUTHORITY_CHILD_ROOT";
const CHILD_READY: &str = "DISSECT3D_AUTHORITY_CHILD_READY";

// The exact-test child mode holds a real OS lock in a separate process. The
// parent can therefore verify kernel ownership and release-on-exit semantics,
// rather than relying on two threads sharing one process's lock behavior.
#[test]
fn child_holds_authority_until_process_exit() {
    let Ok(path) = std::env::var(CHILD_ROOT) else {
        return;
    };
    let root = OwnedRoot::open(path.as_ref(), RootPurpose::EngineData).expect("child root");
    let _lease = AuthorityLease::acquire(&root).expect("child lease");
    fs::write(std::env::var(CHILD_READY).expect("ready path"), b"ready").expect("signal ready");
    thread::sleep(Duration::from_secs(30));
}

#[test]
fn a_second_process_cannot_acquire_until_the_owner_dies() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("owner root");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private root creation");
    let ready = parent.path().join("child.ready");
    let mut child = spawn_holder(&root_path, &ready);
    wait_for_file(&ready, Duration::from_secs(5));

    assert!(matches!(
        AuthorityLease::acquire(&root),
        Err(PlatformError::Busy)
    ));
    stop_child(&mut child);
    drop(child);
    let _lease = AuthorityLease::acquire(&root).expect("lease released after owner exit");
}

fn spawn_holder(root: &std::path::Path, ready: &std::path::Path) -> Child {
    Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "child_holds_authority_until_process_exit",
            "--nocapture",
        ])
        .env(CHILD_ROOT, root)
        .env(CHILD_READY, ready)
        .spawn()
        .expect("spawn test-owned lease holder")
}

fn wait_for_file(path: &std::path::Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("test-owned child did not acquire the lease before deadline");
}

fn stop_child(child: &mut Child) {
    child.kill().expect("terminate only test-owned child");
    child.wait().expect("reap test-owned child");
}
