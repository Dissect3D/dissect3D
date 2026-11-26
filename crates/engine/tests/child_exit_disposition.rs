//! Guard (2026-11-26, Stage B F3): production engine startup must leave
//! child-exit reaping to direct `waitpid` callers. A process-wide SIGCHLD
//! reaper (tokio's process driver is one) makes the Darwin guardian launch
//! refuse every worker, so a future production use would silently disable
//! macOS execution. This runs the production `run_engine` in its own test
//! process and checks the exact predicate the macOS launcher enforces.
#![cfg(unix)]
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn production_startup_leaves_child_exit_reaping_unclaimed() {
    assert!(
        dissect3d_platform::child_exit_reaping_unclaimed().unwrap(),
        "the test process must start with the default SIGCHLD disposition"
    );
    let directory = TempDir::new().expect("isolated data root");
    let root = directory.path().join("engine");
    // The same multi-threaded runtime `#[tokio::main]` builds for the binary.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = runtime.spawn({
        let root = root.clone();
        async move { dissect3d_engine::run_engine(&root).await }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while !root.join("run/endpoint.json").exists() {
        assert!(!engine.is_finished(), "engine exited before readiness");
        assert!(Instant::now() < deadline, "engine readiness deadline");
        std::thread::sleep(Duration::from_millis(20));
    }
    let unclaimed = dissect3d_platform::child_exit_reaping_unclaimed().unwrap();

    // Stop through the engine's own registered interrupt handler.
    let interrupted = Command::new("kill")
        .arg("-INT")
        .arg(std::process::id().to_string())
        .status()
        .expect("send native interrupt");
    assert!(interrupted.success());
    let stopped = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(20), engine).await })
        .expect("engine stop deadline")
        .expect("engine task");
    assert!(stopped.is_ok(), "engine stopped with an error");
    assert!(
        unclaimed,
        "production startup claimed SIGCHLD; macOS worker launches would be refused"
    );
}
