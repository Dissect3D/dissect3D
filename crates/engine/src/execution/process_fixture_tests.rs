//! WE-P04/6 real-process fixtures: the supervisor drives an actual contained
//! worker process through `PlatformLauncher`, its inherited control pipes and
//! its separate diagnostics pipe. The worker is this test binary re-executed
//! with a private mode; it is not a provider or the WE-P05 r2 worker.
//!
//! On Linux and macOS the platform guardian must already be built next to this binary
//! (`cargo build -p dissect3d-platform --bins`); a missing guardian fails the
//! test rather than skipping it.
use super::fake_worker::{LedgerMode, TestLedger, line};
use super::launcher::{PlatformLauncher, WORKER_SESSION_ENV};
use super::supervisor::WorkerSupervisor;
use super::supervisor_tests::{bounded, dispatch, limits, plan, process_limits};
use super::types::*;
use crate::store::execution::DispatchRecord;
use dissect3d_platform::{ProcessIdentity, ProcessWatcher, WorkerCommand};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

const ENTRY: &str = "execution::process_fixture_tests::fixture_worker";
const MODE_ENV: &str = "D3D_PROCESS_FIXTURE";
const ROOT_ENV: &str = "D3D_FIXTURE_ROOT";

/// Worker entry; a no-op in a normal test run.
#[test]
fn fixture_worker() {
    let Ok(mode) = std::env::var(MODE_ENV) else {
        return;
    };
    let root = std::env::var_os(ROOT_ENV).map(PathBuf::from).unwrap();
    if mode == "grandchild" {
        grandchild(&root);
    }
    worker_main(&mode, &root);
}

fn record(root: &Path, name: &str) {
    let id = dissect3d_platform::current_process_identity().unwrap();
    let temporary = root.join(format!("{name}.tmp"));
    std::fs::write(&temporary, format!("{} {}", id.pid, id.start_marker)).unwrap();
    std::fs::rename(temporary, root.join(format!("{name}.id"))).unwrap();
}

fn grandchild(root: &Path) -> ! {
    record(root, "grandchild");
    // Only an escaped grandchild can outlive the tree; it stops on request
    // (or after a bounded lifetime) instead of leaking past the test.
    let started = Instant::now();
    loop {
        if root.join("stop").exists() || started.elapsed() > Duration::from_secs(30) {
            std::process::exit(0);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Speaks the private protocol over the inherited control pipes. Output on
/// stdout/stderr (including the test harness's) is diagnostics only.
fn worker_main(mode: &str, root: &Path) -> ! {
    record(root, "worker");
    let session = std::env::var(WORKER_SESSION_ENV).unwrap();
    let (commands, mut reports) = dissect3d_platform::worker_control_channels().unwrap();
    let mut send = |bytes: Vec<u8>| {
        if reports.write_all(&bytes).is_err() {
            std::process::exit(3);
        }
    };
    let adapter = if mode == "incompatible" {
        "other.adapter"
    } else {
        "test.mesh-copy"
    };
    send(line(
        &session,
        "hello",
        json!({
            "worker_build_sha256": "a".repeat(64),
            "adapter_id": adapter,
            "adapter_revision": "fixture-r2",
            "features": ["cooperative_cancel"],
        }),
        &[],
    ));
    println!("fixture worker: upstream-style output stays in diagnostics");
    for text in std::io::BufReader::new(commands).lines() {
        let Ok(text) = text else { break };
        let command: Value = serde_json::from_str(&text).unwrap();
        let id = command["command_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let scoped = |reply: bool| {
            let mut extra = vec![
                ("job_id", command["job_id"].clone()),
                ("attempt_id", command["attempt_id"].clone()),
            ];
            if reply {
                extra.push(("in_reply_to", Value::from(id.clone())));
            }
            extra
        };
        let reply = [("in_reply_to", Value::from(id.clone()))];
        match command["kind"].as_str().unwrap_or_default() {
            "configure" => send(line(
                &session,
                "configured",
                json!({"accepted": true}),
                &reply,
            )),
            "load" => send(line(
                &session,
                "loaded",
                json!({
                    "grant_id": command["payload"]["grant_id"],
                    "resolution_sha256": "b".repeat(64),
                }),
                &scoped(true),
            )),
            "execute" => {
                let candidate = line(
                    &session,
                    "candidate",
                    json!({"description_handle": "out:desc", "files": [
                        {"relative_name": "mesh.obj", "byte_length": 10, "sha256": "d".repeat(64)}
                    ]}),
                    &scoped(false),
                );
                match mode {
                    "candidate" => send(candidate),
                    "environment" => {
                        let mut names: Vec<_> = std::env::vars_os()
                            .map(|(name, _)| name.to_string_lossy().into_owned())
                            .collect();
                        names.sort();
                        std::fs::write(
                            root.join("environment"),
                            names.join(
                                "
",
                            ),
                        )
                        .unwrap();
                        send(candidate);
                    }
                    "flood" => {
                        // Past the 1 MiB capture: drained, counted, truncated.
                        let chunk = vec![b'x'; 64 * 1024];
                        let mut out = std::io::stdout().lock();
                        for _ in 0..32 {
                            out.write_all(&chunk).unwrap();
                        }
                        out.flush().unwrap();
                        drop(out);
                        send(candidate);
                    }
                    "reject" => send(line(
                        &session,
                        "rejected",
                        json!({"code": "input_unsupported"}),
                        &scoped(false),
                    )),
                    "declared_oom" => send(line(
                        &session,
                        "execution_failed",
                        json!({"code": "out_of_memory"}),
                        &scoped(false),
                    )),
                    // Crash-style failure: no report, abnormal exit.
                    "crash" => std::process::abort(),
                    "blocked" | "escape" => {
                        let mut child =
                            std::process::Command::new(std::env::current_exe().unwrap());
                        child
                            .args(["--exact", ENTRY, "--nocapture", "--test-threads=1"])
                            .env(MODE_ENV, "grandchild");
                        #[cfg(target_os = "linux")]
                        if mode == "escape" {
                            // Leaves the worker's process group: the guardian
                            // cannot confirm closure of this descendant.
                            use std::os::unix::process::CommandExt;
                            child.process_group(0);
                        }
                        let mut child = child.spawn().unwrap();
                        std::thread::spawn(move || {
                            let _ = child.wait();
                        });
                        // The control loop blocks natively: no cancel_ack, no
                        // reads. Only external termination ends this tree.
                        loop {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                    other => panic!("unknown fixture mode {other}"),
                }
            }
            "ping" => send(line(&session, "pong", json!({}), &reply)),
            "cancel" => send(line(
                &session,
                "cancel_ack",
                json!({"observed": true}),
                &scoped(true),
            )),
            "shutdown" => {
                send(line(
                    &session,
                    "shutdown_ack",
                    json!({"observed": true}),
                    &reply,
                ));
                std::process::exit(0);
            }
            _ => {}
        }
    }
    std::process::exit(0)
}

struct Fixture {
    root: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }
    fn command(&self, mode: &str) -> WorkerCommand {
        let mut command = WorkerCommand::new(std::env::current_exe().unwrap());
        command.args = ["--exact", ENTRY, "--nocapture", "--test-threads=1"]
            .map(Into::into)
            .to_vec();
        command.environment = vec![
            (MODE_ENV.into(), mode.into()),
            (ROOT_ENV.into(), self.root.path().as_os_str().into()),
        ];
        #[cfg(unix)]
        {
            let guardian = std::env::current_exe()
                .unwrap()
                .parent()
                .and_then(Path::parent)
                .unwrap()
                .join("dissect3d-worker-guardian");
            assert!(
                guardian.is_file(),
                "build the guardian first: cargo build -p dissect3d-platform --bins ({})",
                guardian.display()
            );
            command.guardian = Some(guardian);
        }
        command
    }
    fn identity(&self, name: &str) -> Option<ProcessIdentity> {
        let text = std::fs::read_to_string(self.root.path().join(format!("{name}.id"))).ok()?;
        let (pid, marker) = text.split_once(' ')?;
        Some(ProcessIdentity {
            pid: pid.parse().ok()?,
            start_marker: marker.into(),
        })
    }
    /// The recorded process has exited (or never matched a live process).
    fn gone(&self, name: &str) -> bool {
        let identity = self.identity(name).expect("process recorded its identity");
        match ProcessWatcher::new(&identity) {
            Ok(watcher) => watcher.wait(Duration::from_secs(2)).unwrap(),
            Err(dissect3d_platform::PlatformError::NotFound) => true,
            Err(error) => panic!("watcher failed: {error:?}"),
        }
    }
}

/// Run one real attempt. `stop` is sent once `grandchild.id` exists (the
/// worker is executing and its control loop is blocked).
async fn run(
    fixture: &Fixture,
    record: &DispatchRecord,
    mode: &str,
    limits: SupervisionLimits,
    stop: Option<StopIntent>,
) -> AttemptExit {
    run_recorded(fixture, record, mode, limits, stop).await.0
}
/// As `run`, also returning the launch ledger the supervisor recorded into.
async fn run_recorded(
    fixture: &Fixture,
    record: &DispatchRecord,
    mode: &str,
    limits: SupervisionLimits,
    stop: Option<StopIntent>,
) -> (AttemptExit, Arc<TestLedger>) {
    let ledger = TestLedger::new(LedgerMode::Accept);
    let (stop_tx, stop_rx) = watch::channel(StopIntent::Continue);
    let (obs_tx, _obs_rx) = watch::channel(None);
    let stop_tx = Arc::new(stop_tx);
    let marker = fixture.root.path().join("grandchild.id");
    let stopper = stop.map(|intent| {
        let stop_tx = Arc::clone(&stop_tx);
        tokio::spawn(async move {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let _ = stop_tx.send(intent);
        })
    });
    let launcher = PlatformLauncher::new(fixture.command(mode));
    let exit = bounded(WorkerSupervisor::run(
        record,
        plan(limits),
        launcher,
        Arc::clone(&ledger),
        stop_rx,
        &obs_tx,
    ))
    .await;
    if let Some(stopper) = stopper {
        stopper.abort();
    }
    (exit, ledger)
}

fn ended(exit: &AttemptExit) -> (AttemptEnd, &AttemptCleanup) {
    match exit {
        AttemptExit::Ended { end, cleanup, .. } => (*end, cleanup),
        other => panic!("expected an ended attempt, got {other:?}"),
    }
}
fn categories(exit: &AttemptExit) -> Vec<&'static str> {
    let (AttemptExit::Ended { diagnostics, .. } | AttemptExit::Candidate { diagnostics, .. }) =
        exit;
    diagnostics
        .categories
        .iter()
        .map(|(name, _)| *name)
        .collect()
}

#[tokio::test]
async fn real_worker_candidate_only_after_confirmed_tree_cleanup() {
    let fixture = Fixture::new();
    let record = dispatch(None);
    let (exit, ledger) = run_recorded(&fixture, &record, "candidate", process_limits(), None).await;
    let AttemptExit::Candidate {
        report,
        cleanup,
        diagnostics,
    } = &exit
    else {
        panic!("expected a candidate, got {exit:?}");
    };
    assert_eq!(report.files.len(), 1);
    // The witness is bound to this session and this native process.
    let worker = fixture.identity("worker").unwrap();
    assert_eq!(cleanup.identity().process, worker);
    assert_eq!(
        cleanup
            .identity()
            .session_nonce
            .map(|b| format!("{b:02x}"))
            .concat(),
        record.session_id["ses_".len()..]
    );
    // The identity durably recorded at launch is exactly the one the native
    // witness confirms, so the Store's release check can bind them.
    assert_eq!(ledger.identities(), [cleanup.identity().clone()]);
    // Harness/upstream output reached diagnostics, never the control parser.
    assert!(diagnostics.bytes_observed > 0);
    assert!(!categories(&exit).contains(&"worker_protocol_violation"));
    assert!(fixture.gone("worker"));
}

#[tokio::test]
async fn worker_environment_is_exactly_the_scoped_launch_list() {
    let fixture = Fixture::new();
    let exit = run(
        &fixture,
        &dispatch(None),
        "environment",
        process_limits(),
        None,
    )
    .await;
    assert!(matches!(exit, AttemptExit::Candidate { .. }), "{exit:?}");
    let names = std::fs::read_to_string(fixture.root.path().join("environment")).unwrap();
    let mut names: Vec<_> = names.lines().map(str::to_uppercase).collect();
    names.sort();
    // No ambient PATH, profile, proxy, credential or engine variables.
    // This fixture worker is the test binary, which links CoreFoundation (via
    // reqwest's platform verifier). CoreFoundation sets this one variable in
    // its own process at load, even from an empty environment; the guardian
    // links no CoreFoundation and forwards only the scoped list.
    let self_set = cfg!(target_os = "macos").then_some("__CF_USER_TEXT_ENCODING");
    let expected: Vec<&str> = [
        "D3D_FIXTURE_ROOT",
        "D3D_PROCESS_FIXTURE",
        "DISSECT3D_WORKER_CONTROL",
        "DISSECT3D_WORKER_INPUTS",
        "DISSECT3D_WORKER_SESSION",
    ]
    .into_iter()
    .chain(self_set)
    .collect();
    assert_eq!(names, expected);
}

/// Cleanup of a "blocked" tree, whose worker forked a grandchild. Linux and
/// Windows confirm closure of the whole tree. The conservative Darwin guardian
/// has no NOTE_TRACK and never confirms closure of a tree that forked, so
/// macOS asserts that fail-closed outcome until forked-descendant closure
/// lands (WE-P02). Callers still require the grandchild to be gone.
fn assert_forked_tree_cleanup(cleanup: &AttemptCleanup) {
    #[cfg(target_os = "macos")]
    assert!(
        matches!(cleanup, AttemptCleanup::Fault("cleanup_ownership_lost")),
        "{cleanup:?}"
    );
    #[cfg(not(target_os = "macos"))]
    assert!(
        matches!(cleanup, AttemptCleanup::Confirmed(_)),
        "{cleanup:?}"
    );
}

#[tokio::test]
async fn blocked_native_control_is_terminated_externally_on_cancel() {
    let fixture = Fixture::new();
    let record = dispatch(None);
    let started = Instant::now();
    let exit = run(
        &fixture,
        &record,
        "blocked",
        process_limits(),
        Some(StopIntent::UserCancel),
    )
    .await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::Stopped(StopIntent::UserCancel));
    assert_forked_tree_cleanup(cleanup);
    // No worker cooperation: the whole real tree is gone.
    assert!(fixture.gone("worker"));
    assert!(fixture.gone("grandchild"));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn blocked_worker_past_the_attempt_deadline_is_a_typed_failure() {
    let fixture = Fixture::new();
    let record = dispatch(Some(Duration::from_millis(1_500)));
    let exit = run(&fixture, &record, "blocked", process_limits(), None).await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::DeadlineExceeded);
    assert_forked_tree_cleanup(cleanup);
    assert!(categories(&exit).contains(&"execution_deadline_exceeded"));
    assert!(fixture.gone("grandchild"));
}

#[tokio::test]
async fn crash_during_execution_is_failure_with_confirmed_cleanup() {
    let fixture = Fixture::new();
    let exit = run(&fixture, &dispatch(None), "crash", process_limits(), None).await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::WorkerFailed);
    assert!(
        matches!(cleanup, AttemptCleanup::Confirmed(_)),
        "{cleanup:?}"
    );
    assert!(fixture.gone("worker"));
}

#[tokio::test]
async fn declared_out_of_memory_is_a_safe_typed_failure() {
    let fixture = Fixture::new();
    let exit = run(
        &fixture,
        &dispatch(None),
        "declared_oom",
        process_limits(),
        None,
    )
    .await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::WorkerFailed);
    assert!(
        matches!(cleanup, AttemptCleanup::Confirmed(_)),
        "{cleanup:?}"
    );
    assert!(categories(&exit).contains(&"worker_declared_failure"));
}

#[tokio::test]
async fn early_rejection_is_failure_without_candidate() {
    let fixture = Fixture::new();
    let exit = run(&fixture, &dispatch(None), "reject", process_limits(), None).await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::WorkerFailed);
    assert!(
        matches!(cleanup, AttemptCleanup::Confirmed(_)),
        "{cleanup:?}"
    );
}

#[tokio::test]
async fn incompatible_hello_is_contained_before_load() {
    let fixture = Fixture::new();
    let exit = run(
        &fixture,
        &dispatch(None),
        "incompatible",
        process_limits(),
        None,
    )
    .await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::ProtocolError);
    assert!(
        matches!(cleanup, AttemptCleanup::Confirmed(_)),
        "{cleanup:?}"
    );
}

#[tokio::test]
async fn diagnostic_flood_is_capped_and_never_blocks_control() {
    let fixture = Fixture::new();
    let exit = run(&fixture, &dispatch(None), "flood", process_limits(), None).await;
    let AttemptExit::Candidate { diagnostics, .. } = &exit else {
        panic!("expected a candidate, got {exit:?}");
    };
    // The worker could send its candidate only after the engine drained the
    // flood; at most one pipe buffer (64 KiB) may remain unread at cleanup.
    assert!(
        diagnostics.bytes_observed >= 2 * 1024 * 1024 - 64 * 1024,
        "{diagnostics:?}"
    );
    assert!(diagnostics.bytes_retained <= 1024 * 1024);
    assert!(diagnostics.truncated);
}

#[tokio::test]
async fn zero_termination_bound_never_confirms_without_observed_closure() {
    let fixture = Fixture::new();
    let limits = SupervisionLimits {
        termination: Duration::ZERO,
        ..limits()
    };
    let exit = run(
        &fixture,
        &dispatch(None),
        "blocked",
        limits,
        Some(StopIntent::UserCancel),
    )
    .await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::Stopped(StopIntent::UserCancel));
    let grandchild = fixture.identity("grandchild").unwrap();
    match cleanup {
        // Windows Job Object accounting can observe closure synchronously:
        // confirmation then means the tree is already gone, with no wait.
        AttemptCleanup::Confirmed(_) => match ProcessWatcher::new(&grandchild) {
            Ok(watcher) => assert!(watcher.wait(Duration::ZERO).unwrap()),
            Err(error) => assert_eq!(error, dissect3d_platform::PlatformError::NotFound),
        },
        AttemptCleanup::Fault(_) => {
            assert!(categories(&exit).contains(&"cleanup_fault"));
            // The native fallback still owns the tree; it is not left running.
            assert!(fixture.gone("grandchild"));
        }
        other => panic!("unexpected cleanup {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn escaped_descendant_is_cleanup_uncertainty_not_success() {
    let fixture = Fixture::new();
    let limits = SupervisionLimits {
        termination: Duration::from_secs(1),
        ..limits()
    };
    let exit = run(
        &fixture,
        &dispatch(None),
        "escape",
        limits,
        Some(StopIntent::UserCancel),
    )
    .await;
    let escaped_alive =
        dissect3d_platform::process_matches(&fixture.identity("grandchild").unwrap()).unwrap();
    // Release the escaped test process before asserting.
    std::fs::write(fixture.root.path().join("stop"), b"stop").unwrap();
    let (_, cleanup) = ended(&exit);
    assert!(matches!(cleanup, AttemptCleanup::Fault(_)), "{cleanup:?}");
    assert!(
        escaped_alive,
        "the escaped descendant really survived the group kill"
    );
    assert!(fixture.gone("grandchild"));
}

#[tokio::test]
async fn rejected_launch_starts_no_process() {
    let fixture = Fixture::new();
    let mut command = fixture.command("candidate");
    command.executable = command.executable.with_file_name("absent-worker.exe");
    let (stop_tx, stop_rx) = watch::channel(StopIntent::Continue);
    let (obs_tx, _obs_rx) = watch::channel(None);
    let ledger = TestLedger::new(LedgerMode::Accept);
    let exit = bounded(WorkerSupervisor::run(
        &dispatch(None),
        plan(limits()),
        PlatformLauncher::new(command),
        Arc::clone(&ledger),
        stop_rx,
        &obs_tx,
    ))
    .await;
    drop(stop_tx);
    assert!(ledger.identities().is_empty());
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::LaunchFailed);
    assert!(
        matches!(cleanup, AttemptCleanup::NeverLaunched(_)),
        "{cleanup:?}"
    );
    assert!(fixture.identity("worker").is_none());
}
