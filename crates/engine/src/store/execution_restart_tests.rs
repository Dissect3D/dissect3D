//! WE-P07/3-4 through real engine processes: the explicit execution host
//! binary (`examples/execution_test_host`) runs a held real worker, is killed
//! with SIGKILL, and restarts; then it is stopped with SIGINT while another
//! worker runs. Evidence is the host it ran on (WSL2/ext4 here), not native
//! acceptance elsewhere.
#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "Fault and migration tests open the SQLite file directly to plant or inspect states \
              the store API cannot express; production opens only via store/schema.rs"
)]
use super::execution_routes_tests::{enroll, submit, terminal, wait};
use super::fixture_attempts_tests::worker_launch;
use super::launch_identity::decode;
use super::*;
use crate::execution_fixture::preparation::prepare;
use dissect3d_platform::{RootPurpose, WorkerIdentity, process_matches};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

fn host_binary() -> PathBuf {
    let path = std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("examples/execution_test_host");
    assert!(
        path.is_file(),
        "BLOCKED: cargo build -p dissect3d-engine --examples --features test-support"
    );
    path
}

/// A prepared r2 root with one enrolled, execution-authorized client.
fn prepared() -> (tempfile::TempDir, PathBuf, (ClientId, [u8; 32])) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine");
    prepare(&path, &worker_launch()).unwrap();
    let root = OwnedRoot::open(&path, RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    let store = Store::open(root, lease, &CorePolicy::default()).unwrap();
    let identity = store.identity().unwrap();
    let client = enroll(&store, &identity, 0x31);
    drop(store);
    (dir, path, client)
}

/// Start the host and connect once it published its endpoint.
async fn start(path: &Path, (client, secret): &(ClientId, [u8; 32])) -> (Child, Client) {
    let endpoint = path.join("run/endpoint.json");
    let _ = std::fs::remove_file(&endpoint);
    let mut child = Command::new(host_binary())
        .arg("--data-root")
        .arg(path)
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !endpoint.is_file() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "host exited at startup"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "host startup timed out"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let root = OwnedRoot::open(path, RootPurpose::EngineData).unwrap();
    let discovery = dissect3d_connection::verify_engine(&root, Duration::from_secs(5))
        .unwrap()
        .discovery;
    let api = Client::new(
        ConnectionMaterial::new(
            discovery.base_url,
            discovery.installation_id,
            discovery.instance_id,
            client.clone(),
            discovery.trust_anchor_der,
            discovery.trust_anchor_sha256.try_into().unwrap(),
            SecretToken::new(secret.to_vec()).unwrap(),
        ),
        ClientLimits::default(),
    )
    .unwrap();
    (child, api)
}

/// The recorded launch identity of the job's attempt.
fn recorded(path: &Path, job: &JobId) -> WorkerIdentity {
    let json: String = Connection::open(path.join(DATABASE_NAME))
        .unwrap()
        .query_row(
            "SELECT native_identity_json FROM job_attempts WHERE job_id=?1",
            [job.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    decode(&json).unwrap()
}

/// Whether any recorded member of the worker tree is still alive.
fn alive(identity: &WorkerIdentity) -> bool {
    std::iter::once(&identity.process)
        .chain(identity.guardian.as_ref())
        .any(|member| process_matches(member).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_death_and_signal_shutdown_reconcile_real_workers() {
    let (_dir, path, client) = prepared();
    let bound = Duration::from_secs(120);

    // 1. A held real worker; then the engine dies without any shutdown.
    let (mut host, api) = start(&path, &client).await;
    let (held, _) = submit(
        &api,
        "restart-held",
        serde_json::json!({"hold_before_candidate": true}),
    )
    .await;
    wait(&api, &held.job_id, |s| s.summary.phase == "executing").await;
    let tree = recorded(&path, &held.job_id);
    assert!(alive(&tree), "the worker runs before the engine dies");
    host.kill().unwrap();
    host.wait().unwrap();
    // Owner-death containment: the tree goes without the engine.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while alive(&tree) {
        assert!(
            std::time::Instant::now() < deadline,
            "a survivor outlived its engine"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // 2. Restart: interrupted, cleanup established before dispatch, and the
    //    freed slot runs new work.
    let (mut host, api) = start(&path, &client).await;
    let restarted = api.execution_job(&held.job_id).await.unwrap();
    assert_eq!(restarted.summary.state, ExecutionJobState::Interrupted);
    assert_eq!(restarted.summary.cleanup.status, CleanupStatus::Confirmed);
    assert_eq!(
        restarted.summary.cleanup.reason.as_deref(),
        Some("owner_death_containment")
    );
    let (fresh, _) = submit(&api, "restart-fresh", serde_json::json!({})).await;
    let done = tokio::time::timeout(bound, wait(&api, &fresh.job_id, terminal))
        .await
        .unwrap();
    assert_eq!(done.summary.state, ExecutionJobState::Succeeded);

    // 3. SIGINT with a held worker: a clean stop within the core deadline.
    let (stopping, _) = submit(
        &api,
        "restart-sigint",
        serde_json::json!({"hold_before_candidate": true}),
    )
    .await;
    wait(&api, &stopping.job_id, |s| s.summary.phase == "executing").await;
    let tree = recorded(&path, &stopping.job_id);
    let signal = Command::new("kill")
        .args(["-INT", &host.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    let started = std::time::Instant::now();
    let status = host.wait().unwrap();
    assert!(status.success(), "clean shutdown: {status:?}");
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "{:?}",
        started.elapsed()
    );
    assert!(!alive(&tree), "shutdown confirmed the tree's cleanup");

    // The outcome was committed before the engine exited.
    let (mut host, api) = start(&path, &client).await;
    let stopped = api.execution_job(&stopping.job_id).await.unwrap();
    assert_eq!(stopped.summary.state, ExecutionJobState::Interrupted);
    assert_eq!(
        stopped.summary.outcome.as_ref().map(|o| o.code.as_str()),
        Some("engine_shutdown")
    );
    assert_eq!(stopped.summary.cleanup.status, CleanupStatus::Confirmed);
    assert_eq!(
        stopped.summary.cleanup.reason, None,
        "a live witness, not restart evidence"
    );
    host.kill().unwrap();
    host.wait().unwrap();
}
