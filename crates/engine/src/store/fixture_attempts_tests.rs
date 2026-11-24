//! WE-P06/3 real attempt source for the prepared r2 package, driven by the
//! controller with the real Store, real contained worker processes (this test
//! binary re-executed as the r2 worker), real publication and finalization.
//!
//! On Linux the guardian must already be built
//! (`cargo build -p dissect3d-platform --bins`). Evidence is WSL2/ext4 or the
//! host it ran on; it is not native acceptance of another platform.
use super::execution_controller_tests::{
    Faults, Shared, accept as accept_r1, facts, result_rows, terminal_within,
};
use super::retry_tests::{authorize, db};
use super::*;
use crate::execution::controller::{
    AttemptSource, ExecutionDependencies, ExecutionHandle, ExecutionLimits, start,
};
use crate::execution::scheduler::Eligibility;
use crate::execution::supervisor_tests::process_limits;
use crate::execution::types::{StopIntent, SupervisionLimits};
use crate::execution_fixture::attempts::{FixtureAttempts, NOT_EXECUTABLE};
use crate::execution_fixture::preparation::{
    PreparedExecutionFixture, WorkerLaunch, load, prepare,
};
use crate::submission::admission::{PreparedAdmission, build_execution_candidate};

/// Harness bound for one real-process job (not a product bound).
const BOUND: std::time::Duration = std::time::Duration::from_secs(120);
const ENTRY: &str = "execution::r2_worker_tests::r2_worker_entry";

pub(super) fn worker_launch() -> WorkerLaunch {
    let guardian = cfg!(target_os = "linux").then(|| {
        let path = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(std::path::Path::parent)
            .unwrap()
            .join("dissect3d-worker-guardian");
        assert!(
            path.is_file(),
            "build the guardian first: cargo build -p dissect3d-platform --bins"
        );
        path
    });
    WorkerLaunch {
        executable: std::env::current_exe().unwrap(),
        args: ["--exact", ENTRY, "--nocapture", "--test-threads=1"]
            .map(str::to_owned)
            .to_vec(),
        environment: vec![("D3D_R2_WORKER".to_owned(), "1".to_owned())],
        guardian,
    }
}

/// A Store whose root also holds the explicitly prepared r2 package.
fn prepared_store() -> (Arc<Shared>, PreparedExecutionFixture) {
    let dir = tempfile::tempdir().unwrap();
    prepare(&dir.path().join("engine"), &worker_launch()).unwrap();
    let shared = Shared::new(Fixture::create(dir), Faults::default());
    let fixture = load(&shared.f.root).unwrap();
    (shared, fixture)
}

/// Accept an r2 job through the real admission path with `parameters`.
pub(super) fn accept_r2(
    f: &Fixture,
    fixture: &PreparedExecutionFixture,
    key: &str,
    parameters: serde_json::Value,
) -> JobId {
    let input = f.capture();
    let request = decode_execution_request(
        &serde_json::to_vec(&serde_json::json!({
            "api_version": "1.0",
            "support_ref": "test.mesh-copy@fixture-r2",
            "task": {"id": "dissect3d.test.mesh-copy", "version": "1.0"},
            "inputs": {"mesh": [{"input_id": input.input_id}]},
            "parameters": parameters,
            "required_features": [EXECUTION_FEATURE],
            "evaluation_consent": false,
            "execution": {"timeout_ms": 600000}
        }))
        .unwrap(),
    )
    .unwrap();
    let pins = f
        .store
        .pin_verified_inputs(f.auth.clone(), vec![input.input_id.clone()])
        .unwrap();
    let mut readers = BTreeMap::new();
    let path = RelativePath::parse(format!("inputs/data/{}.bin", input.input_id.as_str())).unwrap();
    readers.insert(
        input.input_id.as_str().to_owned(),
        Box::new(f.root.open_immutable_input(&path).unwrap()) as Box<dyn Read + Send>,
    );
    let candidate = build_execution_candidate(
        &fixture.catalog,
        &PreparedAdmission::from_verified_fixture(&fixture.readiness),
        &request,
        encode_execution_request(&request).unwrap().len(),
        pins,
        readers,
    )
    .unwrap();
    f.store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse(key).unwrap(),
            request,
            candidate,
        )
        .unwrap()
        .job_id
}

fn controller(shared: &Arc<Shared>, fixture: PreparedExecutionFixture) -> ExecutionHandle {
    let root = Arc::new(OwnedRoot::open(shared.f.root.path(), RootPurpose::EngineData).unwrap());
    let limits = SupervisionLimits {
        handshake: SupervisionLimits::CONTRACT.handshake,
        load: SupervisionLimits::CONTRACT.load,
        ..process_limits()
    };
    start(ExecutionDependencies {
        store: Arc::clone(shared),
        root: Arc::clone(&root),
        source: Arc::new(FixtureAttempts::new(fixture, root).with_limits(limits)),
        limits: ExecutionLimits::CONTROLLED,
    })
}

fn cleanup(f: &Fixture, job: &JobId) -> (String, String) {
    db(f)
        .query_row(
            "SELECT e.cleanup_status,a.cleanup_status FROM job_execution e
             JOIN job_attempts a USING(job_id) WHERE e.job_id=?1",
            [job.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

fn phase(f: &Fixture, job: &JobId) -> String {
    db(f)
        .query_row(
            "SELECT phase FROM job_execution WHERE job_id=?1",
            [job.as_str()],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prepared_r2_job_runs_through_the_real_worker_to_publication() {
    let (shared, fixture) = prepared_store();
    let job = accept_r2(&shared.f, &fixture, "r2-publish", serde_json::json!({}));
    let _handle = controller(&shared, fixture);
    let (state, outcome, held, attempts) = terminal_within(&shared.f, &job, BOUND).await;
    assert_eq!((state.as_str(), outcome), ("succeeded", None));
    assert_eq!((held, attempts), (0, 1));
    assert_eq!(result_rows(&shared.f, &job), 1);
    assert_eq!(
        cleanup(&shared.f, &job),
        ("confirmed".into(), "confirmed".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_r1_job_stays_blocked_while_eligible_r2_work_runs() {
    let (shared, fixture) = prepared_store();
    // Older r1 acceptance first: it keeps its place and is never remapped.
    let (r1, _) = accept_r1(&shared.f, "r1-retained");
    let r2 = accept_r2(&shared.f, &fixture, "r2-after-r1", serde_json::json!({}));
    let r1_resolution: String = db(&shared.f)
        .query_row(
            "SELECT resolved_json FROM jobs WHERE job_id=?1",
            [r1.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    // The real source blocks the r1 job and offers the r2 job.
    let root = Arc::new(OwnedRoot::open(shared.f.root.path(), RootPurpose::EngineData).unwrap());
    let source = FixtureAttempts::new(load(&shared.f.root).unwrap(), root);
    let queued = shared.f.store.queued_candidates(0, 8).unwrap();
    let verdicts: Vec<_> = queued
        .iter()
        .map(|c| (c.job_id.clone(), source.eligibility(c)))
        .collect();
    assert_eq!(
        verdicts,
        vec![
            (r1.clone(), Eligibility::Blocked(NOT_EXECUTABLE)),
            (
                r2.clone(),
                Eligibility::Ready {
                    resources: vec!["cpu:fixture".into()]
                }
            ),
        ]
    );
    let _handle = controller(&shared, fixture);
    assert_eq!(terminal_within(&shared.f, &r2, BOUND).await.0, "succeeded");
    assert_eq!(facts(&shared.f, &r1), ("queued".into(), None, 0, 0));
    let after: String = db(&shared.f)
        .query_row(
            "SELECT resolved_json FROM jobs WHERE job_id=?1",
            [r1.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(after, r1_resolution, "exact captured resolution kept");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_failure_is_finalized_after_confirmed_cleanup() {
    let (shared, fixture) = prepared_store();
    let job = accept_r2(
        &shared.f,
        &fixture,
        "r2-fail",
        serde_json::json!({"fail_execution": true}),
    );
    let _handle = controller(&shared, fixture);
    let (state, outcome, held, _) = terminal_within(&shared.f, &job, BOUND).await;
    assert_eq!(
        (state.as_str(), outcome.as_deref()),
        ("failed", Some("worker_failed"))
    );
    assert_eq!(held, 0);
    assert_eq!(result_rows(&shared.f, &job), 0);
    assert_eq!(cleanup(&shared.f, &job).0, "confirmed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_worker_is_canceled_and_its_tree_cleaned_up() {
    let (shared, fixture) = prepared_store();
    let job = accept_r2(
        &shared.f,
        &fixture,
        "r2-hold",
        serde_json::json!({"hold_before_candidate": true}),
    );
    let handle = controller(&shared, fixture);
    super::execution_controller_tests::until_within("executing", BOUND, || {
        phase(&shared.f, &job) == "executing"
    })
    .await;
    let effect = shared
        .f
        .store
        .cancel_execution_job(authorize(&shared.f), job.clone())
        .unwrap();
    assert_eq!(effect, "requested");
    assert!(handle.signal(&job, StopIntent::UserCancel));
    let (state, _, held, _) = terminal_within(&shared.f, &job, BOUND).await;
    assert_eq!(state, "canceled");
    assert_eq!(held, 0);
    assert_eq!(result_rows(&shared.f, &job), 0);
    assert_eq!(cleanup(&shared.f, &job).0, "confirmed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_changed_after_preparation_is_never_launched() {
    let (shared, fixture) = prepared_store();
    let job = accept_r2(&shared.f, &fixture, "r2-tampered", serde_json::json!({}));
    let worker = shared
        .f
        .root
        .path()
        .join("execution-fixture/realization/worker");
    let mut bytes = std::fs::read(&worker).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&worker, bytes).unwrap();
    let _handle = controller(&shared, fixture);
    let (state, outcome, held, _) = terminal_within(&shared.f, &job, BOUND).await;
    assert_eq!(
        (state.as_str(), outcome.as_deref()),
        ("failed", Some("worker_launch_failed"))
    );
    assert_eq!(held, 0, "no process was started");
}
