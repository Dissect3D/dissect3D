//! WE-P06 controller against the real Store: one owner of dispatch turns,
//! the stop handle registered before launch, attempt-ID-keyed launch,
//! candidate -> publication, ended attempt -> finalization, and explicit
//! `NotOwned`/`Uncertain` handling without retry.
//!
//! The worker is the in-memory fake (codec/legality only, not a process or
//! cleanup proof); publication, finalization and dispatch are the real ones.
#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
use super::results::{PublicationReservation, ReclaimBatch};
use super::results_commit::{CommitOutcome, PublicationCommit, PublicationReceipt};
use super::retry_tests::{authorize, db};
use super::*;
use crate::execution::controller::{
    AttemptSource, ControllerStore, ExecutionDependencies, ExecutionHandle, ExecutionLimits,
    PreparedAttempt, ShutdownOutcome, Unreconciled, start,
};
use crate::execution::fake_worker::{Behavior, FakeLauncher, OnExecute, Record};
use crate::execution::scheduler::{DispatchStore, Eligibility};
use crate::execution::supervisor::LaunchLedger;
use crate::execution::supervisor_tests::{limits, plan};
use crate::execution::types::{StopIntent, SupervisionLimits};
use crate::publication::service::PublicationStore;
use crate::publication::storage::ResultLedger;
use crate::store::cleanup::AttemptRef;
use crate::store::execution::{DispatchRecord, DispatchRequest, QueuedCandidate};
use crate::store::finalize::{AttemptFinalization, AttemptObservation, FinalizationReceipt};
use crate::store::launch_identity::LaunchRecord;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const TETRAHEDRON: &[u8] = include_bytes!("../../tests/fixtures/submission/tetrahedron.obj");

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Accept one execution job with its own captured input. A long execution
/// timeout keeps the deadline out of these routing cases.
pub(super) fn accept(f: &Fixture, key: &str) -> (JobId, InputIdentity) {
    let input = f.capture();
    let request = f.request(&input);
    let job = f
        .store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse(key).unwrap(),
            request.clone(),
            f.candidate(&request),
        )
        .unwrap()
        .job_id;
    db(f)
        .execute(
            "UPDATE job_execution SET timeout_ms=600000 WHERE job_id=?1",
            [job.as_str()],
        )
        .unwrap();
    (job, input)
}

/// (state, outcome code, held reservations, attempt rows)
pub(super) fn facts(f: &Fixture, job: &JobId) -> (String, Option<String>, i64, i64) {
    db(f)
        .query_row(
            "SELECT e.state,e.outcome_code,
                    (SELECT count(*) FROM resource_reservations r JOIN job_attempts a
                      USING(attempt_id) WHERE a.job_id=e.job_id AND r.released=0),
                    (SELECT count(*) FROM job_attempts a WHERE a.job_id=e.job_id)
             FROM job_execution e WHERE e.job_id=?1",
            [job.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
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

/// Poll until `done` holds, failing instead of hanging.
pub(super) async fn until(what: &str, done: impl FnMut() -> bool) {
    until_within(what, Duration::from_secs(15), done).await
}
pub(super) async fn until_within(what: &str, bound: Duration, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + bound;
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
pub(super) async fn terminal(f: &Fixture, job: &JobId) -> (String, Option<String>, i64, i64) {
    terminal_within(f, job, Duration::from_secs(15)).await
}
/// Real worker processes hash their own (large, unoptimized) test binary
/// before `hello`, so process tests get a longer harness bound.
pub(super) async fn terminal_within(
    f: &Fixture,
    job: &JobId,
    bound: Duration,
) -> (String, Option<String>, i64, i64) {
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        let now = facts(f, job);
        if matches!(
            now.0.as_str(),
            "succeeded" | "failed" | "canceled" | "interrupted"
        ) {
            return now;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for a terminal state: {now:?} phase {}",
            db(f)
                .query_row(
                    "SELECT phase FROM job_execution WHERE job_id=?1",
                    [job.as_str()],
                    |r| r.get::<_, String>(0)
                )
                .unwrap()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[derive(Default)]
pub(super) struct Faults {
    /// Every dispatch reports a lost reply; nothing is committed.
    dispatch_lost: bool,
    /// Finalization answers Conflict without writing.
    finalize_conflict: bool,
    /// The success commit and the reconciling read both fail; nothing is committed.
    commit_lost: bool,
    /// Each queued job is offered twice in one page.
    duplicate_candidates: bool,
    /// Commit a user cancellation right after a successful dispatch, before
    /// the controller receives the record (so before registration).
    cancel_after_dispatch: Option<AuthContext>,
    /// The post-registration stop-intent read fails.
    stop_intent_lost: bool,
    /// This many control snapshot reads answer `Busy` first.
    snapshot_busy: Mutex<u32>,
}

/// The real Store, with optional injected faults and call counts.
pub(super) struct Shared {
    pub(super) f: Fixture,
    faults: Faults,
    commits: AtomicU32,
    finalizes: AtomicU32,
}
impl Shared {
    pub(super) fn new(f: Fixture, faults: Faults) -> Arc<Self> {
        Arc::new(Self {
            f,
            faults,
            commits: AtomicU32::new(0),
            finalizes: AtomicU32::new(0),
        })
    }
}
impl DispatchStore for Shared {
    fn queued_candidates(
        &self,
        after_sequence: i64,
        limit: usize,
    ) -> Result<Vec<QueuedCandidate>, CoreError> {
        let page = DispatchStore::queued_candidates(&self.f.store, after_sequence, limit)?;
        if self.faults.duplicate_candidates {
            return Ok(page.into_iter().flat_map(|c| [c.clone(), c]).collect());
        }
        Ok(page)
    }
    fn dispatch(&self, request: DispatchRequest) -> Result<DispatchRecord, CoreError> {
        if self.faults.dispatch_lost {
            return Err(CoreError::StoreUnavailable);
        }
        let record = DispatchStore::dispatch(&self.f.store, request)?;
        if let Some(auth) = &self.faults.cancel_after_dispatch {
            let effect = self
                .f
                .store
                .cancel_execution_job(auth.clone(), record.job_id.clone())
                .unwrap();
            assert_eq!(effect, "requested");
        }
        Ok(record)
    }
}
impl ResultLedger for Shared {
    fn reserve(&self, request: PublicationReservation) -> Result<(), CoreError> {
        ResultLedger::reserve(&self.f.store, request)
    }
    fn mark_prepared(&self, result_id: &str) -> Result<(), CoreError> {
        ResultLedger::mark_prepared(&self.f.store, result_id)
    }
    fn abandon(&self, result_id: &str) -> Result<(), CoreError> {
        ResultLedger::abandon(&self.f.store, result_id)
    }
    fn claim_reclaim(&self) -> Result<ReclaimBatch, CoreError> {
        ResultLedger::claim_reclaim(&self.f.store)
    }
    fn confirm_reclaimed(&self, objects: Vec<String>) -> Result<u64, CoreError> {
        ResultLedger::confirm_reclaimed(&self.f.store, objects)
    }
    fn known_objects(&self, names: Vec<String>) -> Result<Vec<String>, CoreError> {
        ResultLedger::known_objects(&self.f.store, names)
    }
}
impl PublicationStore for Shared {
    fn commit(&self, commit: PublicationCommit) -> Result<CommitOutcome, CoreError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        if self.faults.commit_lost {
            return Err(CoreError::StoreUnavailable);
        }
        PublicationStore::commit(&self.f.store, commit)
    }
    fn committed_for(&self, attempt_id: &str) -> Result<Option<PublicationReceipt>, CoreError> {
        if self.faults.commit_lost {
            return Err(CoreError::StoreUnavailable);
        }
        PublicationStore::committed_for(&self.f.store, attempt_id)
    }
    fn finalize(
        &self,
        finalization: AttemptFinalization,
    ) -> Result<FinalizationReceipt, CoreError> {
        self.finalizes.fetch_add(1, Ordering::SeqCst);
        if self.faults.finalize_conflict {
            return Err(CoreError::Conflict);
        }
        PublicationStore::finalize(&self.f.store, finalization)
    }
}
impl LaunchLedger for Shared {
    fn record_launch(&self, record: LaunchRecord) -> Result<(), CoreError> {
        LaunchLedger::record_launch(&self.f.store, record)
    }
}
impl ControllerStore for Shared {
    fn observe(&self, observation: AttemptObservation) -> Result<(), CoreError> {
        ControllerStore::observe(&self.f.store, observation)
    }
    fn stop_intent(&self, attempt: AttemptRef) -> Result<StopIntent, CoreError> {
        if self.faults.stop_intent_lost {
            return Err(CoreError::StoreUnavailable);
        }
        ControllerStore::stop_intent(&self.f.store, attempt)
    }
}
impl crate::execution::control::ControlStore for Shared {
    fn cancel(&self, auth: AuthContext, job: JobId) -> Result<&'static str, CoreError> {
        self.f.store.cancel_execution_job(auth, job)
    }
    fn snapshot(
        &self,
        auth: AuthContext,
        job: JobId,
    ) -> Result<dissect3d_api::ExecutionJobSnapshot, CoreError> {
        let mut busy = self.faults.snapshot_busy.lock().unwrap();
        if *busy > 0 {
            *busy -= 1;
            return Err(CoreError::Busy);
        }
        drop(busy);
        self.f.store.execution_job_snapshot(auth, job)
    }
    fn committed_snapshot(
        &self,
        auth: AuthContext,
        job: JobId,
    ) -> Result<dissect3d_api::ExecutionJobSnapshot, CoreError> {
        self.f.store.execution_job_snapshot_unconfirmed(auth, job)
    }
}

type Hook = Box<dyn Fn(&DispatchRecord) + Send + Sync>;

/// Test prepared support: every job is ready on one CPU resource; each
/// attempt gets a staging folder holding an exact copy of its input and a
/// fake worker that reports it.
struct Source {
    shared: Arc<Shared>,
    behavior: Behavior,
    inputs: Mutex<HashMap<JobId, InputIdentity>>,
    workers: Mutex<Vec<Arc<Record>>>,
    refuse: bool,
    /// Every worker's tree termination reports a cleanup fault.
    cleanup_fault: bool,
    /// Replaces the harness's short cooperative-cancel bound.
    cooperative: Option<Duration>,
    /// The eligibility check panics for this job.
    panic_for: Mutex<Option<JobId>>,
    /// The eligibility check blocks this job.
    blocked_for: Mutex<Option<JobId>>,
    /// Runs inside `prepare`, after the stop handle is registered.
    hook: Mutex<Option<Hook>>,
    prepared: AtomicU32,
}
impl Source {
    fn new(shared: &Arc<Shared>, behavior: Behavior) -> Self {
        let candidate = serde_json::json!({"description_handle": "output.json", "files": [
            {"relative_name": "mesh.obj", "byte_length": TETRAHEDRON.len(),
             "sha256": sha256(TETRAHEDRON)}
        ]});
        Self {
            shared: Arc::clone(shared),
            behavior: Behavior {
                candidate: Some(candidate),
                ..behavior
            },
            inputs: Mutex::new(HashMap::new()),
            workers: Mutex::new(Vec::new()),
            refuse: false,
            cleanup_fault: false,
            cooperative: None,
            panic_for: Mutex::new(None),
            blocked_for: Mutex::new(None),
            hook: Mutex::new(None),
            prepared: AtomicU32::new(0),
        }
    }
    fn input(&self, job: &JobId, input: InputIdentity) {
        self.inputs.lock().unwrap().insert(job.clone(), input);
    }
    fn launches(&self) -> u32 {
        let workers = self.workers.lock().unwrap();
        workers.iter().map(|w| Record::count(&w.launches)).sum()
    }
}
impl AttemptSource for Source {
    type Launcher = FakeLauncher;
    fn eligibility(&self, candidate: &QueuedCandidate) -> Eligibility {
        if self.panic_for.lock().unwrap().as_ref() == Some(&candidate.job_id) {
            panic!("eligibility check failed");
        }
        if self.blocked_for.lock().unwrap().as_ref() == Some(&candidate.job_id) {
            return Eligibility::Blocked("profile_not_executable");
        }
        Eligibility::Ready {
            resources: vec!["cpu:fixture".into()],
        }
    }
    fn prepare(&self, record: &DispatchRecord) -> Result<PreparedAttempt<FakeLauncher>, ()> {
        self.prepared.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = self.hook.lock().unwrap().as_ref() {
            hook(record);
        }
        if self.refuse {
            return Err(());
        }
        let root = &self.shared.f.root;
        let staging = root
            .create_attempt_root(
                &RelativePath::parse(format!("execution/attempts/{}/staging", record.attempt_id))
                    .unwrap(),
            )
            .map_err(|_| ())?;
        std::fs::write(staging.worker_path().join("mesh.obj"), TETRAHEDRON).unwrap();
        std::fs::write(
            staging.worker_path().join("output.json"),
            br#"{"mesh":["mesh.obj"]}"#,
        )
        .unwrap();
        let input = self.inputs.lock().unwrap()[&record.job_id].clone();
        let input_reader = root
            .open_immutable_input(
                &RelativePath::parse(format!("inputs/data/{}.bin", input.input_id.as_str()))
                    .unwrap(),
            )
            .map_err(|_| ())?;
        let (mut launcher, worker) = FakeLauncher::new(self.behavior.clone());
        if self.cleanup_fault {
            launcher.cleanup = Err(dissect3d_platform::CleanupFault::NativeFailure);
        }
        self.workers.lock().unwrap().push(worker);
        Ok(PreparedAttempt {
            plan: plan(SupervisionLimits {
                cooperative_cancel: self.cooperative.unwrap_or(limits().cooperative_cancel),
                ..limits()
            }),
            launcher,
            staging,
            input,
            input_reader,
        })
    }
}

fn controller(shared: &Arc<Shared>, source: &Arc<Source>, max_active: usize) -> ExecutionHandle {
    start(ExecutionDependencies {
        store: Arc::clone(shared),
        root: Arc::new(OwnedRoot::open(shared.f.root.path(), RootPurpose::EngineData).unwrap()),
        source: Arc::clone(source),
        limits: ExecutionLimits { max_active },
    })
}

pub(super) fn result_rows(f: &Fixture, job: &JobId) -> i64 {
    db(f)
        .query_row(
            "SELECT count(*) FROM results WHERE job_id=?1",
            [job.as_str()],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_candidate_is_published_and_only_publication_succeeds_the_job() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let source = Arc::new(Source::new(&shared, Behavior::default()));
    let (job, input) = accept(&shared.f, "ctl-publish");
    source.input(&job, input);
    let _handle = controller(&shared, &source, 1);
    let (state, outcome, held, attempts) = terminal(&shared.f, &job).await;
    assert_eq!(state, "succeeded");
    assert_eq!(outcome, None);
    assert_eq!(
        (held, attempts),
        (0, 1),
        "released after cleanup, one attempt"
    );
    assert_eq!(result_rows(&shared.f, &job), 1);
    assert_eq!(shared.commits.load(Ordering::SeqCst), 1);
    assert_eq!(shared.finalizes.load(Ordering::SeqCst), 0);
    assert_eq!(source.launches(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ended_attempt_is_finalized_with_its_cleanup_facts() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let behavior = Behavior {
        on_execute: OnExecute::Fail,
        ..Behavior::default()
    };
    let source = Arc::new(Source::new(&shared, behavior));
    let (job, input) = accept(&shared.f, "ctl-fail");
    source.input(&job, input);
    let _handle = controller(&shared, &source, 1);
    let (state, outcome, held, _) = terminal(&shared.f, &job).await;
    assert_eq!(
        (state.as_str(), outcome.as_deref()),
        ("failed", Some("worker_failed"))
    );
    assert_eq!(held, 0, "confirmed cleanup released the reservation");
    assert_eq!(result_rows(&shared.f, &job), 0);
    assert_eq!(shared.commits.load(Ordering::SeqCst), 0, "no publication");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_preparation_ends_the_attempt_without_a_process() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let mut source = Source::new(&shared, Behavior::default());
    source.refuse = true;
    let source = Arc::new(source);
    let (job, input) = accept(&shared.f, "ctl-refuse");
    source.input(&job, input);
    let _handle = controller(&shared, &source, 1);
    let (state, outcome, held, _) = terminal(&shared.f, &job).await;
    assert_eq!(
        (state.as_str(), outcome.as_deref()),
        ("failed", Some("worker_launch_failed"))
    );
    assert_eq!(held, 0, "no process was started, so nothing survives");
    assert_eq!(source.launches(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_jobs_run_one_at_a_time_in_acceptance_order() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let source = Arc::new(Source::new(&shared, Behavior::default()));
    let mut jobs = Vec::new();
    for key in ["ctl-a", "ctl-b", "ctl-c"] {
        let (job, input) = accept(&shared.f, key);
        source.input(&job, input);
        jobs.push(job);
    }
    // Record which job each attempt was for, in preparation order, and how
    // many were running when it started.
    let order = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&order);
    let probe = Arc::clone(&shared);
    *source.hook.lock().unwrap() = Some(Box::new(move |record: &DispatchRecord| {
        let running: i64 = db(&probe.f)
            .query_row(
                "SELECT count(*) FROM job_execution WHERE state='running'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        seen.lock().unwrap().push((record.job_id.clone(), running));
    }));
    let _handle = controller(&shared, &source, 1);
    for job in &jobs {
        assert_eq!(terminal(&shared.f, job).await.0, "succeeded");
    }
    let order = order.lock().unwrap().clone();
    assert_eq!(
        order.iter().map(|(j, _)| j.clone()).collect::<Vec<_>>(),
        jobs,
        "acceptance order"
    );
    assert!(order.iter().all(|(_, running)| *running == 1), "{order:?}");
    assert_eq!(source.launches(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stop_handle_is_registered_before_launch() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let source = Arc::new(Source::new(&shared, Behavior::default()));
    let (job, input) = accept(&shared.f, "ctl-early-cancel");
    source.input(&job, input);
    let auth = authorize(&shared.f);
    let handle = Arc::new(Mutex::new(None::<Arc<ExecutionHandle>>));
    let signaled = Arc::new(AtomicU32::new(0));
    {
        let handle = Arc::clone(&handle);
        let signaled = Arc::clone(&signaled);
        let probe = Arc::clone(&shared);
        let auth = auth.clone();
        // Cancel durably during preparation, then deliver it: the handle
        // must already be registered, and the worker never starts.
        *source.hook.lock().unwrap() = Some(Box::new(move |record: &DispatchRecord| {
            let effect = probe
                .f
                .store
                .cancel_execution_job(auth.clone(), record.job_id.clone())
                .unwrap();
            assert_eq!(effect, "requested");
            // The first turn can start before `start` returns.
            let handle = loop {
                if let Some(handle) = handle.lock().unwrap().clone() {
                    break handle;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            if handle.signal(&record.job_id, StopIntent::UserCancel) {
                signaled.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    let started = Arc::new(controller(&shared, &source, 1));
    *handle.lock().unwrap() = Some(Arc::clone(&started));
    let (state, _, held, _) = terminal(&shared.f, &job).await;
    assert_eq!(state, "canceled");
    assert_eq!(held, 0);
    assert_eq!(
        signaled.load(Ordering::SeqCst),
        1,
        "registered before launch"
    );
    assert_eq!(source.launches(), 0, "a canceled attempt never launches");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_running_attempt_persists_its_phase_and_stops_on_a_committed_cancel() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let behavior = Behavior {
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    };
    let source = Arc::new(Source::new(&shared, behavior));
    let (job, input) = accept(&shared.f, "ctl-hang");
    source.input(&job, input);
    let handle = controller(&shared, &source, 1);
    until("executing persisted", || {
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
    let (state, _, held, _) = terminal(&shared.f, &job).await;
    assert_eq!(state, "canceled");
    assert_eq!(held, 0);
    assert_eq!(shared.commits.load(Ordering::SeqCst), 0);
    let workers = source.workers.lock().unwrap();
    assert_eq!(workers[0].cancel_reasons(), vec!["user_cancel".to_owned()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicate_record_for_the_same_attempt_is_launched_once() {
    let faults = Faults {
        duplicate_candidates: true,
        ..Faults::default()
    };
    let shared = Shared::new(Fixture::new(), faults);
    let behavior = Behavior {
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    };
    let source = Arc::new(Source::new(&shared, behavior));
    let (job, input) = accept(&shared.f, "ctl-duplicate");
    source.input(&job, input);
    // Two slots, so the turn accepts the Store's repeated live record.
    let handle = controller(&shared, &source, 2);
    until("executing", || phase(&shared.f, &job) == "executing").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(source.prepared.load(Ordering::SeqCst), 1);
    assert_eq!(source.launches(), 1);
    shared
        .f
        .store
        .cancel_execution_job(authorize(&shared.f), job.clone())
        .unwrap();
    assert!(handle.signal(&job, StopIntent::UserCancel));
    assert_eq!(terminal(&shared.f, &job).await.0, "canceled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_owned_is_recorded_and_nothing_is_released_or_retried() {
    let faults = Faults {
        finalize_conflict: true,
        ..Faults::default()
    };
    let shared = Shared::new(Fixture::new(), faults);
    let behavior = Behavior {
        on_execute: OnExecute::Fail,
        ..Behavior::default()
    };
    let source = Arc::new(Source::new(&shared, behavior));
    let (first, input) = accept(&shared.f, "ctl-not-owned");
    source.input(&first, input);
    let (second, input) = accept(&shared.f, "ctl-after-not-owned");
    source.input(&second, input);
    let handle = controller(&shared, &source, 1);
    until("not owned recorded", || !handle.unreconciled().0.is_empty()).await;
    let (entries, overflow) = handle.unreconciled();
    assert_eq!(overflow, 0);
    assert!(
        matches!(&entries[..], [Unreconciled::NotOwned { job_id, .. }] if *job_id == first),
        "{entries:?}"
    );
    handle.wake();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Nothing assumed another writer finished it: still running, still held.
    let (state, _, held, attempts) = facts(&shared.f, &first);
    assert_eq!((state.as_str(), held, attempts), ("running", 1, 1));
    assert_eq!(shared.finalizes.load(Ordering::SeqCst), 1, "never retried");
    assert_eq!(source.launches(), 1);
    // The held resource keeps the next job queued.
    assert_eq!(facts(&shared.f, &second).0, "queued");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uncertain_publication_is_recorded_and_never_republished() {
    let faults = Faults {
        commit_lost: true,
        ..Faults::default()
    };
    let shared = Shared::new(Fixture::new(), faults);
    let source = Arc::new(Source::new(&shared, Behavior::default()));
    let (job, input) = accept(&shared.f, "ctl-uncertain");
    source.input(&job, input);
    let handle = controller(&shared, &source, 1);
    until("uncertain recorded", || !handle.unreconciled().0.is_empty()).await;
    let (entries, _) = handle.unreconciled();
    assert!(
        matches!(&entries[..], [Unreconciled::Uncertain { job_id, .. }] if *job_id == job),
        "{entries:?}"
    );
    handle.wake();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(shared.commits.load(Ordering::SeqCst), 1, "never retried");
    assert_eq!(
        shared.finalizes.load(Ordering::SeqCst),
        0,
        "failure not guessed"
    );
    let (state, _, held, _) = facts(&shared.f, &job);
    assert_eq!((state.as_str(), held), ("running", 1));
    assert_eq!(result_rows(&shared.f, &job), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uncertain_dispatch_is_recorded_and_nothing_launches() {
    let faults = Faults {
        dispatch_lost: true,
        ..Faults::default()
    };
    let shared = Shared::new(Fixture::new(), faults);
    let source = Arc::new(Source::new(&shared, Behavior::default()));
    let (job, input) = accept(&shared.f, "ctl-lost-dispatch");
    source.input(&job, input);
    let handle = controller(&shared, &source, 1);
    until("uncertain dispatch", || !handle.unreconciled().0.is_empty()).await;
    let (entries, _) = handle.unreconciled();
    assert_eq!(entries[0], Unreconciled::Dispatch(job.clone()));
    assert_eq!(source.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(facts(&shared.f, &job).0, "queued");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_handle_never_stops_a_running_attempt() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let behavior = Behavior {
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    };
    let source = Arc::new(Source::new(&shared, behavior));
    let (job, input) = accept(&shared.f, "ctl-drop-handle");
    source.input(&job, input);
    let handle = controller(&shared, &source, 1);
    until("executing", || phase(&shared.f, &job) == "executing").await;
    drop(handle);
    tokio::time::sleep(Duration::from_millis(300)).await;
    // No engine stop was committed, so the attempt keeps running.
    assert_eq!(facts(&shared.f, &job).0, "running");
    assert_eq!(phase(&shared.f, &job), "executing");
    let workers = source.workers.lock().unwrap();
    assert!(workers[0].cancel_reasons().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_eligibility_check_blocks_only_that_job() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let source = Arc::new(Source::new(&shared, Behavior::default()));
    let (broken, input) = accept(&shared.f, "ctl-eligibility-panic");
    source.input(&broken, input);
    let (next, input) = accept(&shared.f, "ctl-after-panic");
    source.input(&next, input);
    *source.panic_for.lock().unwrap() = Some(broken.clone());
    let handle = controller(&shared, &source, 1);
    assert_eq!(terminal(&shared.f, &next).await.0, "succeeded");
    // Still queued with its place, nothing reserved; the controller still runs.
    assert_eq!(facts(&shared.f, &broken), ("queued".into(), None, 0, 0));
    assert!(handle.unreconciled().0.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_committed_before_registration_is_read_and_nothing_launches() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let faults = Faults {
        cancel_after_dispatch: Some(auth),
        ..Faults::default()
    };
    let shared = Shared::new(f, faults);
    let source = Arc::new(Source::new(&shared, Behavior::default()));
    let (job, input) = accept(&shared.f, "ctl-cancel-window");
    source.input(&job, input);
    let _handle = controller(&shared, &source, 1);
    let (state, _, held, attempts) = terminal(&shared.f, &job).await;
    assert_eq!((state.as_str(), held, attempts), ("canceled", 0, 1));
    assert_eq!(source.prepared.load(Ordering::SeqCst), 0, "never prepared");
    assert_eq!(source.launches(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_commits_intent_then_delivers_it_and_reports_each_effect() {
    use crate::execution::control::cancel;
    use dissect3d_api::{CancelEffect, ExecutionJobState};
    let shared = Shared::new(Fixture::new(), Faults::default());
    let behavior = Behavior {
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    };
    let source = Arc::new(Source::new(&shared, behavior));
    let (running, input) = accept(&shared.f, "ctl-cancel-running");
    source.input(&running, input);
    let (queued, input) = accept(&shared.f, "ctl-cancel-queued");
    source.input(&queued, input);
    let auth = authorize(&shared.f);
    let handle = controller(&shared, &source, 1);
    until("executing", || phase(&shared.f, &running) == "executing").await;
    let store = Arc::clone(&shared);

    // The queued job (waiting for the CPU) is canceled without launch.
    let response = cancel(store.clone(), &handle, auth.clone(), queued.clone())
        .await
        .unwrap();
    assert_eq!(response.cancel_effect, CancelEffect::CanceledBeforeDispatch);
    assert_eq!(
        response.job_snapshot.summary.state,
        ExecutionJobState::Canceled
    );

    // The running job: intent first, reported as cancel_requested.
    let response = cancel(store.clone(), &handle, auth.clone(), running.clone())
        .await
        .unwrap();
    assert_eq!(response.cancel_effect, CancelEffect::Requested);
    assert!(matches!(
        response.job_snapshot.summary.state,
        ExecutionJobState::CancelRequested | ExecutionJobState::Canceled
    ));
    let (state, _, held, _) = terminal(&shared.f, &running).await;
    assert_eq!((state.as_str(), held), ("canceled", 0));
    let workers = source.workers.lock().unwrap().clone();
    assert_eq!(workers.len(), 1, "the queued job never launched");
    assert_eq!(workers[0].cancel_reasons(), vec!["user_cancel".to_owned()]);

    // Repeats reopen nothing.
    for job in [&running, &queued] {
        let response = cancel(store.clone(), &handle, auth.clone(), job.clone())
            .await
            .unwrap();
        assert_eq!(response.cancel_effect, CancelEffect::AlreadyTerminal);
    }
    let missing = JobId::parse(format!("job_{}", "7".repeat(32))).unwrap();
    let error = cancel(store, &handle, auth, missing).await.unwrap_err();
    assert_eq!(error.code, dissect3d_api::ErrorCode::NotFound);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_stop_intent_never_launches() {
    let faults = Faults {
        stop_intent_lost: true,
        ..Faults::default()
    };
    let shared = Shared::new(Fixture::new(), faults);
    let source = Arc::new(Source::new(&shared, Behavior::default()));
    let (job, input) = accept(&shared.f, "ctl-intent-lost");
    source.input(&job, input);
    let _handle = controller(&shared, &source, 1);
    let (state, outcome, held, _) = terminal(&shared.f, &job).await;
    assert_eq!(
        (state.as_str(), outcome.as_deref(), held),
        ("failed", Some("worker_launch_failed"), 0)
    );
    assert_eq!(source.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(source.launches(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_controller_publishes_current_queued_blockers_even_at_capacity() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let behavior = Behavior {
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    };
    let source = Arc::new(Source::new(&shared, behavior));
    let (running, input) = accept(&shared.f, "ctl-blk-running");
    source.input(&running, input);
    let handle = controller(&shared, &source, 1);
    until("executing", || phase(&shared.f, &running) == "executing").await;
    // Accepted while the only slot is busy: one blocked, one eligible.
    let (blocked, input) = accept(&shared.f, "ctl-blk-blocked");
    source.input(&blocked, input);
    let (waiting, input) = accept(&shared.f, "ctl-blk-waiting");
    source.input(&waiting, input);
    *source.blocked_for.lock().unwrap() = Some(blocked.clone());
    handle.wake();
    until("blocker published", || handle.blocker(&blocked).is_some()).await;
    assert_eq!(handle.blocker(&blocked), Some("profile_not_executable"));
    assert_eq!(handle.blocker(&waiting), None, "eligible, waiting its turn");
    assert_eq!(handle.blocker(&running), None, "not queued");
    // The snapshot carries the controller's answer, not a static one.
    let auth = authorize(&shared.f);
    let lookup = |job: &JobId| handle.blocker(job);
    let read = |job: &JobId| {
        shared
            .f
            .store
            .execution_job_snapshot_with(auth.clone(), job.clone(), Some(&lookup))
            .unwrap()
            .summary
            .blockers
    };
    assert_eq!(read(&blocked), vec!["profile_not_executable".to_owned()]);
    assert!(read(&waiting).is_empty());
    let cancel = |job: &JobId| {
        shared
            .f
            .store
            .cancel_execution_job(auth.clone(), job.clone())
            .unwrap()
    };
    for job in [&running, &blocked, &waiting] {
        cancel(job);
        handle.signal(job, StopIntent::UserCancel);
    }
    terminal(&shared.f, &running).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_committed_cancel_is_not_answered_with_a_transient_read_conflict() {
    use crate::execution::control::cancel;
    use dissect3d_api::CancelEffect;
    let faults = Faults {
        snapshot_busy: Mutex::new(5),
        ..Faults::default()
    };
    let shared = Shared::new(Fixture::new(), faults);
    let source = Arc::new(Source::new(&shared, Behavior::default()));
    let (job, input) = accept(&shared.f, "ctl-cancel-busy-read");
    source.input(&job, input);
    // No controller: the job stays queued and is canceled before dispatch.
    let handle = {
        let probe = Source::new(&shared, Behavior::default());
        *probe.blocked_for.lock().unwrap() = Some(job.clone());
        controller(&shared, &Arc::new(probe), 1)
    };
    let auth = authorize(&shared.f);
    let response = cancel(Arc::clone(&shared), &handle, auth, job.clone())
        .await
        .unwrap();
    assert_eq!(response.cancel_effect, CancelEffect::CanceledBeforeDispatch);
    assert_eq!(*shared.faults.snapshot_busy.lock().unwrap(), 0);
    assert_eq!(facts(&shared.f, &job).0, "canceled");
    let _ = source;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_committed_cancel_still_answers_when_every_confirmed_read_conflicts() {
    use crate::execution::control::cancel;
    use dissect3d_api::CancelEffect;
    // More conflicts than the bounded rereads: the committed cancel is
    // answered from one consistent read, never with Busy.
    let faults = Faults {
        snapshot_busy: Mutex::new(1_000),
        ..Faults::default()
    };
    let shared = Shared::new(Fixture::new(), faults);
    let (job, _) = accept(&shared.f, "ctl-cancel-churn");
    let handle = {
        let probe = Source::new(&shared, Behavior::default());
        *probe.blocked_for.lock().unwrap() = Some(job.clone());
        controller(&shared, &Arc::new(probe), 1)
    };
    let auth = authorize(&shared.f);
    let response = cancel(Arc::clone(&shared), &handle, auth, job.clone())
        .await
        .unwrap();
    assert_eq!(response.cancel_effect, CancelEffect::CanceledBeforeDispatch);
    assert_eq!(response.job_snapshot.summary.job_id, job);
    assert_eq!(
        response.job_snapshot.summary.state,
        dissect3d_api::ExecutionJobState::Canceled
    );
    assert_eq!(facts(&shared.f, &job).0, "canceled");
}

/// (state, outcome code, cleanup status) of one job.
fn outcome(f: &Fixture, job: &JobId) -> (String, Option<String>, String) {
    db(f)
        .query_row(
            "SELECT state,outcome_code,cleanup_status FROM job_execution WHERE job_id=?1",
            [job.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

/// WE-P07/3: engine shutdown stops a running worker, records it
/// `interrupted`/`engine_shutdown` after confirmed cleanup, dispatches
/// nothing new, keeps queued work queued, and reports clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_interrupts_running_work_keeps_queued_work_and_reports_clean() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let source = Arc::new(Source::new(
        &shared,
        Behavior {
            on_execute: OnExecute::Hang,
            ..Behavior::default()
        },
    ));
    let (running, input) = accept(&shared.f, "shutdown-running");
    source.input(&running, input);
    let (queued, input) = accept(&shared.f, "shutdown-queued");
    source.input(&queued, input);
    let handle = controller(&shared, &source, 1);
    until("executing", || phase(&shared.f, &running) == "executing").await;
    let result = handle
        .shutdown(std::time::Instant::now() + Duration::from_secs(5))
        .await;
    assert_eq!(result, ShutdownOutcome::Clean);
    assert_eq!(
        outcome(&shared.f, &running),
        (
            "interrupted".into(),
            Some("engine_shutdown".into()),
            "confirmed".into()
        )
    );
    assert_eq!(
        facts(&shared.f, &running).2,
        0,
        "holds released after cleanup"
    );
    // The slot is free, but shutdown dispatches nothing, even on a wake.
    handle.wake();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(facts(&shared.f, &queued), ("queued".into(), None, 0, 0));
}

/// WE-P07/3: a user cancellation committed before shutdown stays a
/// cancellation; shutdown only bounds its termination.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_keeps_an_earlier_user_cancellation() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let source = Arc::new(Source::new(
        &shared,
        Behavior {
            on_execute: OnExecute::Hang,
            ..Behavior::default()
        },
    ));
    let (job, input) = accept(&shared.f, "shutdown-cancelled");
    source.input(&job, input);
    let handle = controller(&shared, &source, 1);
    until("executing", || phase(&shared.f, &job) == "executing").await;
    // Committed but not yet delivered when shutdown begins.
    let auth = authorize(&shared.f);
    shared
        .f
        .store
        .cancel_execution_job(auth, job.clone())
        .unwrap();
    let result = handle
        .shutdown(std::time::Instant::now() + Duration::from_secs(5))
        .await;
    assert_eq!(result, ShutdownOutcome::Clean);
    let (state, _, cleanup) = outcome(&shared.f, &job);
    assert_eq!(
        (state.as_str(), cleanup.as_str()),
        ("canceled", "confirmed")
    );
}

/// WE-P07/3: every stop phase shares the remaining core deadline. A worker
/// that never acknowledges cancellation costs at most what is left, not the
/// 2-s cooperative bound plus the 5-s termination bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_phases_are_capped_by_the_shared_deadline() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let mut source = Source::new(
        &shared,
        Behavior {
            on_execute: OnExecute::Hang,
            cancel_ack: false,
            ..Behavior::default()
        },
    );
    // The contract's 2-s cooperative bound alone outlasts the deadline.
    source.cooperative = Some(SupervisionLimits::CONTRACT.cooperative_cancel);
    let source = Arc::new(source);
    let (job, input) = accept(&shared.f, "shutdown-silent");
    source.input(&job, input);
    let handle = controller(&shared, &source, 1);
    until("executing", || phase(&shared.f, &job) == "executing").await;
    let started = std::time::Instant::now();
    let result = handle.shutdown(started + Duration::from_millis(1500)).await;
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(1600), "{elapsed:?}");
    assert_eq!(result, ShutdownOutcome::Clean);
    assert_eq!(outcome(&shared.f, &job).0, "interrupted");
}

/// WE-P07/3, WE-005: uncertain worker cleanup is never a clean shutdown;
/// the outcome stays truthful and the holds stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_with_uncertain_cleanup_is_unconfirmed_and_keeps_holds() {
    let shared = Shared::new(Fixture::new(), Faults::default());
    let mut source = Source::new(
        &shared,
        Behavior {
            on_execute: OnExecute::Hang,
            ..Behavior::default()
        },
    );
    source.cleanup_fault = true;
    let source = Arc::new(source);
    let (job, input) = accept(&shared.f, "shutdown-fault");
    source.input(&job, input);
    let handle = controller(&shared, &source, 1);
    until("executing", || phase(&shared.f, &job) == "executing").await;
    let result = handle
        .shutdown(std::time::Instant::now() + Duration::from_secs(5))
        .await;
    assert_eq!(result, ShutdownOutcome::Unconfirmed);
    let (state, _, cleanup) = outcome(&shared.f, &job);
    assert_eq!((state.as_str(), cleanup.as_str()), ("interrupted", "fault"));
    assert_eq!(facts(&shared.f, &job).2, 1, "the reservation is still held");
}
